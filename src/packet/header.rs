#![allow(dead_code, non_upper_case_globals)]

use std::mem;
use std::ops::Deref;
use std::str::FromStr;

use byteorder::{ByteOrder, NetworkEndian};
use bytes::BufMut;
use failure::Error;
use nom::{IResult, Needed, be_u64, be_u8};

use constants::{kPublicFlagsSize, kQuicVersionSize};
use errors::QuicError::{self, IncompletePacket};
use proto::{QuicConnectionId, QuicPacketNumber, QuicPacketNumberLength, QuicPacketNumberLengthFlags};
use types::{QuicDiversificationNonce, QuicTag, QuicVersion};

const kPublicHeaderConnectionIdSize: usize = 8;

/// `kDiversificationNonceSize` is the size, in bytes,
/// of the nonce that a server may set in the packet header
/// to ensure that its INITIAL keys are not duplicated.
const kDiversificationNonceSize: usize = 32;

/// Number of bits the packet number length bits are shifted from the right edge of the public header.
const kPublicHeaderSequenceNumberShift: u8 = 4;
const kPublicHeaderSequenceNumberMask: u8 = 0x03;

bitflags! {
    pub struct PublicFlags: u8 {
        const PACKET_PUBLIC_FLAGS_NONE = 0;

        // Bit 0: Does the packet header contains version info?
        const PACKET_PUBLIC_FLAGS_VERSION = 1;

        // Bit 1: Is this packet a public reset packet?
        const PACKET_PUBLIC_FLAGS_RST = 1 << 1;

        // Bit 2: indicates the that public header includes a nonce.
        const PACKET_PUBLIC_FLAGS_NONCE = 1 << 2;

        // Bit 3: indicates whether a ConnectionID is included.
        const PACKET_PUBLIC_FLAGS_0BYTE_CONNECTION_ID = 0;
        const PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID = 1 << 3;

        // QUIC_VERSION_32 and earlier use two bits for an 8 byte
        // connection id.
        const PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID_OLD = 1 << 3 | 1 << 2;

        // Bits 4 and 5 describe the packet number length as follows:
        // --00----: 1 byte
        // --01----: 2 bytes
        // --10----: 4 bytes
        // --11----: 6 bytes

        // Reserved, unimplemented flags:

        // Bit 7: indicates the presence of a second flags byte.
        const PACKET_PUBLIC_FLAGS_TWO_OR_MORE_BYTES = 1 << 7;

        // All bits set (bits 6 and 7 are not currently used): 00111111
        const PACKET_PUBLIC_FLAGS_MAX = (1 << 6) - 1;
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct QuicPacketPublicHeader<'a> {
    pub reset_flag: bool,
    pub connection_id: Option<QuicConnectionId>,
    pub packet_number_length: QuicPacketNumberLength,
    pub versions: Option<Vec<QuicVersion>>,
    pub nonce: Option<&'a QuicDiversificationNonce>,
}

impl<'a> QuicPacketPublicHeader<'a> {
    pub fn parse(buf: &[u8], is_server: bool) -> Result<(QuicPacketPublicHeader, &[u8]), Error> {
        match parse_public_header(buf, is_server) {
            IResult::Done(remaining, header) => Ok((header, remaining)),
            IResult::Incomplete(needed) => bail!(IncompletePacket(needed)),
            IResult::Error(err) => bail!(QuicError::from(err)),
        }
    }

    pub fn size(&self) -> usize {
        kPublicFlagsSize + if self.connection_id.is_some() {
            kPublicHeaderConnectionIdSize
        } else {
            0
        } + if self.versions.is_some() {
            kQuicVersionSize
        } else {
            0
        } + if self.nonce.is_some() {
            kDiversificationNonceSize
        } else {
            0
        } + self.packet_number_length as usize
    }

    pub fn write_to<E, B>(&self, buf: &mut B) -> Result<usize, Error>
    where
        E: ByteOrder,
        B: BufMut,
    {
        let mut public_flags = PublicFlags::PACKET_PUBLIC_FLAGS_NONE;

        if self.reset_flag {
            public_flags |= PublicFlags::PACKET_PUBLIC_FLAGS_RST;
        }
        if self.versions.is_some() {
            public_flags |= PublicFlags::PACKET_PUBLIC_FLAGS_VERSION;
        }
        if self.nonce.is_some() {
            public_flags |= PublicFlags::PACKET_PUBLIC_FLAGS_NONCE;
        }
        if self.connection_id.is_some() {
            public_flags |= PublicFlags::PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID
        } else {
            public_flags |= PublicFlags::PACKET_PUBLIC_FLAGS_0BYTE_CONNECTION_ID;
        }

        buf.put_u8(
            public_flags.bits() | (self.packet_number_length.as_flags() as u8) << kPublicHeaderSequenceNumberShift,
        );

        let mut wrote = 1;

        if let Some(connection_id) = self.connection_id {
            buf.put_u64::<NetworkEndian>(connection_id);

            wrote += mem::size_of::<u64>();
        }

        if let Some(ref versions) = self.versions {
            if let Some(&version) = versions.first() {
                buf.put_slice(QuicTag::from(version).as_bytes());

                wrote += mem::size_of::<u32>();
            }
        }

        if let Some(nonce) = self.nonce {
            buf.put_slice(nonce);

            wrote += nonce.len();
        }

        Ok(wrote)
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct QuicPacketHeader<'a> {
    pub public_header: QuicPacketPublicHeader<'a>,
    pub packet_number: QuicPacketNumber,
}

impl<'a> QuicPacketHeader<'a> {
    pub fn parse<E>(buf: &'a [u8], is_server: bool) -> Result<(QuicPacketHeader<'a>, &[u8]), Error>
    where
        E: ByteOrder,
    {
        let (public_header, remaining) = QuicPacketPublicHeader::parse(buf, is_server)?;
        let packet_number_length = public_header.packet_number_length as usize;

        if remaining.len() < packet_number_length {
            bail!(IncompletePacket(Needed::Size(packet_number_length)));
        }

        let packet_number = E::read_uint(remaining, packet_number_length);

        Ok((
            QuicPacketHeader {
                public_header,
                packet_number,
            },
            &remaining[packet_number_length..],
        ))
    }

    pub fn size(&self) -> usize {
        self.public_header.size() + self.packet_number_length as usize
    }

    pub fn write_to<E, B>(&self, buf: &mut B) -> Result<usize, Error>
    where
        E: ByteOrder,
        B: BufMut,
    {
        let header_size = self.public_header.write_to::<E, B>(buf)?;

        buf.put_uint::<E>(
            self.packet_number,
            self.public_header.packet_number_length as usize,
        );

        Ok(header_size + self.packet_number_length as usize)
    }
}

impl<'a> Deref for QuicPacketHeader<'a> {
    type Target = QuicPacketPublicHeader<'a>;

    fn deref(&self) -> &Self::Target {
        &self.public_header
    }
}

named_args!(parse_public_header(is_server: bool)<QuicPacketPublicHeader>,
    do_parse!(
        public_flags: map!(call!(be_u8), PublicFlags::from_bits_truncate) >>

        reset_flag: value!(public_flags.contains(PublicFlags::PACKET_PUBLIC_FLAGS_RST)) >>

        connection_id_flag: value!(public_flags.contains(PublicFlags::PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID)) >>
        connection_id: cond!(connection_id_flag, be_u64) >>

        version_flag: value!(public_flags.contains(PublicFlags::PACKET_PUBLIC_FLAGS_VERSION)) >>
        server_version: cond!(version_flag && is_server, quic_version) >>

        nonce_flag: value!(public_flags.contains(PublicFlags::PACKET_PUBLIC_FLAGS_NONCE)) >>
        nonce: cond!(!is_server && nonce_flag && !reset_flag && !version_flag, take!(32)) >>

        packet_number_length_flag: value!(
            (public_flags.bits() >> kPublicHeaderSequenceNumberShift) & kPublicHeaderSequenceNumberMask
        ) >>
        (
            QuicPacketPublicHeader{
                reset_flag,
                connection_id,
                versions: server_version.map(|version| vec![version]),
                nonce: nonce.map(|nonce| array_ref!(nonce, 0, 32)),
                packet_number_length:
                    QuicPacketNumberLength::read(QuicPacketNumberLengthFlags::from(packet_number_length_flag)),
            }
        )
    )
);

named!(pub quic_version<QuicVersion>, map_res!(take_str!(4), FromStr::from_str));

#[cfg(test)]
mod tests {
    use byteorder::NativeEndian;

    use super::*;

    const kConnectionId: QuicConnectionId = 0xFEDCBA9876543210;
    const kPacketNumber: QuicPacketNumber = 0x123456789ABC;

    #[test]
    fn public_header() {
        assert_matches!(
            parse_public_header(b"", true),
            IResult::Incomplete(Needed::Size(1))
        );

        // public flags (8 byte connection_id and 4 byte packet number)
        assert_matches!(
            parse_public_header(&[0x38], true),
            IResult::Incomplete(Needed::Size(9))
        );
    }

    #[test]
    fn packet_header() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        let packet38 = [
            // public flags (8 byte connection_id)
            0x38,
            // connection_id
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            // packet number
            0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,
        ];

        #[cfg_attr(rustfmt, rustfmt_skip)]
        let packet39 = [
            // public flags (8 byte connection_id)
            0x38,
            // connection_id
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            // packet number
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
        ];

        let packet_header = QuicPacketHeader {
            public_header: QuicPacketPublicHeader {
                reset_flag: false,
                connection_id: Some(kConnectionId),
                versions: None,
                nonce: None,
                packet_number_length: QuicPacketNumberLength::PACKET_6BYTE_PACKET_NUMBER,
            },
            packet_number: kPacketNumber,
        };

        assert_eq!(
            QuicPacketHeader::parse::<NativeEndian>(&packet38, true).unwrap(),
            (packet_header.clone(), &[][..],)
        );

        assert_eq!(
            QuicPacketHeader::parse::<NetworkEndian>(&packet39, true).unwrap(),
            (packet_header.clone(), &[][..],)
        );

        let mut buf = vec![];

        assert_eq!(
            packet_header.write_to::<NativeEndian, _>(&mut buf).unwrap(),
            packet38.len()
        );
        assert_eq!(buf.as_slice(), packet38);

        buf.clear();

        assert_eq!(
            packet_header
                .write_to::<NetworkEndian, _>(&mut buf)
                .unwrap(),
            packet39.len()
        );
        assert_eq!(buf.as_slice(), packet39);
    }
}
