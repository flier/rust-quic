#![allow(non_upper_case_globals)]

use std::net::SocketAddr;
use std::ops::Deref;
use std::str::FromStr;

use byteorder::{BigEndian, ByteOrder, LittleEndian};
use bytes::Bytes;
use failure::{Error, Fail};
use nom::{Endianness, IResult, Needed, be_u64, be_u8};

use errors::QuicError;
use version::QuicVersion;

pub type QuicPacketNumberLength = u8;

const PACKET_1BYTE_PACKET_NUMBER: QuicPacketNumberLength = 1;
const PACKET_2BYTE_PACKET_NUMBER: QuicPacketNumberLength = 2;
const PACKET_4BYTE_PACKET_NUMBER: QuicPacketNumberLength = 4;
// TODO(rch): Remove this when we remove QUIC_VERSION_39.
const PACKET_6BYTE_PACKET_NUMBER: QuicPacketNumberLength = 6;
const PACKET_8BYTE_PACKET_NUMBER: QuicPacketNumberLength = 8;

pub type QuicPacketNumberLengthFlags = u8;

const PACKET_FLAGS_1BYTE_PACKET: QuicPacketNumberLengthFlags = 0; // 00
const PACKET_FLAGS_2BYTE_PACKET: QuicPacketNumberLengthFlags = 1; // 01
const PACKET_FLAGS_4BYTE_PACKET: QuicPacketNumberLengthFlags = 1 << 1; // 10
const PACKET_FLAGS_8BYTE_PACKET: QuicPacketNumberLengthFlags = 1 << 1 | 1; // 11

/// Number of bits the packet number length bits are shifted from the right edge of the public header.
const kPublicHeaderSequenceNumberShift: u8 = 4;
const kPublicHeaderSequenceNumberMask: u8 = 0x03;

bitflags! {
    pub struct PublicFlags: u8 {
        const PACKET_PUBLIC_FLAGS_NONE = 0;

        // Bit 0: Does the packet header contains version info?
        const PACKET_PUBLIC_FLAGS_VERSION = 1 << 0;

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
        const PACKET_PUBLIC_FLAGS_1BYTE_PACKET = PACKET_FLAGS_1BYTE_PACKET << kPublicHeaderSequenceNumberShift;
        const PACKET_PUBLIC_FLAGS_2BYTE_PACKET = PACKET_FLAGS_2BYTE_PACKET << kPublicHeaderSequenceNumberShift;
        const PACKET_PUBLIC_FLAGS_4BYTE_PACKET = PACKET_FLAGS_4BYTE_PACKET << kPublicHeaderSequenceNumberShift;
        const PACKET_PUBLIC_FLAGS_6BYTE_PACKET = PACKET_FLAGS_8BYTE_PACKET << kPublicHeaderSequenceNumberShift;

        // Reserved, unimplemented flags:

        // Bit 7: indicates the presence of a second flags byte.
        const PACKET_PUBLIC_FLAGS_TWO_OR_MORE_BYTES = 1 << 7;

        // All bits set (bits 6 and 7 are not currently used): 00111111
        const PACKET_PUBLIC_FLAGS_MAX = (1 << 6) - 1;
    }
}

pub type ConnectionId = u64;
pub type DiversificationNonce = [u8; 32];
pub type QuicPublicResetNonceProof = u64;
pub type PacketNumber = u64;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct QuicPacketPublicHeader<'a> {
    pub reset_flag: bool,
    pub connection_id: Option<ConnectionId>,
    pub packet_number_length: QuicPacketNumberLength,
    pub versions: Option<Vec<QuicVersion>>,
    pub nonce: Option<&'a DiversificationNonce>,
}

impl<'a> QuicPacketPublicHeader<'a> {
    pub fn parse<E>(buf: &[u8], is_server: bool) -> Result<(&[u8], QuicPacketPublicHeader), Error>
    where
        E: ByteOrder + ToEndianness,
    {
        match parse_public_header(buf, E::endianness(), is_server) {
            IResult::Done(remaining, public_header) => Ok((remaining, public_header)),
            IResult::Incomplete(needed) => {
                bail!(QuicError::IncompletePacket(needed).context("incomplete public header."))
            }
            IResult::Error(err) => bail!(QuicError::InvalidPacket(err).context("unable to process public header.")),
        }
    }
}

pub struct QuicPacketHeader<'a> {
    pub public_header: QuicPacketPublicHeader<'a>,
    pub packet_number: PacketNumber,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct QuicPublicResetPacket<'a> {
    pub public_header: QuicPacketPublicHeader<'a>,
    pub nonce_proof: QuicPublicResetNonceProof,
    pub client_address: Option<SocketAddr>,
}

pub trait ToEndianness {
    fn endianness() -> Endianness;
}

impl ToEndianness for LittleEndian {
    fn endianness() -> Endianness {
        Endianness::Little
    }
}

impl ToEndianness for BigEndian {
    fn endianness() -> Endianness {
        Endianness::Big
    }
}

#[derive(Clone, Debug)]
pub struct QuicData {}

#[derive(Clone, Debug)]
pub struct EncryptedPacket(Bytes);

impl Deref for EncryptedPacket {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

pub type QuicVersionNegotiationPacket<'a> = QuicPacketPublicHeader<'a>;

/// Recognizes big endian unsigned 8 bytes integer
#[inline]
pub fn be_u48(i: &[u8]) -> IResult<&[u8], u64> {
    if i.len() < 6 {
        IResult::Incomplete(Needed::Size(6))
    } else {
        let res = ((i[0] as u64) << 40) + ((i[1] as u64) << 32) + ((i[2] as u64) << 24) + ((i[3] as u64) << 16)
            + ((i[4] as u64) << 8) + i[5] as u64;
        IResult::Done(&i[6..], res)
    }
}

/// Recognizes little endian unsigned 8 bytes integer
#[inline]
pub fn le_u48(i: &[u8]) -> IResult<&[u8], u64> {
    if i.len() < 6 {
        IResult::Incomplete(Needed::Size(6))
    } else {
        let res = ((i[5] as u64) << 40) + ((i[4] as u64) << 32) + ((i[3] as u64) << 24) + ((i[2] as u64) << 16)
            + ((i[1] as u64) << 8) + i[0] as u64;
        IResult::Done(&i[6..], res)
    }
}

#[macro_export]
macro_rules! u48 ( ($i:expr, $e:expr) => ( {if Endianness::Big == $e { be_u48($i) } else { le_u48($i) } } ););

named_args!(parse_public_header(endianness: Endianness, is_server: bool)<QuicPacketPublicHeader>,
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
                packet_number_length: match packet_number_length_flag {
                    PACKET_FLAGS_1BYTE_PACKET => PACKET_1BYTE_PACKET_NUMBER,
                    PACKET_FLAGS_2BYTE_PACKET => PACKET_2BYTE_PACKET_NUMBER,
                    PACKET_FLAGS_4BYTE_PACKET => PACKET_4BYTE_PACKET_NUMBER,
                    PACKET_FLAGS_8BYTE_PACKET => PACKET_6BYTE_PACKET_NUMBER,
                    _ => unreachable!()
                },
            }
        )
    )
);

named!(pub quic_version<QuicVersion>, map_res!(take_str!(4), FromStr::from_str));

#[cfg(test)]
mod tests {
    use super::*;
    use packet::{ConnectionId, PacketNumber};

    const kConnectionId: ConnectionId = 0xFEDCBA9876543210;
    const kPacketNumber: PacketNumber = 0x123456789ABC;

    #[test]
    fn test_parse_public_header() {
        assert_matches!(
            parse_public_header(b"", Endianness::Little, true),
            IResult::Incomplete(Needed::Size(1))
        );

        // public flags (8 byte connection_id and 4 byte packet number)
        assert_matches!(
            parse_public_header(&[0x38], Endianness::Little, true),
            IResult::Incomplete(Needed::Size(9))
        );

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

        assert_eq!(
            parse_public_header(&packet38, Endianness::Little, true),
            IResult::Done(
                &[0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12][..],
                QuicPacketPublicHeader {
                    reset_flag: false,
                    connection_id: Some(kConnectionId),
                    versions: None,
                    nonce: None,
                    packet_number_length: PACKET_6BYTE_PACKET_NUMBER,
                }
            )
        );

        assert_eq!(
            parse_public_header(&packet39, Endianness::Big, true),
            IResult::Done(
                &[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC][..],
                QuicPacketPublicHeader {
                    reset_flag: false,
                    connection_id: Some(kConnectionId),
                    versions: None,
                    nonce: None,
                    packet_number_length: PACKET_6BYTE_PACKET_NUMBER,
                }
            )
        );
    }
}
