use byteorder::{ByteOrder, NativeEndian, NetworkEndian};
use bytes::BufMut;

use packet::QuicPacketHeader;
use types::QuicVersion;

pub trait FromWire<'a> {
    type Frame;
    type Error;

    fn parse(
        quic_version: QuicVersion,
        header: &QuicPacketHeader,
        payload: &'a [u8],
    ) -> Result<(Self::Frame, &'a [u8]), Self::Error>;
}

pub trait ToWire {
    type Frame;
    type Error;

    fn frame_size(&self, quic_version: QuicVersion, header: &QuicPacketHeader) -> usize;

    fn write_frame<T>(
        &self,
        quic_version: QuicVersion,
        header: &QuicPacketHeader,
        buf: &mut T,
    ) -> Result<usize, Self::Error>
    where
        T: BufMut,
    {
        if quic_version > QuicVersion::QUIC_VERSION_38 {
            self.write_to::<NetworkEndian, T>(quic_version, header, buf)
        } else {
            self.write_to::<NativeEndian, T>(quic_version, header, buf)
        }
    }

    fn write_to<E, T>(
        &self,
        quic_version: QuicVersion,
        header: &QuicPacketHeader,
        buf: &mut T,
    ) -> Result<usize, Self::Error>
    where
        E: ByteOrder,
        T: BufMut;
}

pub trait BufMutExt: BufMut {
    fn put_string_piece16<T: ByteOrder>(&mut self, s: Option<&str>) {
        self.put_u16::<T>(s.map(|s| s.len() as u16).unwrap_or(0));

        if let Some(s) = s {
            self.put_slice(s.as_bytes())
        }
    }

    fn put_bytes<T: ByteOrder>(&mut self, s: Option<&[u8]>) {
        if let Some(s) = s {
            self.put_u16::<T>(s.len() as u16);
            self.put_slice(s)
        }
    }
}

impl<T: BufMut> BufMutExt for T {}
