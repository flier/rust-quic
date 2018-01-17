use byteorder::{ByteOrder, NativeEndian, NetworkEndian};
use bytes::{Buf, BufMut};

use packet::QuicPacketHeader;
use types::{QuicTime, QuicTimeDelta, QuicVersion};

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

pub trait ReadFrame<'a> {
    type Frame;
    type Error;

    fn read_frame<E, R>(reader: &mut R) -> Result<Self::Frame, Self::Error>
    where
        E: ByteOrder,
        R: QuicFrameReader<'a>;
}

pub trait WriteFrame<'a> {
    type Error;

    fn write_frame<E, W>(&self, writer: &mut W) -> Result<usize, Self::Error>
    where
        E: ByteOrder,
        W: QuicFrameWriter<'a>;
}

pub trait QuicFrameReader<'a>: Buf
where
    Self: Sized,
{
    fn read_frame<F: ReadFrame<'a>>(&mut self) -> Result<F::Frame, F::Error> {
        if self.quic_version() > QuicVersion::QUIC_VERSION_38 {
            F::read_frame::<NetworkEndian, Self>(self)
        } else {
            F::read_frame::<NativeEndian, Self>(self)
        }
    }

    fn packet_header(&self) -> &QuicPacketHeader;

    fn quic_version(&self) -> QuicVersion;

    fn creation_time(&self) -> QuicTime;

    fn last_timestamp(&self) -> QuicTimeDelta;
}

pub trait QuicFrameWriter<'a>: BufMut
where
    Self: Sized,
{
    fn write_frame<F: WriteFrame<'a>>(&mut self, frame: F) -> Result<usize, F::Error> {
        if self.quic_version() > QuicVersion::QUIC_VERSION_38 {
            frame.write_frame::<NetworkEndian, Self>(self)
        } else {
            frame.write_frame::<NativeEndian, Self>(self)
        }
    }

    fn packet_header(&self) -> &QuicPacketHeader;

    fn quic_version(&self) -> QuicVersion;

    fn creation_time(&self) -> QuicTime;
}
