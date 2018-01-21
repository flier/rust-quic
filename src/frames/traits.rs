use byteorder::{ByteOrder, NativeEndian, NetworkEndian};
use bytes::BufMut;

use frames::QuicFrame;
use packet::QuicPacketHeader;
use types::{QuicTime, QuicTimeDelta, QuicVersion};

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

    fn read_frame<E, R>(reader: &'a R, payload: &'a [u8]) -> Result<(Self::Frame, &'a [u8]), Self::Error>
    where
        E: ByteOrder,
        R: QuicFrameReader<'a>;
}

pub trait WriteFrame<'a> {
    type Error;

    fn frame_size<W>(&self, writer: &W) -> usize
    where
        W: QuicFrameWriter<'a>;

    fn write_frame<E, W, B>(&self, writer: &W, buf: &mut B) -> Result<usize, Self::Error>
    where
        E: ByteOrder,
        W: QuicFrameWriter<'a>,
        B: BufMut;
}

pub trait QuicFrameReader<'a>
where
    Self: Sized,
{
    fn read_frame<F>(&'a self, payload: &'a [u8]) -> Result<(F::Frame, &'a [u8]), F::Error>
    where
        F: ReadFrame<'a>,
    {
        if self.quic_version() > QuicVersion::QUIC_VERSION_38 {
            F::read_frame::<NetworkEndian, Self>(self, payload)
        } else {
            F::read_frame::<NativeEndian, Self>(self, payload)
        }
    }

    fn read_frames(&'a self, payload: &'a [u8]) -> Frames<'a, Self> {
        Frames {
            reader: self,
            payload,
        }
    }

    fn packet_header(&self) -> &QuicPacketHeader;

    fn quic_version(&self) -> QuicVersion;

    fn creation_time(&self) -> QuicTime;

    fn last_timestamp(&self) -> QuicTimeDelta;
}

pub struct Frames<'a, R>
where
    R: 'a + QuicFrameReader<'a>,
{
    reader: &'a R,
    payload: &'a [u8],
}

impl<'a, R> Iterator for Frames<'a, R>
where
    R: 'a + QuicFrameReader<'a>,
{
    type Item = Result<QuicFrame<'a>, <QuicFrame<'a> as ReadFrame<'a>>::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.payload.is_empty() {
            match self.reader.read_frame::<QuicFrame<'a>>(self.payload) {
                Ok((frame, remaining)) => {
                    self.payload = remaining;

                    Some(Ok(frame))
                }
                Err(err) => {
                    self.payload = &[][..];

                    Some(Err(err))
                }
            }
        } else {
            None
        }
    }
}

pub trait QuicFrameWriter<'a>
where
    Self: Sized,
{
    fn write_frame<F, B>(&self, frame: &F, buf: &mut B) -> Result<usize, F::Error>
    where
        F: WriteFrame<'a>,
        B: BufMut,
    {
        if self.quic_version() > QuicVersion::QUIC_VERSION_38 {
            frame.write_frame::<NetworkEndian, Self, B>(self, buf)
        } else {
            frame.write_frame::<NativeEndian, Self, B>(self, buf)
        }
    }

    fn write_frames<I, F, B>(&self, frames: I, buf: &mut B) -> Result<usize, F::Error>
    where
        I: IntoIterator<Item = F>,
        F: WriteFrame<'a>,
        B: BufMut,
    {
        let mut wrote = 0;

        for frame in frames {
            wrote += self.write_frame(&frame, buf)?;
        }

        Ok(wrote)
    }

    fn packet_header(&self) -> &QuicPacketHeader;

    fn quic_version(&self) -> QuicVersion;

    fn creation_time(&self) -> QuicTime;
}

#[cfg(test)]
pub mod mocks {
    use time;

    use super::*;

    pub fn pair<'a>(quic_version: QuicVersion) -> (MockFrameReader<'a>, MockFrameWriter<'a>) {
        pair_with_header(quic_version, QuicPacketHeader::default())
    }

    pub fn pair_with_header<'a>(
        quic_version: QuicVersion,
        packet_header: QuicPacketHeader<'a>,
    ) -> (MockFrameReader<'a>, MockFrameWriter<'a>) {
        let creation_time = time::now().to_timespec();

        (
            MockFrameReader {
                quic_version,
                packet_header: packet_header.clone(),
                creation_time,
                last_timestamp: QuicTimeDelta::zero(),
            },
            MockFrameWriter {
                quic_version,
                packet_header: packet_header.clone(),
                creation_time,
                last_timestamp: QuicTimeDelta::zero(),
            },
        )
    }

    #[derive(Clone, Debug)]
    pub struct MockFrameReader<'a> {
        quic_version: QuicVersion,
        packet_header: QuicPacketHeader<'a>,
        creation_time: QuicTime,
        last_timestamp: QuicTimeDelta,
    }

    impl<'a> MockFrameReader<'a> {
        pub fn new(quic_version: QuicVersion) -> Self {
            MockFrameReader {
                quic_version,
                packet_header: QuicPacketHeader::default(),
                creation_time: time::now().to_timespec(),
                last_timestamp: QuicTimeDelta::zero(),
            }
        }
    }

    impl<'a> QuicFrameReader<'a> for MockFrameReader<'a> {
        fn packet_header(&self) -> &QuicPacketHeader {
            &self.packet_header
        }

        fn quic_version(&self) -> QuicVersion {
            self.quic_version
        }

        fn creation_time(&self) -> QuicTime {
            self.creation_time
        }

        fn last_timestamp(&self) -> QuicTimeDelta {
            self.last_timestamp
        }
    }

    #[derive(Clone, Debug)]
    pub struct MockFrameWriter<'a> {
        quic_version: QuicVersion,
        packet_header: QuicPacketHeader<'a>,
        creation_time: QuicTime,
        last_timestamp: QuicTimeDelta,
    }

    impl<'a> MockFrameWriter<'a> {
        pub fn new(quic_version: QuicVersion) -> Self {
            MockFrameWriter {
                quic_version,
                packet_header: QuicPacketHeader::default(),
                creation_time: time::now().to_timespec(),
                last_timestamp: QuicTimeDelta::zero(),
            }
        }
    }

    impl<'a> QuicFrameWriter<'a> for MockFrameWriter<'a> {
        fn packet_header(&self) -> &QuicPacketHeader {
            &self.packet_header
        }

        fn quic_version(&self) -> QuicVersion {
            self.quic_version
        }

        fn creation_time(&self) -> QuicTime {
            self.creation_time
        }
    }
}
