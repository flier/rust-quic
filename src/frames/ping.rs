use byteorder::ByteOrder;
use bytes::BufMut;
use failure::Error;
use nom::Needed;

use errors::QuicError;
use framer::kQuicFrameTypeSize;
use frames::{QuicFrameReader, QuicFrameWriter, ReadFrame, WriteFrame};
use types::QuicFrameType;

/// A ping frame contains no payload, though it is retransmittable,
/// and ACK'd just like other normal frames.
#[derive(Clone, Debug, PartialEq)]
pub struct QuicPingFrame {}

impl<'a> ReadFrame<'a> for QuicPingFrame {
    type Frame = QuicPingFrame;
    type Error = Error;

    fn read_frame<E, R>(_reader: &R, payload: &'a [u8]) -> Result<(Self::Frame, &'a [u8]), Self::Error>
    where
        E: ByteOrder,
        R: QuicFrameReader<'a>,
    {
        match payload.split_first() {
            Some((&frame_type, remaining)) if frame_type == QuicFrameType::Ping as u8 => {
                Ok((QuicPingFrame {}, remaining))
            }
            Some((&frame_type, _)) => bail!(QuicError::IllegalFrameType(frame_type)),
            _ => bail!(QuicError::IncompletePacket(Needed::Size(
                kQuicFrameTypeSize
            ))),
        }
    }
}

impl<'a> WriteFrame<'a> for QuicPingFrame {
    type Error = Error;

    fn frame_size<W>(&self, _writer: &W) -> usize
    where
        W: QuicFrameWriter<'a>,
    {
        // Frame Type
        kQuicFrameTypeSize
    }

    fn write_frame<E, W, B>(&self, writer: &W, buf: &mut B) -> Result<usize, Self::Error>
    where
        E: ByteOrder,
        W: QuicFrameWriter<'a>,
        B: BufMut,
    {
        let frame_size = self.frame_size(writer);

        if buf.remaining_mut() < frame_size {
            bail!(QuicError::NotEnoughBuffer(frame_size))
        }

        // Frame Type
        buf.put_u8(QuicFrameType::Ping as u8);

        Ok(frame_size)
    }
}
