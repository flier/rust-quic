use byteorder::ByteOrder;
use bytes::BufMut;
use failure::Error;
use nom::Needed;

use constants::kQuicFrameTypeSize;
use errors::QuicError;
use frames::{FromWire, ToWire};
use packet::QuicPacketHeader;
use types::{QuicFrameType, QuicVersion};

/// A ping frame contains no payload, though it is retransmittable,
/// and ACK'd just like other normal frames.
#[derive(Clone, Debug, PartialEq)]
pub struct QuicPingFrame {}

impl<'a> FromWire<'a> for QuicPingFrame {
    type Frame = QuicPingFrame;
    type Error = Error;

    fn parse(
        _quic_version: QuicVersion,
        _header: &QuicPacketHeader,
        payload: &'a [u8],
    ) -> Result<(Self::Frame, &'a [u8]), Self::Error> {
        match payload.split_first() {
            Some((&frame_type, remaining)) if frame_type == QuicFrameType::Ping as u8 => {
                Ok((QuicPingFrame {}, remaining))
            },
            Some((&frame_type, _)) => bail!(QuicError::IllegalFrameType(frame_type)),
            _ => bail!(QuicError::IncompletePacket(Needed::Size(kQuicFrameTypeSize))),
        }
    }
}

impl ToWire for QuicPingFrame {
    type Frame = QuicPingFrame;
    type Error = Error;

    fn frame_size(&self, _quic_version: QuicVersion, _header: &QuicPacketHeader) -> usize {
        // Frame Type
        kQuicFrameTypeSize
    }

    fn write_to<E, T>(
        &self,
        quic_version: QuicVersion,
        header: &QuicPacketHeader,
        buf: &mut T,
    ) -> Result<usize, Self::Error>
    where
        E: ByteOrder,
        T: BufMut,
    {
        let frame_size = self.frame_size(quic_version, header);

        if buf.remaining_mut() < frame_size {
            bail!(QuicError::NotEnoughBuffer(frame_size))
        }

        // Frame Type
        buf.put_u8(QuicFrameType::Ping as u8);

        Ok(frame_size)
    }
}
