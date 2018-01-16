use std::mem;

use byteorder::ByteOrder;
use bytes::BufMut;
use failure::Error;
use nom::IResult;

use constants::kQuicFrameTypeSize;
use errors::QuicError;
use frames::{FromWire, ToWire};
use packet::QuicPacketHeader;
use types::{QuicFrameType, QuicStreamId, QuicVersion};

/// The `BLOCKED` frame is used to indicate to the remote endpoint
/// that this endpoint believes itself to be flow-control blocked
/// but otherwise ready to send data.
/// The BLOCKED frame is purely advisory and optional.
#[derive(Clone, Debug, PartialEq)]
pub struct QuicBlockedFrame {
    // The stream this frame applies to.  0 is a special case meaning the overall
    // connection rather than a specific stream.
    stream_id: QuicStreamId,
}

impl<'a> FromWire<'a> for QuicBlockedFrame {
    type Frame = QuicBlockedFrame;
    type Error = Error;

    fn parse(
        quic_version: QuicVersion,
        _header: &QuicPacketHeader,
        payload: &'a [u8],
    ) -> Result<(Self::Frame, &'a [u8]), Self::Error> {
        match parse_quic_blocked_frame(payload, quic_version) {
            IResult::Done(remaining, frame) => Ok((frame, remaining)),
            IResult::Incomplete(needed) => bail!(QuicError::IncompletePacket(needed)),
            IResult::Error(err) => bail!(QuicError::from(err)),
        }
    }
}

impl ToWire for QuicBlockedFrame {
    type Frame = QuicBlockedFrame;
    type Error = Error;

    fn frame_size(&self, _quic_version: QuicVersion, _header: &QuicPacketHeader) -> usize {
        // Frame Type
        kQuicFrameTypeSize +
        // Stream ID
        mem::size_of::<QuicStreamId>()
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
        buf.put_u8(QuicFrameType::Blocked as u8);
        // Stream ID
        buf.put_u32::<E>(self.stream_id);

        Ok(frame_size)
    }
}

named_args!(
    parse_quic_blocked_frame(quic_version: QuicVersion)<QuicBlockedFrame>, do_parse!(
        _frame_type: frame_type!(QuicFrameType::Blocked) >>
        stream_id: u32!(quic_version.endianness()) >>
        (
            QuicBlockedFrame {
                stream_id,
            }
        )
    )
);

#[cfg(test)]
mod tests {
    use super::*;

    const kStreamId: QuicStreamId = 0x01020304;

    #[test]
    fn blocked_frame() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        const test_cases: &[(QuicVersion, &[u8])] = &[
            (
                QuicVersion::QUIC_VERSION_38,
                &[
                    // frame type (blocked frame)
                    0x05,
                    // stream id
                    0x04, 0x03, 0x02, 0x01
                ],
            ),
            (
                QuicVersion::QUIC_VERSION_39,
                &[
                    // frame type (blocked frame)
                    0x05,
                    // stream id
                    0x01, 0x02, 0x03, 0x04
                ],
            ),
        ];

        let header = QuicPacketHeader::default();
        let blocked_frame = QuicBlockedFrame {
            stream_id: kStreamId,
        };

        for &(quic_version, payload) in test_cases {
            assert_eq!(
                blocked_frame.frame_size(quic_version, &header),
                payload.len()
            );
            assert_eq!(
                QuicBlockedFrame::parse(quic_version, &header, payload).unwrap(),
                (blocked_frame.clone(), &[][..]),
                "parse blocked frame, version {:?}",
                quic_version,
            );

            let mut buf = Vec::with_capacity(payload.len());

            assert_eq!(
                blocked_frame
                    .write_frame(quic_version, &header, &mut buf)
                    .unwrap(),
                buf.len()
            );
            assert_eq!(&buf, &payload);
        }
    }
}
