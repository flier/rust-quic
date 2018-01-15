use std::mem;

use failure::{Error, Fail};
use nom::IResult;

use errors::QuicError;
use frames::kQuicFrameTypeSize;
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

impl QuicBlockedFrame {
    pub fn parse(quic_version: QuicVersion, payload: &[u8]) -> Result<(QuicBlockedFrame, &[u8]), Error> {
        match parse_quic_blocked_frame(payload, quic_version) {
            IResult::Done(remaining, frame) => Ok((frame, remaining)),
            IResult::Incomplete(needed) => {
                bail!(QuicError::IncompletePacket(needed).context("incomplete blocked frame."))
            }
            IResult::Error(err) => bail!(QuicError::from(err).context("unable to process blocked frame.")),
        }
    }

    pub fn frame_size(&self) -> usize {
        kQuicFrameTypeSize + mem::size_of::<QuicStreamId>()
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
    fn parse_blocked_frame() {
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

        let blocked_frame = QuicBlockedFrame {
            stream_id: kStreamId,
        };

        for &(quic_version, bytes) in test_cases {
            assert_eq!(blocked_frame.frame_size(), bytes.len());
            assert_eq!(
                QuicBlockedFrame::parse(quic_version, bytes).unwrap(),
                (blocked_frame.clone(), &[][..]),
                "parse blocked frame, version {:?}",
                quic_version,
            );
        }
    }
}
