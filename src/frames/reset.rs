use failure::{Error, Fail};
use nom::IResult;
use num::FromPrimitive;

use errors::{QuicError, QuicRstStreamErrorCode};
use types::{QuicStreamId, QuicStreamOffset, QuicVersion};

/// The `RST_STREAM` frame allows for abnormal termination of a stream.
///
/// When sent by the creator of a stream, it indicates the creator wishes to cancel the stream.
/// When sent by the receiver of a stream, it indicates an error
/// or that the receiver did not want to accept the stream, so the stream should be closed.
#[derive(Clone, Debug, PartialEq)]
pub struct QuicRstStreamFrame {
    pub stream_id: QuicStreamId,
    pub error_code: QuicRstStreamErrorCode,
    pub byte_offset: QuicStreamOffset,
}

impl QuicRstStreamFrame {
    pub fn parse(quic_version: QuicVersion, payload: &[u8]) -> Result<(QuicRstStreamFrame, &[u8]), Error> {
        match parse_quic_reset_stream_frame(payload, quic_version) {
            IResult::Done(remaining, frame) => Ok((frame, remaining)),
            IResult::Incomplete(needed) => {
                bail!(QuicError::IncompletePacket(needed).context("incomplete reset frame."))
            }
            IResult::Error(err) => bail!(QuicError::from(err).context("unable to process reset frame.")),
        }
    }
}

named_args!(
    parse_quic_reset_stream_frame(quic_version: QuicVersion)<QuicRstStreamFrame>, do_parse!(
        stream_id: u32!(quic_version.endianness()) >>
        byte_offset_pre40: cond!(quic_version <= QuicVersion::QUIC_VERSION_39, u64!(quic_version.endianness())) >>
        error_code: apply!(reset_stream_error_code, quic_version.endianness()) >>
        byte_offset_new: cond!(quic_version > QuicVersion::QUIC_VERSION_39, u64!(quic_version.endianness())) >>
        byte_offset: expr_opt!(byte_offset_pre40.or(byte_offset_new)) >>
        (
            QuicRstStreamFrame {
                stream_id,
                error_code,
                byte_offset,
            }
        )
    )
);

named_args!(
    reset_stream_error_code(endianness: ::nom::Endianness)<QuicRstStreamErrorCode>, map!(u32!(endianness), |code| {
        QuicRstStreamErrorCode::from_u32(code).unwrap_or(QuicRstStreamErrorCode::QUIC_STREAM_LAST_ERROR)
    })
);

#[cfg(test)]
mod tests {
    use super::*;

    const kStreamId: QuicStreamId = 0x01020304;
    const kStreamOffset: QuicStreamOffset = 0xBA98FEDC32107654;

    #[test]
    fn parse_reset_frame() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        const test_cases: &[(QuicVersion, &[u8])] = &[
            (
                QuicVersion::QUIC_VERSION_38,
                &[
                    // stream id
                    0x04, 0x03, 0x02, 0x01,
                    // sent byte offset
                    0x54, 0x76, 0x10, 0x32,
                    0xDC, 0xFE, 0x98, 0xBA,
                    // error code
                    0x01, 0x00, 0x00, 0x00,
                ],
            ),
            (
                QuicVersion::QUIC_VERSION_39,
                &[
                    // stream id
                    0x01, 0x02, 0x03, 0x04,
                    // offset
                    0xBA, 0x98, 0xFE, 0xDC,
                    0x32, 0x10, 0x76, 0x54,
                    // error code
                    0x00, 0x00, 0x00, 0x01,
                ],
            ),
            (
                QuicVersion::QUIC_VERSION_40,
                &[
                    // stream id
                    0x01, 0x02, 0x03, 0x04,
                    // error code
                    0x00, 0x00, 0x00, 0x01,
                    // offset
                    0xBA, 0x98, 0xFE, 0xDC,
                    0x32, 0x10, 0x76, 0x54,
                ],
            ),
        ];

        let reset_stream_frame = QuicRstStreamFrame {
            stream_id: kStreamId,
            error_code: QuicRstStreamErrorCode::QUIC_ERROR_PROCESSING_STREAM,
            byte_offset: kStreamOffset,
        };

        for &(quic_version, packet) in test_cases {
            assert_eq!(
                QuicRstStreamFrame::parse(quic_version, packet).unwrap(),
                (reset_stream_frame.clone(), &[][..]),
                "parse reset stream frame, version {:?}",
                quic_version,
            );
        }
    }
}
