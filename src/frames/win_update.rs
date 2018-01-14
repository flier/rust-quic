use failure::{Error, Fail};
use nom::IResult;

use errors::QuicError;
use types::{QuicStreamId, QuicStreamOffset, QuicVersion};

/// The GOAWAY frame allows for notification that the connection should stop being used,
/// and will likely be aborted in the future. Any active streams will continue to be processed,
/// but the sender of the GOAWAY will not initiate any additional streams, and will not accept any new streams.
#[derive(Clone, Debug, PartialEq)]
pub struct QuicWindowUpdateFrame {
    /// The stream this frame applies to.
    ///
    /// 0 is a special case meaning the overall connection rather than a specific stream.
    stream_id: QuicStreamId,
    /// Byte offset in the stream or connection.
    ///
    /// The receiver of this frame must not send data which would result in this offset being exceeded.
    byte_offset: QuicStreamOffset,
}

impl QuicWindowUpdateFrame {
    pub fn parse(quic_version: QuicVersion, payload: &[u8]) -> Result<(QuicWindowUpdateFrame, &[u8]), Error> {
        match parse_quic_window_update_frame(payload, quic_version) {
            IResult::Done(remaining, frame) => Ok((frame, remaining)),
            IResult::Incomplete(needed) => {
                bail!(QuicError::IncompletePacket(needed).context("incomplete window update frame."))
            }
            IResult::Error(err) => bail!(QuicError::from(err).context("unable to process window update frame.")),
        }
    }
}

named_args!(
    parse_quic_window_update_frame(quic_version: QuicVersion)<QuicWindowUpdateFrame>, do_parse!(
        stream_id: u32!(quic_version.endianness()) >>
        byte_offset: u64!(quic_version.endianness()) >>
        (
            QuicWindowUpdateFrame {
                stream_id,
                byte_offset,
            }
        )
    )
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_window_update_frame() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        const test_cases: &[(QuicVersion, &[u8])] = &[
            (
                QuicVersion::QUIC_VERSION_38,
                &[
                    // stream id
                    0x04, 0x03, 0x02, 0x01,
                    // byte offset
                    0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0a, 0x0b, 0x0c,
                ],
            ),
            (
                QuicVersion::QUIC_VERSION_39,
                &[
                    // stream id
                    0x01, 0x02, 0x03, 0x04,
                    // error details length
                    0x0c, 0x0b, 0x0a, 0x09,
                    0x08, 0x07, 0x06, 0x05,
                ],
            ),
        ];

        let window_update_frame = QuicWindowUpdateFrame {
            stream_id: 0x01020304,
            byte_offset: 0x0c0b0a0908070605,
        };

        for &(quic_version, bytes) in test_cases {
            assert_eq!(
                QuicWindowUpdateFrame::parse(quic_version, bytes).unwrap(),
                (window_update_frame.clone(), &[][..]),
                "parse window update stream frame, version {:?}",
                quic_version,
            );
        }
    }
}
