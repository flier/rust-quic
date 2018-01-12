#![allow(non_camel_case_types)]

use failure::{Error, Fail};
use nom::IResult;
use num::FromPrimitive;

use errors::QuicError;
use types::{QuicStreamId, QuicStreamOffset, QuicVersion};

#[repr(u32)]
#[derive(Clone, Copy, Debug, FromPrimitive, PartialEq)]
pub enum QuicRstStreamErrorCode {
    /// Complete response has been sent, sending a RST to ask the other endpoint
    /// to stop sending request data without discarding the response.
    QUIC_STREAM_NO_ERROR = 0,

    /// There was some error which halted stream processing.
    QUIC_ERROR_PROCESSING_STREAM,
    /// We got two fin or reset offsets which did not match.
    QUIC_MULTIPLE_TERMINATION_OFFSETS,
    /// We got bad payload and can not respond to it at the protocol level.
    QUIC_BAD_APPLICATION_PAYLOAD,
    /// Stream closed due to connection error. No reset frame is sent when this happens.
    QUIC_STREAM_CONNECTION_ERROR,
    /// GoAway frame sent. No more stream can be created.
    QUIC_STREAM_PEER_GOING_AWAY,
    /// The stream has been cancelled.
    QUIC_STREAM_CANCELLED,
    /// Closing stream locally, sending a RST to allow for proper flow control accounting.
    /// Sent in response to a RST from the peer.
    QUIC_RST_ACKNOWLEDGEMENT,
    /// Receiver refused to create the stream (because its limit on open streams has been reached).
    /// The sender should retry the request later (using another stream).
    QUIC_REFUSED_STREAM,
    /// Invalid URL in PUSH_PROMISE request header.
    QUIC_INVALID_PROMISE_URL,
    /// Server is not authoritative for this URL.
    QUIC_UNAUTHORIZED_PROMISE_URL,
    /// Can't have more than one active PUSH_PROMISE per URL.
    QUIC_DUPLICATE_PROMISE_URL,
    /// Vary check failed.
    QUIC_PROMISE_VARY_MISMATCH,
    /// Only GET and HEAD methods allowed.
    QUIC_INVALID_PROMISE_METHOD,
    /// The push stream is unclaimed and timed out.
    QUIC_PUSH_STREAM_TIMED_OUT,
    /// Received headers were too large.
    QUIC_HEADERS_TOO_LARGE,
    /// No error. Used as bound while iterating.
    QUIC_STREAM_LAST_ERROR,
}

#[derive(Clone, Debug, PartialEq)]
pub struct QuicRstStreamFrame {
    pub stream_id: QuicStreamId,
    pub error_code: QuicRstStreamErrorCode,
    pub byte_offset: QuicStreamOffset,
}

impl QuicRstStreamFrame {
    pub fn parse(quic_version: QuicVersion, payload: &[u8]) -> Result<(QuicRstStreamFrame, &[u8]), Error> {
        match parse_quic_reset_frame(payload, quic_version) {
            IResult::Done(remaining, frame) => Ok((frame, remaining)),
            IResult::Incomplete(needed) => {
                bail!(QuicError::IncompletePacket(needed).context("incomplete reset frame."))
            }
            IResult::Error(err) => bail!(QuicError::from(err).context("unable to process reset frame.")),
        }
    }
}

named_args!(
    parse_quic_reset_frame(quic_version: QuicVersion)<QuicRstStreamFrame>, do_parse!(
        stream_id: u32!(quic_version.endianness()) >>
        byte_offset_pre40: cond!(quic_version <= QuicVersion::QUIC_VERSION_39, u64!(quic_version.endianness())) >>
        error_code: map!(u32!(quic_version.endianness()), |code| {
            QuicRstStreamErrorCode::from_u32(code).unwrap_or(QuicRstStreamErrorCode::QUIC_STREAM_LAST_ERROR)
        }) >>
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
