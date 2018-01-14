use failure::{Error, Fail};
use nom::IResult;

use errors::{QuicError, QuicErrorCode};
use types::{QuicStreamId, QuicVersion};

#[derive(Clone, Debug, PartialEq)]
pub struct QuicGoAwayFrame<'a> {
    error_code: QuicErrorCode,
    last_good_stream_id: QuicStreamId,
    reason_phrase: Option<&'a str>,
}

impl<'a> QuicGoAwayFrame<'a> {
    pub fn parse(quic_version: QuicVersion, payload: &'a [u8]) -> Result<(QuicGoAwayFrame<'a>, &'a [u8]), Error> {
        match parse_quic_go_away_frame(payload, quic_version) {
            IResult::Done(remaining, frame) => Ok((frame, remaining)),
            IResult::Incomplete(needed) => {
                bail!(QuicError::IncompletePacket(needed).context("incomplete go away frame."))
            }
            IResult::Error(err) => bail!(QuicError::from(err).context("unable to process go away frame.")),
        }
    }
}

named_args!(
    parse_quic_go_away_frame(quic_version: QuicVersion)<QuicGoAwayFrame>, do_parse!(
        error_code: error_code!(quic_version.endianness()) >>
        last_good_stream_id: u32!(quic_version.endianness()) >>
        reason_phrase: string_piece16!(quic_version.endianness()) >>
        (
            QuicGoAwayFrame {
                error_code,
                last_good_stream_id,
                reason_phrase,
            }
        )
    )
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_connection_close_frame() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        const test_cases: &[(QuicVersion, &[u8])] = &[
            (
                QuicVersion::QUIC_VERSION_38,
                &[
                    // error code
                    0x09, 0x00, 0x00, 0x00,
                    // stream id
                    0x04, 0x03, 0x02, 0x01,
                    // error details length
                    0x0d, 0x00,
                    // error details
                    b'b',  b'e',  b'c',  b'a',
                    b'u',  b's',  b'e',  b' ',
                    b'I',  b' ',  b'c',  b'a',
                    b'n',
                ],
            ),
            (
                QuicVersion::QUIC_VERSION_39,
                &[
                    // error code
                    0x00, 0x00, 0x00, 0x09,
                    // stream id
                    0x01, 0x02, 0x03, 0x04,
                    // error details length
                    0x00, 0x0d,
                    // error details
                    b'b',  b'e',  b'c',  b'a',
                    b'u',  b's',  b'e',  b' ',
                    b'I',  b' ',  b'c',  b'a',
                    b'n',
                ],
            ),
        ];

        let go_away_frame = QuicGoAwayFrame {
            error_code: QuicErrorCode::QUIC_INVALID_ACK_DATA,
            last_good_stream_id: 0x01020304,
            reason_phrase: Some("because I can"),
        };

        for &(quic_version, bytes) in test_cases {
            assert_eq!(
                QuicGoAwayFrame::parse(quic_version, bytes).unwrap(),
                (go_away_frame.clone(), &[][..]),
                "parse go away stream frame, version {:?}",
                quic_version,
            );
        }
    }
}
