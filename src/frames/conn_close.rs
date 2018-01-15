use failure::{Error, Fail};
use nom::IResult;

use errors::{QuicError, QuicErrorCode};
use types::QuicVersion;

/// The `CONNECTION_CLOSE` frame allows for notification that the connection is being closed.
///
/// If there are streams in flight, those streams are all implicitly closed when the connection is closed.
/// (Ideally, a GOAWAY frame would be sent with enough time that all streams are torn down.)
#[derive(Clone, Debug, PartialEq)]
pub struct QuicConnectionCloseFrame<'a> {
    /// A 32-bit field containing the `QuicErrorCode` which indicates the reason for closing this connection.
    pub error_code: QuicErrorCode,
    /// An optional human-readable explanation for why the connection was closed.
    pub error_details: Option<&'a str>,
}

impl<'a> QuicConnectionCloseFrame<'a> {
    pub fn parse(
        quic_version: QuicVersion,
        payload: &'a [u8],
    ) -> Result<(QuicConnectionCloseFrame<'a>, &'a [u8]), Error> {
        match parse_quic_connection_close_frame(payload, quic_version) {
            IResult::Done(remaining, frame) => Ok((frame, remaining)),
            IResult::Incomplete(needed) => {
                bail!(QuicError::IncompletePacket(needed).context("incomplete connection close frame."))
            }
            IResult::Error(err) => bail!(QuicError::from(err).context("unable to process connection close frame.")),
        }
    }
}

named_args!(
    parse_quic_connection_close_frame(quic_version: QuicVersion)<QuicConnectionCloseFrame>, do_parse!(
        error_code: error_code!(quic_version.endianness()) >>
        error_details: string_piece16!(quic_version.endianness()) >>
        (
            QuicConnectionCloseFrame {
                error_code,
                error_details,
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
                    0x11, 0x00, 0x00, 0x00,
                    // error details length
                    0x0d, 0x00,
                    // error details
                    b'b',  b'e',  b'c',  b'a',
                    b'u',  b's',  b'e',  b' ',
                    b'I',  b' ',  b'c',  b'a',
                    b'n'
                ],
            ),
            (
                QuicVersion::QUIC_VERSION_39,
                &[
                    // error code
                    0x00, 0x00, 0x00, 0x11,
                    // error details length
                    0x00, 0x0d,
                    // error details
                    b'b',  b'e',  b'c',  b'a',
                    b'u',  b's',  b'e',  b' ',
                    b'I',  b' ',  b'c',  b'a',
                    b'n'
                ],
            ),
        ];

        let connection_close_frame = QuicConnectionCloseFrame {
            error_code: QuicErrorCode::QUIC_INVALID_STREAM_ID,
            error_details: Some("because I can"),
        };

        for &(quic_version, packet) in test_cases {
            assert_eq!(
                QuicConnectionCloseFrame::parse(quic_version, packet).unwrap(),
                (connection_close_frame.clone(), &[][..]),
                "parse connection close frame, version {:?}",
                quic_version,
            );
        }
    }
}
