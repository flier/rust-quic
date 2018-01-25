use byteorder::ByteOrder;
use bytes::BufMut;
use failure::Error;
use nom::IResult;

use errors::{QuicError, QuicErrorCode};
use frames::{BufMutExt, QuicFrameReader, QuicFrameType, QuicFrameWriter, ReadFrame, WriteFrame, kQuicErrorCodeSize,
             kQuicErrorDetailsLengthSize, kQuicFrameTypeSize};
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

impl<'a> ReadFrame<'a> for QuicConnectionCloseFrame<'a> {
    type Frame = QuicConnectionCloseFrame<'a>;
    type Error = Error;

    fn read_frame<E, R>(reader: &R, payload: &'a [u8]) -> Result<(Self::Frame, &'a [u8]), Self::Error>
    where
        E: ByteOrder,
        R: QuicFrameReader<'a>,
    {
        match parse_quic_connection_close_frame(payload, reader.quic_version()) {
            IResult::Done(remaining, frame) => Ok((frame, remaining)),
            IResult::Incomplete(needed) => bail!(QuicError::IncompletePacket(needed)),
            IResult::Error(err) => bail!(QuicError::from(err)),
        }
    }
}

impl<'a> WriteFrame<'a> for QuicConnectionCloseFrame<'a> {
    type Error = Error;

    fn frame_size<W>(&self, _writer: &W) -> usize
    where
        W: QuicFrameWriter<'a>,
    {
        // Frame Type
        kQuicFrameTypeSize +
        // Error Code
        kQuicErrorCodeSize +
        // Reason Phrase
        kQuicErrorDetailsLengthSize + self.error_details.map(|s| s.len()).unwrap_or_default()
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
        buf.put_u8(QuicFrameType::ConnectionClose as u8);
        // Error Code
        buf.put_u32::<E>(self.error_code as u32);
        // Reason Phrase
        buf.put_string_piece16::<E>(self.error_details);

        Ok(frame_size)
    }
}

fn parse_quic_connection_close_frame(
    input: &[u8],
    quic_version: QuicVersion,
) -> IResult<&[u8], QuicConnectionCloseFrame> {
    do_parse!(
        input,
        _frame_type: frame_type!(QuicFrameType::ConnectionClose) >> error_code: error_code!(quic_version.endianness())
            >> error_details: string_piece16!(quic_version.endianness()) >> (QuicConnectionCloseFrame {
            error_code,
            error_details,
        })
    )
}

#[cfg(test)]
mod tests {
    use frames::mocks;

    use super::*;

    #[test]
    fn connection_close_frame() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        const test_cases: &[(QuicVersion, &[u8])] = &[
            (
                QuicVersion::QUIC_VERSION_38,
                &[
                    // frame type (connection close frame)
                    0x02,
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
                    // frame type (connection close frame)
                    0x02,
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

        for &(quic_version, payload) in test_cases {
            let (reader, writer) = mocks::pair(quic_version);

            assert_eq!(connection_close_frame.frame_size(&writer), payload.len());
            assert_eq!(
                reader
                    .read_frame::<QuicConnectionCloseFrame>(payload)
                    .unwrap(),
                (connection_close_frame.clone(), &[][..]),
                "parse connection close frame, version {:?}",
                quic_version,
            );

            let mut buf = Vec::with_capacity(payload.len());

            assert_eq!(
                writer
                    .write_frame(&connection_close_frame, &mut buf)
                    .unwrap(),
                buf.len()
            );
            assert_eq!(&buf, &payload);
        }
    }
}
