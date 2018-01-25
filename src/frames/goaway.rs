use byteorder::ByteOrder;
use bytes::BufMut;
use failure::Error;
use nom::IResult;

use errors::{QuicError, QuicErrorCode};
use frames::{BufMutExt, QuicFrameReader, QuicFrameType, QuicFrameWriter, ReadFrame, WriteFrame, kQuicErrorCodeSize,
             kQuicErrorDetailsLengthSize, kQuicFrameTypeSize, kQuicMaxStreamIdSize};
use proto::QuicStreamId;
use types::QuicVersion;

/// The GOAWAY frame allows for notification that the connection should stop being used,
/// and will likely be aborted in the future. Any active streams will continue to be processed,
/// but the sender of the GOAWAY will not initiate any additional streams, and will not accept any new streams.
#[derive(Clone, Debug, PartialEq)]
pub struct QuicGoAwayFrame<'a> {
    /// A 32-bit field containing the `QuicErrorCode` which indicates the reason for closing this connection.
    pub error_code: QuicErrorCode,
    /// The last Stream ID which was accepted by the sender of the GOAWAY message.
    pub last_good_stream_id: Option<QuicStreamId>,
    /// An optional human-readable explanation for why the connection was closed.
    pub reason_phrase: Option<&'a str>,
}

impl<'a> ReadFrame<'a> for QuicGoAwayFrame<'a> {
    type Frame = QuicGoAwayFrame<'a>;
    type Error = Error;

    fn read_frame<E, R>(reader: &R, payload: &'a [u8]) -> Result<(Self::Frame, &'a [u8]), Self::Error>
    where
        E: ByteOrder,
        R: QuicFrameReader<'a>,
    {
        match parse_quic_go_away_frame(payload, reader.quic_version()) {
            IResult::Done(remaining, frame) => Ok((frame, remaining)),
            IResult::Incomplete(needed) => bail!(QuicError::IncompletePacket(needed)),
            IResult::Error(err) => bail!(QuicError::from(err)),
        }
    }
}

impl<'a> WriteFrame<'a> for QuicGoAwayFrame<'a> {
    type Error = Error;

    fn frame_size<W>(&self, _writer: &W) -> usize
    where
        W: QuicFrameWriter<'a>,
    {
        // Frame Type
        kQuicFrameTypeSize +
        // Error Code
        kQuicErrorCodeSize +
        // Last Good Stream ID
        kQuicMaxStreamIdSize +
        // Reason Phrase
        kQuicErrorDetailsLengthSize + self.reason_phrase.map(|s| s.len()).unwrap_or_default()
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
        buf.put_u8(QuicFrameType::GoAway as u8);
        // Error Code
        buf.put_u32::<E>(self.error_code as u32);
        // Last Good Stream ID
        buf.put_u32::<E>(self.last_good_stream_id.unwrap_or_default());
        // Reason Phrase
        buf.put_string_piece16::<E>(self.reason_phrase);

        Ok(frame_size)
    }
}

named_args!(
    parse_quic_go_away_frame(quic_version: QuicVersion)<QuicGoAwayFrame>, do_parse!(
        _frame_type: frame_type!(QuicFrameType::GoAway) >>
        error_code: error_code!(quic_version.endianness()) >>
        stream_id: u32!(quic_version.endianness()) >>
        reason_phrase: string_piece16!(quic_version.endianness()) >>
        (
            QuicGoAwayFrame {
                error_code,
                last_good_stream_id: if stream_id > 0 { Some(stream_id) } else { None },
                reason_phrase,
            }
        )
    )
);

#[cfg(test)]
mod tests {
    use frames::mocks;

    use super::*;

    #[test]
    fn go_away_frame() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        const test_cases: &[(QuicVersion, &[u8])] = &[
            (
                QuicVersion::QUIC_VERSION_38,
                &[
                    // frame type (go away frame)
                    0x03,
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
                    // frame type (go away frame)
                    0x03,
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
            last_good_stream_id: Some(0x01020304),
            reason_phrase: Some("because I can"),
        };

        for &(quic_version, payload) in test_cases {
            let (reader, writer) = mocks::pair(quic_version);

            assert_eq!(go_away_frame.frame_size(&writer), payload.len());
            assert_eq!(
                reader.read_frame::<QuicGoAwayFrame>(payload).unwrap(),
                (go_away_frame.clone(), &[][..]),
                "parse go away stream frame, version {:?}",
                quic_version,
            );

            let mut buf = Vec::with_capacity(payload.len());

            assert_eq!(
                writer.write_frame(&go_away_frame, &mut buf).unwrap(),
                buf.len()
            );
            assert_eq!(&buf, &payload);
        }
    }
}
