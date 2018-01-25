use byteorder::ByteOrder;
use bytes::BufMut;
use failure::Error;
use nom::IResult;

use errors::QuicError;
use frames::{QuicFrameReader, QuicFrameType, QuicFrameWriter, ReadFrame, WriteFrame, kQuicFrameTypeSize,
             kQuicMaxStreamIdSize, kQuicMaxStreamOffsetSize};
use proto::{QuicStreamId, QuicStreamOffset};
use types::QuicVersion;

/// The GOAWAY frame allows for notification that the connection should stop being used,
/// and will likely be aborted in the future. Any active streams will continue to be processed,
/// but the sender of the GOAWAY will not initiate any additional streams, and will not accept any new streams.
#[derive(Clone, Debug, PartialEq)]
pub struct QuicWindowUpdateFrame {
    /// The stream this frame applies to.
    ///
    /// 0 is a special case meaning the overall connection rather than a specific stream.
    pub stream_id: QuicStreamId,
    /// Byte offset in the stream or connection.
    ///
    /// The receiver of this frame must not send data which would result in this offset being exceeded.
    pub byte_offset: QuicStreamOffset,
}

impl<'a> ReadFrame<'a> for QuicWindowUpdateFrame {
    type Frame = QuicWindowUpdateFrame;
    type Error = Error;

    fn read_frame<E, R>(reader: &R, payload: &'a [u8]) -> Result<(Self::Frame, &'a [u8]), Self::Error>
    where
        E: ByteOrder,
        R: QuicFrameReader<'a>,
    {
        match parse_quic_window_update_frame(payload, reader.quic_version()) {
            IResult::Done(remaining, frame) => Ok((frame, remaining)),
            IResult::Incomplete(needed) => bail!(QuicError::IncompletePacket(needed)),
            IResult::Error(err) => bail!(QuicError::from(err)),
        }
    }
}

impl<'a> WriteFrame<'a> for QuicWindowUpdateFrame {
    type Error = Error;

    fn frame_size<W>(&self, _writer: &W) -> usize
    where
        W: QuicFrameWriter<'a>,
    {
        // Frame Type
        kQuicFrameTypeSize +
        // Stream ID
        kQuicMaxStreamIdSize +
        // Byte offset
        kQuicMaxStreamOffsetSize
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
        buf.put_u8(QuicFrameType::WindowUpdate as u8);
        // Stream ID
        buf.put_u32::<E>(self.stream_id);
        // Byte offset
        buf.put_u64::<E>(self.byte_offset);

        Ok(frame_size)
    }
}

named_args!(
    parse_quic_window_update_frame(quic_version: QuicVersion)<QuicWindowUpdateFrame>, do_parse!(
        _frame_type: frame_type!(QuicFrameType::WindowUpdate) >>
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
    use frames::mocks;

    use super::*;

    #[test]
    fn window_update_frame() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        const test_cases: &[(QuicVersion, &[u8])] = &[
            (
                QuicVersion::QUIC_VERSION_38,
                &[
                    // frame type (window update frame)
                    0x04,
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
                    // frame type (window update frame)
                    0x04,
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

        for &(quic_version, payload) in test_cases {
            let (reader, writer) = mocks::pair(quic_version);

            assert_eq!(window_update_frame.frame_size(&writer), payload.len());
            assert_eq!(
                reader.read_frame::<QuicWindowUpdateFrame>(payload).unwrap(),
                (window_update_frame.clone(), &[][..]),
                "parse window update stream frame, version {:?}",
                quic_version,
            );

            let mut buf = Vec::with_capacity(payload.len());

            assert_eq!(
                writer.write_frame(&window_update_frame, &mut buf).unwrap(),
                buf.len()
            );
            assert_eq!(&buf, &payload);
        }
    }
}
