use std::mem;

use byteorder::ByteOrder;
use bytes::BufMut;
use failure::Error;
use nom::IResult;
use num::FromPrimitive;

use constants::kQuicFrameTypeSize;
use errors::{QuicError, QuicRstStreamErrorCode};
use frames::{FromWire, ToWire};
use packet::QuicPacketHeader;
use types::{QuicFrameType, QuicStreamId, QuicStreamOffset, QuicVersion};

/// The `RST_STREAM` frame allows for abnormal termination of a stream.
///
/// When sent by the creator of a stream, it indicates the creator wishes to cancel the stream.
/// When sent by the receiver of a stream, it indicates an error
/// or that the receiver did not want to accept the stream, so the stream should be closed.
#[derive(Clone, Debug, PartialEq)]
pub struct QuicRstStreamFrame {
    /// The 32-bit Stream ID of the stream being terminated.
    pub stream_id: QuicStreamId,
    /// A 32-bit `QuicErrorCode` which indicates why the stream is being closed.
    pub error_code: QuicRstStreamErrorCode,
    /// A 64-bit unsigned integer indicating the absolute byte offset of the end of data for this stream.
    pub byte_offset: QuicStreamOffset,
}

impl<'a> FromWire<'a> for QuicRstStreamFrame {
    type Frame = QuicRstStreamFrame;
    type Error = Error;

    fn parse(
        quic_version: QuicVersion,
        _header: &QuicPacketHeader,
        payload: &'a [u8],
    ) -> Result<(Self::Frame, &'a [u8]), Self::Error> {
        match parse_quic_reset_stream_frame(payload, quic_version) {
            IResult::Done(remaining, frame) => Ok((frame, remaining)),
            IResult::Incomplete(needed) => bail!(QuicError::IncompletePacket(needed)),
            IResult::Error(err) => bail!(QuicError::from(err)),
        }
    }
}

impl ToWire for QuicRstStreamFrame {
    type Frame = QuicRstStreamFrame;
    type Error = Error;

    fn frame_size(&self, _quic_version: QuicVersion, _header: &QuicPacketHeader) -> usize {
        // Frame type
        kQuicFrameTypeSize +
        // Stream ID
        mem::size_of::<QuicStreamId>() +
        // Error code
        mem::size_of::<QuicRstStreamErrorCode>()+
        // Byte offset
        mem::size_of::<QuicStreamOffset>()
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
        buf.put_u8(QuicFrameType::ResetStream as u8);
        // Stream ID
        buf.put_u32::<E>(self.stream_id);

        if quic_version <= QuicVersion::QUIC_VERSION_39 {
            // Byte offset
            buf.put_u64::<E>(self.byte_offset);
        }

        // Error code
        buf.put_u32::<E>(self.error_code as u32);

        if quic_version > QuicVersion::QUIC_VERSION_39 {
            // Byte offset
            buf.put_u64::<E>(self.byte_offset);
        }

        Ok(frame_size)
    }
}

named_args!(
    parse_quic_reset_stream_frame(quic_version: QuicVersion)<QuicRstStreamFrame>, do_parse!(
        _frame_type: frame_type!(QuicFrameType::ResetStream) >>
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
    fn reset_frame() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        const test_cases: &[(QuicVersion, &[u8])] = &[
            (
                QuicVersion::QUIC_VERSION_38,
                &[
                    // frame type (rst stream frame)
                    0x01,
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
                    // frame type (rst stream frame)
                    0x01,
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
                    // frame type (rst stream frame)
                    0x01,
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

        let header = QuicPacketHeader::default();
        let reset_stream_frame = QuicRstStreamFrame {
            stream_id: kStreamId,
            error_code: QuicRstStreamErrorCode::QUIC_ERROR_PROCESSING_STREAM,
            byte_offset: kStreamOffset,
        };

        for &(quic_version, payload) in test_cases {
            assert_eq!(
                reset_stream_frame.frame_size(quic_version, &header),
                payload.len()
            );
            assert_eq!(
                QuicRstStreamFrame::parse(quic_version, &header, payload).unwrap(),
                (reset_stream_frame.clone(), &[][..]),
                "parse reset stream frame, version {:?}",
                quic_version,
            );

            let mut buf = Vec::with_capacity(payload.len());

            assert_eq!(
                reset_stream_frame
                    .write_frame(quic_version, &header, &mut buf)
                    .unwrap(),
                buf.len()
            );
            assert_eq!(&buf, &payload);
        }
    }
}
