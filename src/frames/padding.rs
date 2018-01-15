use failure::Error;

use errors::QuicError;
use frames::kQuicFrameTypeSize;
use types::{QuicFrameType, QuicVersion};

/// The `PADDING` frame pads a packet with 0x00 bytes.
///
/// When this frame is encountered, the rest of the packet is expected to be padding bytes.
/// The frame contains 0x00 bytes and extends to the end of the QUIC packet.
/// A `PADDING` frame only has a Frame Type field, and must have the 8-bit Frame Type field set to 0x00.
#[derive(Clone, Debug, PartialEq)]
pub struct QuicPaddingFrame {
    /// -1: full padding to the end of a max-sized packet
    /// otherwise: only pad up to num_padding_bytes bytes
    pub num_padding_bytes: isize,
}

impl QuicPaddingFrame {
    pub fn parse(quic_version: QuicVersion, payload: &[u8]) -> Result<(QuicPaddingFrame, &[u8]), Error> {
        match payload.split_first() {
            Some((&frame_type, remaining)) if frame_type == QuicFrameType::Padding as u8 => {
                let num_padding_bytes = if quic_version < QuicVersion::QUIC_VERSION_37 {
                    remaining.len()
                } else {
                    remaining.iter().take_while(|&&b| b == 0).count()
                };

                Ok((
                    QuicPaddingFrame {
                        num_padding_bytes: num_padding_bytes as isize,
                    },
                    &remaining[num_padding_bytes..],
                ))
            }
            _ => bail!(QuicError::IllegalFrameType(
                payload.first().cloned().unwrap_or_default()
            )),
        }
    }

    pub fn frame_size(&self) -> usize {
        kQuicFrameTypeSize + self.num_padding_bytes as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_padding_frame() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        const bytes: &[u8] = &[
            // frame type (padding frame)
            0x00,
            0x00, 0x00,
            // Ignored data (which in this case is a stream frame)
            // frame type (stream frame with fin)
            0xFF,
            // stream id
            0x04, 0x03, 0x02, 0x01,
            // offset
            0x54, 0x76, 0x10, 0x32,
            0xDC, 0xFE, 0x98, 0xBA,
            // data length
            0x0c, 0x00,
            // data
            b'h',  b'e',  b'l',  b'l',
            b'o',  b' ',  b'w',  b'o',
            b'r',  b'l',  b'd',  b'!',
        ];

        let padding_frame = QuicPaddingFrame {
            num_padding_bytes: 29,
        };

        assert_eq!(padding_frame.frame_size(), bytes.len());
        assert_eq!(
            QuicPaddingFrame::parse(QuicVersion::QUIC_VERSION_35, bytes).unwrap(),
            (padding_frame, &[][..])
        );

        let padding_frame = QuicPaddingFrame {
            num_padding_bytes: 2,
        };

        assert_eq!(padding_frame.frame_size(), 3);
        assert_eq!(
            QuicPaddingFrame::parse(QuicVersion::QUIC_VERSION_37, bytes).unwrap(),
            (padding_frame, &bytes[3..])
        );
    }
}
