use failure::Error;

use types::QuicVersion;

/// The `PADDING` frame pads a packet with 0x00 bytes.
///
/// When this frame is encountered, the rest of the packet is expected to be padding bytes.
/// The frame contains 0x00 bytes and extends to the end of the QUIC packet.
/// A `PADDING` frame only has a Frame Type field, and must have the 8-bit Frame Type field set to 0x00.
#[derive(Clone, Debug, PartialEq)]
pub struct QuicPaddingFrame {
    /// -1: full padding to the end of a max-sized packet
    /// otherwise: only pad up to num_padding_bytes bytes
    pub num_padding_bytes: usize,
}

impl QuicPaddingFrame {
    pub fn parse(quic_version: QuicVersion, payload: &[u8]) -> Result<(QuicPaddingFrame, &[u8]), Error> {
        let num_padding_bytes = if quic_version < QuicVersion::QUIC_VERSION_37 {
            payload.len()
        } else {
            payload.iter().take_while(|&&b| b == 0).count()
        };

        Ok((
            QuicPaddingFrame { num_padding_bytes },
            &payload[num_padding_bytes..],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_padding_frame() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        const packet: &[u8] = &[
            // frame type (padding frame)
            0x00, 0x00, 0x00,
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

        assert_eq!(
            QuicPaddingFrame::parse(QuicVersion::QUIC_VERSION_35, packet).unwrap(),
            (
                QuicPaddingFrame {
                    num_padding_bytes: 30,
                },
                &[][..]
            )
        );
        assert_eq!(
            QuicPaddingFrame::parse(QuicVersion::QUIC_VERSION_37, packet).unwrap(),
            (
                QuicPaddingFrame {
                    num_padding_bytes: 3,
                },
                &packet[3..]
            )
        );
    }
}
