use byteorder::ByteOrder;
use bytes::BufMut;
use failure::Error;
use nom::Needed;

use constants::kQuicFrameTypeSize;
use errors::QuicError;
use frames::{FromWire, ToWire};
use packet::QuicPacketHeader;
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

impl<'a> FromWire<'a> for QuicPaddingFrame {
    type Frame = QuicPaddingFrame;
    type Error = Error;

    fn parse(
        quic_version: QuicVersion,
        _header: &QuicPacketHeader,
        payload: &'a [u8],
    ) -> Result<(Self::Frame, &'a [u8]), Self::Error> {
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
            Some((&frame_type, _)) => bail!(QuicError::IllegalFrameType(frame_type)),
            _ => bail!(QuicError::IncompletePacket(Needed::Size(
                kQuicFrameTypeSize
            ))),
        }
    }
}

impl ToWire for QuicPaddingFrame {
    type Frame = QuicPaddingFrame;
    type Error = Error;

    fn frame_size(&self, _quic_version: QuicVersion, _header: &QuicPacketHeader) -> usize {
        // Frame Type
        kQuicFrameTypeSize +
        // Padding Bytes
        self.num_padding_bytes as usize
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
        buf.put_u8(QuicFrameType::Padding as u8);
        // Padding Bytes
        buf.put(vec![0u8; self.num_padding_bytes as usize]);

        Ok(frame_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_frame() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        const test_cases: &[(QuicVersion, isize, &[u8])] = &[
            (
                QuicVersion::QUIC_VERSION_35,
                29,
                &[
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
                ]
            ),
            (
                QuicVersion::QUIC_VERSION_37,
                2,
                &[
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
                ]
            )
        ];

        let header = QuicPacketHeader::default();

        for &(quic_version, num_padding_bytes, payload) in test_cases {
            let padding_frame = QuicPaddingFrame { num_padding_bytes };

            assert_eq!(
                padding_frame.frame_size(quic_version, &header),
                1 + num_padding_bytes as usize
            );
            assert_eq!(
                QuicPaddingFrame::parse(quic_version, &header, payload)
                    .unwrap()
                    .0,
                padding_frame
            );

            let mut buf = Vec::with_capacity(payload.len());

            assert_eq!(
                padding_frame
                    .write_frame(quic_version, &header, &mut buf)
                    .unwrap(),
                buf.len()
            );
            assert!(buf.into_iter().all(|b| b == 0));
        }
    }
}
