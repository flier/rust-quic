use byteorder::ByteOrder;
use bytes::BufMut;
use failure::Error;
use nom::IResult;

use constants::kQuicFrameTypeSize;
use errors::QuicError;
use frames::{FromWire, ToWire};
use packet::{QuicPacketHeader, QuicPacketNumberLength};
use types::{QuicFrameType, QuicPacketNumber, QuicVersion};

/// The `STOP_WAITING` frame is sent to inform the peer
/// that it should not continue to wait for packets with packet numbers lower than a specified value.
/// The packet number is encoded in 1, 2, 4 or 6 bytes,
/// using the same coding length as is specified for the packet number for the enclosing packet's header.
#[derive(Clone, Debug, PartialEq)]
pub struct QuicStopWaitingFrame {
    /// The lowest packet we've sent which is unacked, and we expect an ack for.
    least_unacked: QuicPacketNumber,
}


impl<'a> FromWire<'a> for QuicStopWaitingFrame {
    type Frame = QuicStopWaitingFrame;
    type Error = Error;

    fn parse(
        quic_version: QuicVersion,
        header: &QuicPacketHeader,
        payload: &'a [u8],
    ) -> Result<(Self::Frame, &'a [u8]), Self::Error> {
        match parse_quic_blocked_frame(
            payload,
            quic_version,
            header.public_header.packet_number_length,
            header.packet_number,
        ) {
            IResult::Done(remaining, frame) => Ok((frame, remaining)),
            IResult::Incomplete(needed) => bail!(QuicError::IncompletePacket(needed)),
            IResult::Error(err) => bail!(QuicError::from(err)),
        }
    }
}

impl ToWire for QuicStopWaitingFrame {
    type Frame = QuicStopWaitingFrame;
    type Error = Error;

    fn frame_size(&self, _quic_version: QuicVersion, header: &QuicPacketHeader) -> usize {
        // Frame Type
        kQuicFrameTypeSize +
        // Least Unacked Delta
        header.public_header.packet_number_length as usize
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
        buf.put_u8(QuicFrameType::StopWaiting as u8);
        // Least Unacked Delta
        buf.put_uint::<E>(
            header.packet_number - self.least_unacked,
            header.public_header.packet_number_length as usize,
        );

        Ok(frame_size)
    }
}

named_args!(
    parse_quic_blocked_frame(quic_version: QuicVersion,
                             packet_number_length: QuicPacketNumberLength,
                             packet_number: QuicPacketNumber)<QuicStopWaitingFrame>,
    do_parse!(
        _frame_type: frame_type!(QuicFrameType::StopWaiting) >>
        least_unacked: verify!(
            uint!(quic_version.endianness(), packet_number_length as usize),
            |least_unacked| least_unacked < packet_number
         ) >>
        (
            QuicStopWaitingFrame {
                least_unacked: packet_number - least_unacked,
            }
        )
    )
);

#[cfg(test)]
mod tests {
    use packet::{PACKET_6BYTE_PACKET_NUMBER, QuicPacketPublicHeader};

    use super::*;

    const kPacketNumber: QuicPacketNumber = 0x0123456789AA8;
    const kLeastUnacked: QuicPacketNumber = 0x0123456789AA0;

    #[test]
    fn stop_waiting_frame() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        const test_cases: &[(QuicVersion, &[u8])] = &[
            (
                QuicVersion::QUIC_VERSION_38,
                &[
                    // frame type (stop waiting frame)
                    0x06,
                    // least packet number awaiting an ack, delta from packet number.
                    0x08, 0x00, 0x00, 0x00, 0x00, 0x00
                ],
            ),
            (
                QuicVersion::QUIC_VERSION_39,
                &[
                    // frame type (stop waiting frame)
                    0x06,
                    // least packet number awaiting an ack, delta from packet number.
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x08
                ],
            ),
        ];

        let header = QuicPacketHeader {
            public_header: QuicPacketPublicHeader {
                reset_flag: false,
                connection_id: None,
                packet_number_length: PACKET_6BYTE_PACKET_NUMBER,
                versions: None,
                nonce: None,
            },
            packet_number: kPacketNumber,
        };
        let stop_waiting_frame = QuicStopWaitingFrame {
            least_unacked: kLeastUnacked,
        };

        for &(quic_version, payload) in test_cases {
            assert_eq!(
                stop_waiting_frame.frame_size(quic_version, &header),
                payload.len()
            );
            assert_eq!(
                QuicStopWaitingFrame::parse(quic_version, &header, payload).unwrap(),
                (stop_waiting_frame.clone(), &[][..]),
                "parse blocked frame, version {:?}",
                quic_version,
            );

            let mut buf = Vec::with_capacity(payload.len());

            assert_eq!(
                stop_waiting_frame
                    .write_frame(quic_version, &header, &mut buf)
                    .unwrap(),
                buf.len()
            );
            assert_eq!(&buf, &payload);
        }
    }
}
