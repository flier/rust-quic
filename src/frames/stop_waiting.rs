use failure::{Error, Fail};
use nom::IResult;

use errors::QuicError;
use packet::{QuicPacketHeader, QuicPacketNumberLength};
use types::{QuicPacketNumber, QuicVersion};

/// The `STOP_WAITING` frame is sent to inform the peer
/// that it should not continue to wait for packets with packet numbers lower than a specified value.
/// The packet number is encoded in 1, 2, 4 or 6 bytes,
/// using the same coding length as is specified for the packet number for the enclosing packet's header.
#[derive(Clone, Debug, PartialEq)]
pub struct QuicStopWaitingFrame {
    /// The lowest packet we've sent which is unacked, and we expect an ack for.
    least_unacked: QuicPacketNumber,
}

impl QuicStopWaitingFrame {
    pub fn parse<'p>(
        quic_version: QuicVersion,
        header: &QuicPacketHeader,
        payload: &'p [u8],
    ) -> Result<(QuicStopWaitingFrame, &'p [u8]), Error> {
        match parse_quic_blocked_frame(
            payload,
            quic_version,
            header.public_header.packet_number_length,
            header.packet_number,
        ) {
            IResult::Done(remaining, frame) => Ok((frame, remaining)),
            IResult::Incomplete(needed) => {
                bail!(QuicError::IncompletePacket(needed).context("incomplete stop waiting frame."))
            }
            IResult::Error(err) => bail!(QuicError::from(err).context("unable to process stop waiting frame.")),
        }
    }
}

named_args!(
    parse_quic_blocked_frame(quic_version: QuicVersion,
                             packet_number_length: QuicPacketNumberLength,
                             packet_number: QuicPacketNumber)<QuicStopWaitingFrame>,
    do_parse!(
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
    fn parse_stop_waiting_frame() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        const test_cases: &[(QuicVersion, &[u8])] = &[
            (
                QuicVersion::QUIC_VERSION_38,
                &[
                    // least packet number awaiting an ack, delta from packet number.
                    0x08, 0x00, 0x00, 0x00, 0x00, 0x00
                ],
            ),
            (
                QuicVersion::QUIC_VERSION_39,
                &[
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

        for &(quic_version, packet) in test_cases {
            assert_eq!(
                QuicStopWaitingFrame::parse(quic_version, &header, packet).unwrap(),
                (stop_waiting_frame.clone(), &[][..]),
                "parse blocked frame, version {:?}",
                quic_version,
            );
        }
    }
}
