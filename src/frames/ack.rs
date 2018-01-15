use std::mem;

use failure::{Error, Fail};
use nom::{self, IResult, Needed, be_u8};
use time::Duration;

use errors::ParseError::*;
use errors::QuicError::{self, IncompletePacket};
use frames::kQuicFrameTypeSize;
use packet::{read_ack_packet_number_length, PACKET_1BYTE_PACKET_NUMBER, PACKET_2BYTE_PACKET_NUMBER,
             PACKET_4BYTE_PACKET_NUMBER, PACKET_6BYTE_PACKET_NUMBER, PACKET_8BYTE_PACKET_NUMBER,
             QuicPacketNumberLength};
use types::{QuicPacketNumber, QuicTime, QuicTimeDelta, QuicVersion, ToQuicTimeDelta, UFloat16, ufloat16};

// packet number size shift used in AckFrames.
const kQuicSequenceNumberLengthNumBits: usize = 2;
const kActBlockLengthOffset: usize = 0;
const kLargestAckedOffset: usize = 2;

// Acks may have only one ack block.
const kQuicHasMultipleAckBlocksOffset_Pre40: usize = 5;
const kQuicHasMultipleAckBlocksOffset: usize = 4;

/// The ACK frame is sent to inform the peer which packets have been received,
/// as well as which packets are still considered missing by the receiver
/// (the contents of missing packets may need to be resent).
/// The ack frame contains between 1 and 256 ack blocks.
/// Ack blocks are ranges of acknowledged packets,
/// similar to TCP’s SACK blocks, but QUIC has no equivalent of TCP’s cumulative ack point,
/// because packets are retransmitted with new sequence numbers.
#[derive(Clone, Debug, PartialEq)]
pub struct QuicAckFrame {
    /// The highest packet number we've observed from the peer.
    pub largest_observed: QuicPacketNumber,
    /// Time elapsed since largest_observed was received until this Ack frame was sent.
    pub ack_delay_time: QuicTimeDelta,
    /// Vector of <packet_number, time> for when packets arrived.
    pub received_packet_times: Option<Vec<(QuicPacketNumber, QuicTime)>>,
    /// Set of packets.
    pub packets: PacketNumberQueue,
}

impl QuicAckFrame {
    pub fn parse(
        quic_version: QuicVersion,
        creation_time: QuicTime,
        last_timestamp: QuicTimeDelta,
        payload: &[u8],
    ) -> Result<(QuicAckFrame, &[u8]), Error> {
        if let Some((&frame_type, remaining)) = payload.split_first() {
            let has_ack_blocks = extract_bool!(
                frame_type,
                if quic_version < QuicVersion::QUIC_VERSION_40 {
                    kQuicHasMultipleAckBlocksOffset_Pre40
                } else {
                    kQuicHasMultipleAckBlocksOffset
                }
            );
            let ack_block_length = read_ack_packet_number_length(
                quic_version,
                extract_bits!(
                    frame_type,
                    kQuicSequenceNumberLengthNumBits,
                    kActBlockLengthOffset
                ),
            );
            let largest_acked_length = read_ack_packet_number_length(
                quic_version,
                extract_bits!(
                    frame_type,
                    kQuicSequenceNumberLengthNumBits,
                    kLargestAckedOffset
                ),
            );

            match parse_quic_ack_frame(
                remaining,
                quic_version,
                creation_time,
                last_timestamp,
                has_ack_blocks,
                ack_block_length,
                largest_acked_length,
            ) {
                IResult::Done(remaining, frame) => Ok((frame, remaining)),
                IResult::Incomplete(needed) => bail!(IncompletePacket(needed).context("incomplete ack frame.")),
                IResult::Error(err) => bail!(QuicError::from(err).context("unable to process ack frame.")),
            }
        } else {
            bail!(IncompletePacket(Needed::Size(1)).context("incomplete data frame."))
        }
    }

    pub fn frame_size(&self, quic_version: QuicVersion) -> usize {
        let ack_block_length = packet_number_size(
            quic_version,
            self.packets
                .ranges
                .iter()
                .map(|&(min, max)| max - min)
                .max()
                .unwrap_or(0),
        );

        // Frame Type:
        kQuicFrameTypeSize +
        // Largest Acked
        packet_number_size(quic_version, self.largest_observed) +
        // Largest Acked Delta Time
        mem::size_of::<u16>() +
        // Ack Block
        match self.packets.ranges.iter().fold((0, self.largest_observed + 1), |(acc, last), &(min, max)| {
            (acc + (last - max) / 256 + 1, min)
        }).0 {
            1 => ack_block_length,
            n => mem::size_of::<u8>() + ack_block_length + (n as usize - 1) * (1 + ack_block_length)
        } +
        // Timestamp Section
        mem::size_of::<u8>()
            + self.received_packet_times
                .as_ref()
                .map_or(0, |times| times.len() * 3 + 2)
    }
}

named_args!(parse_quic_ack_frame(quic_version: QuicVersion,
                                 creation_time: QuicTime,
                                 last_timestamp: QuicTimeDelta,
                                 has_ack_blocks: bool,
                                 ack_block_length: QuicPacketNumberLength,
                                 largest_acked_length: QuicPacketNumberLength)<QuicAckFrame>,
    do_parse!(
        num_ack_blocks_new: cond!(quic_version > QuicVersion::QUIC_VERSION_39 && has_ack_blocks, be_u8) >>
        num_received_packets_new: cond!(quic_version > QuicVersion::QUIC_VERSION_39, be_u8) >>
        largest_observed: uint!(quic_version.endianness(), largest_acked_length as usize) >>
        ack_delay_time_us: map!(u16!(quic_version.endianness()), UFloat16::from) >>
        num_ack_blocks_pre40: cond!(quic_version <= QuicVersion::QUIC_VERSION_39 && has_ack_blocks, be_u8) >>
        first_block_length: add_return_error!(
            nom::ErrorKind::Custom(FirstAckBlockLengthOverflow as u32),
            verify!(
                uint!(quic_version.endianness(), ack_block_length as usize),
                |first_block_length| first_block_length < largest_observed + 1
            )
        ) >>
        first_received: value!(largest_observed + 1 - first_block_length) >>
        num_ack_blocks: map!(value!(num_ack_blocks_new.or(num_ack_blocks_pre40)), |n| n.unwrap_or(0)) >>
        packet_ranges: many_m_n!(num_ack_blocks as usize, num_ack_blocks as usize,
            tuple!(map!(be_u8, u64::from), uint!(quic_version.endianness(), ack_block_length as usize))
        ) >>
        _packet_ranges_overflow: add_return_error!(
            nom::ErrorKind::Custom(AckBlockLengthOverflow as u32),
            verify!(value!(&packet_ranges),
                |ranges: &[(u64, u64)]| {
                    ranges
                        .iter()
                        .fold(0, |acc, &(gap, current_block_length)| acc + gap + current_block_length)
                    <= first_received
                }
            )
        ) >>
        num_received_packets_pre40: cond!(quic_version <= QuicVersion::QUIC_VERSION_39, be_u8) >>
        num_received_packets: map!(
            expr_opt!(num_received_packets_new.or(num_received_packets_pre40)), |n| n as usize
        ) >>
        timestamps: cond!(
            num_received_packets > 0,
            tuple!(
                map!(be_u8, QuicPacketNumber::from),
                u32!(quic_version.endianness()),
                many_m_n!(num_received_packets-1, num_received_packets-1,
                    tuple!(be_u8, map!(u16!(quic_version.endianness()), UFloat16::from))
                )
            )
        ) >>
        (
            QuicAckFrame {
                largest_observed,
                ack_delay_time: if ack_delay_time_us == ufloat16::MAX {
                    Duration::max_value()
                } else {
                    Duration::microseconds(ack_delay_time_us.into())
                },
                received_packet_times: timestamps.map(|(delta_from_largest_observed, time_delta_us, timestamps)| {
                    let last_timestamp = QuicTimeDelta::from_wire(last_timestamp, time_delta_us);

                    timestamps.into_iter().fold(
                        (
                            vec![(largest_observed - delta_from_largest_observed, creation_time + last_timestamp)],
                            last_timestamp,
                        ),
                        |(mut times, last_timestamp), (delta_from_largest_observed, incremental_time_delta_us)| {
                            let seq_num = largest_observed - u64::from(delta_from_largest_observed);
                            let last_timestamp = last_timestamp
                                + Duration::microseconds(i64::from(incremental_time_delta_us));

                            times.push((seq_num, creation_time + last_timestamp));

                            (times, last_timestamp)
                        }
                    ).0
                }),
                packets: PacketNumberQueue {
                    ranges: packet_ranges.iter().fold(
                        (vec![(first_received, largest_observed+1)], first_received),
                        |(mut ranges, mut first_received), &(gap, current_block_length)| {
                            first_received -= gap + current_block_length;

                            if current_block_length > 0 {
                                ranges.push((first_received, first_received + current_block_length))
                            }

                            (ranges, first_received)
                        }
                    ).0
                },
            }
        )
    )
);

fn packet_number_size(quic_version: QuicVersion, packet_number: QuicPacketNumber) -> usize {
    [
        PACKET_1BYTE_PACKET_NUMBER,
        PACKET_2BYTE_PACKET_NUMBER,
        PACKET_4BYTE_PACKET_NUMBER,
    ].into_iter()
        .cloned()
        .find(|&n| packet_number < 1 << 8 * n as usize)
        .unwrap_or(if quic_version <= QuicVersion::QUIC_VERSION_39 {
            PACKET_6BYTE_PACKET_NUMBER
        } else {
            PACKET_8BYTE_PACKET_NUMBER
        }) as usize
}

/// A sequence of packet numbers where each number is unique.
///
/// Intended to be used in a sliding window fashion,
/// where smaller old packet numbers are removed and larger new packet numbers are added,
/// with the occasional random access.
#[derive(Clone, Debug, PartialEq)]
pub struct PacketNumberQueue {
    ranges: Vec<(u64, u64)>,
}

#[cfg(test)]
mod tests {
    use time;

    use super::*;

    const kSmallLargestObserved: QuicPacketNumber = 0x1234;
    const kLargeLargestObserved: QuicPacketNumber = 0x123456789abc;

    #[test]
    fn one_ack_block() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        const test_cases: &[(QuicVersion, &[u8])] = &[
            (
                QuicVersion::QUIC_VERSION_38,
                &[
                    // frame type (ack frame)
                    // (no ack blocks, 2 byte largest observed, 2 byte block length)
                    0x45,
                    // largest acked
                    0x34, 0x12,
                    // Zero delta time.
                    0x00, 0x00,
                    // first ack block length.
                    0x34, 0x12,
                    // num timestamps.
                    0x00,
                ],
            ),
            (
                QuicVersion::QUIC_VERSION_39,
                &[
                    // frame type (ack frame)
                    // (no ack blocks, 2 byte largest observed, 2 byte block length)
                    0x45,
                    // largest acked
                    0x12, 0x34,
                    // Zero delta time.
                    0x00, 0x00,
                    // first ack block length.
                    0x12, 0x34,
                    // num timestamps.
                    0x00,
                ],
            ),
            (
                QuicVersion::QUIC_VERSION_40,
                &[
                    // frame type (ack frame)
                    // (no ack blocks, 2 byte largest observed, 2 byte block length)
                    0x45,
                    // num timestamps.
                    0x00,
                    // largest acked
                    0x12, 0x34,
                    // Zero delta time.
                    0x00, 0x00,
                    // first ack block length.
                    0x12, 0x34,
                ],
            ),
        ];

        let creation_time = time::now().to_timespec();
        let last_timestamp = QuicTimeDelta::zero();
        let ack_frame = QuicAckFrame {
            largest_observed: kSmallLargestObserved,
            ack_delay_time: QuicTimeDelta::zero(),
            received_packet_times: None,
            packets: PacketNumberQueue {
                ranges: vec![(1, kSmallLargestObserved + 1)],
            },
        };

        for &(quic_version, bytes) in test_cases {
            assert_eq!(
                ack_frame.frame_size(quic_version),
                bytes.len(),
                "calculate ACK frame size: {:?}, version {:?}",
                ack_frame,
                quic_version
            );
            assert_eq!(
                QuicAckFrame::parse(quic_version, creation_time, last_timestamp, bytes).unwrap(),
                (ack_frame.clone(), &[][..]),
                "parse ACK frame, version {:?}",
                quic_version,
            );
        }
    }

    #[test]
    fn overflow() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        const test_cases: &[(QuicVersion, &[u8])] = &[
            (
                QuicVersion::QUIC_VERSION_38,
                &[
                    // frame type (ack frame)
                    // (no ack blocks, 2 byte largest observed, 2 byte block length)
                    0x45,
                    // largest acked
                    0x34, 0x12,
                    // Zero delta time.
                    0x00, 0x00,
                    // first ack block length.
                    0x88, 0x88,
                    // num timestamps.
                    0x00,
                ],
            ),
            (
                QuicVersion::QUIC_VERSION_39,
                &[
                    // frame type (ack frame)
                    // (no ack blocks, 2 byte largest observed, 2 byte block length)
                    0x45,
                    // largest acked
                    0x12, 0x34,
                    // Zero delta time.
                    0x00, 0x00,
                    // first ack block length.
                    0x88, 0x88,
                    // num timestamps.
                    0x00,
                ],
            ),
            (
                QuicVersion::QUIC_VERSION_40,
                &[
                    // frame type (ack frame)
                    // (no ack blocks, 2 byte largest observed, 2 byte block length)
                    0x45,
                    // num timestamps.
                    0x00,
                    // largest acked
                    0x12, 0x34,
                    // Zero delta time.
                    0x00, 0x00,
                    // first ack block length.
                    0x88, 0x88,
                ],
            ),
        ];

        let creation_time = time::now().to_timespec();
        let last_timestamp = QuicTimeDelta::zero();

        for &(quic_version, bytes) in test_cases {
            assert!(
                QuicAckFrame::parse(quic_version, creation_time, last_timestamp, bytes).is_err(),
                "parse ACK frame with overflow block length, version {:?}",
                quic_version,
            );
        }
    }

    #[test]
    fn one_ack_block_max_length() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        const test_cases: &[(QuicVersion, &[u8])] = &[
            (
                QuicVersion::QUIC_VERSION_38,
                &[
                    // frame type (ack frame)
                    // (one ack block, 6 byte largest observed, 2 byte block length)
                    0x4D,
                    // largest acked
                    0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,
                    // Zero delta time.
                    0x00, 0x00,
                    // first ack block length.
                    0x34, 0x12,
                    // num timestamps.
                    0x00,
                ],
            ),
            (
                QuicVersion::QUIC_VERSION_39,
                &[
                    // frame type (ack frame)
                    // (one ack block, 6 byte largest observed, 2 byte block length)
                    0x4D,
                    // largest acked
                    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
                    // Zero delta time.
                    0x00, 0x00,
                    // first ack block length.
                    0x12, 0x34,
                    // num timestamps.
                    0x00,
                ],
            ),
            (
                QuicVersion::QUIC_VERSION_40,
                &[
                    // frame type (ack frame)
                    // (one ack block, 8 byte largest observed, 2 byte block length)
                    0xAD,
                    // num timestamps.
                    0x00,
                    // largest acked
                    0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
                    // Zero delta time.
                    0x00, 0x00,
                    // first ack block length.
                    0x12, 0x34,
                ],
            ),
        ];

        let creation_time = time::now().to_timespec();
        let last_timestamp = QuicTimeDelta::zero();
        let ack_frame = QuicAckFrame {
            largest_observed: kLargeLargestObserved,
            ack_delay_time: QuicTimeDelta::zero(),
            received_packet_times: None,
            packets: PacketNumberQueue {
                ranges: vec![
                    (
                        kLargeLargestObserved - kSmallLargestObserved + 1,
                        kLargeLargestObserved + 1,
                    ),
                ],
            },
        };

        for &(quic_version, bytes) in test_cases {
            assert_eq!(
                ack_frame.frame_size(quic_version),
                bytes.len(),
                "calculate ACK frame size: {:?}, version {:?}",
                ack_frame,
                quic_version
            );
            assert_eq!(
                QuicAckFrame::parse(quic_version, creation_time, last_timestamp, bytes).unwrap(),
                (ack_frame.clone(), &[][..]),
                "parse ACK frame with one ack block, version {:?}",
                quic_version,
            );
        }
    }

    #[test]
    fn two_timestamps_with_multiple_ack_blocks() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        const test_cases: &[(QuicVersion, &[u8])] = &[
            (
                QuicVersion::QUIC_VERSION_38,
                &[
                    // frame type (ack frame)
                    // (more than one ack block, 2 byte largest observed, 2 byte block length)
                    0x65,
                    // largest acked
                    0x34, 0x12,
                    // Zero delta time.
                    0x00, 0x00,
                    // num ack blocks ranges.
                    0x04,
                    // first ack block length.
                    0x01, 0x00,
                    // gap to next block.
                    0x01,
                    // ack block length.
                    0xaf, 0x0e,
                    // gap to next block.
                    0xff,
                    // ack block length.
                    0x00, 0x00,
                    // gap to next block.
                    0x91,
                    // ack block length.
                    0xea, 0x01,
                    // gap to next block.
                    0x05,
                    // ack block length.
                    0x04, 0x00,
                    // Number of timestamps.
                    0x02,
                    // Delta from largest observed.
                    0x01,
                    // Delta time.
                    0x10, 0x32, 0x54, 0x76,
                    // Delta from largest observed.
                    0x02,
                    // Delta time.
                    0x10, 0x32,
                ],
            ),
            (
                QuicVersion::QUIC_VERSION_39,
                &[
                    // frame type (ack frame)
                    // (more than one ack block, 2 byte largest observed, 2 byte block length)
                    0x65,
                    // largest acked
                    0x12, 0x34,
                    // Zero delta time.
                    0x00, 0x00,
                    // num ack blocks ranges.
                    0x04,
                    // first ack block length.
                    0x00, 0x01,
                    // gap to next block.
                    0x01,
                    // ack block length.
                    0x0e, 0xaf,
                    // gap to next block.
                    0xff,
                    // ack block length.
                    0x00, 0x00,
                    // gap to next block.
                    0x91,
                    // ack block length.
                    0x01, 0xea,
                    // gap to next block.
                    0x05,
                    // ack block length.
                    0x00, 0x04,
                    // Number of timestamps.
                    0x02,
                    // Delta from largest observed.
                    0x01,
                    // Delta time.
                    0x76, 0x54, 0x32, 0x10,
                    // Delta from largest observed.
                    0x02 ,
                    // Delta time.
                    0x32, 0x10
                ],
            ),
            (
                QuicVersion::QUIC_VERSION_40,
                &[
                    // frame type (ack frame)
                    // (more than one ack block, 2 byte largest observed, 2 byte block length)
                    0xB5,
                    // num ack blocks ranges.
                    0x04,
                    // Number of timestamps.
                    0x02,
                    // largest acked
                    0x12, 0x34,
                    // Zero delta time.
                    0x00, 0x00,
                    // first ack block length.
                    0x00, 0x01,
                    // gap to next block.
                    0x01,
                    // ack block length.
                    0x0e, 0xaf,
                    // gap to next block.
                    0xff,
                    // ack block length.
                    0x00, 0x00,
                    // gap to next block.
                    0x91,
                    // ack block length.
                    0x01, 0xea,
                    // gap to next block.
                    0x05,
                    // ack block length.
                    0x00, 0x04,
                    // Delta from largest observed.
                    0x01,
                    // Delta time.
                    0x76, 0x54, 0x32, 0x10,
                    // Delta from largest observed.
                    0x02 ,
                    // Delta time.
                    0x32, 0x10
                ],
            ),
        ];

        let creation_time = time::now().to_timespec();
        let last_timestamp = QuicTimeDelta::zero();
        let ack_frame = QuicAckFrame {
            largest_observed: kSmallLargestObserved,
            ack_delay_time: QuicTimeDelta::zero(),
            received_packet_times: Some(vec![
                (
                    kSmallLargestObserved - 1,
                    creation_time + Duration::microseconds(0x76543210),
                ),
                (
                    kSmallLargestObserved - 2,
                    creation_time + Duration::microseconds(0x76543210)
                        + Duration::microseconds(i64::from(UFloat16::from(0x3210))),
                ),
            ]),
            packets: PacketNumberQueue {
                ranges: vec![
                    (kSmallLargestObserved, kSmallLargestObserved + 1),
                    (900, kSmallLargestObserved - 1),
                    (10, 500),
                    (1, 5),
                ],
            },
        };

        for &(quic_version, bytes) in test_cases {
            assert_eq!(
                ack_frame.frame_size(quic_version),
                bytes.len(),
                "calculate ACK frame size: {:?}, version {:?}",
                ack_frame,
                quic_version
            );
            assert_eq!(
                QuicAckFrame::parse(quic_version, creation_time, last_timestamp, bytes).unwrap(),
                (ack_frame.clone(), &[][..]),
                "parse ACK frame with one ack block, version {:?}",
                quic_version,
            );
        }
    }
}
