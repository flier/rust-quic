use failure::{Error, Fail};
use nom::{IResult, be_u8};
use time::Duration;

use errors::QuicError;
use packet::{read_ack_packet_number_length, QuicPacketNumberLength};
use types::{QuicPacketNumber, QuicTime, QuicTimeDelta, ToQuicTimeDelta, UFloat16};
use version::QuicVersion;

// packet number size shift used in AckFrames.
const kQuicSequenceNumberLengthNumBits: usize = 2;
const kActBlockLengthOffset: usize = 0;
const kLargestAckedOffset: usize = 2;

// Acks may have only one ack block.
const kQuicHasMultipleAckBlocksOffset_Pre40: usize = 5;
const kQuicHasMultipleAckBlocksOffset: usize = 4;

pub struct QuicAckFrame {
    /// The highest packet number we've observed from the peer.
    pub largest_observed: QuicPacketNumber,
    /// Time elapsed since largest_observed was received until this Ack frame was sent.
    pub ack_delay_time: QuicTimeDelta,
    /// Vector of <packet_number, time> for when packets arrived.
    pub received_packet_times: Vec<(QuicPacketNumber, QuicTime)>,
    /// Set of packets.
    pub packets: PacketNumberQueue,
}

impl QuicAckFrame {
    pub fn parse(
        quic_version: QuicVersion,
        creation_time: QuicTime,
        last_timestamp: QuicTimeDelta,
        frame_type: u8,
        payload: &[u8],
    ) -> Result<QuicAckFrame, Error> {
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
            payload,
            quic_version,
            creation_time,
            last_timestamp,
            has_ack_blocks,
            ack_block_length,
            largest_acked_length,
        ) {
            IResult::Done(remaining, (largest_observed, ack_delay_time, received_packet_times, packets)) => {
                debug_assert!(
                    remaining.is_empty(),
                    "unfinished ACK frame, {:?}",
                    remaining
                );

                Ok(QuicAckFrame {
                    largest_observed,
                    ack_delay_time,
                    received_packet_times,
                    packets,
                })
            }
            IResult::Incomplete(needed) => bail!(QuicError::IncompletePacket(needed).context("incomplete ack frame.")),
            IResult::Error(err) => bail!(QuicError::InvalidPacket(err).context("unable to process ack frame.")),
        }
    }
}

named_args!(parse_quic_ack_frame(quic_version: QuicVersion,
                                 creation_time: QuicTime,
                                 last_timestamp: QuicTimeDelta,
                                 has_ack_blocks: bool,
                                 ack_block_length: QuicPacketNumberLength,
                                 largest_acked_length: QuicPacketNumberLength)
                                 <(u64, Duration, Vec<(QuicPacketNumber, QuicTime)>, PacketNumberQueue)>,
    do_parse!(
        num_ack_blocks_new: cond!(quic_version > QuicVersion::QUIC_VERSION_39 && has_ack_blocks, be_u8) >>
        num_received_packets_new: cond!(quic_version > QuicVersion::QUIC_VERSION_39, be_u8) >>
        largest_observed: uint!(quic_version.endianness(), largest_acked_length as usize) >>
        ack_delay_time_us: map!(u16!(quic_version.endianness()), UFloat16::from) >>
        num_ack_blocks_pre40: cond!(quic_version <= QuicVersion::QUIC_VERSION_39 && has_ack_blocks, be_u8) >>
        first_block_length: uint!(quic_version.endianness(), ack_block_length as usize) >>
        first_received: value!(largest_observed + 1 - first_block_length) >>
        num_ack_blocks: expr_opt!(num_ack_blocks_new.or(num_ack_blocks_pre40)) >>
        packet_ranges: many_m_n!(num_ack_blocks as usize, num_ack_blocks as usize,
            tuple!(be_u8, uint!(quic_version.endianness(), ack_block_length as usize))
        ) >>
        num_received_packets_pre40: cond!(quic_version <= QuicVersion::QUIC_VERSION_39, be_u8) >>
        num_received_packets: map!(
            expr_opt!(num_received_packets_new.or(num_received_packets_pre40)), |n| n as usize
        ) >>
        delta_from_largest_observed: map!(be_u8, |n| n as QuicPacketNumber) >>
        time_delta_us: u32!(quic_version.endianness()) >>
        timestamps: many_m_n!(num_received_packets-1, num_received_packets-1,
            tuple!(be_u8, map!(u16!(quic_version.endianness()), UFloat16::from))
        ) >>
        (
            (
                largest_observed,
                if ack_delay_time_us == UFloat16::max_value() {
                    Duration::max_value()
                } else {
                    Duration::microseconds(ack_delay_time_us.into())
                },
                timestamps.into_iter().fold(
                    (
                        vec![(largest_observed - delta_from_largest_observed, creation_time + last_timestamp)],
                        QuicTimeDelta::from_wire(last_timestamp, time_delta_us),
                    ),
                    |(mut times, last_timestamp), (delta_from_largest_observed, incremental_time_delta_us)| {
                        let seq_num = largest_observed - delta_from_largest_observed as u64;
                        let last_timestamp = last_timestamp + Duration::microseconds(incremental_time_delta_us.into());

                        times.push((seq_num, creation_time + last_timestamp));

                        (times, last_timestamp)
                    }
                ).0,
                PacketNumberQueue {
                    ranges: packet_ranges.into_iter().fold(
                        (vec![(first_received, largest_observed+1)], first_received),
                        |(mut ranges, mut first_received), (gap, current_block_length)| {
                            first_received -= gap as u64 + current_block_length;

                            if current_block_length > 0 {
                                ranges.push((first_received, first_received + current_block_length))
                            }

                            (ranges, first_received)
                        }
                    ).0
                },
            )
        )
    )
);

/// A sequence of packet numbers where each number is unique.
///
/// Intended to be used in a sliding window fashion,
/// where smaller old packet numbers are removed and larger new packet numbers are added,
/// with the occasional random access.
pub struct PacketNumberQueue {
    ranges: Vec<(u64, u64)>,
}
