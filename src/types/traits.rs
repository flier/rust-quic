use std::ops::Sub;

use byteorder::{BigEndian, LittleEndian};
use nom::Endianness;
use time::Duration;

use proto::QuicPacketNumber;
use types::QuicTimeDelta;

pub trait Perspective {
    fn is_server() -> bool;
}

pub struct ForServer {}

impl Perspective for ForServer {
    fn is_server() -> bool {
        true
    }
}

pub struct ForClient {}

impl Perspective for ForClient {
    fn is_server() -> bool {
        false
    }
}

pub trait ToEndianness {
    fn endianness() -> Endianness;
}

impl ToEndianness for LittleEndian {
    fn endianness() -> Endianness {
        Endianness::Little
    }
}

impl ToEndianness for BigEndian {
    fn endianness() -> Endianness {
        Endianness::Big
    }
}

pub trait ToQuicPacketNumber {
    fn from_wire(
        packet_number_length: usize,
        base_packet_number: QuicPacketNumber,
        packet_number: QuicPacketNumber,
    ) -> Self;
}

impl ToQuicPacketNumber for QuicPacketNumber {
    fn from_wire(
        packet_number_length: usize,
        base_packet_number: QuicPacketNumber,
        packet_number: QuicPacketNumber,
    ) -> Self {
        // The new packet number might have wrapped to the next epoch, or
        // it might have reverse wrapped to the previous epoch, or it might
        // remain in the same epoch.  Select the packet number closest to the
        // next expected packet number, the previous packet number plus 1.

        // epoch_delta is the delta between epochs the packet number was serialized
        // with, so the correct value is likely the same epoch as the last sequence
        // number or an adjacent epoch.
        let epoch_delta = 1 << (8 * packet_number_length);

        let next_packet_number = base_packet_number + 1;
        let epoch = base_packet_number & !(epoch_delta - 1);
        let prev_epoch = epoch.wrapping_sub(epoch_delta);
        let next_epoch = epoch.wrapping_add(epoch_delta);

        closest_to(
            next_packet_number,
            epoch + packet_number,
            closest_to(
                next_packet_number,
                prev_epoch + packet_number,
                next_epoch + packet_number,
            ),
        )
    }
}

pub trait ToQuicTimeDelta {
    fn from_wire(last_timestamp: Duration, time_delta_us: u32) -> Self;
}

impl ToQuicTimeDelta for QuicTimeDelta {
    fn from_wire(last_timestamp: Duration, time_delta_us: u32) -> Self {
        // The new time_delta might have wrapped to the next epoch, or it
        // might have reverse wrapped to the previous epoch, or it might
        // remain in the same epoch. Select the time closest to the previous
        // time.
        //
        // epoch_delta is the delta between epochs. A delta is 4 bytes of
        // microseconds.
        let epoch_delta = 1u64 << 32;
        let time_delta_us = u64::from(time_delta_us);

        Duration::microseconds(
            if let Some(last_timestamp_us) = last_timestamp.num_microseconds() {
                let epoch: u64 = (last_timestamp_us as u64) & !(epoch_delta - 1);
                // Wrapping is safe here because a wrapped value will not be ClosestTo below.
                let prev_epoch: u64 = epoch.wrapping_sub(epoch_delta);
                let next_epoch: u64 = epoch.wrapping_add(epoch_delta);

                closest_to(
                    last_timestamp_us as u64,
                    epoch + time_delta_us,
                    closest_to(
                        last_timestamp_us as u64,
                        prev_epoch + time_delta_us,
                        next_epoch + time_delta_us,
                    ),
                )
            } else {
                time_delta_us
            } as i64,
        )
    }
}

fn delta<T>(a: T, b: T) -> <T as Sub>::Output
where
    T: PartialOrd + Sub + Copy,
{
    if a < b {
        b - a
    } else {
        a - b
    }
}

fn closest_to<T>(target: T, a: T, b: T) -> T
where
    T: PartialOrd + Sub + Copy,
    <T as Sub>::Output: PartialOrd,
{
    if delta(target, a) < delta(target, b) {
        a
    } else {
        b
    }
}
