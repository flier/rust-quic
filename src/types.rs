#![allow(dead_code, non_upper_case_globals)]

use std::ops::Sub;
use std::u16;

use byteorder::{BigEndian, LittleEndian};
use nom::Endianness;
use time::{Duration, Timespec};

pub type QuicPacketLength = u16;
pub type QuicHeaderId = u32;
pub type QuicStreamId = u32;
pub type QuicByteCount = u64;
pub type QuicConnectionId = u64;
pub type QuicPacketCount = u64;
pub type QuicPacketNumber = u64;
pub type QuicPublicResetNonceProof = u64;
pub type QuicStreamOffset = u64;
pub type QuicDiversificationNonce = [u8; 32];
pub type QuicTime = Timespec;
pub type QuicTimeDelta = Duration;

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
        let epoch_delta = 1 << 32;

        Duration::microseconds(
            if let Some(last_timestamp) = last_timestamp.num_microseconds() {
                let epoch = last_timestamp & !(epoch_delta - 1);
                // Wrapping is safe here because a wrapped value will not be ClosestTo below.
                let prev_epoch = epoch.wrapping_sub(epoch_delta);
                let next_epoch = epoch.wrapping_add(epoch_delta);

                closest_to(
                    last_timestamp,
                    epoch + time_delta_us as i64,
                    closest_to(
                        last_timestamp,
                        prev_epoch + time_delta_us as i64,
                        next_epoch + time_delta_us as i64,
                    ),
                )
            } else {
                time_delta_us as i64
            },
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

/// EncryptionLevel enumerates the stages of encryption that a QUIC connection progresses through.
/// When retransmitting a packet, the encryption level needs to be specified so
/// that it is retransmitted at a level which the peer can understand.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub enum EncryptionLevel {
    None,
    Initial,
    ForwardSecure,
}

pub trait Perspective {
    fn is_server() -> bool;
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

/// We define an unsigned 16-bit floating point value, inspired by IEEE floats
/// (http://en.wikipedia.org/wiki/Half_precision_floating-point_format),
/// with 5-bit exponent (bias 1), 11-bit mantissa (effective 12 with hidden
/// bit) and denormals, but without signs, transfinites or fractions. Wire format
/// 16 bits (little-endian byte order) are split into exponent (high 5) and
/// mantissa (low 11) and decoded as:
///   uint64_t value;
///   if (exponent == 0) value = mantissa;
///   else value = (mantissa | 1 << 11) << (exponent - 1)

const kUFloat16ExponentBits: usize = 5;
const kUFloat16MaxExponent: usize = (1 << kUFloat16ExponentBits) - 2; // 30
const kUFloat16MantissaBits: usize = 16 - kUFloat16ExponentBits; // 11
const kUFloat16MantissaEffectiveBits: usize = kUFloat16MantissaBits + 1; // 12
const kUFloat16MaxValue: u64 = ((1u64 << kUFloat16MantissaEffectiveBits) - 1) << kUFloat16MaxExponent; // 0x3FFC0000000

#[derive(Clone, Copy, Debug, Default, PartialEq, PartialOrd)]
pub struct UFloat16(u64);

impl UFloat16 {
    /// Returns the smallest value that can be represented by this integer type.
    pub fn min_value() -> Self {
        UFloat16(0)
    }

    /// Returns the largest value that can be represented by this integer type.
    pub fn max_value() -> Self {
        UFloat16(kUFloat16MaxValue)
    }
}

impl From<UFloat16> for u64 {
    fn from(f: UFloat16) -> u64 {
        f.0
    }
}

impl From<UFloat16> for i64 {
    fn from(f: UFloat16) -> i64 {
        f.0 as i64
    }
}

impl From<UFloat16> for u16 {
    fn from(f: UFloat16) -> u16 {
        let v = f.0;

        if v < (1 << kUFloat16MantissaEffectiveBits) {
            // Fast path: either the value is denormalized, or has exponent zero.
            // Both cases are represented by the value itself.
            v as u16
        } else if v >= kUFloat16MaxValue {
            // Value is out of range; clamp it to the maximum representable.
            u16::MAX
        } else {
            // The highest bit is between position 13 and 42 (zero-based), which
            // corresponds to exponent 1-30. In the output, mantissa is from 0 to 10,
            // hidden bit is 11 and exponent is 11 to 15. Shift the highest bit to 11
            // and count the shifts.
            let (exponent, value) = [16, 8, 4, 2, 1]
                .into_iter()
                .fold((0, v), |(exponent, value), offset| {
                    if value >= (1 << (kUFloat16MantissaBits + offset)) {
                        (exponent + offset, value >> offset)
                    } else {
                        (exponent, value)
                    }
                });

            debug_assert!(exponent >= 1, "exponent {} >= 1", exponent);
            debug_assert!(
                exponent <= kUFloat16MaxExponent,
                "exponent {} <= {}",
                exponent,
                kUFloat16MaxExponent
            );
            debug_assert!(
                value >= 1 << kUFloat16MantissaBits,
                "value {} >= {}",
                value,
                1 << kUFloat16MantissaBits
            );
            debug_assert!(
                value < 1 << kUFloat16MantissaEffectiveBits,
                "value {} < {}",
                value,
                1 << kUFloat16MantissaEffectiveBits
            );

            // Hidden bit (position 11) is set. We should remove it and increment the
            // exponent. Equivalently, we just add it to the exponent.
            // This hides the bit.
            (value + (exponent << kUFloat16MantissaBits) as u64) as u16
        }
    }
}

impl From<u16> for UFloat16 {
    fn from(v: u16) -> Self {
        UFloat16(if v < 1 << kUFloat16MantissaEffectiveBits {
            // Fast path: either the value is denormalized (no hidden bit), or
            // normalized (hidden bit set, exponent offset by one) with exponent zero.
            // Zero exponent offset by one sets the bit exactly where the hidden bit is.
            // So in both cases the value encodes itself.
            v as u64
        } else {
            let exponent = (v >> kUFloat16MantissaBits) - 1; // No sign extend on uint!

            // After the fast pass, the exponent is at least one (offset by one).
            // Un-offset the exponent.
            debug_assert!(exponent >= 1, "exponent {} >= 1", exponent);
            debug_assert!(
                exponent <= kUFloat16MaxExponent as u16,
                "exponent {} <= {}",
                exponent,
                kUFloat16MaxExponent
            );

            // Here we need to clear the exponent and set the hidden bit. We have already
            // decremented the exponent, so when we subtract it, it leaves behind the
            // hidden bit.
            let value = (v as u64 - (exponent << kUFloat16MantissaBits) as u64) << exponent as usize;

            debug_assert!(
                value >= 1 << kUFloat16MantissaEffectiveBits,
                "value {} >= {}",
                value,
                1 << kUFloat16MantissaEffectiveBits
            );
            debug_assert!(
                value <= kUFloat16MaxValue,
                "value {} < {}",
                value,
                kUFloat16MaxValue
            );

            value
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_ufloat16() {
        const test_cases: &[(u64, u16)] = &[
            // There are fewer decoding test cases because encoding truncates, and
            // decoding returns the smallest expansion.
            // Small numbers represent themselves.
            (0, 0),
            (1, 1),
            (2, 2),
            (3, 3),
            (4, 4),
            (5, 5),
            (6, 6),
            (7, 7),
            (15, 15),
            (31, 31),
            (42, 42),
            (123, 123),
            (1234, 1234),
            // Check transition through 2^11.
            (2046, 2046),
            (2047, 2047),
            (2048, 2048),
            (2049, 2049),
            // Running out of mantissa at 2^12.
            (4094, 4094),
            (4095, 4095),
            (4096, 4096),
            (4098, 4097),
            (4100, 4098),
            // Check transition through 2^13.
            (8190, 6143),
            (8192, 6144),
            (8196, 6145),
            // Half-way through the exponents.
            (0x7FF8000, 0x87FF),
            (0x8000000, 0x8800),
            (0xFFF0000, 0x8FFF),
            (0x10000000, 0x9000),
            // Transition into the largest exponent.
            (0x1FFE0000000, 0xF7FF),
            (0x20000000000, 0xF800),
            (0x20040000000, 0xF801),
            // Transition into the max value.
            (0x3FF80000000, 0xFFFE),
            (0x3FFC0000000, 0xFFFF),
        ];
        for &(v, f) in test_cases {
            assert_eq!(
                UFloat16::from(f).0,
                v,
                "from ufloat16 0x{:x} to u64 0x{:x}",
                f,
                v
            );
        }
    }

    #[test]
    fn test_to_ufloat16() {
        const test_cases: &[(u64, u16)] = &[
            // Small numbers represent themselves.
            (0, 0),
            (1, 1),
            (2, 2),
            (3, 3),
            (4, 4),
            (5, 5),
            (6, 6),
            (7, 7),
            (15, 15),
            (31, 31),
            (42, 42),
            (123, 123),
            (1234, 1234),
            // Check transition through 2^11.
            (2046, 2046),
            (2047, 2047),
            (2048, 2048),
            (2049, 2049),
            // Running out of mantissa at 2^12.
            (4094, 4094),
            (4095, 4095),
            (4096, 4096),
            (4097, 4096),
            (4098, 4097),
            (4099, 4097),
            (4100, 4098),
            (4101, 4098),
            // Check transition through 2^13.
            (8190, 6143),
            (8191, 6143),
            (8192, 6144),
            (8193, 6144),
            (8194, 6144),
            (8195, 6144),
            (8196, 6145),
            (8197, 6145),
            // Half-way through the exponents.
            (0x7FF8000, 0x87FF),
            (0x7FFFFFF, 0x87FF),
            (0x8000000, 0x8800),
            (0xFFF0000, 0x8FFF),
            (0xFFFFFFF, 0x8FFF),
            (0x10000000, 0x9000),
            // Transition into the largest exponent.
            (0x1FFFFFFFFFE, 0xF7FF),
            (0x1FFFFFFFFFF, 0xF7FF),
            (0x20000000000, 0xF800),
            (0x20000000001, 0xF800),
            (0x2003FFFFFFE, 0xF800),
            (0x2003FFFFFFF, 0xF800),
            (0x20040000000, 0xF801),
            (0x20040000001, 0xF801),
            // Transition into the max value and clamping.
            (0x3FF80000000, 0xFFFE),
            (0x3FFBFFFFFFF, 0xFFFE),
            (0x3FFC0000000, 0xFFFF),
            (0x3FFC0000001, 0xFFFF),
            (0x3FFFFFFFFFF, 0xFFFF),
            (0x40000000000, 0xFFFF),
            (0xFFFFFFFFFFFFFFFF, 0xFFFF),
        ];

        for &(v, f) in test_cases {
            assert_eq!(
                u16::from(UFloat16(v)),
                f,
                "from u64 0x{:x} to ufloat16 0x{:x}",
                v,
                f
            );
        }
    }
}
