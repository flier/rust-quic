#![allow(non_upper_case_globals)]

mod stream;

pub use self::stream::{QuicStreamFrame, QuicStreamFrameType};

use version::QuicVersion;

// New Frame Types, QUIC v. >= 10:
// There are two interpretations for the Frame Type byte in the QUIC protocol,
// resulting in two Frame Types: Special Frame Types and Regular Frame Types.
//
// Regular Frame Types use the Frame Type byte simply. Currently defined
// Regular Frame Types are:
// Padding            : 0b 00000000 (0x00)
// ResetStream        : 0b 00000001 (0x01)
// ConnectionClose    : 0b 00000010 (0x02)
// GoAway             : 0b 00000011 (0x03)
// WindowUpdate       : 0b 00000100 (0x04)
// Blocked            : 0b 00000101 (0x05)
//
// Special Frame Types encode both a Frame Type and corresponding flags
// all in the Frame Type byte. Currently defined Special Frame Types are:
// Stream             : 0b 11xxxxxx
// Ack                : 0b 101xxxxx
//
// Semantics of the flag bits above (the x bits) depends on the frame type.

// Masks to determine if the frame type is a special use and for specific special frame types.
pub const kQuicFrameTypeSpecialMask: u8 = 0xE0; // 0b 11100000

const kQuicFrameTypeStreamMask_Pre40: u8 = 0x80;
const kQuicFrameTypeStreamMask: u8 = 0xC0;
const kQuicFrameTypeAckMask_Pre40: u8 = 0x40;
const kQuicFrameTypeAckMask: u8 = 0xA0;

pub fn is_stream_frame(quic_version: QuicVersion, frame_type: u8) -> bool {
    match quic_version {
        _ if quic_version < QuicVersion::QUIC_VERSION_40 => {
            (frame_type & kQuicFrameTypeStreamMask_Pre40) == kQuicFrameTypeStreamMask_Pre40
        }
        _ => (frame_type & kQuicFrameTypeStreamMask) == kQuicFrameTypeStreamMask,
    }
}

pub fn is_ack_frame(quic_version: QuicVersion, frame_type: u8) -> bool {
    match quic_version {
        _ if quic_version < QuicVersion::QUIC_VERSION_40 => {
            (frame_type & kQuicFrameTypeAckMask_Pre40) == kQuicFrameTypeAckMask_Pre40
        }
        _ => (frame_type & kQuicFrameTypeAckMask) == kQuicFrameTypeAckMask,
    }
}
