#![allow(non_upper_case_globals)]

#[macro_use]
mod macros;
mod traits;
mod stream;
mod ack;
mod padding;
mod reset;
mod conn_close;
mod goaway;
mod win_update;
mod blocked;
mod stop_waiting;
mod ping;
mod types;
mod frame;

pub use self::ack::{PacketNumberQueue, QuicAckFrame};
pub use self::blocked::QuicBlockedFrame;
pub use self::conn_close::QuicConnectionCloseFrame;
pub use self::frame::QuicFrame;
pub use self::goaway::QuicGoAwayFrame;
pub use self::padding::{PaddingBytes, QuicPaddingFrame};
pub use self::ping::QuicPingFrame;
pub use self::reset::QuicRstStreamFrame;
pub use self::stop_waiting::QuicStopWaitingFrame;
pub use self::stream::QuicStreamFrame;
pub use self::traits::{BufMutExt, QuicFrameContext, QuicFrameReader, QuicFrameWriter, ReadFrame, WriteFrame};
pub use self::types::QuicFrameType;
pub use self::win_update::QuicWindowUpdateFrame;

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
pub const kQuicFrameTypeRegularMask: u8 = 0xE0; // 0b 11100000

pub const kQuicFrameTypeStreamMask_Pre40: u8 = 0x80;
pub const kQuicFrameTypeStreamMask: u8 = 0xC0;
pub const kQuicFrameTypeAckMask_Pre40: u8 = 0x40;
pub const kQuicFrameTypeAckMask: u8 = 0xA0;

// Number of bytes reserved for the frame type preceding each frame.
pub const kQuicFrameTypeSize: usize = 1;
// Number of bytes reserved for error code.
pub const kQuicErrorCodeSize: usize = 4;
// Number of bytes reserved to denote the length of error details field.
pub const kQuicErrorDetailsLengthSize: usize = 2;

// Maximum number of bytes reserved for stream id.
pub const kQuicMaxStreamIdSize: usize = 4;
// Maximum number of bytes reserved for byte offset in stream frame.
pub const kQuicMaxStreamOffsetSize: usize = 8;
// Number of bytes reserved to store payload length in stream frame.
pub const kQuicStreamPayloadLengthSize: usize = 2;

// Size in bytes reserved for the delta time of the largest observed
// packet number in ack frames.
pub const kQuicDeltaTimeLargestObservedSize: usize = 2;
// Size in bytes reserved for the number of received packets with timestamps.
pub const kQuicNumTimestampsSize: usize = 1;
// Size in bytes reserved for the number of missing packets in ack frames.
pub const kNumberOfNackRangesSize: usize = 1;
// Size in bytes reserved for the number of ack blocks in ack frames.
pub const kNumberOfAckBlocksSize: usize = 1;
// Maximum number of missing packet ranges that can fit within an ack frame.
pub const kMaxNackRanges: usize = (1 << (kNumberOfNackRangesSize * 8)) - 1;
// Maximum number of ack blocks that can fit within an ack frame.
pub const kMaxAckBlocks: usize = (1 << (kNumberOfAckBlocksSize * 8)) - 1;

#[cfg(test)]
mod mocks {
    pub use super::traits::mocks::{pair, pair_with_header, MockFrameReader, MockFrameWriter};
}
