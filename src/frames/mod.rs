#![allow(non_upper_case_globals)]

#[macro_use]
mod macros;
mod stream;
mod ack;
mod padding;
mod reset;
mod conn_close;
mod goaway;
mod win_update;
mod blocked;
mod stop_waiting;
mod frame;

pub use self::ack::{PacketNumberQueue, QuicAckFrame};
pub use self::blocked::QuicBlockedFrame;
pub use self::conn_close::QuicConnectionCloseFrame;
pub use self::frame::QuicFrame;
pub use self::goaway::QuicGoAwayFrame;
pub use self::padding::QuicPaddingFrame;
pub use self::reset::QuicRstStreamFrame;
pub use self::stop_waiting::QuicStopWaitingFrame;
pub use self::stream::QuicStreamFrame;
pub use self::win_update::QuicWindowUpdateFrame;

pub const kQuicFrameTypeSize: usize = 1; // u8
pub const kStringPieceLenSize: usize = 2; // u16

/// A ping frame contains no payload, though it is retransmittable,
/// and ACK'd just like other normal frames.
#[derive(Clone, Debug, PartialEq)]
pub struct QuicPingFrame {}

impl QuicPingFrame {
    pub fn frame_size(&self) -> usize {
        kQuicFrameTypeSize
    }
}
