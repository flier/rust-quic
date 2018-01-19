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
mod frame;

pub use self::ack::{PacketNumberQueue, QuicAckFrame};
pub use self::blocked::QuicBlockedFrame;
pub use self::conn_close::QuicConnectionCloseFrame;
pub use self::frame::QuicFrame;
pub use self::goaway::QuicGoAwayFrame;
pub use self::padding::QuicPaddingFrame;
pub use self::ping::QuicPingFrame;
pub use self::reset::QuicRstStreamFrame;
pub use self::stop_waiting::QuicStopWaitingFrame;
pub use self::stream::QuicStreamFrame;
pub use self::traits::{BufMutExt, FromWire, QuicFrameReader, QuicFrameWriter, ReadFrame, ToWire, WriteFrame};
pub use self::win_update::QuicWindowUpdateFrame;

#[cfg(test)]
mod mocks {
    pub use super::traits::mocks::{pair, pair_with_header, MockFrameReader, MockFrameWriter};
}
