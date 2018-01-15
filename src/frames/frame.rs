use failure::Error;

use frames::{QuicAckFrame, QuicBlockedFrame, QuicConnectionCloseFrame, QuicGoAwayFrame, QuicPaddingFrame,
             QuicPingFrame, QuicRstStreamFrame, QuicStopWaitingFrame, QuicStreamFrame, QuicWindowUpdateFrame};
use types::QuicVersion;

#[derive(Clone, Debug, PartialEq)]
pub enum QuicFrame<'a> {
    Padding(QuicPaddingFrame),
    ResetStream(QuicRstStreamFrame),
    ConnectionClose(QuicConnectionCloseFrame<'a>),
    GoAway(QuicGoAwayFrame<'a>),
    WindowUpdate(QuicWindowUpdateFrame),
    Blocked(QuicBlockedFrame),
    StopWaiting(QuicStopWaitingFrame),
    Ping(QuicPingFrame),
    Stream(QuicStreamFrame<'a>),
    Ack(QuicAckFrame),
}

impl<'a> QuicFrame<'a> {
    pub fn frame_size(&self, quic_version: QuicVersion) -> usize {
        match *self {
            QuicFrame::Padding(ref padding) => padding.frame_size(),
            QuicFrame::ResetStream(ref reset_stream) => reset_stream.frame_size(),
            QuicFrame::ConnectionClose(ref conn_close) => conn_close.frame_size(),
            QuicFrame::GoAway(ref go_away) => go_away.frame_size(),
            QuicFrame::WindowUpdate(ref win_update) => win_update.frame_size(),
            QuicFrame::Blocked(ref blocked) => blocked.frame_size(),
            QuicFrame::StopWaiting(ref stop_waiting) => stop_waiting.frame_size(),
            QuicFrame::Ping(ref ping) => ping.frame_size(),
            QuicFrame::Stream(ref stream) => stream.frame_size(quic_version),
            QuicFrame::Ack(ref ack) => ack.frame_size(),
        }
    }
}

pub trait WriteFrame {
    fn write_frame(&mut self, frame: &QuicFrame) -> Result<usize, Error>;
}

// impl<T> WriteFrame for T
// where
//     T: BufMut,
// {
//     fn write_frame(&mut self, frame: &QuicFrame) -> Result<usize, Error> {
//         match *frame {
//             QuicFrame::Padding(ref padding) => {}
//             QuicFrame::ResetStream(ref reset_stream) => {}
//             QuicFrame::ConnectionClose(ref conn_close) => {}
//             QuicFrame::GoAway(ref go_away) => {}
//             QuicFrame::WindowUpdate(ref win_update) => {}
//             QuicFrame::Blocked(ref blocked) => {}
//             QuicFrame::StopWaiting(ref stop_waiting) => {}
//             QuicFrame::Ping(ref ping) => {}
//             QuicFrame::Stream(ref stream) => {}
//             QuicFrame::Ack(ref ack) => {}
//         }
//     }
// }
