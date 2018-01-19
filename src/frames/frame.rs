use byteorder::ByteOrder;
use bytes::BufMut;
use failure::Error;

use frames::{QuicAckFrame, QuicBlockedFrame, QuicConnectionCloseFrame, QuicFrameReader, QuicFrameWriter,
             QuicGoAwayFrame, QuicPaddingFrame, QuicPingFrame, QuicRstStreamFrame, QuicStopWaitingFrame,
             QuicStreamFrame, QuicWindowUpdateFrame, ReadFrame, ToWire, WriteFrame};

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

impl<'a> ReadFrame<'a> for QuicFrame<'a> {
    type Frame = QuicFrame<'a>;
    type Error = Error;

    fn read_frame<E, R>(reader: &'a R, payload: &'a [u8]) -> Result<(Self::Frame, &'a [u8]), Self::Error>
    where
        E: ByteOrder,
        R: QuicFrameReader<'a>,
    {
        unreachable!()
    }
}

impl<'a> WriteFrame<'a> for QuicFrame<'a> {
    type Error = Error;

    fn frame_size<W>(&self, writer: &W) -> usize
    where
        W: QuicFrameWriter<'a>,
    {
        match *self {
            QuicFrame::Padding(ref padding) => padding.frame_size(writer),
            QuicFrame::ResetStream(ref reset_stream) => reset_stream.frame_size(writer),
            QuicFrame::ConnectionClose(ref conn_close) => conn_close.frame_size(writer),
            QuicFrame::GoAway(ref go_away) => go_away.frame_size(writer),
            QuicFrame::WindowUpdate(ref win_update) => win_update.frame_size(writer),
            QuicFrame::Blocked(ref blocked) => blocked.frame_size(writer),
            QuicFrame::StopWaiting(ref stop_waiting) => stop_waiting.frame_size(writer),
            QuicFrame::Ping(ref ping) => ping.frame_size(writer.quic_version(), writer.packet_header()),
            QuicFrame::Stream(ref stream) => stream.frame_size(writer),
            QuicFrame::Ack(ref ack) => ack.frame_size(writer),
        }
    }

    fn write_frame<E, W, B>(&self, writer: &W, buf: &mut B) -> Result<usize, Self::Error>
    where
        E: ByteOrder,
        W: QuicFrameWriter<'a>,
        B: BufMut,
    {
        match *self {
            QuicFrame::Padding(ref frame) => frame.write_frame::<E, W, B>(writer, buf),
            QuicFrame::ResetStream(ref frame) => frame.write_frame::<E, W, B>(writer, buf),
            QuicFrame::ConnectionClose(ref frame) => frame.write_frame::<E, W, B>(writer, buf),
            QuicFrame::GoAway(ref frame) => frame.write_frame::<E, W, B>(writer, buf),
            QuicFrame::WindowUpdate(ref frame) => frame.write_frame::<E, W, B>(writer, buf),
            QuicFrame::Blocked(ref frame) => frame.write_frame::<E, W, B>(writer, buf),
            QuicFrame::StopWaiting(ref frame) => frame.write_frame::<E, W, B>(writer, buf),
            QuicFrame::Ping(ref frame) => frame.write_to::<E, B>(writer.quic_version(), writer.packet_header(), buf),
            QuicFrame::Stream(ref frame) => frame.write_frame::<E, W, B>(writer, buf),
            QuicFrame::Ack(ref frame) => frame.write_frame::<E, W, B>(writer, buf),
        }
    }
}
