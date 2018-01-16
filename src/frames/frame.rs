use byteorder::ByteOrder;
use bytes::BufMut;
use failure::Error;

use frames::{QuicAckFrame, QuicBlockedFrame, QuicConnectionCloseFrame, QuicGoAwayFrame, QuicPaddingFrame,
             QuicPingFrame, QuicRstStreamFrame, QuicStopWaitingFrame, QuicStreamFrame, QuicWindowUpdateFrame, ToWire};
use packet::QuicPacketHeader;
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

impl<'a> ToWire for QuicFrame<'a> {
    type Frame = QuicBlockedFrame;
    type Error = Error;

    fn frame_size(&self, quic_version: QuicVersion, header: &QuicPacketHeader) -> usize {
        match *self {
            QuicFrame::Padding(ref padding) => padding.frame_size(quic_version, header),
            QuicFrame::ResetStream(ref reset_stream) => reset_stream.frame_size(quic_version, header),
            QuicFrame::ConnectionClose(ref conn_close) => conn_close.frame_size(quic_version, header),
            QuicFrame::GoAway(ref go_away) => go_away.frame_size(quic_version, header),
            QuicFrame::WindowUpdate(ref win_update) => win_update.frame_size(quic_version, header),
            QuicFrame::Blocked(ref blocked) => blocked.frame_size(quic_version, header),
            QuicFrame::StopWaiting(ref stop_waiting) => stop_waiting.frame_size(quic_version, header),
            QuicFrame::Ping(ref ping) => ping.frame_size(quic_version, header),
            QuicFrame::Stream(ref stream) => stream.frame_size(quic_version, header),
            QuicFrame::Ack(ref ack) => ack.frame_size(quic_version),
        }
    }

    fn write_to<E, T>(
        &self,
        quic_version: QuicVersion,
        header: &QuicPacketHeader,
        buf: &mut T,
    ) -> Result<usize, Self::Error>
    where
        E: ByteOrder,
        T: BufMut,
    {
        match *self {
            QuicFrame::Padding(ref frame) => frame.write_to::<E, T>(quic_version, header, buf),
            QuicFrame::ResetStream(ref frame) => frame.write_to::<E, T>(quic_version, header, buf),
            QuicFrame::ConnectionClose(ref frame) => frame.write_to::<E, T>(quic_version, header, buf),
            QuicFrame::GoAway(ref frame) => frame.write_to::<E, T>(quic_version, header, buf),
            QuicFrame::WindowUpdate(ref frame) => frame.write_to::<E, T>(quic_version, header, buf),
            QuicFrame::Blocked(ref frame) => frame.write_to::<E, T>(quic_version, header, buf),
            QuicFrame::StopWaiting(ref frame) => frame.write_to::<E, T>(quic_version, header, buf),
            QuicFrame::Ping(ref frame) => frame.write_to::<E, T>(quic_version, header, buf),
            QuicFrame::Stream(ref frame) => frame.write_to::<E, T>(quic_version, header, buf),
            //             QuicFrame::Ack(ref ack) => {}
            _ => unreachable!(),
        }
    }
}
