use byteorder::ByteOrder;
use bytes::BufMut;
use failure::Error;
use nom::Needed;

use errors::{QuicErrorCode, QuicRstStreamErrorCode};
use errors::QuicError::IncompletePacket;
use frames::{PaddingBytes, QuicAckFrame, QuicBlockedFrame, QuicConnectionCloseFrame, QuicFrameReader, QuicFrameWriter,
             QuicGoAwayFrame, QuicPaddingFrame, QuicPingFrame, QuicRstStreamFrame, QuicStopWaitingFrame,
             QuicStreamFrame, QuicWindowUpdateFrame, ReadFrame, WriteFrame};
use proto::{QuicPacketNumber, QuicStreamId, QuicStreamOffset};
use types::QuicFrameType;

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
    pub fn padding(padding_bytes: PaddingBytes) -> Self {
        QuicFrame::Padding(QuicPaddingFrame { padding_bytes })
    }

    pub fn reset_stream(
        stream_id: QuicStreamId,
        error_code: QuicRstStreamErrorCode,
        byte_offset: QuicStreamOffset,
    ) -> Self {
        QuicFrame::ResetStream(QuicRstStreamFrame {
            stream_id,
            error_code,
            byte_offset,
        })
    }

    pub fn connection_close(error_code: QuicErrorCode, error_details: Option<&'a str>) -> Self {
        QuicFrame::ConnectionClose(QuicConnectionCloseFrame {
            error_code,
            error_details,
        })
    }

    pub fn go_away(
        error_code: QuicErrorCode,
        last_good_stream_id: Option<QuicStreamId>,
        reason_phrase: Option<&'a str>,
    ) -> Self {
        QuicFrame::GoAway(QuicGoAwayFrame {
            error_code,
            last_good_stream_id,
            reason_phrase,
        })
    }

    pub fn window_update(stream_id: QuicStreamId, byte_offset: QuicStreamOffset) -> Self {
        QuicFrame::WindowUpdate(QuicWindowUpdateFrame {
            stream_id,
            byte_offset,
        })
    }

    pub fn blocked(stream_id: QuicStreamId) -> Self {
        QuicFrame::Blocked(QuicBlockedFrame { stream_id })
    }

    pub fn stop_waiting(least_unacked: QuicPacketNumber) -> Self {
        QuicFrame::StopWaiting(QuicStopWaitingFrame { least_unacked })
    }

    pub fn ping() -> Self {
        QuicFrame::Ping(QuicPingFrame {})
    }

    pub fn stream(stream_id: QuicStreamId, offset: QuicStreamOffset, fin: bool, data: Option<&'a [u8]>) -> Self {
        QuicFrame::Stream(QuicStreamFrame {
            stream_id,
            offset,
            fin,
            data,
        })
    }

    pub fn frame_type(&self) -> QuicFrameType {
        match *self {
            QuicFrame::Padding(_) => QuicFrameType::Padding,
            QuicFrame::ResetStream(_) => QuicFrameType::ResetStream,
            QuicFrame::ConnectionClose(_) => QuicFrameType::ConnectionClose,
            QuicFrame::GoAway(_) => QuicFrameType::GoAway,
            QuicFrame::WindowUpdate(_) => QuicFrameType::WindowUpdate,
            QuicFrame::Blocked(_) => QuicFrameType::Blocked,
            QuicFrame::StopWaiting(_) => QuicFrameType::StopWaiting,
            QuicFrame::Ping(_) => QuicFrameType::Ping,
            QuicFrame::Stream(_) => QuicFrameType::Stream,
            QuicFrame::Ack(_) => QuicFrameType::Ack,
        }
    }

    pub fn as_padding_frame(&self) -> Option<&QuicPaddingFrame> {
        if let QuicFrame::Padding(ref frame) = *self {
            Some(frame)
        } else {
            None
        }
    }

    pub fn as_reset_stream_frame(&self) -> Option<&QuicRstStreamFrame> {
        if let QuicFrame::ResetStream(ref frame) = *self {
            Some(frame)
        } else {
            None
        }
    }

    pub fn as_connection_close_frame(&self) -> Option<&QuicConnectionCloseFrame> {
        if let QuicFrame::ConnectionClose(ref frame) = *self {
            Some(frame)
        } else {
            None
        }
    }

    pub fn as_go_away_frame(&self) -> Option<&QuicGoAwayFrame> {
        if let QuicFrame::GoAway(ref frame) = *self {
            Some(frame)
        } else {
            None
        }
    }

    pub fn as_window_update_frame(&self) -> Option<&QuicWindowUpdateFrame> {
        if let QuicFrame::WindowUpdate(ref frame) = *self {
            Some(frame)
        } else {
            None
        }
    }

    pub fn as_blocked_frame(&self) -> Option<&QuicBlockedFrame> {
        if let QuicFrame::Blocked(ref frame) = *self {
            Some(frame)
        } else {
            None
        }
    }

    pub fn as_stop_waiting_frame(&self) -> Option<&QuicStopWaitingFrame> {
        if let QuicFrame::StopWaiting(ref frame) = *self {
            Some(frame)
        } else {
            None
        }
    }

    pub fn as_ping_frame(&self) -> Option<&QuicPingFrame> {
        if let QuicFrame::Ping(ref frame) = *self {
            Some(frame)
        } else {
            None
        }
    }

    pub fn as_stream_frame(&self) -> Option<&QuicStreamFrame> {
        if let QuicFrame::Stream(ref frame) = *self {
            Some(frame)
        } else {
            None
        }
    }

    pub fn as_ack_frame(&self) -> Option<&QuicAckFrame> {
        if let QuicFrame::Ack(ref frame) = *self {
            Some(frame)
        } else {
            None
        }
    }
}

impl<'a> ReadFrame<'a> for QuicFrame<'a> {
    type Frame = QuicFrame<'a>;
    type Error = Error;

    fn read_frame<E, R>(reader: &'a R, payload: &'a [u8]) -> Result<(Self::Frame, &'a [u8]), Self::Error>
    where
        E: ByteOrder,
        R: QuicFrameReader<'a>,
    {
        if let Some(&frame_type) = payload.first() {
            match QuicFrameType::with_version(reader.quic_version(), frame_type)? {
                QuicFrameType::Padding => reader
                    .read_frame::<QuicPaddingFrame>(payload)
                    .map(|(frame, remaining)| (QuicFrame::Padding(frame), remaining)),

                QuicFrameType::ResetStream => reader.read_frame::<QuicRstStreamFrame>(payload).map(
                    |(frame, remaining)| (QuicFrame::ResetStream(frame), remaining),
                ),

                QuicFrameType::ConnectionClose => reader.read_frame::<QuicConnectionCloseFrame>(payload).map(
                    |(frame, remaining)| (QuicFrame::ConnectionClose(frame), remaining),
                ),

                QuicFrameType::GoAway => reader
                    .read_frame::<QuicGoAwayFrame>(payload)
                    .map(|(frame, remaining)| (QuicFrame::GoAway(frame), remaining)),

                QuicFrameType::WindowUpdate => reader.read_frame::<QuicWindowUpdateFrame>(payload).map(
                    |(frame, remaining)| (QuicFrame::WindowUpdate(frame), remaining),
                ),

                QuicFrameType::Blocked => reader
                    .read_frame::<QuicBlockedFrame>(payload)
                    .map(|(frame, remaining)| (QuicFrame::Blocked(frame), remaining)),

                QuicFrameType::StopWaiting => reader.read_frame::<QuicStopWaitingFrame>(payload).map(
                    |(frame, remaining)| (QuicFrame::StopWaiting(frame), remaining),
                ),

                QuicFrameType::Ping | QuicFrameType::MtuDiscovery => reader
                    .read_frame::<QuicPingFrame>(payload)
                    .map(|(frame, remaining)| (QuicFrame::Ping(frame), remaining)),

                QuicFrameType::Stream => reader
                    .read_frame::<QuicStreamFrame>(payload)
                    .map(|(frame, remaining)| (QuicFrame::Stream(frame), remaining)),

                QuicFrameType::Ack => reader
                    .read_frame::<QuicAckFrame>(payload)
                    .map(|(frame, remaining)| (QuicFrame::Ack(frame), remaining)),
            }
        } else {
            bail!(IncompletePacket(Needed::Unknown))
        }
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
            QuicFrame::Ping(ref ping) => ping.frame_size(writer),
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
            QuicFrame::Ping(ref frame) => frame.write_frame::<E, W, B>(writer, buf),
            QuicFrame::Stream(ref frame) => frame.write_frame::<E, W, B>(writer, buf),
            QuicFrame::Ack(ref frame) => frame.write_frame::<E, W, B>(writer, buf),
        }
    }
}
