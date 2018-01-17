use failure::Error;
use num::FromPrimitive;

use constants::{kQuicFrameTypeAckMask, kQuicFrameTypeAckMask_Pre40, kQuicFrameTypeRegularMask,
                kQuicFrameTypeSpecialMask, kQuicFrameTypeStreamMask, kQuicFrameTypeStreamMask_Pre40};
use errors::QuicError;
use types::QuicVersion;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum QuicFrameType {
    // Regular frame types. The values set here cannot change without the
    // introduction of a new QUIC version.
    Padding = 0,
    ResetStream = 1,
    ConnectionClose = 2,
    GoAway = 3,
    WindowUpdate = 4,
    Blocked = 5,
    StopWaiting = 6,
    Ping = 7,

    // STREAM and ACK frames are special frames. They are encoded differently on
    // the wire and their values do not need to be stable.
    Stream,
    Ack,
    // The path MTU discovery frame is encoded as a PING frame on the wire.
    MtuDiscovery,
}

impl QuicFrameType {
    pub fn with_version(quic_version: QuicVersion, flags: u8) -> Result<QuicFrameType, Error> {
        if is_regular_frame(flags) {
            QuicFrameType::from_u8(flags & kQuicFrameTypeRegularMask)
                .ok_or_else(|| QuicError::IllegalFrameType(flags).into())
        } else if is_stream_frame(quic_version, flags) {
            Ok(QuicFrameType::Stream)
        } else if is_ack_frame(quic_version, flags) {
            Ok(QuicFrameType::Ack)
        } else {
            bail!(QuicError::IllegalFrameType(flags))
        }
    }
}

fn is_regular_frame(frame_type: u8) -> bool {
    (frame_type & kQuicFrameTypeSpecialMask) == 0
}

fn is_stream_frame(quic_version: QuicVersion, frame_type: u8) -> bool {
    match quic_version {
        _ if quic_version < QuicVersion::QUIC_VERSION_40 => {
            (frame_type & kQuicFrameTypeStreamMask_Pre40) == kQuicFrameTypeStreamMask_Pre40
        }
        _ => (frame_type & kQuicFrameTypeStreamMask) == kQuicFrameTypeStreamMask,
    }
}

fn is_ack_frame(quic_version: QuicVersion, frame_type: u8) -> bool {
    match quic_version {
        _ if quic_version < QuicVersion::QUIC_VERSION_40 => {
            (frame_type & kQuicFrameTypeAckMask_Pre40) == kQuicFrameTypeAckMask_Pre40
        }
        _ => (frame_type & kQuicFrameTypeAckMask) == kQuicFrameTypeAckMask,
    }
}
