#![allow(non_snake_case, non_camel_case_types)]

use std::mem;
use std::str::FromStr;

use errors::QuicError;

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub enum QuicVersion {
    /// Allows endpoints to independently set stream limit.
    QUIC_VERSION_35 = 35,
    /// Add perspective into null encryption.
    QUIC_VERSION_37 = 37,
    /// PADDING frame is a 1-byte frame with type 0x00.
    /// Respect NSTP connection option.
    QUIC_VERSION_38 = 38,
    /// Integers and floating numbers are written in big endian.
    /// Dot not ack acks.
    /// Send a connection level WINDOW_UPDATE every 20 sent packets
    /// which do not contain retransmittable frames.
    QUIC_VERSION_39 = 39,
    /// RST_STREAM, ACK and STREAM frames match IETF format.
    QUIC_VERSION_40 = 40,
    /// Use IETF packet header format.
    QUIC_VERSION_41 = 41,
}

pub type QuicTag = [u8; 4];

impl From<QuicVersion> for QuicTag {
    fn from(version: QuicVersion) -> Self {
        let mut tag: QuicTag = unsafe { mem::uninitialized() };

        tag.copy_from_slice(match version {
            QuicVersion::QUIC_VERSION_35 => b"Q035",
            QuicVersion::QUIC_VERSION_37 => b"Q037",
            QuicVersion::QUIC_VERSION_38 => b"Q038",
            QuicVersion::QUIC_VERSION_39 => b"Q039",
            QuicVersion::QUIC_VERSION_40 => b"Q040",
            QuicVersion::QUIC_VERSION_41 => b"Q041",
        });

        tag
    }
}

impl FromStr for QuicVersion {
    type Err = QuicError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Q035" => Ok(QuicVersion::QUIC_VERSION_35),
            "Q037" => Ok(QuicVersion::QUIC_VERSION_37),
            "Q038" => Ok(QuicVersion::QUIC_VERSION_38),
            "Q039" => Ok(QuicVersion::QUIC_VERSION_39),
            "Q040" => Ok(QuicVersion::QUIC_VERSION_40),
            "Q041" => Ok(QuicVersion::QUIC_VERSION_41),
            _ => {
                let mut tag: QuicTag = unsafe { mem::uninitialized() };

                tag.copy_from_slice(s.as_bytes());

                Err(QuicError::UnsupportedVersion(tag))
            }
        }
    }
}
