#![allow(non_snake_case, non_camel_case_types)]

use std::str::FromStr;

use byteorder::{NativeEndian, NetworkEndian};
use failure::Error;
use nom::Endianness;

use errors::QuicError;
use tag::QuicTag;
use types::ToEndianness;

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

impl QuicVersion {
    pub fn endianness(self) -> Endianness {
        if self > QuicVersion::QUIC_VERSION_38 {
            NetworkEndian::endianness()
        } else {
            NativeEndian::endianness()
        }
    }
}

impl From<QuicVersion> for QuicTag {
    fn from(version: QuicVersion) -> Self {
        QuicTag::new(match version {
            QuicVersion::QUIC_VERSION_35 => b"Q035",
            QuicVersion::QUIC_VERSION_37 => b"Q037",
            QuicVersion::QUIC_VERSION_38 => b"Q038",
            QuicVersion::QUIC_VERSION_39 => b"Q039",
            QuicVersion::QUIC_VERSION_40 => b"Q040",
            QuicVersion::QUIC_VERSION_41 => b"Q041",
        })
    }
}

impl FromStr for QuicVersion {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Q035" => Ok(QuicVersion::QUIC_VERSION_35),
            "Q037" => Ok(QuicVersion::QUIC_VERSION_37),
            "Q038" => Ok(QuicVersion::QUIC_VERSION_38),
            "Q039" => Ok(QuicVersion::QUIC_VERSION_39),
            "Q040" => Ok(QuicVersion::QUIC_VERSION_40),
            "Q041" => Ok(QuicVersion::QUIC_VERSION_41),
            _ if s.len() >= 4 => bail!(QuicError::UnsupportedVersion(QuicTag::new(s.as_bytes()))),
            _ => bail!("incomplete QUIC tag, {}", s),
        }
    }
}
