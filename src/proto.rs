#![allow(non_camel_case_types)]

use std::{u32, u8};
use std::mem;

use types::QuicVersion;

pub type QuicConnectionId = u64;
pub type QuicStreamId = u32;
pub type QuicStreamOffset = u64;
pub type QuicPacketNumber = u64;
pub type QuicPublicResetNonceProof = u64;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, FromPrimitive)]
pub enum QuicPacketNumberLength {
    PACKET_1BYTE_PACKET_NUMBER = 1,
    PACKET_2BYTE_PACKET_NUMBER = 2,
    PACKET_4BYTE_PACKET_NUMBER = 4,
    // TODO(rch): Remove this when we remove QUIC_VERSION_39.
    PACKET_6BYTE_PACKET_NUMBER = 6,
    PACKET_8BYTE_PACKET_NUMBER = 8,
}

impl Default for QuicPacketNumberLength {
    fn default() -> Self {
        QuicPacketNumberLength::PACKET_1BYTE_PACKET_NUMBER
    }
}

impl From<QuicPacketNumberLengthFlags> for QuicPacketNumberLength {
    fn from(flags: QuicPacketNumberLengthFlags) -> Self {
        QuicPacketNumberLength::from_flags(QuicVersion::default(), flags)
    }
}

impl QuicPacketNumberLength {
    pub fn from_flags(version: QuicVersion, flags: QuicPacketNumberLengthFlags) -> Self {
        match flags {
            QuicPacketNumberLengthFlags::PACKET_FLAGS_8BYTE_PACKET => if version <= QuicVersion::QUIC_VERSION_39 {
                QuicPacketNumberLength::PACKET_6BYTE_PACKET_NUMBER
            } else {
                QuicPacketNumberLength::PACKET_8BYTE_PACKET_NUMBER
            },
            QuicPacketNumberLengthFlags::PACKET_FLAGS_4BYTE_PACKET => {
                QuicPacketNumberLength::PACKET_4BYTE_PACKET_NUMBER
            }
            QuicPacketNumberLengthFlags::PACKET_FLAGS_2BYTE_PACKET => {
                QuicPacketNumberLength::PACKET_2BYTE_PACKET_NUMBER
            }
            QuicPacketNumberLengthFlags::PACKET_FLAGS_1BYTE_PACKET => {
                QuicPacketNumberLength::PACKET_1BYTE_PACKET_NUMBER
            }
        }
    }

    pub fn for_packet_number(quic_version: QuicVersion, packet_number: QuicPacketNumber) -> Self {
        [
            QuicPacketNumberLength::PACKET_1BYTE_PACKET_NUMBER,
            QuicPacketNumberLength::PACKET_2BYTE_PACKET_NUMBER,
            QuicPacketNumberLength::PACKET_4BYTE_PACKET_NUMBER,
        ].into_iter()
            .cloned()
            .find(|&n| packet_number < (1 << (8 * n as usize)))
            .unwrap_or(if quic_version <= QuicVersion::QUIC_VERSION_39 {
                QuicPacketNumberLength::PACKET_6BYTE_PACKET_NUMBER
            } else {
                QuicPacketNumberLength::PACKET_8BYTE_PACKET_NUMBER
            })
    }

    pub fn as_flags(&self) -> QuicPacketNumberLengthFlags {
        match *self {
            QuicPacketNumberLength::PACKET_1BYTE_PACKET_NUMBER => {
                QuicPacketNumberLengthFlags::PACKET_FLAGS_1BYTE_PACKET
            }
            QuicPacketNumberLength::PACKET_2BYTE_PACKET_NUMBER => {
                QuicPacketNumberLengthFlags::PACKET_FLAGS_2BYTE_PACKET
            }
            QuicPacketNumberLength::PACKET_4BYTE_PACKET_NUMBER => {
                QuicPacketNumberLengthFlags::PACKET_FLAGS_4BYTE_PACKET
            }
            QuicPacketNumberLength::PACKET_6BYTE_PACKET_NUMBER | QuicPacketNumberLength::PACKET_8BYTE_PACKET_NUMBER => {
                QuicPacketNumberLengthFlags::PACKET_FLAGS_8BYTE_PACKET
            }
        }
    }
}

#[repr(u8)]
#[derive(Clone, Debug, PartialEq)]
pub enum QuicPacketNumberLengthFlags {
    PACKET_FLAGS_1BYTE_PACKET = 0,          // 00
    PACKET_FLAGS_2BYTE_PACKET = 1,          // 01
    PACKET_FLAGS_4BYTE_PACKET = 1 << 1,     // 10
    PACKET_FLAGS_8BYTE_PACKET = 1 << 1 | 1, // 11
}

impl From<u8> for QuicPacketNumberLengthFlags {
    fn from(v: u8) -> Self {
        unsafe { mem::transmute(v) }
    }
}

#[derive(Clone, Debug, PartialEq, PartialOrd, FromPrimitive)]
pub enum QuicConnectionIdLength {
    PACKET_0BYTE_CONNECTION_ID = 0,
    PACKET_1BYTE_CONNECTION_ID = 1,
    PACKET_4BYTE_CONNECTION_ID = 4,
    PACKET_8BYTE_CONNECTION_ID = 8,
}

impl QuicConnectionIdLength {
    pub fn size_of(connection_id: Option<QuicConnectionId>) -> Self {
        match connection_id {
            None => QuicConnectionIdLength::PACKET_0BYTE_CONNECTION_ID,
            Some(id) if id < u8::MAX as u64 => QuicConnectionIdLength::PACKET_1BYTE_CONNECTION_ID,
            Some(id) if id < u32::MAX as u64 => QuicConnectionIdLength::PACKET_4BYTE_CONNECTION_ID,
            _ => QuicConnectionIdLength::PACKET_8BYTE_CONNECTION_ID,
        }
    }
}
