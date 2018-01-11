#![allow(dead_code)]

mod traits;
pub mod ufloat16;

pub use self::traits::{Perspective, ToEndianness, ToQuicPacketNumber, ToQuicTimeDelta};
pub use self::ufloat16::UFloat16;

use time::{Duration, Timespec};

pub type QuicPacketLength = u16;
pub type QuicHeaderId = u32;
pub type QuicStreamId = u32;
pub type QuicByteCount = u64;
pub type QuicConnectionId = u64;
pub type QuicPacketCount = u64;
pub type QuicPacketNumber = u64;
pub type QuicPublicResetNonceProof = u64;
pub type QuicStreamOffset = u64;
pub type QuicDiversificationNonce = [u8; 32];
pub type QuicTime = Timespec;
pub type QuicTimeDelta = Duration;

/// EncryptionLevel enumerates the stages of encryption that a QUIC connection progresses through.
/// When retransmitting a packet, the encryption level needs to be specified so
/// that it is retransmitted at a level which the peer can understand.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub enum EncryptionLevel {
    None,
    Initial,
    ForwardSecure,
}
