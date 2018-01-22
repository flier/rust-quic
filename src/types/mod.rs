#![allow(dead_code, non_camel_case_types)]

mod traits;
#[macro_use]
mod version;
#[macro_use]
mod tag;
pub mod ufloat16;
mod frame;

pub use self::frame::QuicFrameType;
pub use self::tag::{quic_tag, QuicTag};
pub use self::traits::{Perspective, ToEndianness, ToQuicPacketNumber, ToQuicTimeDelta};
pub use self::ufloat16::UFloat16;
pub use self::version::QuicVersion;

use time::{Duration, Timespec};

pub type QuicPacketLength = u16;
pub type QuicHeaderId = u32;
pub type QuicByteCount = u64;
pub type QuicPacketCount = u64;
pub type QuicDiversificationNonce = [u8; 32];
pub type QuicTime = Timespec;
pub type QuicTimeDelta = Duration;

/// `EncryptionLevel` enumerates the stages of encryption that a QUIC connection progresses through.
/// When retransmitting a packet, the encryption level needs to be specified so
/// that it is retransmitted at a level which the peer can understand.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, FromPrimitive)]
pub enum EncryptionLevel {
    None,
    Initial,
    ForwardSecure,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PeerAddressChangeType {
    /// IP address and port remain unchanged.
    NO_CHANGE,
    /// Port changed, but IP address remains unchanged.
    PORT_CHANGE,
    /// IPv4 address changed, but within the /24 subnet (port may have changed.)
    IPV4_SUBNET_CHANGE,
    /// IPv4 address changed, excluding /24 subnet change (port may have changed.)
    IPV4_TO_IPV4_CHANGE,
    /// IP address change from an IPv4 to an IPv6 address (port may have changed.)
    IPV4_TO_IPV6_CHANGE,
    /// IP address change from an IPv6 to an IPv4 address (port may have changed.)
    IPV6_TO_IPV4_CHANGE,
    /// IP address change from an IPv6 to an IPv6 address (port may have changed.)
    IPV6_TO_IPV6_CHANGE,
}
