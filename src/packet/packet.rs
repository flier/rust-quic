use std::net::SocketAddr;
use std::ops::Deref;

use bytes::Bytes;

use packet::QuicPacketPublicHeader;
use proto::QuicPublicResetNonceProof;
use types::QuicTime;

#[derive(Clone, Debug)]
pub struct QuicData {}

#[derive(Clone, Debug)]
pub struct QuicEncryptedPacket(Bytes);

impl QuicEncryptedPacket {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Deref for QuicEncryptedPacket {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

// A received encrypted QUIC packet, with a recorded time of receipt.
#[derive(Clone, Debug)]
pub struct QuicReceivedPacket {
    pub packet: QuicEncryptedPacket,
    /// the time at which the packet was received.
    pub receipt_time: QuicTime,
    /// the TTL of the packet
    pub ttl: isize,
}

impl Deref for QuicReceivedPacket {
    type Target = QuicEncryptedPacket;

    fn deref(&self) -> &Self::Target {
        &self.packet
    }
}

impl From<QuicReceivedPacket> for QuicEncryptedPacket {
    fn from(packet: QuicReceivedPacket) -> Self {
        packet.packet
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct QuicPublicResetPacket<'a> {
    pub public_header: QuicPacketPublicHeader<'a>,
    pub nonce_proof: QuicPublicResetNonceProof,
    pub client_address: Option<SocketAddr>,
}

pub type QuicVersionNegotiationPacket<'a> = QuicPacketPublicHeader<'a>;
