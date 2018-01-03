use std::time::Instant;

use byteorder::{ByteOrder, NativeEndian, NetworkEndian};
use failure::{Error, ResultExt};
use nom::IResult;

use crypto::{CryptoHandshakeMessage, kCADR, kPRST, kRNON};
use errors::QuicError;
use packet::{quic_version, EncryptedPacket, QuicPacketHeader, QuicPacketPublicHeader, QuicPublicResetPacket,
             QuicVersionNegotiationPacket, ToEndianness};
use sockaddr::socket_address;
use version::QuicVersion;

pub trait Perspective {
    fn is_server() -> bool;
}

pub trait QuicFramerVisitor {
    /// Called when a new packet has been received, before it has been validated or processed.
    fn on_packet(&self);

    /// Called when the public header has been parsed, but has not been authenticated.
    /// If it returns false, framing for this packet will cease.
    fn on_unauthenticated_public_header(&self, header: &QuicPacketPublicHeader) -> bool;

    /// Called only when `perspective` is IS_SERVER and the framer gets a packet with version flag true
    /// and the version on the packet doesn't match `quic_version`.
    /// The visitor should return true after it updates the version of the `framer` to `received_version`
    /// or false to stop processing this packet.
    fn on_protocol_version_mismatch(&self, received_version: QuicVersion) -> bool;

    /// Called only when `perspective` is IS_CLIENT and a version negotiation packet has been parsed.
    fn on_version_negotiation_packet(&self, packet: QuicVersionNegotiationPacket);

    /// Called when a public reset packet has been parsed but has not yet been validated.
    fn on_public_reset_packet(&self, packet: QuicPublicResetPacket);

    /// Called when the unauthenticated portion of the header has been parsed.
    /// If OnUnauthenticatedHeader returns false, framing for this packet will cease.
    fn on_unauthenticated_header(&self, header: &QuicPacketHeader) -> bool;
}

/// Class for parsing and constructing QUIC packets.
/// It has a `FramerVisitor` that is called when packets are parsed.
pub struct QuicFramer<'a, V> {
    supported_versions: &'a [QuicVersion],
    quic_version: QuicVersion,
    creation_time: Instant,
    visitor: V,
}

impl<'a, V> QuicFramer<'a, V> {
    pub fn new(supported_versions: &'a [QuicVersion], creation_time: Instant, visitor: V) -> Self {
        QuicFramer {
            supported_versions,
            quic_version: supported_versions[0],
            creation_time,
            visitor,
        }
    }

    pub fn version(&self) -> QuicVersion {
        self.quic_version
    }
}

impl<'a, V> QuicFramer<'a, V>
where
    V: QuicFramerVisitor,
{
    pub fn process_packet<P>(&self, packet: &EncryptedPacket) -> Result<(), Error>
    where
        P: Perspective,
    {
        let remaining = if self.quic_version > QuicVersion::QUIC_VERSION_38 {
            self.parse_packet::<P, NetworkEndian>(packet)
        } else {
            self.parse_packet::<P, NativeEndian>(packet)
        };

        Ok(())
    }

    fn parse_packet<'p, P, E>(&self, packet: &'p EncryptedPacket) -> Result<&'p [u8], Error>
    where
        P: Perspective,
        E: ByteOrder + ToEndianness,
    {
        self.visitor.on_packet();

        // First parse the public header.
        let (remaining, public_header) = QuicPacketPublicHeader::parse::<E>(packet, P::is_server())?;

        if public_header.reset_flag && public_header.versions.is_some() {
            bail!("Got version flag in reset packet");
        }

        if !self.visitor
            .on_unauthenticated_public_header(&public_header)
        {
            // The visitor suppresses further processing of the packet.
            Ok(remaining)
        } else if P::is_server() && public_header.versions.as_ref().map_or(false, |versions| {
            versions[0] != self.quic_version && !self.visitor.on_protocol_version_mismatch(versions[0])
        }) {
            Ok(remaining)
        } else if !P::is_server() && public_header.versions.as_ref().is_some() {
            self.process_version_negotiation_packet(remaining, public_header)
        } else if public_header.reset_flag {
            self.process_public_reset_packet(remaining, public_header)
        } else {
            self.process_data_packet(remaining, public_header)
        }
    }

    fn process_version_negotiation_packet<'p>(
        &self,
        input: &'p [u8],
        mut public_header: QuicPacketPublicHeader<'p>,
    ) -> Result<&'p [u8], Error> {
        // Try reading at least once to raise error if the packet is invalid.
        public_header.versions = Some(parse_version_negotiation_packet(input)
            .to_full_result()
            .map_err(QuicError::from)
            .context("Unable to read supported version in negotiation.")?);

        self.visitor.on_version_negotiation_packet(public_header);

        Ok(input)
    }

    fn process_public_reset_packet<'p>(
        &self,
        input: &'p [u8],
        public_header: QuicPacketPublicHeader<'p>,
    ) -> Result<&'p [u8], Error> {
        let (remaining, message) = CryptoHandshakeMessage::parse(input).context("unable to read reset message")?;

        if message.tag() != kPRST {
            bail!("Incorrect message tag: {}.", message.tag());
        }

        let packet = QuicPublicResetPacket {
            public_header,
            nonce_proof: message.get_u64(kRNON)?,
            client_address: message.get_bytes(kCADR).and_then(|s| {
                if let IResult::Done(_, addr) = socket_address(s) {
                    addr
                } else {
                    None
                }
            }),
        };

        self.visitor.on_public_reset_packet(packet);

        Ok(remaining)
    }

    fn process_data_packet<'p>(
        &self,
        input: &'p [u8],
        public_header: QuicPacketPublicHeader<'p>,
    ) -> Result<&'p [u8], Error> {
        Ok(input)
    }

    fn process_unauthenticated_header<'p>(
        &self,
        input: &'p [u8],
        public_header: QuicPacketPublicHeader<'p>,
    ) -> Result<&'p [u8], Error> {
        Ok(input)
    }
}

named!(
    parse_version_negotiation_packet<Vec<QuicVersion>>,
    many1!(quic_version)
);
