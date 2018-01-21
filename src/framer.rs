#![allow(non_upper_case_globals)]

use std::cmp;
use std::io::Cursor;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use byteorder::{ByteOrder, NativeEndian, NetworkEndian};
use bytes::{BufMut, Bytes};
use failure::{Error, ResultExt};
use nom::{IResult, le_u16};

use constants::kMaxPacketSize;
use crypto::{CryptoHandshakeMessage, NullDecrypter, QuicDecrypter, kCADR, kPRST, kRNON};
use errors::QuicError;
use errors::QuicError::*;
use frames::{QuicAckFrame, QuicBlockedFrame, QuicConnectionCloseFrame, QuicFrameReader, QuicFrameWriter,
             QuicGoAwayFrame, QuicPaddingFrame, QuicPingFrame, QuicRstStreamFrame, QuicStopWaitingFrame,
             QuicStreamFrame, QuicWindowUpdateFrame, ReadFrame, WriteFrame};
use packet::{quic_version, EncryptedPacket, QuicPacketHeader, QuicPacketPublicHeader, QuicPublicResetPacket,
             QuicVersionNegotiationPacket};
use types::{EncryptionLevel, Perspective, QuicFrameType, QuicPacketNumber, QuicTime, QuicTimeDelta, QuicVersion,
            ToEndianness, ToQuicPacketNumber};

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
    /// If `on_unauthenticated_header` returns false, framing for this packet will cease.
    fn on_unauthenticated_header(&self, header: &QuicPacketHeader) -> bool;

    /// Called when a packet has been decrypted. `level` is the encryption level of the packet.
    fn on_decrypted_packet(&self, level: EncryptionLevel);

    /// Called when the complete header of a packet had been parsed.
    /// If `on_packet_header` returns false, framing for this packet will cease.
    fn on_packet_header(&self, header: &QuicPacketHeader) -> bool;

    /// Called when a `QuicStreamFrame` has been parsed.
    ///
    /// If `on_stream_frame` returns false, the framer will stop parsing the current packet.
    fn on_stream_frame(&self, frame: QuicStreamFrame) -> bool;

    /// Called when a `QuicAckFrame` has been parsed.
    ///
    /// If `on_ack_frame` returns false, the framer will stop parsing the current packet.
    fn on_ack_frame(&self, frame: QuicAckFrame) -> bool;

    /// Called when a `QuicPaddingFrame` has been parsed.
    fn on_padding_frame(&self, frame: QuicPaddingFrame) -> bool;

    /// Called when a `QuicRstStreamFrame` has been parsed.
    fn on_reset_stream_frame(&self, frame: QuicRstStreamFrame) -> bool;

    /// Called when a `QuicConnectionCloseFrame` has been parsed.
    fn on_connection_close_frame(&self, frame: QuicConnectionCloseFrame) -> bool;

    /// Called when a `QuicGoAwayFrame` has been parsed.
    fn on_go_away_frame(&self, frame: QuicGoAwayFrame) -> bool;

    /// Called when a `QuicWindowUpdateFrame` has been parsed.
    fn on_window_update_frame(&self, frame: QuicWindowUpdateFrame) -> bool;

    /// Called when a `QuicBlockedFrame` has been parsed.
    fn on_blocked_frame(&self, frame: QuicBlockedFrame) -> bool;

    /// Called when a `QuicStopWaitingFrame` has been parsed.
    fn on_stop_waiting_frame(&self, frame: QuicStopWaitingFrame) -> bool;

    /// Called when a PingFrame has been parsed.
    fn on_ping_frame(&self, frame: QuicPingFrame) -> bool;

    /// Called when a packet has been completely processed.
    fn on_packet_complete(&self);
}

/// Class for parsing and constructing QUIC packets.
///
/// It has a `QuicFramerVisitor` that is called when packets are parsed.
pub struct QuicFramer<'a, V> {
    supported_versions: &'a [QuicVersion],
    quic_version: QuicVersion,
    visitor: V,
    /// Updated by `process_packet_header` when it succeeds.
    last_packet_number: QuicPacketNumber,
    /// Updated by `process_packet_header` when it succeeds decrypting a larger packet.
    largest_packet_number: QuicPacketNumber,
    /// Primary decrypter used to decrypt packets during parsing.
    decrypter: Box<QuicDecrypter>,
    /// Alternative decrypter that can also be used to decrypt packets.
    alternative_decrypter: Option<Box<QuicDecrypter>>,
    /// The encryption level of `decrypter`.
    decrypter_level: EncryptionLevel,
    /// The encryption level of `alternative_decrypter`.
    alternative_decrypter_level: EncryptionLevel,
    /// `alternative_decrypter_latch` is true if,
    /// when `alternative_decrypter` successfully decrypts a packet,
    /// we should install it as the only decrypter.
    alternative_decrypter_latch: bool,
    /// The time this framer was created.
    /// Time written to the wire will be written as a delta from this value.
    creation_time: QuicTime,
    /// The time delta computed for the last timestamp frame.
    /// This is relative to the creation_time.
    last_timestamp: QuicTimeDelta,
}

impl<'a, V> QuicFramer<'a, V> {
    pub fn new<P>(supported_versions: &'a [QuicVersion], creation_time: QuicTime, visitor: V) -> Self
    where
        P: 'static + Perspective,
    {
        QuicFramer {
            supported_versions,
            quic_version: supported_versions[0],
            visitor,
            last_packet_number: 0,
            largest_packet_number: 0,
            decrypter: Box::new(NullDecrypter::<P>::default()),
            alternative_decrypter: None,
            decrypter_level: EncryptionLevel::None,
            alternative_decrypter_level: EncryptionLevel::None,
            alternative_decrypter_latch: false,
            creation_time,
            last_timestamp: QuicTimeDelta::zero(),
        }
    }

    pub fn version(&self) -> QuicVersion {
        self.quic_version
    }

    /// `set_decrypter` sets the primary decrypter, replacing any that already exists, and takes ownership.
    /// If an alternative decrypter is in place then the function DCHECKs.
    /// This is intended for cases where one knows that future packets will be using the new decrypter and
    /// the previous decrypter is now obsolete. `level` indicates the encryption level of the new decrypter.
    pub fn set_decrypter(&mut self, level: EncryptionLevel, decrypter: Box<QuicDecrypter>) {
        debug_assert!(self.alternative_decrypter.is_none());
        debug_assert!(level >= self.decrypter_level);

        self.decrypter = decrypter;
        self.decrypter_level = level;
    }

    /// `set_alternative_decrypter` sets a decrypter that may be used to decrypt future packets and takes ownership of it.
    /// `level` indicates the encryption level of the decrypter.
    /// If `latch_once_used` is true, then the first time that the decrypter is successful it will replace the primary decrypter.
    /// Otherwise both decrypters will remain active and the primary decrypter will be the one last used.
    pub fn set_alternative_decrypter(
        &mut self,
        level: EncryptionLevel,
        decrypter: Box<QuicDecrypter>,
        latch_once_used: bool,
    ) {
        self.alternative_decrypter = Some(decrypter);
        self.alternative_decrypter_level = level;
        self.alternative_decrypter_latch = latch_once_used;
    }

    pub fn decrypter(&self) -> &QuicDecrypter {
        self.decrypter.as_ref()
    }

    pub fn alternative_decrypter(&self) -> Option<&QuicDecrypter> {
        self.alternative_decrypter.as_ref().map(|d| d.as_ref())
    }
}

impl<'a, V> QuicFramer<'a, V>
where
    V: QuicFramerVisitor,
{
    pub fn process_packet<P>(&mut self, packet: &EncryptedPacket) -> Result<(), Error>
    where
        P: Perspective,
    {
        if self.quic_version > QuicVersion::QUIC_VERSION_38 {
            self.parse_packet::<P, NetworkEndian>(packet)
        } else {
            self.parse_packet::<P, NativeEndian>(packet)
        }
    }

    fn parse_packet<'p, P, E>(&mut self, packet: &'p EncryptedPacket) -> Result<(), Error>
    where
        P: Perspective,
        E: ByteOrder + ToEndianness,
    {
        self.visitor.on_packet();

        // First parse the public header.
        let (payload, public_header) = QuicPacketPublicHeader::parse::<E>(packet, P::is_server())?;

        if public_header.reset_flag && public_header.versions.is_some() {
            bail!(InvalidPacketHeader(
                "got version flag in reset packet".to_owned()
            ));
        }

        if !self.visitor
            .on_unauthenticated_public_header(&public_header)
        {
            // The visitor suppresses further processing of the packet.
            Ok(())
        } else {
            let protocol_version_mismatched = P::is_server()
                && public_header.versions.as_ref().map_or(false, |versions| {
                    versions[0] != self.quic_version && !self.visitor.on_protocol_version_mismatch(versions[0])
                });

            if protocol_version_mismatched {
                Ok(())
            } else if !P::is_server() && public_header.versions.as_ref().is_some() {
                self.process_version_negotiation_packet(payload, public_header)
            } else if public_header.reset_flag {
                self.process_public_reset_packet(payload, public_header)
            } else {
                self.process_data_packet::<P, E>(payload, public_header, packet)
            }
        }
    }

    fn process_version_negotiation_packet<'p>(
        &self,
        input: &'p [u8],
        mut public_header: QuicPacketPublicHeader<'p>,
    ) -> Result<(), Error> {
        // Try reading at least once to raise error if the packet is invalid.
        public_header.versions = Some(parse_version_negotiation_packet(input)
            .to_full_result()
            .map_err(QuicError::from)
            .context("Unable to read supported version in negotiation.")?);

        self.visitor.on_version_negotiation_packet(public_header);

        Ok(())
    }

    fn process_public_reset_packet<'p>(
        &self,
        input: &'p [u8],
        public_header: QuicPacketPublicHeader<'p>,
    ) -> Result<(), Error> {
        let (remaining, message) = CryptoHandshakeMessage::parse(input).context("unable to read reset message")?;

        debug_assert!(
            remaining.is_empty(),
            "unfinished reset message, {:?}",
            remaining
        );

        if message.tag() != kPRST {
            bail!(InvalidResetPacket(
                format!("incorrect message tag: {}", message.tag())
            ));
        }

        let packet = QuicPublicResetPacket {
            public_header,
            nonce_proof: message.get_u64(kRNON)?,
            client_address: message.get_bytes(kCADR).and_then(|s| {
                if let IResult::Done(_, addr) = parse_socket_address(s) {
                    addr
                } else {
                    None
                }
            }),
        };

        self.visitor.on_public_reset_packet(packet);

        Ok(())
    }

    fn process_data_packet<'p, P, E>(
        &mut self,
        input: &'p [u8],
        public_header: QuicPacketPublicHeader<'p>,
        packet: &'p EncryptedPacket,
    ) -> Result<(), Error>
    where
        P: Perspective,
        E: ByteOrder + ToEndianness,
    {
        let (remaining, header) = self.process_unauthenticated_header::<E>(input, public_header)?;

        if !self.visitor.on_unauthenticated_header(&header) {
            debug!("Visitor asked to stop processing of unauthenticated header.");

            return Ok(());
        }

        let payload = self.decrypt_payload::<P>(remaining, &header, packet)
            .context("Unable to decrypt payload.")?;

        // Set the last packet number after we have decrypted the packet
        // so we are confident is not attacker controlled.
        self.set_last_packet_number(&header);

        if !self.visitor.on_packet_header(&header) {
            // The visitor suppresses further processing of the packet.
            return Ok(());
        }

        if packet.len() > kMaxPacketSize {
            bail!(PacketTooLarge(packet.len()));
        }

        // Handle the payload.
        self.process_frame_data(&header, &payload)?;

        self.visitor.on_packet_complete();

        Ok(())
    }

    fn process_unauthenticated_header<'p, E>(
        &self,
        input: &'p [u8],
        public_header: QuicPacketPublicHeader<'p>,
    ) -> Result<(&'p [u8], QuicPacketHeader<'p>), Error>
    where
        E: ByteOrder,
    {
        let base_packet_number = self.largest_packet_number;

        let (remaining, packet_number) = self.process_and_calculate_packet_number::<E>(
            input,
            public_header.packet_number_length as usize,
            base_packet_number,
        )?;

        if packet_number == 0 {
            bail!(InvalidPacketHeader("packet numbers cannot be 0".to_owned()));
        }

        Ok((
            remaining,
            QuicPacketHeader {
                public_header,
                packet_number,
            },
        ))
    }

    fn process_and_calculate_packet_number<'p, E>(
        &self,
        input: &'p [u8],
        packet_number_length: usize,
        base_packet_number: QuicPacketNumber,
    ) -> Result<(&'p [u8], QuicPacketNumber), Error>
    where
        E: ByteOrder,
    {
        let wire_packet_number = E::read_uint(input, packet_number_length);

        let packet_number = QuicPacketNumber::from_wire(packet_number_length, base_packet_number, wire_packet_number);

        Ok((&input[packet_number_length..], packet_number))
    }

    fn decrypt_payload<'p, P>(
        &mut self,
        input: &'p [u8],
        header: &'p QuicPacketHeader,
        packet: &'p EncryptedPacket,
    ) -> Result<Bytes, Error>
    where
        P: Perspective,
    {
        let associated_data = self.get_associated_data_from_encrypted_packet(header, packet);

        if let Ok(decrypted) = self.decrypter.decrypt_packet(
            self.quic_version,
            header.packet_number,
            associated_data,
            input,
        ) {
            self.visitor.on_decrypted_packet(self.decrypter_level);

            return Ok(decrypted);
        }

        if let Some(decrypter) = self.alternative_decrypter.take() {
            let try_alternative_decryption = self.alternative_decrypter_level != EncryptionLevel::Initial
                || P::is_server() || header.public_header.nonce.is_some();

            if try_alternative_decryption {
                if let Ok(decrypted) = decrypter.decrypt_packet(
                    self.quic_version,
                    header.packet_number,
                    associated_data,
                    input,
                ) {
                    self.visitor
                        .on_decrypted_packet(self.alternative_decrypter_level);

                    if self.alternative_decrypter_latch {
                        self.decrypter = decrypter;
                        self.decrypter_level = self.alternative_decrypter_level;
                        self.alternative_decrypter_level = EncryptionLevel::None;
                    } else {
                        self.alternative_decrypter = Some(mem::replace(&mut self.decrypter, decrypter));
                        self.decrypter_level =
                            mem::replace(&mut self.alternative_decrypter_level, self.decrypter_level);
                    }

                    return Ok(decrypted);
                }
            }
        }

        bail!(
            "decrypt packet failed for packet_number: {}",
            header.packet_number
        );
    }

    fn get_associated_data_from_encrypted_packet<'p>(
        &self,
        header: &QuicPacketHeader,
        packet: &'p EncryptedPacket,
    ) -> &'p [u8] {
        &packet.as_bytes()[..header.size()]
    }

    fn set_last_packet_number(&mut self, header: &QuicPacketHeader) {
        self.last_packet_number = header.packet_number;
        self.largest_packet_number = cmp::max(self.largest_packet_number, header.packet_number);
    }

    fn process_frame_data(&self, header: &QuicPacketHeader, data: &[u8]) -> Result<(), Error> {
        let reader = FrameReader {
            framer: self,
            header,
        };
        let mut payload = data;

        while let Some(&frame_type) = payload.first() {
            match QuicFrameType::with_version(self.quic_version, frame_type)? {
                QuicFrameType::Padding => {
                    let (frame, remaining) = reader.read_frame::<QuicPaddingFrame>(payload)?;

                    debug!("parsed frame: {:?}", frame);

                    if !self.visitor.on_padding_frame(frame) {
                        debug!("Visitor asked to stop further processing.");

                        return Ok(());
                    }

                    payload = remaining;
                }
                QuicFrameType::ResetStream => {
                    let (frame, remaining) = reader.read_frame::<QuicRstStreamFrame>(payload)?;

                    debug!("parsed frame: {:?}", frame);

                    if !self.visitor.on_reset_stream_frame(frame) {
                        debug!("Visitor asked to stop further processing.");

                        return Ok(());
                    }

                    payload = remaining;
                }
                QuicFrameType::ConnectionClose => {
                    let (frame, remaining) = reader.read_frame::<QuicConnectionCloseFrame>(payload)?;

                    debug!("parsed frame: {:?}", frame);

                    if !self.visitor.on_connection_close_frame(frame) {
                        debug!("Visitor asked to stop further processing.");

                        return Ok(());
                    }

                    payload = remaining;
                }
                QuicFrameType::GoAway => {
                    let (frame, remaining) = reader.read_frame::<QuicGoAwayFrame>(payload)?;

                    debug!("parsed frame: {:?}", frame);

                    if !self.visitor.on_go_away_frame(frame) {
                        debug!("Visitor asked to stop further processing.");

                        return Ok(());
                    }

                    payload = remaining;
                }
                QuicFrameType::WindowUpdate => {
                    let (frame, remaining) = reader.read_frame::<QuicWindowUpdateFrame>(payload)?;

                    debug!("parsed frame: {:?}", frame);

                    if !self.visitor.on_window_update_frame(frame) {
                        debug!("Visitor asked to stop further processing.");

                        return Ok(());
                    }

                    payload = remaining;
                }
                QuicFrameType::Blocked => {
                    let (frame, remaining) = reader.read_frame::<QuicBlockedFrame>(payload)?;

                    debug!("parsed frame: {:?}", frame);

                    if !self.visitor.on_blocked_frame(frame) {
                        debug!("Visitor asked to stop further processing.");

                        return Ok(());
                    }

                    payload = remaining;
                }
                QuicFrameType::StopWaiting => {
                    let (frame, remaining) = reader.read_frame::<QuicStopWaitingFrame>(payload)?;

                    debug!("parsed frame: {:?}", frame);

                    if !self.visitor.on_stop_waiting_frame(frame) {
                        debug!("Visitor asked to stop further processing.");

                        return Ok(());
                    }

                    payload = remaining;
                }
                QuicFrameType::Ping => {
                    let (frame, remaining) = reader.read_frame::<QuicPingFrame>(payload)?;

                    debug!("parsed frame: {:?}", frame);

                    if !self.visitor.on_ping_frame(frame) {
                        debug!("Visitor asked to stop further processing.");

                        return Ok(());
                    }

                    payload = remaining;
                }
                QuicFrameType::Stream => {
                    let (frame, remaining) = reader.read_frame::<QuicStreamFrame>(payload)?;

                    debug!("parsed frame: {:?}", frame);

                    if !self.visitor.on_stream_frame(frame) {
                        debug!("Visitor asked to stop further processing.");

                        return Ok(());
                    }

                    payload = remaining;
                }
                QuicFrameType::Ack => {
                    let (frame, remaining) = reader.read_frame::<QuicAckFrame>(payload)?;

                    debug!("parsed frame: {:?}", frame);

                    if !self.visitor.on_ack_frame(frame) {
                        debug!("Visitor asked to stop further processing.");

                        return Ok(());
                    }

                    payload = remaining;
                }
                _ => bail!(IllegalFrameType(frame_type)),
            }
        }

        Ok(())
    }
}

struct FrameReader<'a, 'p, V>
where
    V: 'a,
    'a: 'p,
{
    framer: &'a QuicFramer<'a, V>,
    header: &'p QuicPacketHeader<'p>,
}

impl<'a, 'p, V> QuicFrameReader<'a> for FrameReader<'a, 'p, V> {
    fn packet_header(&self) -> &QuicPacketHeader {
        self.header
    }

    fn quic_version(&self) -> QuicVersion {
        self.framer.quic_version
    }

    fn creation_time(&self) -> QuicTime {
        self.framer.creation_time
    }

    fn last_timestamp(&self) -> QuicTimeDelta {
        self.framer.last_timestamp
    }
}

struct FrameWriter<'a, 'p, V>
where
    V: 'a,
{
    framer: &'a QuicFramer<'a, V>,
    header: &'p QuicPacketHeader<'p>,
    payload: Cursor<&'p mut [u8]>,
}

impl<'a, 'p, V> BufMut for FrameWriter<'a, 'p, V> {
    fn remaining_mut(&self) -> usize {
        self.payload.remaining_mut()
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        self.payload.advance_mut(cnt)
    }

    unsafe fn bytes_mut(&mut self) -> &mut [u8] {
        self.payload.bytes_mut()
    }
}

impl<'a, 'p, V> QuicFrameWriter<'a> for FrameWriter<'a, 'p, V> {
    fn packet_header(&self) -> &QuicPacketHeader {
        self.header
    }

    fn quic_version(&self) -> QuicVersion {
        self.framer.quic_version
    }

    fn creation_time(&self) -> QuicTime {
        self.framer.creation_time
    }
}

named!(
    parse_version_negotiation_packet<Vec<QuicVersion>>,
    many1!(quic_version)
);

/// For convenience, the values of these constants match the values of `AF_INET` and `AF_INET6` on Linux.
const kIPv4: u16 = 2;
const kIPv6: u16 = 10;

const kIPv4AddressSize: usize = 4;
const kIPv6AddressSize: usize = 16;

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    parse_socket_address<Option<SocketAddr>>,
    do_parse!(
        address_family: le_u16 >>
        ip: switch!(value!(address_family),
            kIPv4 => take!(kIPv4AddressSize) |
            kIPv6 => take!(kIPv6AddressSize)
        ) >>
        port: le_u16 >>
        (
            match address_family {
                kIPv4 => Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(*array_ref!(ip, 0, kIPv4AddressSize))),
                    port
                )),
                kIPv6 => Some(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(*array_ref!(ip, 0, kIPv6AddressSize))),
                    port
                )),
                _ => None,
            }
        )
    )
);
