use std::cmp;
use std::mem;
use std::time::Instant;

use byteorder::{ByteOrder, NativeEndian, NetworkEndian};
use bytes::Bytes;
use failure::{Error, ResultExt};
use nom::IResult;

use constants::kMaxPacketSize;
use crypto::{CryptoHandshakeMessage, NullDecrypter, QuicDecrypter, kCADR, kPRST, kRNON};
use errors::QuicError;
use frames::{is_stream_frame, QuicStreamFrame, kQuicFrameTypeSpecialMask};
use packet::{quic_version, EncryptedPacket, QuicPacketHeader, QuicPacketPublicHeader, QuicPublicResetPacket,
             QuicVersionNegotiationPacket};
use sockaddr::socket_address;
use types::{EncryptionLevel, Perspective, QuicPacketNumber, ToEndianness};
use version::{QuicVersion};

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
    fn on_stream_frame(&self, frame: QuicStreamFrame) -> bool;

    /// Called when a packet has been completely processed.
    fn on_packet_complete(&self);
}

/// Class for parsing and constructing QUIC packets.
///
/// It has a `QuicFramerVisitor` that is called when packets are parsed.
pub struct QuicFramer<'a, V> {
    supported_versions: &'a [QuicVersion],
    quic_version: QuicVersion,
    creation_time: Instant,
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
}

impl<'a, V> QuicFramer<'a, V> {
    pub fn new<P>(supported_versions: &'a [QuicVersion], creation_time: Instant, visitor: V) -> Self
    where
        P: 'static + Perspective,
    {
        QuicFramer {
            supported_versions,
            quic_version: supported_versions[0],
            creation_time,
            visitor,
            last_packet_number: 0,
            largest_packet_number: 0,
            decrypter: Box::new(NullDecrypter::<P>::new()),
            alternative_decrypter: None,
            decrypter_level: EncryptionLevel::None,
            alternative_decrypter_level: EncryptionLevel::None,
            alternative_decrypter_latch: false,
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
        let remaining = if self.quic_version > QuicVersion::QUIC_VERSION_38 {
            self.parse_packet::<P, NetworkEndian>(packet)
        } else {
            self.parse_packet::<P, NativeEndian>(packet)
        };

        Ok(())
    }

    fn parse_packet<'p, P, E>(&mut self, packet: &'p EncryptedPacket) -> Result<(), Error>
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
            Ok(())
        } else if P::is_server() && public_header.versions.as_ref().map_or(false, |versions| {
            versions[0] != self.quic_version && !self.visitor.on_protocol_version_mismatch(versions[0])
        }) {
            Ok(())
        } else if !P::is_server() && public_header.versions.as_ref().is_some() {
            self.process_version_negotiation_packet(remaining, public_header)
        } else if public_header.reset_flag {
            self.process_public_reset_packet(remaining, public_header)
        } else {
            self.process_data_packet::<P, E>(remaining, public_header, packet)
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
            bail!("Visitor asked to stop processing of unauthenticated header.")
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
            bail!(QuicError::PacketTooLarge(packet.len()));
        }

        // Handle the payload.
        self.process_frame_data(&payload, header)?;

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
            bail!("packet numbers cannot be 0.")
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

        let packet_number =
            self.calculate_packet_number_from_wire(packet_number_length, base_packet_number, wire_packet_number);

        return Ok((&input[packet_number_length..], packet_number));
    }

    fn calculate_packet_number_from_wire(
        &self,
        packet_number_length: usize,
        base_packet_number: QuicPacketNumber,
        packet_number: QuicPacketNumber,
    ) -> QuicPacketNumber {
        // The new packet number might have wrapped to the next epoch, or
        // it might have reverse wrapped to the previous epoch, or it might
        // remain in the same epoch.  Select the packet number closest to the
        // next expected packet number, the previous packet number plus 1.

        // epoch_delta is the delta between epochs the packet number was serialized
        // with, so the correct value is likely the same epoch as the last sequence
        // number or an adjacent epoch.
        let epoch_delta = 1 << (8 * packet_number_length);

        let next_packet_number = base_packet_number + 1;
        let epoch = base_packet_number & !(epoch_delta - 1);
        let prev_epoch = epoch - epoch_delta;
        let next_epoch = epoch + epoch_delta;

        return closest_to(
            next_packet_number,
            epoch + packet_number,
            closest_to(
                next_packet_number,
                prev_epoch + packet_number,
                next_epoch + packet_number,
            ),
        );
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
        let associated_data = self.get_associated_data_from_encrypted_packet(&header, packet);

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

    fn process_frame_data(&self, payload: &[u8], header: QuicPacketHeader) -> Result<(), Error>
    {
        while let Some((frame_type, remaining)) = payload.split_first() {
            let frame_type = *frame_type;

            if (frame_type & kQuicFrameTypeSpecialMask) == 0 {
                bail!(QuicError::InvalidFrameType(frame_type));
            }

            if is_stream_frame(self.quic_version, frame_type) {
                let frame = self.process_stream_frame(remaining, frame_type)?;

                if !self.visitor.on_stream_frame(frame) {
                    debug!("Visitor asked to stop further processing.");

                    return Ok(());
                }
            }
        }

        Ok(())
    }

    fn process_stream_frame<'p>(&self, payload: &'p [u8], frame_type: u8) -> Result<QuicStreamFrame<'p>, Error>
    {
        QuicStreamFrame::parse(self.quic_version, frame_type, payload)
    }
}

fn delta(a: QuicPacketNumber, b: QuicPacketNumber) -> QuicPacketNumber {
    if a < b {
        b - a
    } else {
        a - b
    }
}

fn closest_to(target: QuicPacketNumber, a: QuicPacketNumber, b: QuicPacketNumber) -> QuicPacketNumber {
    if delta(target, a) < delta(target, b) {
        a
    } else {
        b
    }
}

named!(
    parse_version_negotiation_packet<Vec<QuicVersion>>,
    many1!(quic_version)
);
