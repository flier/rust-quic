#![allow(non_upper_case_globals)]

use std::cell::RefCell;
use std::cmp;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Deref;

use byteorder::{ByteOrder, NativeEndian, NetworkEndian};
use bytes::{BufMut, Bytes};
use failure::{Error, ResultExt};
use nom::{IResult, le_u16};

use constants::kMaxPacketSize;
use crypto::{CryptoHandshakeMessage, NullDecrypter, NullEncrypter, QuicDecrypter, QuicEncrypter, kCADR, kPRST, kRNON};
use errors::QuicError;
use errors::QuicError::*;
use frames::{PaddingBytes, QuicAckFrame, QuicBlockedFrame, QuicConnectionCloseFrame, QuicFrame, QuicFrameContext,
             QuicFrameReader, QuicFrameWriter, QuicGoAwayFrame, QuicPaddingFrame, QuicPingFrame, QuicRstStreamFrame,
             QuicStopWaitingFrame, QuicStreamFrame, QuicWindowUpdateFrame};
use packet::{quic_version, QuicEncryptedPacket, QuicPacketHeader, QuicPacketPublicHeader, QuicPublicResetPacket,
             QuicVersionNegotiationPacket};
use proto::QuicPacketNumber;
use types::{EncryptionLevel, Perspective, QuicTime, QuicTimeDelta, QuicVersion, ToEndianness, ToQuicPacketNumber};

pub trait QuicFramerVisitor {
    /// Called when a new packet has been received, before it has been validated or processed.
    fn on_packet(&self) {}

    /// Called when the public header has been parsed, but has not been authenticated.
    /// If it returns false, framing for this packet will cease.
    fn on_unauthenticated_public_header(&self, _header: &QuicPacketPublicHeader) -> bool {
        true
    }

    /// Called only when `perspective` is IS_SERVER and the framer gets a packet with version flag true
    /// and the version on the packet doesn't match `quic_version`.
    /// The visitor should return true after it updates the version of the `framer` to `received_version`
    /// or false to stop processing this packet.
    fn on_protocol_version_mismatch(&self, _received_version: QuicVersion) -> bool {
        false
    }

    /// Called only when `perspective` is IS_CLIENT and a version negotiation packet has been parsed.
    fn on_version_negotiation_packet(&self, _packet: QuicVersionNegotiationPacket) {}

    /// Called when a public reset packet has been parsed but has not yet been validated.
    fn on_public_reset_packet(&self, _packet: QuicPublicResetPacket) {}

    /// Called when the unauthenticated portion of the header has been parsed.
    /// If `on_unauthenticated_header` returns false, framing for this packet will cease.
    fn on_unauthenticated_header(&self, _header: &QuicPacketHeader) -> bool {
        true
    }

    /// Called when a packet has been decrypted. `level` is the encryption level of the packet.
    fn on_decrypted_packet(&self, _level: EncryptionLevel) {}

    /// Called when the complete header of a packet had been parsed.
    /// If `on_packet_header` returns false, framing for this packet will cease.
    fn on_packet_header(&self, _header: &QuicPacketHeader) -> bool {
        true
    }

    /// Called when a `QuicStreamFrame` has been parsed.
    ///
    /// If `on_stream_frame` returns false, the framer will stop parsing the current packet.
    fn on_stream_frame(&self, _frame: QuicStreamFrame) -> bool {
        true
    }

    /// Called when a `QuicAckFrame` has been parsed.
    ///
    /// If `on_ack_frame` returns false, the framer will stop parsing the current packet.
    fn on_ack_frame(&self, _frame: QuicAckFrame) -> bool {
        true
    }

    /// Called when a `QuicPaddingFrame` has been parsed.
    fn on_padding_frame(&self, _frame: QuicPaddingFrame) -> bool {
        true
    }

    /// Called when a `QuicRstStreamFrame` has been parsed.
    fn on_reset_stream_frame(&self, _frame: QuicRstStreamFrame) -> bool {
        true
    }

    /// Called when a `QuicConnectionCloseFrame` has been parsed.
    fn on_connection_close_frame(&self, _frame: QuicConnectionCloseFrame) -> bool {
        true
    }

    /// Called when a `QuicGoAwayFrame` has been parsed.
    fn on_go_away_frame(&self, _frame: QuicGoAwayFrame) -> bool {
        true
    }

    /// Called when a `QuicWindowUpdateFrame` has been parsed.
    fn on_window_update_frame(&self, _frame: QuicWindowUpdateFrame) -> bool {
        true
    }

    /// Called when a `QuicBlockedFrame` has been parsed.
    fn on_blocked_frame(&self, _frame: QuicBlockedFrame) -> bool {
        true
    }

    /// Called when a `QuicStopWaitingFrame` has been parsed.
    fn on_stop_waiting_frame(&self, _frame: QuicStopWaitingFrame) -> bool {
        true
    }

    /// Called when a PingFrame has been parsed.
    fn on_ping_frame(&self, _frame: QuicPingFrame) -> bool {
        true
    }

    /// Called when a packet has been completely processed.
    fn on_packet_complete(&self) {}
}

/// Class for parsing and constructing QUIC packets.
///
/// It has a `QuicFramerVisitor` that is called when packets are parsed.
pub struct QuicFramer<'a, T, V>
where
    T: 'a + Deref<Target = V>,
    V: 'a,
{
    pub supported_versions: &'a [QuicVersion],
    pub quic_version: QuicVersion,
    /// The time this framer was created.
    /// Time written to the wire will be written as a delta from this value.
    pub creation_time: QuicTime,
    /// Encrypters used to encrypt packets via encrypt_payload().
    pub encrypters: [Option<Box<QuicEncrypter>>; 3],
    visitor: Option<T>,
    state: RefCell<State>,
}

impl<'a, T, V> QuicFramer<'a, T, V>
where
    T: 'a + Deref<Target = V>,
    V: 'a,
{
    pub fn new<P>(supported_versions: &'a [QuicVersion], creation_time: QuicTime) -> Self
    where
        P: 'static + Perspective,
    {
        QuicFramer {
            supported_versions,
            quic_version: supported_versions[0],
            creation_time,
            encrypters: [Some(Box::new(NullEncrypter::<P>::default())), None, None],
            visitor: None,
            state: RefCell::new(State::new::<P>()),
        }
    }

    /// Changes the encrypter used for level `level` to `encrypter`.
    pub fn set_encrypter(&mut self, level: EncryptionLevel, encrypter: Box<QuicEncrypter>) {
        self.encrypters[level as usize] = Some(encrypter);
    }

    /// Encrypts a payload.
    pub fn encrypt_payload(
        &self,
        level: EncryptionLevel,
        packet_number: QuicPacketNumber,
        associated_data: &[u8],
        plain_text: &[u8],
    ) -> Result<Bytes, Error> {
        if let Some(encrypter) = self.encrypters[level as usize].as_ref() {
            encrypter.encrypt_packet(
                self.quic_version,
                packet_number,
                associated_data,
                plain_text,
            )
        } else {
            bail!(QuicError::EncryptionFailure(packet_number))
        }
    }

    /// Returns the maximum length of plaintext
    /// that can be encrypted to ciphertext no larger than `ciphertext_size`.
    pub fn max_plaintext_size(&self, ciphertext_size: usize) -> usize {
        self.encrypters
            .iter()
            .flat_map(|encrypter| encrypter)
            .fold(ciphertext_size, |min_plaintext_size, encrypter| {
                cmp::min(
                    min_plaintext_size,
                    encrypter.max_plaintext_size(ciphertext_size),
                )
            })
    }

    /// Returns the number of bytes added to the packet for the specified frame,
    /// and 0 if the frame doesn't fit.
    /// Includes the header size for the first frame.
    pub fn serialized_frame_length(
        &self,
        frame: &QuicFrame<'a>,
        free_bytes: usize,
        first_frame: bool,
        frame_size: usize,
    ) -> usize {
        match *frame {
            QuicFrame::Padding(QuicPaddingFrame { padding_bytes }) => {
                match padding_bytes {
                    PaddingBytes::Size(num_padding_bytes) => {
                        // Lite padding.
                        cmp::min(free_bytes, num_padding_bytes)
                    }
                    PaddingBytes::Fill => {
                        // Full padding to the end of the packet.
                        free_bytes
                    }
                }
            }
            QuicFrame::Ack(ref frame) if first_frame && frame.min_size(self.quic_version) <= free_bytes => {
                // Truncate the frame so the packet will not exceed kMaxPacketSize.
                // Note that we may not use every byte of the writer in this case.
                free_bytes
            }
            _ => {
                if frame_size <= free_bytes {
                    // Frame fits within packet. Note that acks may be truncated.
                    frame_size
                } else {
                    // Only truncate the first frame in a packet,
                    // so if subsequent ones go over, stop including more frames.
                    0
                }
            }
        }
    }
}

impl<'a, T, V> QuicFramer<'a, T, V>
where
    T: 'a + Deref<Target = V>,
    V: 'a + QuicFramerVisitor,
{
    // Returns true if |version| is a supported protocol version.
    pub fn is_supported_version(&self, version: QuicVersion) -> bool {
        self.supported_versions.contains(&version)
    }

    /// Set callbacks to be called from the framer.
    pub fn set_visitor(&mut self, visitor: T) {
        self.visitor = Some(visitor);
    }

    pub fn process_packet<P>(&self, packet: &QuicEncryptedPacket) -> Result<(), Error>
    where
        P: Perspective,
    {
        if self.quic_version > QuicVersion::QUIC_VERSION_38 {
            self.parse_packet::<P, NetworkEndian>(packet)
        } else {
            self.parse_packet::<P, NativeEndian>(packet)
        }
    }

    fn parse_packet<'p, P, E>(&self, packet: &'p QuicEncryptedPacket) -> Result<(), Error>
    where
        P: Perspective,
        E: ByteOrder + ToEndianness,
    {
        if let Some(ref visitor) = self.visitor {
            visitor.on_packet();
        }

        // First parse the public header.
        let (public_header, payload) = QuicPacketPublicHeader::parse(packet, P::is_server())?;

        if public_header.reset_flag && public_header.versions.is_some() {
            bail!(InvalidPacketHeader(
                "got version flag in reset packet".to_owned()
            ));
        }

        if let Some(ref visitor) = self.visitor {
            if visitor.on_unauthenticated_public_header(&public_header) {
                // The visitor suppresses further processing of the packet.
                return Ok(());
            }
        }

        let protocol_version_mismatched = P::is_server() && public_header.versions.as_ref().map_or(false, |versions| {
            versions[0] != self.quic_version && if let Some(ref visitor) = self.visitor {
                !visitor.on_protocol_version_mismatch(versions[0])
            } else {
                false
            }
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

        if let Some(ref visitor) = self.visitor {
            visitor.on_version_negotiation_packet(public_header);
        }

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
            bail!(InvalidResetPacket(format!(
                "incorrect message tag: {}",
                message.tag()
            )));
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

        if let Some(ref visitor) = self.visitor {
            visitor.on_public_reset_packet(packet);
        }

        Ok(())
    }

    fn process_data_packet<'p, P, E>(
        &self,
        input: &'p [u8],
        public_header: QuicPacketPublicHeader<'p>,
        packet: &'p QuicEncryptedPacket,
    ) -> Result<(), Error>
    where
        P: Perspective,
        E: ByteOrder + ToEndianness,
    {
        let (remaining, header) = self.process_unauthenticated_header::<E>(input, public_header)?;

        if !self.visitor
            .as_ref()
            .map_or(true, |visitor| visitor.on_unauthenticated_header(&header))
        {
            debug!("Visitor asked to stop processing of unauthenticated header.");

            return Ok(());
        }

        let payload = self.decrypt_payload::<P>(remaining, &header, packet)?;

        // Set the last packet number after we have decrypted the packet
        // so we are confident is not attacker controlled.
        self.state.borrow_mut().set_last_packet_number(&header);

        if !self.visitor
            .as_ref()
            .map_or(true, |visitor| visitor.on_packet_header(&header))
        {
            // The visitor suppresses further processing of the packet.
            return Ok(());
        }

        if packet.len() > kMaxPacketSize {
            bail!(PacketTooLarge(packet.len()));
        }

        // Handle the payload.
        self.process_frame_data(&header, &payload)?;

        if let Some(ref visitor) = self.visitor {
            visitor.on_packet_complete();
        }

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
        let base_packet_number = self.state.borrow().largest_packet_number;

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
        &self,
        input: &'p [u8],
        header: &'p QuicPacketHeader,
        packet: &'p QuicEncryptedPacket,
    ) -> Result<Bytes, Error>
    where
        P: Perspective,
    {
        let associated_data = &packet.as_bytes()[..header.size()];

        if let Ok(decrypted) = self.state.borrow().decrypter.decrypt_packet(
            self.quic_version,
            header.packet_number,
            associated_data,
            input,
        ) {
            if let Some(ref visitor) = self.visitor {
                visitor.on_decrypted_packet(self.state.borrow().decrypter_level);
            }

            return Ok(decrypted);
        }

        if let Some(decrypter) = self.state.borrow_mut().alternative_decrypter.take() {
            let try_alternative_decryption = self.state.borrow().alternative_decrypter_level != EncryptionLevel::Initial
                || P::is_server() || header.public_header.nonce.is_some();

            if try_alternative_decryption {
                if let Ok(decrypted) = decrypter.decrypt_packet(
                    self.quic_version,
                    header.packet_number,
                    associated_data,
                    input,
                ) {
                    if let Some(ref visitor) = self.visitor {
                        visitor.on_decrypted_packet(self.state.borrow().alternative_decrypter_level);
                    }

                    if self.state.borrow().alternative_decrypter_latch {
                        self.state.borrow_mut().decrypter = decrypter;
                        self.state.borrow_mut().decrypter_level = self.state.borrow().alternative_decrypter_level;
                        self.state.borrow_mut().alternative_decrypter_level = EncryptionLevel::None;
                    } else {
                        self.state.borrow_mut().alternative_decrypter = Some(mem::replace(
                            &mut self.state.borrow_mut().decrypter,
                            decrypter,
                        ));
                        self.state.borrow_mut().decrypter_level = mem::replace(
                            &mut self.state.borrow_mut().alternative_decrypter_level,
                            self.state.borrow().decrypter_level,
                        );
                    }

                    return Ok(decrypted);
                }
            }
        }

        bail!(DecryptionFailure(header.packet_number));
    }

    fn process_frame_data(&self, header: &QuicPacketHeader, payload: &[u8]) -> Result<(), Error> {
        let reader = FrameReader::new(self, header);

        for frame in reader.read_frames(payload) {
            debug!("parsed frame: {:?}", frame);

            match frame? {
                QuicFrame::Padding(frame) => if !self.visitor
                    .as_ref()
                    .map_or(true, |visitor| visitor.on_padding_frame(frame))
                {
                    debug!("Visitor asked to stop further processing.");

                    break;
                },
                QuicFrame::ResetStream(frame) => if !self.visitor
                    .as_ref()
                    .map_or(true, |visitor| visitor.on_reset_stream_frame(frame))
                {
                    debug!("Visitor asked to stop further processing.");

                    break;
                },
                QuicFrame::ConnectionClose(frame) => if !self.visitor
                    .as_ref()
                    .map_or(true, |visitor| visitor.on_connection_close_frame(frame))
                {
                    debug!("Visitor asked to stop further processing.");

                    break;
                },
                QuicFrame::GoAway(frame) => if !self.visitor
                    .as_ref()
                    .map_or(true, |visitor| visitor.on_go_away_frame(frame))
                {
                    debug!("Visitor asked to stop further processing.");

                    break;
                },
                QuicFrame::WindowUpdate(frame) => if !self.visitor
                    .as_ref()
                    .map_or(true, |visitor| visitor.on_window_update_frame(frame))
                {
                    debug!("Visitor asked to stop further processing.");

                    break;
                },
                QuicFrame::Blocked(frame) => if !self.visitor
                    .as_ref()
                    .map_or(true, |visitor| visitor.on_blocked_frame(frame))
                {
                    debug!("Visitor asked to stop further processing.");

                    break;
                },
                QuicFrame::StopWaiting(frame) => if !self.visitor
                    .as_ref()
                    .map_or(true, |visitor| visitor.on_stop_waiting_frame(frame))
                {
                    debug!("Visitor asked to stop further processing.");

                    break;
                },
                QuicFrame::Ping(frame) => if !self.visitor
                    .as_ref()
                    .map_or(true, |visitor| visitor.on_ping_frame(frame))
                {
                    debug!("Visitor asked to stop further processing.");

                    break;
                },
                QuicFrame::Stream(frame) => if !self.visitor
                    .as_ref()
                    .map_or(true, |visitor| visitor.on_stream_frame(frame))
                {
                    debug!("Visitor asked to stop further processing.");

                    break;
                },
                QuicFrame::Ack(frame) => if !self.visitor
                    .as_ref()
                    .map_or(true, |visitor| visitor.on_ack_frame(frame))
                {
                    debug!("Visitor asked to stop further processing.");

                    break;
                },
            }
        }

        Ok(())
    }
}

impl<'a, T, V> QuicFramer<'a, T, V>
where
    T: 'a + Deref<Target = V>,
    V: 'a,
{
    pub fn build_data_packet<I, B>(
        &'a self,
        header: &'a QuicPacketHeader<'a>,
        frames: I,
        buf: &mut B,
    ) -> Result<usize, Error>
    where
        I: IntoIterator<Item = QuicFrame<'a>>,
        B: BufMut,
    {
        let header_size = if self.quic_version > QuicVersion::QUIC_VERSION_38 {
            header.write_to::<NetworkEndian, B>(buf)?
        } else {
            header.write_to::<NativeEndian, B>(buf)?
        };

        let frames_size = FrameWriter::new(self, header).write_frames(frames, buf)?;

        Ok(header_size + frames_size)
    }
}

struct State {
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
    /// The time delta computed for the last timestamp frame.
    /// This is relative to the creation_time.
    last_timestamp: QuicTimeDelta,
}

impl State {
    fn new<P>() -> Self
    where
        P: 'static + Perspective,
    {
        State {
            last_packet_number: 0,
            largest_packet_number: 0,
            decrypter: Box::new(NullDecrypter::<P>::default()),
            alternative_decrypter: None,
            decrypter_level: EncryptionLevel::None,
            alternative_decrypter_level: EncryptionLevel::None,
            alternative_decrypter_latch: false,
            last_timestamp: QuicTimeDelta::zero(),
        }
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

    /// `set_alternative_decrypter` sets a decrypter
    /// that may be used to decrypt future packets and takes ownership of it.
    /// `level` indicates the encryption level of the decrypter.
    /// If `latch_once_used` is true, then the first time that the decrypter is successful
    /// it will replace the primary decrypter.
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

    pub fn set_last_packet_number(&mut self, header: &QuicPacketHeader) {
        self.last_packet_number = header.packet_number;
        self.largest_packet_number = cmp::max(self.largest_packet_number, header.packet_number);
    }
}

pub struct FrameContext<'a, T, V>
where
    T: 'a + Deref<Target = V>,
    V: 'a,
{
    framer: &'a QuicFramer<'a, T, V>,
    header: &'a QuicPacketHeader<'a>,
}

impl<'a, T, V> FrameContext<'a, T, V>
where
    T: 'a + Deref<Target = V>,
    V: 'a,
{
    pub fn new(framer: &'a QuicFramer<'a, T, V>, header: &'a QuicPacketHeader<'a>) -> FrameContext<'a, T, V> {
        FrameContext { framer, header }
    }
}

impl<'a, T, V> QuicFrameContext for FrameContext<'a, T, V>
where
    T: Deref<Target = V>,
{
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
        self.framer.state.borrow().last_timestamp
    }
}

pub type FrameReader<'a, T, V> = FrameContext<'a, T, V>;

impl<'a, T, V> QuicFrameReader<'a> for FrameReader<'a, T, V>
where
    T: 'a + Deref<Target = V>,
    V: 'a,
{
}

pub type FrameWriter<'a, T, V> = FrameContext<'a, T, V>;

impl<'a, T, V> QuicFrameWriter<'a> for FrameWriter<'a, T, V>
where
    T: 'a + Deref<Target = V>,
    V: 'a,
{
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

#[cfg(test)]
pub mod mocks {
    use super::*;

    #[derive(Default)]
    pub struct MockFramerVisitor {}

    impl QuicFramerVisitor for MockFramerVisitor {}
}
