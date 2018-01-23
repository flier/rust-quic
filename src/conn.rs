#![allow(non_camel_case_types)]

use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;

use failure::Error;
use prometheus::{Counter, Opts};
use time;

use errors::{QuicError, QuicErrorCode};
use framer::{QuicFramer, QuicFramerVisitor};
use packet::{QuicEncryptedPacket, QuicPacketPublicHeader, QuicReceivedPacket, QuicVersionNegotiationPacket};
use proto::QuicConnectionId;
use types::{ConnectionCloseSource, EncryptionLevel, PeerAddressChangeType, Perspective, QuicTime, QuicVersion,
            TransmissionType};

/// `QuicConnectionVisitor` receives callbacks from the connection
/// when frames are received and when other interesting events happen.
pub trait QuicConnectionVisitor {
    /// Called when the connection is closed either locally by the framer, or remotely by the peer.
    fn on_connection_closed(&self, _error: QuicErrorCode, _error_details: &str, _source: ConnectionCloseSource) {}

    /// Called once a specific QUIC version is agreed by both endpoints.
    fn on_successful_version_negotiation(&self, _version: QuicVersion) {}
}

/// `QuicConnectionDebugVisitor` receives callbacks from the `QuicConnection` at interesting points.
pub trait QuicConnectionDebugVisitor {
    /// Called when a packet has been received, but before it is validated or parsed.
    fn on_packet_received(&self, _self_addr: SocketAddr, _peer_addr: SocketAddr, _packet: &QuicReceivedPacket) {}

    /// Called when an undecryptable packet has been received.
    fn on_undecryptable_packet(&self, _packet: &QuicReceivedPacket) {}

    /// Called when a packet is received with a connection id that does not match the ID of this connection.
    fn on_incorrect_connection_id(&self, _connection_id: Option<QuicConnectionId>) {}

    /// Called when the connection is closed either locally by the framer, or remotely by the peer.
    fn on_connection_closed(&self, _error: QuicErrorCode, _error_details: &str, _source: ConnectionCloseSource) {}

    /// Called when the protocol version on the received packet
    /// doensn't match current protocol version of the connection.
    fn on_protocol_version_mismatch(&self, _received_version: QuicVersion) {}

    /// Called once a specific QUIC version is agreed by both endpoints.
    fn on_successful_version_negotiation(&self, _version: QuicVersion) {}

    // Called when a version negotiation packet has been received.
    fn on_version_negotiation_packet(&self, _packet: &QuicVersionNegotiationPacket) {}
}

pub struct QuicConnection<'a, V, D>
where
    V: 'a + QuicConnectionVisitor,
    D: 'a + QuicConnectionDebugVisitor,
{
    inner: Rc<Inner<'a, V, D>>,
}

impl<'a, V, D> QuicConnection<'a, V, D>
where
    V: QuicConnectionVisitor,
    D: QuicConnectionDebugVisitor,
{
    pub fn new<P>(
        connection_id: QuicConnectionId,
        supported_versions: &'a [QuicVersion],
        visitor: &'a V,
        debug_visitor: Option<&'a D>,
    ) -> Result<QuicConnection<'a, V, D>, Error>
    where
        P: 'static + Perspective,
    {
        let framer = Rc::new(RefCell::new(
            QuicFramer::new::<P>(supported_versions, time::get_time()),
        ));
        let inner = Rc::new(Inner {
            connection_id,
            is_server: P::is_server(),
            visitor: Some(visitor),
            debug_visitor,
            framer: framer.clone(),
            stats: QuicConnectionStats::new()?,
            state: RefCell::new(State::new()),
        });

        framer.borrow_mut().set_visitor(inner.clone());

        Ok(QuicConnection { inner })
    }

    pub fn process_packet<P>(
        &self,
        self_addr: SocketAddr,
        peer_addr: SocketAddr,
        packet: QuicReceivedPacket,
    ) -> Result<(), Error>
    where
        P: Perspective,
    {
        self.inner.process_packet::<P>(self_addr, peer_addr, packet)
    }
}

type InnerQuicFramer<'a, V, D> = QuicFramer<'a, Rc<Inner<'a, V, D>>, Inner<'a, V, D>>;

struct Inner<'a, V, D>
where
    V: 'a + QuicConnectionVisitor,
    D: 'a + QuicConnectionDebugVisitor,
{
    connection_id: QuicConnectionId,
    is_server: bool,
    visitor: Option<&'a V>,
    debug_visitor: Option<&'a D>,
    framer: Rc<RefCell<InnerQuicFramer<'a, V, D>>>,
    stats: QuicConnectionStats,
    state: RefCell<State>,
}

impl<'a, V, D> QuicFramerVisitor for Inner<'a, V, D>
where
    V: QuicConnectionVisitor,
    D: QuicConnectionDebugVisitor,
{
    fn on_unauthenticated_public_header(&self, header: &QuicPacketPublicHeader) -> bool {
        if header.connection_id == Some(self.connection_id) {
            true
        } else {
            self.stats.packets_dropped.inc();

            trace!(
                "ignoring packet from unexpected ConnectionId: {:?}",
                header.connection_id
            );

            if let Some(visitor) = self.debug_visitor {
                visitor.on_incorrect_connection_id(header.connection_id)
            }

            // If this is a server, the dispatcher routes each packet to the
            // QuicConnection responsible for the packet's connection ID.  So if control
            // arrives here and this is a server, the dispatcher must be malfunctioning.
            debug_assert!(!self.is_server);

            false
        }
    }

    fn on_protocol_version_mismatch(&self, received_version: QuicVersion) -> bool {
        trace!(
            "received packet with mismatched version: {:?}",
            received_version
        );

        if !self.is_server {
            self.tear_down_local_connection_state(
                QuicErrorCode::QUIC_INTERNAL_ERROR,
                "Protocol version mismatch.",
                ConnectionCloseSource::FROM_SELF,
            );

            return false;
        }

        debug_assert_ne!(self.version(), received_version);

        if let Some(visitor) = self.debug_visitor {
            visitor.on_protocol_version_mismatch(received_version);
        }

        match self.state.borrow().version_negotiation_state {
            QuicVersionNegotiationState::START_NEGOTIATION => {
                if !self.framer.borrow().is_supported_version(received_version) {
                    self.send_version_negotiation_packet();

                    self.state.borrow_mut().version_negotiation_state =
                        QuicVersionNegotiationState::NEGOTIATION_IN_PROGRESS;

                    return false;
                }
            }
            QuicVersionNegotiationState::NEGOTIATION_IN_PROGRESS => {
                if !self.framer.borrow().is_supported_version(received_version) {
                    self.send_version_negotiation_packet();

                    return false;
                }
            }
            QuicVersionNegotiationState::NEGOTIATED_VERSION => return false,
        };

        self.state.borrow_mut().version_negotiation_state = QuicVersionNegotiationState::NEGOTIATED_VERSION;

        if let Some(visitor) = self.visitor {
            visitor.on_successful_version_negotiation(received_version);
        }

        if let Some(visitor) = self.debug_visitor {
            visitor.on_successful_version_negotiation(received_version);
        }

        debug!("version negotiated {:?}", received_version);

        // Store the new version.
        self.framer.borrow_mut().quic_version = received_version;

        true
    }

    fn on_version_negotiation_packet(&self, packet: QuicVersionNegotiationPacket) {
        // Check that any public reset packet with a different connection ID that was
        // routed to this QuicConnection has been redirected before control reaches
        // here.  (Check for a bug regression.)
        debug_assert_eq!(Some(self.connection_id), packet.connection_id);

        if !self.is_server {
            self.tear_down_local_connection_state(
                QuicErrorCode::QUIC_INTERNAL_ERROR,
                "Server receieved version negotiation packet.",
                ConnectionCloseSource::FROM_SELF,
            );

            return;
        }

        if let Some(visitor) = self.debug_visitor {
            visitor.on_version_negotiation_packet(&packet);
        }

        if self.state.borrow().version_negotiation_state != QuicVersionNegotiationState::START_NEGOTIATION {
            // Possibly a duplicate version negotiation packet.
            return;
        }

        if let Some(ref versions) = packet.versions {
            if versions.contains(&self.version()) {
                self.tear_down_local_connection_state(
                    QuicErrorCode::QUIC_INVALID_VERSION_NEGOTIATION_PACKET,
                    "Server already supports client's version and should have accepted the connection.",
                    ConnectionCloseSource::FROM_SELF,
                );

                return;
            }
        }

        if let Some(version) = packet
            .versions
            .as_ref()
            .and_then(|versions| self.select_mutual_version(versions))
        {
            self.framer.borrow_mut().quic_version = version;
        } else {
            self.tear_down_local_connection_state(
                QuicErrorCode::QUIC_INVALID_VERSION,
                format!(
                    "No common version found. Supported versions: {:?}, peer supported versions: {:?}",
                    self.framer.borrow().supported_versions,
                    packet.versions
                ).as_str(),
                ConnectionCloseSource::FROM_SELF,
            );

            return;
        }

        self.state.borrow_mut().server_supported_versions = packet.versions;

        debug!("Negotiated version: {:?}", self.version());

        self.state.borrow_mut().version_negotiation_state = QuicVersionNegotiationState::NEGOTIATION_IN_PROGRESS;

        self.retransmit_unacked_packets(TransmissionType::ALL_UNACKED_RETRANSMISSION);
    }
}

impl<'a, V, D> Inner<'a, V, D>
where
    V: QuicConnectionVisitor,
    D: QuicConnectionDebugVisitor,
{
    // The version of the protocol this connection is using.
    pub fn version(&self) -> QuicVersion {
        self.framer.borrow().quic_version
    }

    pub fn process_packet<P>(
        &self,
        self_addr: SocketAddr,
        peer_addr: SocketAddr,
        packet: QuicReceivedPacket,
    ) -> Result<(), Error>
    where
        P: Perspective,
    {
        if let Some(visitor) = self.debug_visitor {
            visitor.on_packet_received(self_addr, peer_addr, &packet)
        }

        self.state.borrow_mut().update_address(self_addr, peer_addr);

        self.stats.bytes_received.inc_by(packet.len() as f64)?;
        self.stats.packets_received.inc();

        self.state
            .borrow_mut()
            .set_time_of_last_received_packet(packet.receipt_time);

        if let Err(err) = self.framer.borrow().process_packet::<P>(&packet) {
            match err.downcast::<QuicError>() {
                Ok(QuicError::DecryptionFailure(_)) => {
                    // If we are unable to decrypt this packet, it might be
                    // because the CHLO or SHLO packet was lost.
                    if self.state.borrow().encryption_level != EncryptionLevel::ForwardSecure
                        && !self.state.borrow().is_undecryptable_packets_queue_full()
                    {
                        self.state
                            .borrow_mut()
                            .queue_undecryptable_packet(packet.into())
                    } else if let Some(visitor) = self.debug_visitor {
                        visitor.on_undecryptable_packet(&packet)
                    }

                    return Ok(());
                }
                Ok(err) => bail!(err),
                Err(err) => {
                    return Err(err);
                }
            }
        }

        self.stats.packets_processed.inc();

        Ok(())
    }

    fn tear_down_local_connection_state(
        &self,
        error: QuicErrorCode,
        error_details: &str,
        source: ConnectionCloseSource,
    ) {
        if !self.state.borrow().connected {
            info!("Connection is already closed.")
        } else {
            self.state.borrow_mut().connected = false;

            if let Some(visitor) = self.visitor {
                visitor.on_connection_closed(error, error_details, source);
            }

            if let Some(visitor) = self.debug_visitor {
                visitor.on_connection_closed(error, error_details, source);
            }
        }
    }

    /// Selects the version of the protocol being used
    /// by selecting a version from `available_versions` which is also supported.
    fn select_mutual_version(&self, available_versions: &[QuicVersion]) -> Option<QuicVersion> {
        self.framer
            .borrow()
            .supported_versions
            .iter()
            .find(|&version| available_versions.contains(version))
            .cloned()
    }

    // Sends a version negotiation packet to the peer.
    fn send_version_negotiation_packet(&self) {}

    /// Retransmits all unacked packets with retransmittable frames if
    /// `retransmission_type` is `ALL_UNACKED_PACKETS`, otherwise retransmits only
    /// initially encrypted packets. Used when the negotiated protocol version is
    /// different from what was initially assumed and when the initial encryption
    /// changes.
    fn retransmit_unacked_packets(&self, retransmission_type: TransmissionType) {}
}

/// The state of connection in version negotiation finite state machine.
#[derive(Clone, Copy, Debug, PartialEq)]
enum QuicVersionNegotiationState {
    START_NEGOTIATION,
    /// Server-side this implies we've sent a version negotiation packet and are
    /// waiting on the client to select a compatible version.  Client-side this
    /// implies we've gotten a version negotiation packet, are retransmitting the
    /// initial packets with a supported version and are waiting for our first
    /// packet from the server.
    NEGOTIATION_IN_PROGRESS,
    /// This indicates this endpoint has received a packet from the peer with a
    /// version this endpoint supports.  Version negotiation is complete, and the
    /// version number will no longer be sent with future packets.
    NEGOTIATED_VERSION,
}

struct State {
    /// The state of connection in version negotiation finite state machine.
    pub version_negotiation_state: QuicVersionNegotiationState,
    /// True by default.  False if we've received or sent an explicit connection close.
    pub connected: bool,
    /// Encryption level for new packets.
    pub encryption_level: EncryptionLevel,
    /// Local address on the last successfully processed packet received from the client.
    pub self_addr: Option<SocketAddr>,
    /// Peer address on the last successfully processed packet received from the client.
    pub peer_addr: Option<SocketAddr>,
    /// Destination address of the last received packet.
    pub last_packet_destination_address: Option<SocketAddr>,
    /// Source address of the last received packet.
    pub last_packet_source_address: Option<SocketAddr>,
    /// Records change type when the peer initiates migration to a new peer address.
    /// Reset to NO_CHANGE after peer migration is validated.
    pub active_peer_migration_type: PeerAddressChangeType,
    /// The time that we got a packet for this connection.
    /// This is used for timeouts, and does not indicate the packet was processed.
    pub time_of_last_received_packet: QuicTime,
    /// The last time this connection began sending a new (non-retransmitted) packet.
    pub time_of_last_sent_new_packet: QuicTime,
    /// Collection of packets which were received before encryption was established,
    /// but which could not be decrypted.
    /// We buffer these on the assumption that they could not be processed
    /// because they were sent with the INITIAL encryption and the CHLO message was lost.
    pub undecryptable_packets: Vec<QuicEncryptedPacket>,
    /// Maximum number of undecryptable packets the connection will store.
    pub max_undecryptable_packets: usize,
    /// Creation time
    pub connection_creation_time: QuicTime,
    /// If non-empty this contains the set of versions received in a version negotiation packet.
    pub server_supported_versions: Option<Vec<QuicVersion>>,
}

impl State {
    pub fn new() -> Self {
        let now = time::get_time();

        State {
            version_negotiation_state: QuicVersionNegotiationState::START_NEGOTIATION,
            connected: true,
            encryption_level: EncryptionLevel::None,
            self_addr: None,
            peer_addr: None,
            last_packet_destination_address: None,
            last_packet_source_address: None,
            active_peer_migration_type: PeerAddressChangeType::NO_CHANGE,
            time_of_last_received_packet: now,
            time_of_last_sent_new_packet: now,
            undecryptable_packets: vec![],
            max_undecryptable_packets: 0,
            connection_creation_time: now,
            server_supported_versions: None,
        }
    }

    pub fn set_time_of_last_received_packet(&mut self, receipt_time: QuicTime) {
        trace!("time of last received packet {:?}", receipt_time);

        self.time_of_last_received_packet = receipt_time;
    }

    pub fn is_undecryptable_packets_queue_full(&self) -> bool {
        self.undecryptable_packets.len() < self.max_undecryptable_packets
    }

    pub fn queue_undecryptable_packet(&mut self, packet: QuicEncryptedPacket) {
        trace!("queueing undecryptable packet");

        self.undecryptable_packets.push(packet)
    }

    pub fn update_address(&mut self, self_addr: SocketAddr, peer_addr: SocketAddr) {
        self.last_packet_source_address = Some(self_addr);
        self.last_packet_destination_address = Some(peer_addr);

        if self.self_addr.is_none() {
            self.self_addr = Some(self_addr);
        }
        if self.peer_addr.is_none() {
            self.peer_addr = Some(peer_addr);
        }
    }
}

pub type QuicByteCount = Counter;
pub type QuicPacketCount = Counter;
pub type QuicPacketNumber = Counter;

/// Structure to hold stats for a `QuicConnection`.
pub struct QuicConnectionStats {
    /// Includes retransmissions.
    pub bytes_sent: QuicByteCount,
    /// Packet sent
    pub packet_sent: QuicPacketCount,
    /// Non-retransmitted bytes sent in a stream frame.
    pub stream_bytes_sent: QuicByteCount,
    /// Packets serialized and discarded before sending.
    pub packets_discarded: QuicPacketCount,
    /// These include version negotiation and public reset packets,
    /// which do not have packet numbers or frame data.
    /// Includes duplicate data for a stream.
    pub bytes_received: QuicByteCount,
    /// Includes packets which were not processable.
    pub packets_received: QuicPacketCount,
    /// Excludes packets which were not processable.
    pub packets_processed: QuicPacketCount,
    /// Bytes received in a stream frame.
    pub stream_bytes_received: QuicByteCount,

    pub bytes_retransmitted: QuicByteCount,
    pub packets_retransmitted: QuicPacketCount,

    pub bytes_spuriously_retransmitted: QuicByteCount,
    pub packets_spuriously_retransmitted: QuicPacketCount,
    /// Number of packets abandoned as lost by the loss detection algorithm.
    pub packets_lost: QuicPacketCount,
    /// Number of packets sent in slow start.
    pub slowstart_packets_sent: QuicPacketCount,
    /// Number of packets lost exiting slow start.
    pub slowstart_packets_lost: QuicPacketCount,
    /// Number of bytes lost exiting slow start.
    pub slowstart_bytes_lost: QuicByteCount,
    /// Duplicate or less than least unacked.
    pub packets_dropped: QuicPacketCount,
    /// Number of packets received out of packet number order.
    pub packets_reordered: QuicPacketCount,
    // Maximum reordering observed in packet number space.
    pub max_sequence_reordering: QuicPacketNumber,
}

impl QuicConnectionStats {
    pub fn new() -> Result<Self, Error> {
        Ok(QuicConnectionStats {
            bytes_sent: QuicByteCount::with_opts(
                Opts::new("bytes_sent", "Bytes sent.")
                    .namespace("quic")
                    .subsystem("conn"),
            )?,
            packet_sent: QuicPacketCount::with_opts(
                Opts::new("packet_sent", "Packet sent.")
                    .namespace("quic")
                    .subsystem("conn"),
            )?,
            stream_bytes_sent: QuicByteCount::with_opts(
                Opts::new(
                    "stream_bytes_sent",
                    "Non-retransmitted bytes sent in a stream frame.",
                ).namespace("quic")
                    .subsystem("conn"),
            )?,
            packets_discarded: QuicPacketCount::with_opts(
                Opts::new(
                    "packets_discarded",
                    " Packets serialized and discarded before sending.",
                ).namespace("quic")
                    .subsystem("conn"),
            )?,
            bytes_received: QuicByteCount::with_opts(
                Opts::new("bytes_received", "")
                    .namespace("quic")
                    .subsystem("conn"),
            )?,
            packets_received: QuicPacketCount::with_opts(
                Opts::new("packets_received", "")
                    .namespace("quic")
                    .subsystem("conn"),
            )?,
            packets_processed: QuicPacketCount::with_opts(
                Opts::new("packets_processed", "")
                    .namespace("quic")
                    .subsystem("conn"),
            )?,
            stream_bytes_received: QuicByteCount::with_opts(
                Opts::new("stream_bytes_received", "Bytes received in a stream frame.")
                    .namespace("quic")
                    .subsystem("conn"),
            )?,
            bytes_retransmitted: QuicByteCount::with_opts(
                Opts::new("bytes_retransmitted", "")
                    .namespace("quic")
                    .subsystem("conn"),
            )?,
            packets_retransmitted: QuicPacketCount::with_opts(
                Opts::new("packets_retransmitted", "")
                    .namespace("quic")
                    .subsystem("conn"),
            )?,
            bytes_spuriously_retransmitted: QuicByteCount::with_opts(
                Opts::new("bytes_spuriously_retransmitted", "")
                    .namespace("quic")
                    .subsystem("conn"),
            )?,
            packets_spuriously_retransmitted: QuicPacketCount::with_opts(
                Opts::new("packets_spuriously_retransmitted", "")
                    .namespace("quic")
                    .subsystem("conn"),
            )?,
            packets_lost: QuicPacketCount::with_opts(
                Opts::new("packets_lost", "")
                    .namespace("quic")
                    .subsystem("conn"),
            )?,
            slowstart_packets_sent: QuicPacketCount::with_opts(
                Opts::new(
                    "slowstart_packets_sent",
                    "Number of packets sent in slow start.",
                ).namespace("quic")
                    .subsystem("conn"),
            )?,
            slowstart_packets_lost: QuicPacketCount::with_opts(
                Opts::new(
                    "slowstart_packets_lost",
                    "Number of packets lost exiting slow start.",
                ).namespace("quic")
                    .subsystem("conn"),
            )?,
            slowstart_bytes_lost: QuicByteCount::with_opts(
                Opts::new(
                    "slowstart_bytes_lost",
                    "Number of bytes lost exiting slow start.",
                ).namespace("quic")
                    .subsystem("conn"),
            )?,
            packets_dropped: QuicPacketCount::with_opts(
                Opts::new("packets_dropped", "")
                    .namespace("quic")
                    .subsystem("conn"),
            )?,
            packets_reordered: QuicPacketCount::with_opts(
                Opts::new("packets_reordered", "")
                    .namespace("quic")
                    .subsystem("conn"),
            )?,
            max_sequence_reordering: QuicPacketNumber::with_opts(
                Opts::new("max_sequence_reordering", "")
                    .namespace("quic")
                    .subsystem("conn"),
            )?,
        })
    }
}
