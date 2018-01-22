use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;

use failure::Error;
use prometheus::{Counter, Opts};
use time::{self, Duration};

use errors::QuicError;
use framer::{QuicFramer, QuicFramerVisitor};
use frames::{QuicAckFrame, QuicBlockedFrame, QuicConnectionCloseFrame, QuicFrameWriter, QuicGoAwayFrame,
             QuicPaddingFrame, QuicPingFrame, QuicRstStreamFrame, QuicStopWaitingFrame, QuicStreamFrame,
             QuicWindowUpdateFrame};
use packet::{QuicEncryptedPacket, QuicPacketHeader, QuicPacketPublicHeader, QuicPublicResetPacket, QuicReceivedPacket,
             QuicVersionNegotiationPacket};
use types::{EncryptionLevel, PeerAddressChangeType, Perspective, QuicTime, QuicVersion};

/// `QuicConnectionVisitor` receives callbacks from the connection
/// when frames are received and when other interesting events happen.
pub trait QuicConnectionVisitor {}

/// `QuicConnectionDebugVisitor` receives callbacks from the QuicConnection at interesting points.
pub trait QuicConnectionDebugVisitor {
    /// Called when a packet has been received, but before it is validated or parsed.
    fn on_packet_received(&self, self_addr: &SocketAddr, peer_addr: &SocketAddr, packet: &QuicReceivedPacket) {}

    /// Called when an undecryptable packet has been received.
    fn on_undecryptable_packet(&self, packet: &QuicReceivedPacket) {}
}

pub struct QuicConnection<'a, V, D>
where
    V: 'a,
    D: 'a,
{
    framer: QuicFramer<'a, Inner>,
    stats: QuicConnectionStats,
    visitor: &'a V,
    debug_visitor: Option<&'a D>,
    inner: Rc<Inner>,
    state: RefCell<State>,
}

impl<'a, V, D> QuicConnection<'a, V, D> {
    pub fn new<P>(
        supported_versions: &'a [QuicVersion],
        visitor: &'a V,
        debug_visitor: Option<&'a D>,
    ) -> Result<QuicConnection<'a, V, D>, Error>
    where
        P: 'static + Perspective,
    {
        let inner = Rc::new(Inner {});
        let mut conn = QuicConnection {
            framer: QuicFramer::new::<P>(supported_versions, time::get_time()),
            stats: QuicConnectionStats::new()?,
            visitor,
            debug_visitor,
            inner: inner.clone(),
            state: RefCell::new(State::new()),
        };

        conn.framer.set_visitor(inner.clone());

        Ok(conn)
    }
}

impl<'a, V, D> QuicConnection<'a, V, D>
where
    V: QuicConnectionVisitor,
    D: QuicConnectionDebugVisitor,
{
    pub fn process_packet<P>(
        &self,
        self_addr: &SocketAddr,
        peer_addr: &SocketAddr,
        packet: QuicReceivedPacket,
    ) -> Result<(), Error>
    where
        P: Perspective,
    {
        if let Some(visitor) = self.debug_visitor {
            visitor.on_packet_received(self_addr, peer_addr, &packet)
        }

        self.stats.bytes_received.inc_by(packet.len() as f64)?;
        self.stats.packets_received.inc();

        self.state
            .borrow_mut()
            .set_time_of_last_received_packet(packet.receipt_time);

        if let Err(err) = self.framer.process_packet::<P>(&packet) {
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
}

struct Inner {}

impl QuicFramerVisitor for Inner {}

struct State {
    /// Encryption level for new packets.
    pub encryption_level: EncryptionLevel,
    /// Local address on the last successfully processed packet received from the client.
    pub self_addr: Option<SocketAddr>,
    /// Peer address on the last successfully processed packet received from the client.
    pub peer_addr: Option<SocketAddr>,
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
}

impl State {
    pub fn new() -> Self {
        let now = time::get_time();

        State {
            encryption_level: EncryptionLevel::None,
            self_addr: None,
            peer_addr: None,
            active_peer_migration_type: PeerAddressChangeType::NO_CHANGE,
            time_of_last_received_packet: now,
            time_of_last_sent_new_packet: now,
            undecryptable_packets: vec![],
            max_undecryptable_packets: 0,
            connection_creation_time: now,
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
}

pub type QuicByteCount = Counter;
pub type QuicPacketCount = Counter;
pub type QuicPacketNumber = Counter;

/// Structure to hold stats for a QuicConnection.
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
