#![allow(dead_code, non_upper_case_globals)]

use proto::QuicStreamId;
use types::QuicByteCount;

// Default initial maximum size in bytes of a QUIC packet.
pub const kDefaultMaxPacketSize: QuicByteCount = 1350;
// Default initial maximum size in bytes of a QUIC packet for servers.
pub const kDefaultServerMaxPacketSize: QuicByteCount = 1000;
// The maximum packet size of any QUIC packet, based on ethernet's max size,
// minus the IP and UDP headers. IPv6 has a 40 byte header, UDP adds an
// additional 8 bytes.  This is a total overhead of 48 bytes.  Ethernet's
// max packet size is 1500 bytes,  1500 - 48 = 1452.
pub const kMaxPacketSize: QuicByteCount = 1452;
// Default maximum packet size used in the Linux TCP implementation.
// Used in QUIC for congestion window computations in bytes.
pub const kDefaultTCPMSS: QuicByteCount = 1460;

/// Number of bytes reserved for public flags in the packet header.
pub const kPublicFlagsSize: usize = 1;
/// Number of bytes reserved for version number in the packet header.
pub const kQuicVersionSize: usize = 4;
/// Number of bytes reserved for path id in the packet header.
pub const kQuicPathIdSize: usize = 1;
/// Number of bytes reserved for private flags in the packet header.
pub const kPrivateFlagsSize: usize = 1;

// Stream ID is reserved to denote an invalid ID.
pub const kInvalidStreamId: QuicStreamId = 0;

// Reserved ID for the crypto stream.
pub const kCryptoStreamId: QuicStreamId = 1;

// Reserved ID for the headers stream.
pub const kHeadersStreamId: QuicStreamId = 3;
