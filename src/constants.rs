#![allow(non_upper_case_globals)]

/// The maximum packet size of any QUIC packet, based on ethernet's max size,
/// minus the IP and UDP headers. IPv6 has a 40 byte header, UDP adds an
/// additional 8 bytes.  This is a total overhead of 48 bytes.  Ethernet's
/// max packet size is 1500 bytes,  1500 - 48 = 1452.
pub const kMaxPacketSize: usize = 1452;

/// Number of bytes reserved for public flags in the packet header.
pub const kPublicFlagsSize: usize = 1;
/// Number of bytes reserved for version number in the packet header.
pub const kQuicVersionSize: usize = 4;
/// Number of bytes reserved for path id in the packet header.
pub const kQuicPathIdSize: usize = 1;
/// Number of bytes reserved for private flags in the packet header.
pub const kPrivateFlagsSize: usize = 1;
