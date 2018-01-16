#![allow(dead_code, non_upper_case_globals)]

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

// New Frame Types, QUIC v. >= 10:
// There are two interpretations for the Frame Type byte in the QUIC protocol,
// resulting in two Frame Types: Special Frame Types and Regular Frame Types.
//
// Regular Frame Types use the Frame Type byte simply. Currently defined
// Regular Frame Types are:
// Padding            : 0b 00000000 (0x00)
// ResetStream        : 0b 00000001 (0x01)
// ConnectionClose    : 0b 00000010 (0x02)
// GoAway             : 0b 00000011 (0x03)
// WindowUpdate       : 0b 00000100 (0x04)
// Blocked            : 0b 00000101 (0x05)
//
// Special Frame Types encode both a Frame Type and corresponding flags
// all in the Frame Type byte. Currently defined Special Frame Types are:
// Stream             : 0b 11xxxxxx
// Ack                : 0b 101xxxxx
//
// Semantics of the flag bits above (the x bits) depends on the frame type.

// Masks to determine if the frame type is a special use and for specific special frame types.
pub const kQuicFrameTypeSpecialMask: u8 = 0xE0; // 0b 11100000
pub const kQuicFrameTypeRegularMask: u8 = 0xE0; // 0b 11100000

pub const kQuicFrameTypeStreamMask_Pre40: u8 = 0x80;
pub const kQuicFrameTypeStreamMask: u8 = 0xC0;
pub const kQuicFrameTypeAckMask_Pre40: u8 = 0x40;
pub const kQuicFrameTypeAckMask: u8 = 0xA0;

pub const kQuicFrameTypeSize: usize = 1; // u8
pub const kStringPieceLenSize: usize = 2; // u16
