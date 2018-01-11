#![allow(dead_code, non_upper_case_globals)]

use types::QuicTag;

/// Client hello
pub const kCHLO: QuicTag = quic_tag!(b"CHLO");
/// Server hello
pub const kSHLO: QuicTag = quic_tag!(b"SHLO");
/// Server config
pub const kSCFG: QuicTag = quic_tag!(b"SCFG");
/// Reject
pub const kREJ: QuicTag = quic_tag!(b"REJ\0");
/// Stateless reject
pub const kSREJ: QuicTag = quic_tag!(b"SREJ");
/// Client encrypted tag-value pairs
pub const kCETV: QuicTag = quic_tag!(b"CETV");
/// Public reset
pub const kPRST: QuicTag = quic_tag!(b"PRST");
/// Server config update
pub const kSCUP: QuicTag = quic_tag!(b"SCUP");
/// Application-layer protocol
pub const kALPN: QuicTag = quic_tag!(b"ALPN");

// Key exchange methods

/// ECDH, Curve P-256
pub const kP256: QuicTag = quic_tag!(b"P256");
/// ECDH, Curve25519
pub const kC255: QuicTag = quic_tag!(b"C255");

// AEAD algorithms

/// AES128 + GCM-12
pub const kAESG: QuicTag = quic_tag!(b"AESG");
/// `ChaCha20` + `Poly1305` RFC7539
pub const kCC20: QuicTag = quic_tag!(b"CC20");

// Socket receive buffer

/// Socket receive buffer
pub const kSRBF: QuicTag = quic_tag!(b"SRBF");

// Congestion control feedback types

/// TCP cubic
pub const kQBIC: QuicTag = quic_tag!(b"QBIC");

// Connection options (COPT) values

/// Auto-tune flow control receive windows.
pub const kAFCW: QuicTag = quic_tag!(b"AFCW");
/// Set initial size of stream flow control receive window to 32KB. (2<sup>5</sup> KB).
pub const kIFW5: QuicTag = quic_tag!(b"IFW5");
/// Set initial size of stream flow control receive window to 64KB. (2<sup>6</sup> KB).
pub const kIFW6: QuicTag = quic_tag!(b"IFW6");
/// Set initial size of stream flow control receive window to 128KB. (2<sup>7</sup> KB).
pub const kIFW7: QuicTag = quic_tag!(b"IFW7");
/// Set initial size of stream flow control receive window to 256KB. (2<sup>8</sup> KB).
pub const kIFW8: QuicTag = quic_tag!(b"IFW8");
/// Set initial size of stream flow control receive window to 512KB. (2<sup>9</sup> KB).
pub const kIFW9: QuicTag = quic_tag!(b"IFW9");
/// Set initial size of stream flow control receive window to 1MB. (2<sup>10</sup> KB).
pub const kIFWA: QuicTag = quic_tag!(b"IFWa");
/// Reduced Buffer Bloat TCP
pub const kTBBR: QuicTag = quic_tag!(b"TBBR");
/// STARTUP in BBR for 1 RTT
pub const k1RTT: QuicTag = quic_tag!(b"1RTT");
/// STARTUP in BBR for 2 RTTs
pub const k2RTT: QuicTag = quic_tag!(b"2RTT");
/// Exit STARTUP in BBR on loss
pub const kLRTT: QuicTag = quic_tag!(b"LRTT");
/// Rate-based recovery in BBR
pub const kBBRR: QuicTag = quic_tag!(b"BBRR");
/// Ack aggregatation v1
pub const kBBR1: QuicTag = quic_tag!(b"BBR1");
/// Ack aggregatation v2
pub const kBBR2: QuicTag = quic_tag!(b"BBR2");
/// Reno Congestion Control
pub const kRENO: QuicTag = quic_tag!(b"RENO");
/// Performance-Oriented Congestion Control
pub const kTPCC: QuicTag = quic_tag!(b"PCC\0");
/// TCP cubic or reno in bytes
pub const kBYTE: QuicTag = quic_tag!(b"BYTE");
/// Force ICWND to 3
pub const kIW03: QuicTag = quic_tag!(b"IW03");
/// Force ICWND to 10
pub const kIW10: QuicTag = quic_tag!(b"IW10");
/// Force ICWND to 20
pub const kIW20: QuicTag = quic_tag!(b"IW20");
/// Force ICWND to 50
pub const kIW50: QuicTag = quic_tag!(b"IW50");
/// Emulate a single connection
pub const k1CON: QuicTag = quic_tag!(b"1CON");
/// No tail loss probe
pub const kNTLP: QuicTag = quic_tag!(b"NTLP");
/// N Connection Congestion Ctrl
pub const kNCON: QuicTag = quic_tag!(b"NCON");
/// CWND reduction on loss
pub const kNRTO: QuicTag = quic_tag!(b"NRTO");
/// Time based loss detection
pub const kTIME: QuicTag = quic_tag!(b"TIME");
/// Adaptive time loss detection
pub const kATIM: QuicTag = quic_tag!(b"ATIM");
/// Min CWND of 1 packet
pub const kMIN1: QuicTag = quic_tag!(b"MIN1");
/// Min CWND of 4 packets, with a min rate of 1 BDP.
pub const kMIN4: QuicTag = quic_tag!(b"MIN4");
/// Tail loss probe delay of 0.5RTT.
pub const kTLPR: QuicTag = quic_tag!(b"TLPR");
/// Ack decimation style acking.
pub const kACKD: QuicTag = quic_tag!(b"ACKD");
/// Ack decimation tolerating out of order packets.
pub const kAKD2: QuicTag = quic_tag!(b"AKD2");
/// Ack decimation style acking with 1/8 RTT acks.
pub const kAKD3: QuicTag = quic_tag!(b"AKD3");
/// Ack decimation with 1/8 RTT tolerating out of order.
pub const kAKD4: QuicTag = quic_tag!(b"AKD4");
/// Unlimited number of packets receieved before acking
pub const kAKDU: QuicTag = quic_tag!(b"AKDU");
/// Slow Start Large Reduction.
pub const kSSLR: QuicTag = quic_tag!(b"SSLR");
/// Pace at unity instead of PRR
pub const kNPRR: QuicTag = quic_tag!(b"NPRR");
/// Close connection on 5 RTOs
pub const k5RTO: QuicTag = quic_tag!(b"5RTO");
/// Close connection on 3 RTOs
pub const k3RTO: QuicTag = quic_tag!(b"3RTO");
/// Client timestamp in seconds since UNIX epoch.
pub const kCTIM: QuicTag = quic_tag!(b"CTIM");
/// Disable HPACK dynamic table.
pub const kDHDT: QuicTag = quic_tag!(b"DHDT");
/// Conservative Handshake Retransmissions.
pub const kCONH: QuicTag = quic_tag!(b"CONH");
/// Don't invoke FACK on the first ack.
pub const kLFAK: QuicTag = quic_tag!(b"LFAK");
/// Support `MAX_HEADER_LIST_SIZE` settings frame.
pub const kSMHL: QuicTag = quic_tag!(b"SMHL");
/// Fix Cubic convex bug.
pub const kCCVX: QuicTag = quic_tag!(b"CCVX");
/// Fix `CubicBytes` quantization.
pub const kCBQT: QuicTag = quic_tag!(b"CBQT");
/// Fix Cubic `BetaLastMax` bug.
pub const kBLMX: QuicTag = quic_tag!(b"BLMX");
/// Allow Cubic per-ack-updates.
pub const kCPAU: QuicTag = quic_tag!(b"CPAU");
/// No stop waiting frames.
pub const kNSTP: QuicTag = quic_tag!(b"NSTP");

// Optional support of truncated Connection IDs.  If sent by a peer, the value
// is the minimum number of bytes allowed for the connection ID sent to the
// peer.

/// Connection ID truncation.
pub const kTCID: QuicTag = quic_tag!(b"TCID");

// Multipath option.

/// Enable multipath.
pub const kMPTH: QuicTag = quic_tag!(b"MPTH");

/// Do not attempt connection migration.
pub const kNCMR: QuicTag = quic_tag!(b"NCMR");

// Enable bandwidth resumption experiment.

/// Bandwidth resumption.
pub const kBWRE: QuicTag = quic_tag!(b"BWRE");
/// Max bandwidth resumption.
pub const kBWMX: QuicTag = quic_tag!(b"BWMX");
/// Server bandwidth resumption.
pub const kBWRS: QuicTag = quic_tag!(b"BWRS");
/// Server bw resumption v2.
pub const kBWS2: QuicTag = quic_tag!(b"BWS2");

// Enable path MTU discovery experiment.

/// High-target MTU discovery.
pub const kMTUH: QuicTag = quic_tag!(b"MTUH");
/// Low-target MTU discovery.
pub const kMTUL: QuicTag = quic_tag!(b"MTUL");

// Tags for async signing experiments

/// Perform asynchronous signing
pub const kASYN: QuicTag = quic_tag!(b"ASYN");
/// Perform synchronous signing
pub const kSYNC: QuicTag = quic_tag!(b"SYNC");

// Proof types (i.e. certificate types)
// NOTE: although it would be silly to do so, specifying both kX509 and kX59R
// is allowed and is equivalent to specifying only kX509.

/// X.509 certificate, all key types
pub const kX509: QuicTag = quic_tag!(b"X509");
/// X.509 certificate, RSA keys only
pub const kX59R: QuicTag = quic_tag!(b"X59R");
/// Channel ID.
pub const kCHID: QuicTag = quic_tag!(b"CHID");

// Client hello tags

/// Version
pub const kVER: QuicTag = quic_tag!(b"VER\0");
/// The client's nonce
pub const kNONC: QuicTag = quic_tag!(b"NONC");
/// The client's proof nonce
pub const kNONP: QuicTag = quic_tag!(b"NONP");
/// Key exchange methods
pub const kKEXS: QuicTag = quic_tag!(b"KEXS");
/// Authenticated encryption algorithms
pub const kAEAD: QuicTag = quic_tag!(b"AEAD");
/// Connection options
pub const kCOPT: QuicTag = quic_tag!(b"COPT");
/// Client connection options
pub const kCLOP: QuicTag = quic_tag!(b"CLOP");
/// Idle network timeout
pub const kICSL: QuicTag = quic_tag!(b"ICSL");
/// Silently close on timeout
pub const kSCLS: QuicTag = quic_tag!(b"SCLS");
/// Max streams per connection.
pub const kMSPC: QuicTag = quic_tag!(b"MSPC");
/// Max incoming dynamic streams
pub const kMIDS: QuicTag = quic_tag!(b"MIDS");
/// Estimated initial RTT in us.
pub const kIRTT: QuicTag = quic_tag!(b"IRTT");
/// Server's Initial congestion window.
pub const kSWND: QuicTag = quic_tag!(b"SWND");
/// Server name indication
pub const kSNI: QuicTag = quic_tag!(b"SNI\0");
/// Public key values
pub const kPUBS: QuicTag = quic_tag!(b"PUBS");
/// Server config id
pub const kSCID: QuicTag = quic_tag!(b"SCID");
/// Server orbit.
pub const kORBT: QuicTag = quic_tag!(b"OBIT");
/// Proof demand.
pub const kPDMD: QuicTag = quic_tag!(b"PDMD");
/// Proof (signature).
pub const kPROF: QuicTag = quic_tag!(b"PROF");
/// Common certificate set
pub const kCCS: QuicTag = quic_tag!(b"CCS\0");
/// Cached certificate
pub const kCCRT: QuicTag = quic_tag!(b"CCRT");
/// Expiry
pub const kEXPY: QuicTag = quic_tag!(b"EXPY");
/// Server Config TTL
pub const kSTTL: QuicTag = quic_tag!(b"STTL");
/// Initial stream flow control receive window.
pub const kSFCW: QuicTag = quic_tag!(b"SFCW");
/// Initial session/connection flow control receive window.
pub const kCFCW: QuicTag = quic_tag!(b"CFCW");
/// Client's User Agent ID.
pub const kUAID: QuicTag = quic_tag!(b"UAID");
/// Expected leaf certificate.
pub const kXLCT: QuicTag = quic_tag!(b"XLCT");
/// Token Binding key params.
pub const kTBKP: QuicTag = quic_tag!(b"TBKP");

// Token Binding tags

/// TB draft 10 with P256.
pub const kTB10: QuicTag = quic_tag!(b"TB10");

// Rejection tags

/// Reasons for server sending Stateless Reject tags
pub const kRREJ: QuicTag = quic_tag!(b"RREJ");
/// Server-designated connection ID Server hello tags
pub const kRCID: QuicTag = quic_tag!(b"RCID");
/// Client IP address and port
pub const kCADR: QuicTag = quic_tag!(b"CADR");
/// Alternate Server IP address and port.
pub const kASAD: QuicTag = quic_tag!(b"ASAD");

// CETV tags

/// Channel ID key
pub const kCIDK: QuicTag = quic_tag!(b"CIDK");
/// Channel ID signature
pub const kCIDS: QuicTag = quic_tag!(b"CIDS");

// Public reset tags

/// Public reset nonce proof
pub const kRNON: QuicTag = quic_tag!(b"RNON");
/// Rejected packet number
pub const kRSEQ: QuicTag = quic_tag!(b"RSEQ");

// Universal tags

/// Padding
pub const kPAD: QuicTag = quic_tag!(b"PAD\0");

// Server push tags

/// Support server push.
pub const kSPSH: QuicTag = quic_tag!(b"SPSH");
