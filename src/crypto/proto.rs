#![allow(dead_code, non_upper_case_globals)]

use tag::QuicTag;

pub const kCHLO: QuicTag = quic_tag!(b"CHLO");// Client hello
pub const kSHLO: QuicTag = quic_tag!(b"SHLO");   // Server hello
pub const kSCFG: QuicTag = quic_tag!(b"SCFG");   // Server config
pub const kREJ: QuicTag  = quic_tag!(b"REJ\0");  // Reject
pub const kSREJ: QuicTag = quic_tag!(b"SREJ");   // Stateless reject
pub const kCETV: QuicTag = quic_tag!(b"CETV");   // Client encrypted tag-value
                                                 // pairs
pub const kPRST: QuicTag = quic_tag!(b"PRST");   // Public reset
pub const kSCUP: QuicTag = quic_tag!(b"SCUP");   // Server config update
pub const kALPN: QuicTag = quic_tag!(b"ALPN");   // Application-layer protocol

// Key exchange methods
pub const kP256: QuicTag = quic_tag!(b"P256");   // ECDH, Curve P-256
pub const kC255: QuicTag = quic_tag!(b"C255");   // ECDH, Curve25519

// AEAD algorithms
pub const kAESG: QuicTag = quic_tag!(b"AESG");   // AES128 + GCM-12
pub const kCC20: QuicTag = quic_tag!(b"CC20");   // ChaCha20 + Poly1305 RFC7539

// Socket receive buffer
pub const kSRBF: QuicTag = quic_tag!(b"SRBF");   // Socket receive buffer

// Congestion control feedback types
pub const kQBIC: QuicTag = quic_tag!(b"QBIC");   // TCP cubic

// Connection options (COPT) values
pub const kAFCW: QuicTag = quic_tag!(b"AFCW");   // Auto-tune flow control
                                                 // receive windows.
pub const kIFW5: QuicTag = quic_tag!(b"IFW5");   // Set initial size
                                                 // of stream flow control
                                                 // receive window to
                                                 // 32KB. (2^5 KB).
pub const kIFW6: QuicTag = quic_tag!(b"IFW6");   // Set initial size
                                                 // of stream flow control
                                                 // receive window to
                                                 // 64KB. (2^6 KB).
pub const kIFW7: QuicTag = quic_tag!(b"IFW7");   // Set initial size
                                                 // of stream flow control
                                                 // receive window to
                                                 // 128KB. (2^7 KB).
pub const kIFW8: QuicTag = quic_tag!(b"IFW8");   // Set initial size
                                                 // of stream flow control
                                                 // receive window to
                                                 // 256KB. (2^8 KB).
pub const kIFW9: QuicTag = quic_tag!(b"IFW9");   // Set initial size
                                                 // of stream flow control
                                                 // receive window to
                                                 // 512KB. (2^9 KB).
pub const kIFWA: QuicTag = quic_tag!(b"IFWa");   // Set initial size
                                                 // of stream flow control
                                                 // receive window to
                                                 // 1MB. (2^0xa KB).
pub const kTBBR: QuicTag = quic_tag!(b"TBBR");   // Reduced Buffer Bloat TCP
pub const k1RTT: QuicTag = quic_tag!(b"1RTT");   // STARTUP in BBR for 1 RTT
pub const k2RTT: QuicTag = quic_tag!(b"2RTT");   // STARTUP in BBR for 2 RTTs
pub const kLRTT: QuicTag = quic_tag!(b"LRTT");   // Exit STARTUP in BBR on loss
pub const kBBRR: QuicTag = quic_tag!(b"BBRR");   // Rate-based recovery in BBR
pub const kBBR1: QuicTag= quic_tag!(b"BBR1");   // Ack aggregatation v1
pub const kBBR2: QuicTag = quic_tag!(b"BBR2");   // Ack aggregatation v2
pub const kRENO: QuicTag = quic_tag!(b"RENO");   // Reno Congestion Control
pub const kTPCC: QuicTag = quic_tag!(b"PCC\0");  // Performance-Oriented
                                                 // Congestion Control
pub const kBYTE: QuicTag = quic_tag!(b"BYTE");   // TCP cubic or reno in bytes
pub const kIW03: QuicTag = quic_tag!(b"IW03");   // Force ICWND to 3
pub const kIW10: QuicTag = quic_tag!(b"IW10");   // Force ICWND to 10
pub const kIW20: QuicTag = quic_tag!(b"IW20");   // Force ICWND to 20
pub const kIW50: QuicTag = quic_tag!(b"IW50");   // Force ICWND to 50
pub const k1CON: QuicTag = quic_tag!(b"1CON");   // Emulate a single connection
pub const kNTLP: QuicTag = quic_tag!(b"NTLP");   // No tail loss probe
pub const kNCON: QuicTag = quic_tag!(b"NCON");   // N Connection Congestion Ctrl
pub const kNRTO: QuicTag = quic_tag!(b"NRTO");   // CWND reduction on loss
pub const kTIME: QuicTag = quic_tag!(b"TIME");   // Time based loss detection
pub const kATIM: QuicTag = quic_tag!(b"ATIM");   // Adaptive time loss detection
pub const kMIN1: QuicTag = quic_tag!(b"MIN1");   // Min CWND of 1 packet
pub const kMIN4: QuicTag = quic_tag!(b"MIN4");   // Min CWND of 4 packets,
                                                 // with a min rate of 1 BDP.
pub const kTLPR: QuicTag = quic_tag!(b"TLPR");   // Tail loss probe delay of
                                                 // 0.5RTT.
pub const kACKD: QuicTag = quic_tag!(b"ACKD");   // Ack decimation style acking.
pub const kAKD2: QuicTag = quic_tag!(b"AKD2");   // Ack decimation tolerating
                                                 // out of order packets.
pub const kAKD3: QuicTag = quic_tag!(b"AKD3");   // Ack decimation style acking
                                                 // with 1/8 RTT acks.
pub const kAKD4: QuicTag = quic_tag!(b"AKD4");   // Ack decimation with 1/8 RTT
                                                 // tolerating out of order.
pub const kAKDU: QuicTag = quic_tag!(b"AKDU");   // Unlimited number of packets
                                                 // receieved before acking
pub const kSSLR: QuicTag = quic_tag!(b"SSLR");   // Slow Start Large Reduction.
pub const kNPRR: QuicTag = quic_tag!(b"NPRR");   // Pace at unity instead of PRR
pub const k5RTO: QuicTag = quic_tag!(b"5RTO");   // Close connection on 5 RTOs
pub const k3RTO: QuicTag = quic_tag!(b"3RTO");   // Close connection on 3 RTOs
pub const kCTIM: QuicTag = quic_tag!(b"CTIM");   // Client timestamp in seconds
                                                 // since UNIX epoch.
pub const kDHDT: QuicTag = quic_tag!(b"DHDT");   // Disable HPACK dynamic table.
pub const kCONH: QuicTag = quic_tag!(b"CONH");   // Conservative Handshake
                                                 // Retransmissions.
pub const kLFAK: QuicTag = quic_tag!(b"LFAK");   // Don't invoke FACK on the
                                                 // first ack.
// TODO(fayang): Remove this connection option in QUIC_VERSION_37, in which
// MAX_HEADER_LIST_SIZE settings frame should be supported.
pub const kSMHL: QuicTag = quic_tag!(b"SMHL");   // Support MAX_HEADER_LIST_SIZE
                                                 // settings frame.
pub const kCCVX: QuicTag = quic_tag!(b"CCVX");   // Fix Cubic convex bug.
pub const kCBQT: QuicTag = quic_tag!(b"CBQT");   // Fix CubicBytes quantization.
pub const kBLMX: QuicTag = quic_tag!(b"BLMX");   // Fix Cubic BetaLastMax bug.
pub const kCPAU: QuicTag = quic_tag!(b"CPAU");   // Allow Cubic per-ack-updates.
pub const kNSTP: QuicTag = quic_tag!(b"NSTP");   // No stop waiting frames.

// Optional support of truncated Connection IDs.  If sent by a peer, the value
// is the minimum number of bytes allowed for the connection ID sent to the
// peer.
pub const kTCID: QuicTag = quic_tag!(b"TCID");   // Connection ID truncation.

// Multipath option.
pub const kMPTH: QuicTag = quic_tag!(b"MPTH");   // Enable multipath.

pub const kNCMR: QuicTag= quic_tag!(b"NCMR");   // Do not attempt connection
                                                 // migration.

// Enable bandwidth resumption experiment.
pub const kBWRE: QuicTag = quic_tag!(b"BWRE");  // Bandwidth resumption.
pub const kBWMX: QuicTag = quic_tag!(b"BWMX");  // Max bandwidth resumption.
pub const kBWRS: QuicTag = quic_tag!(b"BWRS");  // Server bandwidth resumption.
pub const kBWS2: QuicTag = quic_tag!(b"BWS2");  // Server bw resumption v2.

// Enable path MTU discovery experiment.
pub const kMTUH: QuicTag = quic_tag!(b"MTUH");  // High-target MTU discovery.
pub const kMTUL: QuicTag = quic_tag!(b"MTUL");  // Low-target MTU discovery.

// Tags for async signing experiments
pub const kASYN: QuicTag = quic_tag!(b"ASYN");  // Perform asynchronous signing
pub const kSYNC: QuicTag = quic_tag!(b"SYNC");  // Perform synchronous signing

// Proof types (i.e. certificate types)
// NOTE: although it would be silly to do so, specifying both kX509 and kX59R
// is allowed and is equivalent to specifying only kX509.
pub const kX509: QuicTag = quic_tag!(b"X509");   // X.509 certificate, all key
                                                 // types
pub const kX59R: QuicTag = quic_tag!(b"X59R");   // X.509 certificate, RSA keys
                                                 // only
pub const kCHID: QuicTag = quic_tag!(b"CHID");   // Channel ID.

// Client hello tags
pub const kVER : QuicTag = quic_tag!(b"VER\0");  // Version
pub const kNONC: QuicTag = quic_tag!(b"NONC");   // The client's nonce
pub const kNONP: QuicTag = quic_tag!(b"NONP");   // The client's proof nonce
pub const kKEXS: QuicTag = quic_tag!(b"KEXS");   // Key exchange methods
pub const kAEAD: QuicTag = quic_tag!(b"AEAD");   // Authenticated
                                                 // encryption algorithms
pub const kCOPT: QuicTag = quic_tag!(b"COPT");   // Connection options
pub const kCLOP: QuicTag = quic_tag!(b"CLOP");   // Client connection options
pub const kICSL: QuicTag = quic_tag!(b"ICSL");   // Idle network timeout
pub const kSCLS: QuicTag = quic_tag!(b"SCLS");   // Silently close on timeout
pub const kMSPC: QuicTag = quic_tag!(b"MSPC");   // Max streams per connection.
pub const kMIDS: QuicTag = quic_tag!(b"MIDS");   // Max incoming dynamic streams
pub const kIRTT: QuicTag = quic_tag!(b"IRTT");   // Estimated initial RTT in us.
pub const kSWND: QuicTag = quic_tag!(b"SWND");   // Server's Initial congestion
                                                 // window.
pub const kSNI : QuicTag = quic_tag!(b"SNI\0");  // Server name
                                                 // indication
pub const kPUBS: QuicTag = quic_tag!(b"PUBS");   // Public key values
pub const kSCID: QuicTag = quic_tag!(b"SCID");   // Server config id
pub const kORBT: QuicTag = quic_tag!(b"OBIT");   // Server orbit.
pub const kPDMD: QuicTag = quic_tag!(b"PDMD");   // Proof demand.
pub const kPROF: QuicTag = quic_tag!(b"PROF");   // Proof (signature).
pub const kCCS : QuicTag = quic_tag!(b"CCS\0");     // Common certificate set
pub const kCCRT: QuicTag = quic_tag!(b"CCRT");   // Cached certificate
pub const kEXPY: QuicTag = quic_tag!(b"EXPY");   // Expiry
pub const kSTTL: QuicTag = quic_tag!(b"STTL");   // Server Config TTL
pub const kSFCW: QuicTag = quic_tag!(b"SFCW");   // Initial stream flow control
                                                 // receive window.
pub const kCFCW: QuicTag = quic_tag!(b"CFCW");   // Initial session/connection
                                                 // flow control receive window.
pub const kUAID: QuicTag = quic_tag!(b"UAID");   // Client's User Agent ID.
pub const kXLCT: QuicTag = quic_tag!(b"XLCT");   // Expected leaf certificate.
pub const kTBKP: QuicTag = quic_tag!(b"TBKP");   // Token Binding key params.

// Token Binding tags
pub const kTB10: QuicTag = quic_tag!(b"TB10");   // TB draft 10 with P256.

// Rejection tags
pub const kRREJ: QuicTag = quic_tag!(b"RREJ");   // Reasons for server sending
// Stateless Reject tags
pub const kRCID: QuicTag = quic_tag!(b"RCID");   // Server-designated
                                                 // connection ID
// Server hello tags
pub const kCADR: QuicTag = quic_tag!(b"CADR");   // Client IP address and port
pub const kASAD: QuicTag = quic_tag!(b"ASAD");   // Alternate Server IP address
                                                 // and port.

// CETV tags
pub const kCIDK: QuicTag = quic_tag!(b"CIDK");   // ChannelID key
pub const kCIDS: QuicTag = quic_tag!(b"CIDS");   // ChannelID signature

// Public reset tags
pub const kRNON: QuicTag = quic_tag!(b"RNON");   // Public reset nonce proof
pub const kRSEQ: QuicTag = quic_tag!(b"RSEQ");   // Rejected packet number

// Universal tags
pub const kPAD : QuicTag = quic_tag!(b"PAD\0");  // Padding

// Server push tags
pub const kSPSH: QuicTag = quic_tag!(b"SPSH");  // Support server push.

