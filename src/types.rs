/// EncryptionLevel enumerates the stages of encryption that a QUIC connection progresses through.
/// When retransmitting a packet, the encryption level needs to be specified so
/// that it is retransmitted at a level which the peer can understand.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub enum EncryptionLevel {
    None,
    Initial,
    ForwardSecure,
}

pub trait Perspective {
    fn is_server() -> bool;
}
