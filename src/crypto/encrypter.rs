use bytes::Bytes;
use failure::Error;

use types::{QuicPacketNumber, QuicVersion};

/// `QuicEncrypter` implements the QUIC encrypter
pub trait QuicEncrypter {
    /// Writes encrypted `plain_text` and a MAC over `plaintext` and `associated_data` into output.
    /// `packet_number` is appended to the `nonce_prefix` value provided in set_nonce_prefix() to form the nonce.
    fn encrypt_packet(
        &self,
        version: QuicVersion,
        packet_number: QuicPacketNumber,
        associated_data: &[u8],
        plain_text: &[u8],
    ) -> Result<Bytes, Error>;
}
