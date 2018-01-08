use failure::Error;

use bytes::Bytes;

use packet::{QuicDiversificationNonce, QuicPacketNumber};
use version::QuicVersion;

/// `QuicDecrypter` implements the QUIC decrypter
pub trait QuicDecrypter {
    /// Sets the encryption key.
    ///
    /// `decrypt_packet` may not be called until `with_preliminary_key` is called and
    /// the preliminary keying material will be combined with that nonce in order to
    /// create the actual key and nonce-prefix.
    fn with_preliminary_key(self, nonce: &QuicDiversificationNonce) -> Box<QuicDecrypter>;

    /// Populates `output` with the decrypted `cipher_text`.
    /// `packet_number` is appended to the `nonce_prefix` value provided in `set_nonce_prefix` to form the nonce.
    fn decrypt_packet(
        &self,
        version: QuicVersion,
        packet_number: QuicPacketNumber,
        associated_data: &[u8],
        cipher_text: &[u8],
    ) -> Result<Bytes, Error>;
}
