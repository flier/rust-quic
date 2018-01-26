use failure::Error;

use bytes::Bytes;

use crypto::{Aes128Gcm12Decrypter, ChaCha20Poly1305Decrypter, NullDecrypter};
use proto::QuicPacketNumber;
use types::{QuicDiversificationNonce, QuicTag, QuicVersion};

/// `QuicDecrypter` implements the QUIC decrypter
pub trait QuicDecrypter {
    fn tag(&self) -> QuicTag;

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

pub fn null<P>() -> NullDecrypter<P> {
    NullDecrypter::<P>::default()
}

pub fn aes128_gcm12<'a>(key: &'a [u8], nonce_prefix: &'a [u8]) -> Aes128Gcm12Decrypter<'a> {
    Aes128Gcm12Decrypter::new(key, nonce_prefix)
}

pub fn chacha20_poly1305<'a>(key: &'a [u8], nonce_prefix: &'a [u8]) -> ChaCha20Poly1305Decrypter<'a> {
    ChaCha20Poly1305Decrypter::new(key, nonce_prefix)
}
