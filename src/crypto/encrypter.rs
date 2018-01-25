use bytes::Bytes;
use failure::Error;

use crypto::{Aes128Gcm12Encrypter, ChaCha20Poly1305Encrypter, NullEncrypter};
use proto::QuicPacketNumber;
use types::QuicVersion;

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

    // Returns the size in bytes of a key for the algorithm.
    fn key_size(&self) -> usize;

    // Returns the size in bytes of the fixed initial part of the nonce.
    fn nonce_prefix_size(&self) -> usize;

    /// Returns the maximum length of plaintext
    /// that can be encrypted to ciphertext no larger than `ciphertext_size`.
    fn max_plaintext_size(&self, ciphertext_size: usize) -> usize;

    /// Returns the length of the ciphertext
    /// that would be generated by encrypting to plaintext of size `plaintext_size`.
    fn ciphertext_size(&self, plaintext_size: usize) -> usize;
}

pub fn null<P>() -> NullEncrypter<P> {
    NullEncrypter::<P>::default()
}

pub fn aes128_gcm12<'a>(key: &'a [u8], nonce_prefix: &'a [u8]) -> Aes128Gcm12Encrypter<'a> {
    Aes128Gcm12Encrypter::new(key, nonce_prefix)
}

pub fn chacha20_poly1305<'a>(key: &'a [u8], nonce_prefix: &'a [u8]) -> ChaCha20Poly1305Encrypter<'a> {
    ChaCha20Poly1305Encrypter::new(key, nonce_prefix)
}
