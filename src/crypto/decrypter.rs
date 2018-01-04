use failure::Error;

use bytes::Bytes;

use packet::QuicPacketNumber;
use version::QuicVersion;

pub trait QuicDecrypter {
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
