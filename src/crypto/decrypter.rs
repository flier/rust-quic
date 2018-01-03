use failure::Error;
use std::borrow::Cow;

use packet::QuicPacketNumber;
use version::QuicVersion;

pub trait QuicDecrypter {
    /// Populates `output` with the decrypted `cipher_text`.
    /// `packet_number` is appended to the `nonce_prefix` value provided in `set_nonce_prefix` to form the nonce.
    fn decrypt_packet<'p>(
        &self,
        version: QuicVersion,
        packet_number: QuicPacketNumber,
        associated_data: &'p [u8],
        cipher_text: &'p [u8],
    ) -> Result<Cow<'p, [u8]>, Error>;
}
