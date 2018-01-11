#![allow(non_upper_case_globals)]

use std::marker::PhantomData;

use bytes::{BufMut, Bytes, BytesMut, LittleEndian};
use extprim::u128::u128;
use failure::{Error, Fail};
use nom::{IResult, le_u32, le_u64};

use crypto::{QuicDecrypter, QuicEncrypter};
use crypto::fnv::{fnv1a, kOffset};
use errors::QuicError;
use types::{Perspective, QuicDiversificationNonce, QuicPacketNumber, QuicVersion};

const kHashSizeShort: usize = 12; // size of uint128 serialized short

/// A `NullEncrypter` is a `QuicEncrypter` used before a crypto negotiation has occurred.
///
/// It does not actually encrypt the payload,
/// but does generate a MAC (fnv128) over both the payload and associated data.
#[derive(Clone, Debug)]
pub struct NullEncrypter<P> {
    phantom: PhantomData<P>,
}

impl<P> NullEncrypter<P> {
    pub fn new() -> Self {
        NullEncrypter {
            phantom: PhantomData,
        }
    }
}

impl<P> QuicEncrypter for NullEncrypter<P>
where
    P: Perspective,
{
    fn encrypt_packet<'p>(
        &self,
        version: QuicVersion,
        _packet_number: QuicPacketNumber,
        associated_data: &[u8],
        plain_text: &[u8],
    ) -> Result<Bytes, Error> {
        debug!("encrypt {} bytes data with FNV128", plain_text.len());

        let mut buf = BytesMut::with_capacity(kHashSizeShort + plain_text.len());
        let hash = compute_hash::<P>(version, associated_data, plain_text);

        buf.put_u64::<LittleEndian>(hash.low64());
        buf.put_u32::<LittleEndian>(hash.high64() as u32);
        buf.extend_from_slice(plain_text);

        Ok(buf.freeze())
    }
}

/// A `NullDecrypter` is a `QuicDecrypter` used before a crypto negotiation has occurred.
///
/// It does not actually decrypt the payload,
/// but does verify a hash (fnv128) over both the payload and associated data.
#[derive(Clone, Debug)]
pub struct NullDecrypter<P> {
    phantom: PhantomData<P>,
}

impl<P> NullDecrypter<P> {
    pub fn new() -> Self {
        NullDecrypter {
            phantom: PhantomData,
        }
    }
}

impl<P> QuicDecrypter for NullDecrypter<P>
where
    P: 'static + Perspective,
{
    fn with_preliminary_key(self, _nonce: &QuicDiversificationNonce) -> Box<QuicDecrypter> {
        Box::new(self)
    }

    fn decrypt_packet<'p>(
        &self,
        version: QuicVersion,
        _packet_number: QuicPacketNumber,
        associated_data: &'p [u8],
        cipher_text: &'p [u8],
    ) -> Result<Bytes, Error> {
        debug!("decrypt {} bytes packet with FNV128", cipher_text.len());

        let (plain_text, hash) = match read_hash(cipher_text) {
            IResult::Done(remaining, hash) => (remaining, hash),
            IResult::Incomplete(needed) => {
                bail!(QuicError::IncompletePacket(needed).context("incomplete packet hash."))
            }
            IResult::Error(err) => bail!(QuicError::InvalidPacket(err).context("unable to process crypted packet.")),
        };

        if hash != compute_hash::<P>(version, associated_data, plain_text) {
            bail!("packet hash mismatch")
        }

        Ok(plain_text.into())
    }
}

named!(
    read_hash<u128>,
    do_parse!(lo: le_u64 >> hi: le_u32 >> (u128::from_parts(hi as u64, lo)))
);

fn compute_hash<P>(version: QuicVersion, associated_data: &[u8], plain_text: &[u8]) -> u128
where
    P: Perspective,
{
    let hash = if version > QuicVersion::QUIC_VERSION_35 {
        if P::is_server() {
            fnv1a(
                fnv1a(fnv1a(kOffset, associated_data), plain_text),
                b"Server",
            )
        } else {
            fnv1a(
                fnv1a(fnv1a(kOffset, associated_data), plain_text),
                b"Client",
            )
        }
    } else {
        fnv1a(fnv1a(kOffset, associated_data), plain_text)
    };

    let mask: u128 = u128!(0xffffffff) << 96;

    hash & !mask
}

#[cfg(test)]
mod tests {
    use super::*;

    pub struct Client {}

    impl Perspective for Client {
        fn is_server() -> bool {
            false
        }
    }

    pub struct Server {}

    impl Perspective for Server {
        fn is_server() -> bool {
            true
        }
    }

    #[cfg_attr(rustfmt, rustfmt_skip)]
    const encrypted_client_packet: &[u8] =
        &[
            // fnv hash
            0x97, 0xdc, 0x27, 0x2f, 0x18, 0xa8, 0x56, 0x73, 0xdf, 0x8d, 0x1d, 0xd0,
            // payload
            b'g', b'o', b'o', b'd', b'b', b'y', b'e', b'!'
        ];

    #[cfg_attr(rustfmt, rustfmt_skip)]
    const encrypted_server_packet: &[u8] =
        &[
            // fnv hash
            0x63, 0x5e, 0x08, 0x03, 0x32, 0x80, 0x8f, 0x73, 0xdf, 0x8d, 0x1d, 0x1a,
            // payload
            b'g', b'o', b'o', b'd', b'b', b'y', b'e', b'!'
        ];

    #[cfg_attr(rustfmt, rustfmt_skip)]
    const encrypted_client_packet_pre37: &[u8] =
        &[
            // fnv hash
            0xa0, 0x6f, 0x44, 0x8a, 0x44, 0xf8, 0x18, 0x3b, 0x47, 0x91, 0xb2, 0x13,
            // payload
            b'g', b'o', b'o', b'd', b'b', b'y', b'e', b'!'
        ];

    #[cfg_attr(rustfmt, rustfmt_skip)]
    const encrypted_server_packet_pre37: &[u8] =
        &[
            // fnv hash
            0xa0, 0x6f, 0x44, 0x8a, 0x44, 0xf8, 0x18, 0x3b, 0x47, 0x91, 0xb2, 0x13,
            // payload
            b'g', b'o', b'o', b'd', b'b', b'y', b'e', b'!'
        ];

    #[cfg_attr(rustfmt, rustfmt_skip)]
    const encrypted_bad_hash_client_packet: &[u8] =
        &[
            // fnv hash (mismatch)
            0x46, 0x11, 0xea, 0x5f, 0xcf, 0x1d, 0x66, 0x5b, 0xba, 0xf0, 0xbc, 0xfd,
            // payload
            b'g', b'o', b'o', b'd', b'b', b'y', b'e', b'!'
        ];

    #[cfg_attr(rustfmt, rustfmt_skip)]
    const encrypted_short_client_packet: &[u8] =
        &[
            // fnv hash (truncated)
            0x46, 0x11, 0xea, 0x5f, 0xcf, 0x1d, 0x66, 0x5b, 0xba, 0xf0, 0xbc, 0xfd,
        ];

    #[test]
    fn null_encrypt_client() {
        let encrypter = NullEncrypter::<Client>::new();

        assert_eq!(
            encrypter
                .encrypt_packet(
                    QuicVersion::QUIC_VERSION_37,
                    0,
                    b"hello world!",
                    b"goodbye!"
                )
                .unwrap(),
            encrypted_client_packet
        );
    }

    #[test]
    fn null_encrypt_server() {
        let encrypter = NullEncrypter::<Server>::new();

        assert_eq!(
            encrypter
                .encrypt_packet(
                    QuicVersion::QUIC_VERSION_37,
                    0,
                    b"hello world!",
                    b"goodbye!"
                )
                .unwrap(),
            encrypted_server_packet
        );
    }

    #[test]
    fn null_encrypt_client_pre37() {
        let encrypter = NullEncrypter::<Client>::new();

        assert_eq!(
            encrypter
                .encrypt_packet(
                    QuicVersion::QUIC_VERSION_35,
                    0,
                    b"hello world!",
                    b"goodbye!"
                )
                .unwrap(),
            encrypted_client_packet_pre37
        );
    }

    #[test]
    fn null_encrypt_server_pre37() {
        let encrypter = NullEncrypter::<Server>::new();

        assert_eq!(
            encrypter
                .encrypt_packet(
                    QuicVersion::QUIC_VERSION_35,
                    0,
                    b"hello world!",
                    b"goodbye!"
                )
                .unwrap(),
            encrypted_server_packet_pre37
        );
    }

    #[test]
    fn null_decrypt_client() {
        let decrypter = NullDecrypter::<Client>::new();

        assert_eq!(
            decrypter
                .decrypt_packet(
                    QuicVersion::QUIC_VERSION_37,
                    0,
                    b"hello world!",
                    encrypted_client_packet
                )
                .unwrap(),
            b"goodbye!"[..]
        );
    }

    #[test]
    fn null_decrypt_server() {
        let decrypter = NullDecrypter::<Server>::new();

        assert_eq!(
            decrypter
                .decrypt_packet(
                    QuicVersion::QUIC_VERSION_37,
                    0,
                    b"hello world!",
                    encrypted_server_packet
                )
                .unwrap(),
            b"goodbye!"[..]
        );
    }

    #[test]
    fn null_decrypt_client_pre37() {
        let decrypter = NullDecrypter::<Client>::new();

        assert_eq!(
            decrypter
                .decrypt_packet(
                    QuicVersion::QUIC_VERSION_35,
                    0,
                    b"hello world!",
                    encrypted_client_packet_pre37
                )
                .unwrap(),
            b"goodbye!"[..]
        );
    }

    #[test]
    fn null_decrypt_server_pre37() {
        let decrypter = NullDecrypter::<Server>::new();

        assert_eq!(
            decrypter
                .decrypt_packet(
                    QuicVersion::QUIC_VERSION_35,
                    0,
                    b"hello world!",
                    encrypted_server_packet_pre37
                )
                .unwrap(),
            b"goodbye!"[..]
        );
    }

    #[test]
    fn null_decrypt_bad_hash() {
        let decrypter = NullDecrypter::<Client>::new();

        assert_matches!(
            decrypter
                .decrypt_packet(
                    QuicVersion::QUIC_VERSION_35,
                    0,
                    b"hello world!",
                    encrypted_bad_hash_client_packet
                )
                .err()
                .unwrap()
                .to_string()
                .as_str(),
            "packet hash mismatch"
        );
    }

    #[test]
    fn null_decrypt_short() {
        let decrypter = NullDecrypter::<Client>::new();

        assert_matches!(
            decrypter
                .decrypt_packet(
                    QuicVersion::QUIC_VERSION_35,
                    0,
                    b"hello world!",
                    encrypted_short_client_packet
                )
                .err()
                .unwrap()
                .to_string()
                .as_str(),
            "packet hash mismatch"
        );
    }
}
