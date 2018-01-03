use std::borrow::Cow;
use std::hash::Hash;
use std::marker::PhantomData;

use extprim::u128::u128;
use failure::{Error, Fail};
use nom::{IResult, le_u32, le_u64};

use crypto::{QuicDecrypter, fnv1a, kOffset};
use errors::QuicError;
use framer::Perspective;
use packet::QuicPacketNumber;
use version::QuicVersion;

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

impl<P> NullDecrypter<P>
where
    P: Perspective,
{
    fn compute_hash(&self, version: QuicVersion, associated_data: &[u8], plain_text: &[u8]) -> u128 {
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
}

impl<P> QuicDecrypter for NullDecrypter<P>
where
    P: Perspective,
{
    fn decrypt_packet<'p>(
        &self,
        version: QuicVersion,
        packet_number: QuicPacketNumber,
        associated_data: &'p [u8],
        cipher_text: &'p [u8],
    ) -> Result<Cow<'p, [u8]>, Error> {
        let (plain_text, hash) = match read_hash(cipher_text) {
            IResult::Done(remaining, hash) => (remaining, hash),
            IResult::Incomplete(needed) => {
                bail!(QuicError::IncompletePacket(needed).context("incomplete packet hash."))
            }
            IResult::Error(err) => bail!(QuicError::InvalidPacket(err).context("unable to process crypted packet.")),
        };

        if hash != self.compute_hash(version, associated_data, plain_text) {
            bail!("packet hash mismatch")
        }

        Ok(plain_text.into())
    }
}

named!(
    read_hash<u128>,
    do_parse!(lo: le_u64 >> hi: le_u32 >> (u128::from_parts(hi as u64, lo)))
);
