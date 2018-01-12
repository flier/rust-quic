#![allow(non_upper_case_globals)]

use std::borrow::Cow;
use std::iter;
use std::marker::PhantomData;

use byteorder::NativeEndian;
use bytes::{BufMut, Bytes};
use failure::Error;
use ring::aead::{open_in_place, seal_in_place, AES_128_GCM_TRUNCATED_TAG_96, Algorithm,
                 CHACHA_POLY1305_TRUNCATED_TAG_96, OpeningKey, SealingKey};
use ring::digest::SHA256;
use ring::hkdf::extract_and_expand;
use ring::hmac::SigningKey;

use crypto::{QuicDecrypter, QuicEncrypter};
use errors::QuicError::*;
use types::{QuicDiversificationNonce, QuicPacketNumber, QuicVersion};

/// An `Aes128Gcm12Encrypter` is a `QuicEncrypter`
/// that implements the `AEAD_AES_128_GCM_12` algorithm specified in RFC 5282.
///
/// Create an instance by calling `encrypter::new(kAESG)`.
///
/// It uses an authentication tag of 12 bytes (96 bits).
/// The fixed prefix of the nonce is four bytes.
pub type Aes128Gcm12Encrypter<'a> = AeadBaseEncrypter<'a, Aes128Gcm12>;

/// An `Aes128Gcm12Decrypter` is a `QuicDecrypter`
/// that implements the `AEAD_AES_128_GCM_12` algorithm specified in RFC 5282.
///
/// Create an instance by calling `decrypter::new(kAESG)`.
///
/// It uses an authentication tag of 12 bytes (96 bits).
/// The fixed prefix of the nonce is four bytes.
pub type Aes128Gcm12Decrypter<'a> = AeadBaseDecrypter<'a, Aes128Gcm12>;

/// A `ChaCha20Poly1305Encrypter` is a `QuicEncrypter`
/// that implements the `AEAD_CHACHA20_POLY1305` algorithm specified in RFC 7539,
/// except that it truncates the Poly1305 authenticator to 12 bytes.
///
/// Create an instance by calling `encrypter::new(kCC12)`.
///
/// It uses an authentication tag of 16 bytes (128 bits).
/// There is no fixed nonce prefix.
pub type ChaCha20Poly1305Encrypter<'a> = AeadBaseEncrypter<'a, ChaCha20Poly1305>;

/// A `ChaCha20Poly1305Decrypter` is a `QuicDecrypter`
/// that implements the `AEAD_CHACHA20_POLY1305` algorithm specified in draft-agl-tls-chacha20poly1305-04,
/// except that it truncates the Poly1305 authenticator to 12 bytes.
///
/// Create an instance by calling `decrypter::new(kCC12)`.
///
/// It uses an authentication tag of 16 bytes (128 bits).
/// There is no fixed nonce prefix.
pub type ChaCha20Poly1305Decrypter<'a> = AeadBaseDecrypter<'a, ChaCha20Poly1305>;

/// `AeadAlgorithm` implements the AEAD algorithm.
pub trait AeadAlgorithm {
    /// The name of algorithm.
    fn name() -> &'static str;

    /// The AEAD algorithm.
    fn algorithm() -> &'static Algorithm;
}

/// `Aes128Gcm12` implements the `AEAD_AES_128_GCM_12` algorithm specified in RFC 5282.
pub struct Aes128Gcm12 {}

impl AeadAlgorithm for Aes128Gcm12 {
    fn name() -> &'static str {
        "AES128_GCM12"
    }

    fn algorithm() -> &'static Algorithm {
        &AES_128_GCM_TRUNCATED_TAG_96
    }
}

/// `ChaCha20Poly1305` implements the `AEAD_CHACHA20_POLY1305` algorithm specified in RFC 7539
pub struct ChaCha20Poly1305 {}

impl AeadAlgorithm for ChaCha20Poly1305 {
    fn name() -> &'static str {
        "AEAD_CHACHA20_POLY1305"
    }

    fn algorithm() -> &'static Algorithm {
        &CHACHA_POLY1305_TRUNCATED_TAG_96
    }
}

/// `AeadBaseEncrypter` is the base class of AEAD `QuicEncrypter` subclasses.
pub struct AeadBaseEncrypter<'a, A> {
    key: Cow<'a, [u8]>,          // The key.
    nonce_prefix: Cow<'a, [u8]>, // The nonce prefix.
    phantom: PhantomData<A>,
}

impl<'a, A> AeadBaseEncrypter<'a, A>
where
    A: AeadAlgorithm,
{
    pub fn new(key: &'a [u8], nonce_prefix: &'a [u8]) -> AeadBaseEncrypter<'a, A> {
        AeadBaseEncrypter {
            key: key.into(),
            nonce_prefix: nonce_prefix.into(),
            phantom: PhantomData,
        }
    }

    fn encrypt(&self, nonce: &[u8], associated_data: &[u8], plain_text: &[u8]) -> Result<Bytes, Error> {
        let key = SealingKey::new(A::algorithm(), &self.key)?;
        let tag_len = key.algorithm().tag_len();
        let mut buf = plain_text.to_vec();

        buf.extend(iter::repeat(0).take(tag_len));

        let size = seal_in_place(&key, nonce, associated_data, &mut buf, tag_len)?;

        Ok(Bytes::from(buf).split_to(size))
    }
}

impl<'a, A> QuicEncrypter for AeadBaseEncrypter<'a, A>
where
    A: AeadAlgorithm,
{
    fn encrypt_packet(
        &self,
        _version: QuicVersion,
        packet_number: QuicPacketNumber,
        associated_data: &[u8],
        plain_text: &[u8],
    ) -> Result<Bytes, Error> {
        debug!(
            "encrypt {} bytes data with {:?}",
            plain_text.len(),
            A::name()
        );

        let mut nonce = self.nonce_prefix.as_ref().to_vec();

        nonce.put_u64::<NativeEndian>(packet_number);

        if nonce.len() != A::algorithm().nonce_len() {
            bail!(NonceLenMismatch(nonce.len()));
        }

        self.encrypt(&nonce, associated_data, plain_text)
    }
}

/// `AeadBaseDecrypter` is the base class of AEAD `QuicDecrypter` subclasses.
pub struct AeadBaseDecrypter<'a, A> {
    key: Cow<'a, [u8]>,          // The key.
    nonce_prefix: Cow<'a, [u8]>, // The nonce prefix.
    phantom: PhantomData<A>,
}

impl<'a, A> AeadBaseDecrypter<'a, A>
where
    A: AeadAlgorithm,
{
    pub fn new(key: &'a [u8], nonce_prefix: &'a [u8]) -> AeadBaseDecrypter<'a, A> {
        AeadBaseDecrypter {
            key: key.into(),
            nonce_prefix: nonce_prefix.into(),
            phantom: PhantomData,
        }
    }
}

impl<'a, A> QuicDecrypter for AeadBaseDecrypter<'a, A>
where
    A: 'static + AeadAlgorithm,
{
    fn with_preliminary_key(self, nonce: &QuicDiversificationNonce) -> Box<QuicDecrypter> {
        let salt = SigningKey::new(&SHA256, nonce);
        let mut secret = self.key.to_vec();

        secret.extend_from_slice(&self.nonce_prefix);

        let mut out = vec![];

        extract_and_expand(&salt, &secret, b"QUIC key diversification", &mut out);

        let (key, out) = out.split_at(self.key.len());
        let (nonce_prefix, _) = out.split_at(self.nonce_prefix.len());

        Box::new(AeadBaseDecrypter::<A> {
            key: key.to_owned().into(),
            nonce_prefix: nonce_prefix.to_owned().into(),
            phantom: PhantomData,
        })
    }

    fn decrypt_packet(
        &self,
        _version: QuicVersion,
        packet_number: QuicPacketNumber,
        associated_data: &[u8],
        cipher_text: &[u8],
    ) -> Result<Bytes, Error> {
        debug!(
            "decrypt {} bytes packet with {:?}",
            cipher_text.len(),
            A::name()
        );

        let key = OpeningKey::new(A::algorithm(), self.key.as_ref())?;
        let mut nonce = self.nonce_prefix.as_ref().to_vec();

        nonce.put_u64::<NativeEndian>(packet_number);

        if nonce.len() != A::algorithm().nonce_len() {
            bail!(NonceLenMismatch(nonce.len()));
        }

        let mut buf = cipher_text.to_vec();

        let size = open_in_place(&key, &nonce, associated_data, 0, &mut buf)?.len();

        buf.truncate(size);

        Ok(Bytes::from(buf))
    }
}

#[allow(non_upper_case_globals)]
#[cfg(test)]
mod tests {
    use std::mem;

    use byteorder::ByteOrder;
    use hex;

    use super::*;

    const kAuthTagSize: usize = 12;

    const aes_128_gcm_12_encrypt_test_groups: &[(
        // key_len, iv_len, pt_len, aad_len, tag_len
        (usize, usize, usize, usize, usize),
        // key, iv, pt, aad, ct, tag
        &[(&str, &str, &str, &str, &str, &str)],
    )] = &[
        // test_group_0
        (
            (128, 96, 0, 0, 128),
            &[
                (
                    "11754cd72aec309bf52f7687212e8957",
                    "3c819d9a9bed087615030b65",
                    "",
                    "",
                    "",
                    "250327c674aaf477aef2675748cf6971",
                ),
                (
                    "ca47248ac0b6f8372a97ac43508308ed",
                    "ffd2b598feabc9019262d2be",
                    "",
                    "",
                    "",
                    "60d20404af527d248d893ae495707d1a",
                ),
            ],
        ),
        // test_group_1
        (
            (128, 96, 0, 128, 128),
            &[
                (
                    "77be63708971c4e240d1cb79e8d77feb",
                    "e0e00f19fed7ba0136a797f3",
                    "",
                    "7a43ec1d9c0a5a78a0b16533a6213cab",
                    "",
                    "209fcc8d3675ed938e9c7166709dd946",
                ),
                (
                    "7680c5d3ca6154758e510f4d25b98820",
                    "f8f105f9c3df4965780321f8",
                    "",
                    "c94c410194c765e3dcc7964379758ed3",
                    "",
                    "94dca8edfcf90bb74b153c8d48a17930",
                ),
            ],
        ),
        // test_group_2
        (
            (128, 96, 128, 0, 128),
            &[
                (
                    "7fddb57453c241d03efbed3ac44e371c",
                    "ee283a3fc75575e33efd4887",
                    "d5de42b461646c255c87bd2962d3b9a2",
                    "",
                    "2ccda4a5415cb91e135c2a0f78c9b2fd",
                    "b36d1df9b9d5e596f83e8b7f52971cb3",
                ),
                (
                    "ab72c77b97cb5fe9a382d9fe81ffdbed",
                    "54cc7dc2c37ec006bcc6d1da",
                    "007c5e5b3e59df24a7c355584fc1518d",
                    "",
                    "0e1bde206a07a9c2c1b65300f8c64997",
                    "2b4401346697138c7a4891ee59867d0c",
                ),
            ],
        ),
        // test_group_3
        (
            (128, 96, 408, 160, 128),
            &[
                (
                    "fe47fcce5fc32665d2ae399e4eec72ba",
                    "5adb9609dbaeb58cbd6e7275",
                    "7c0e88c88899a779228465074797cd4c2e1498d2\
                     59b54390b85e3eef1c02df60e743f1b840382c4bc\
                     caf3bafb4ca8429bea063",
                    "88319d6e1d3ffa5f987199166c8a9b56c2aeba5a",
                    "98f4826f05a265e6dd2be82db241c0fbbbf9ffb1\
                     c173aa83964b7cf5393043736365253ddbc5db877\
                     8371495da76d269e5db3e",
                    "291ef1982e4defedaa2249f898556b47",
                ),
                (
                    "ec0c2ba17aa95cd6afffe949da9cc3a8",
                    "296bce5b50b7d66096d627ef",
                    "b85b3753535b825cbe5f632c0b843c741351f18a\
                     a484281aebec2f45bb9eea2d79d987b764b9611f6\
                     c0f8641843d5d58f3a242",
                    "f8d00f05d22bf68599bcdeb131292ad6e2df5d14",
                    "a7443d31c26bdf2a1c945e29ee4bd344a99cfaf3\
                     aa71f8b3f191f83c2adfc7a07162995506fde6309\
                     ffc19e716eddf1a828c5a",
                    "890147971946b627c40016da1ecf3e77",
                ),
            ],
        ),
        // test_group_4
        (
            (128, 96, 408, 720, 128),
            &[
                (
                    "2c1f21cf0f6fb3661943155c3e3d8492",
                    "23cb5ff362e22426984d1907",
                    "42f758836986954db44bf37c6ef5e4ac0adaf38f27252a1b82d02ea9\
                     49c8a1a2dbc0d68b5615ba7c1220ff6510e259f06655d8",
                    "5d3624879d35e46849953e45a32a624d6a6c536ed9857c613b572b033\
                     3e701557a713e3f010ecdf9a6bd6c9e3e44b065208645aff4aabee611b\
                     391528514170084ccf587177f4488f33cfb5e979e42b6e1cfc0a60238982a7aec",
                    "81824f0e0d523db30d3da369fdc0d60894c7a0a20646dd015073ad273\
                     2bd989b14a222b6ad57af43e1895df9dca2a5344a62cc",
                    "57a3ee28136e94c74838997ae9823f3a",
                ),
                (
                    "d9f7d2411091f947b4d6f1e2d1f0fb2e",
                    "e1934f5db57cc983e6b180e7",
                    "73ed042327f70fe9c572a61545eda8b2a0c6e1d6c291ef19248e973ae\
                     e6c312012f490c2c6f6166f4a59431e182663fcaea05a",
                    "0a8a18a7150e940c3d87b38e73baee9a5c049ee21795663e264b694a9\
                     49822b639092d0e67015e86363583fcf0ca645af9f43375f05fdb4ce84\
                     f411dcbca73c2220dea03a20115d2e51398344b16bee1ed7c499b353d6c597af8",
                    "aaadbd5c92e9151ce3db7210b8714126b73e43436d242677afa50384f\
                     2149b831f1d573c7891c2a91fbc48db29967ec9542b23",
                    "21b51ca862cb637cdd03b99a0f93b134",
                ),
            ],
        ),
        // test_group_5
        (
            (128, 96, 104, 0, 128),
            &[
                (
                    "fe9bb47deb3a61e423c2231841cfd1fb",
                    "4d328eb776f500a2f7fb47aa",
                    "f1cc3818e421876bb6b8bbd6c9",
                    "",
                    "b88c5c1977b35b517b0aeae967",
                    "43fd4727fe5cdb4b5b42818dea7ef8c9",
                ),
                (
                    "6703df3701a7f54911ca72e24dca046a",
                    "12823ab601c350ea4bc2488c",
                    "793cd125b0b84a043e3ac67717",
                    "",
                    "b2051c80014f42f08735a7b0cd",
                    "38e6bcd29962e5f2c13626b85a877101",
                ),
            ],
        ),
    ];

    const aes_128_gcm_12_decrypt_test_groups: &[(
        // key_len, iv_len, pt_len, aad_len, tag_len
        (usize, usize, usize, usize, usize),
        // key, iv, ct, aad, tag, pt
        &[(&str, &str, &str, &str, &str, Option<&str>)],
    )] = &[
        // test_group_0
        (
            (128, 96, 0, 0, 128),
            &[
                (
                    "cf063a34d4a9a76c2c86787d3f96db71",
                    "113b9785971864c83b01c787",
                    "",
                    "",
                    "72ac8493e3a5228b5d130a69d2510e42",
                    Some(""),
                ),
                (
                    "a49a5e26a2f8cb63d05546c2a62f5343",
                    "907763b19b9b4ab6bd4f0281",
                    "",
                    "",
                    "a2be08210d8c470a8df6e8fbd79ec5cf",
                    None, // FAIL
                ),
            ],
        ),
        // test_group_1
        (
            (128, 96, 0, 128, 128),
            &[
                (
                    "d1f6af919cde85661208bdce0c27cb22",
                    "898c6929b435017bf031c3c5",
                    "",
                    "7c5faa40e636bbc91107e68010c92b9f",
                    "ae45f11777540a2caeb128be8092468a",
                    None, // FAIL
                ),
                (
                    "2370e320d4344208e0ff5683f243b213",
                    "04dbb82f044d30831c441228",
                    "",
                    "d43a8e5089eea0d026c03a85178b27da",
                    "2a049c049d25aa95969b451d93c31c6e",
                    Some(""),
                ),
            ],
        ),
        // test_group_2
        (
            (128, 96, 128, 0, 128),
            &[
                (
                    "e98b72a9881a84ca6b76e0f43e68647a",
                    "8b23299fde174053f3d652ba",
                    "5a3c1cf1985dbb8bed818036fdd5ab42",
                    "",
                    "23c7ab0f952b7091cd324835043b5eb5",
                    Some("28286a321293253c3e0aa2704a278032"),
                ),
                (
                    "33240636cd3236165f1a553b773e728e",
                    "17c4d61493ecdc8f31700b12",
                    "47bb7e23f7bdfe05a8091ac90e4f8b2e",
                    "",
                    "b723c70e931d9785f40fd4ab1d612dc9",
                    Some("95695a5b12f2870b9cc5fdc8f218a97d"),
                ),
                (
                    "5164df856f1e9cac04a79b808dc5be39",
                    "e76925d5355e0584ce871b2b",
                    "0216c899c88d6e32c958c7e553daa5bc",
                    "",
                    "a145319896329c96df291f64efbe0e3a",
                    None, // FAIL
                ),
            ],
        ),
        // test_group_3
        (
            (128, 96, 408, 160, 128),
            &[
                (
                    "af57f42c60c0fc5a09adb81ab86ca1c3",
                    "a2dc01871f37025dc0fc9a79",
                    "b9a535864f48ea7b6b1367914978f9bfa087d854\
                     bb0e269bed8d279d2eea1210e48947338b22f9bad\
                     09093276a331e9c79c7f4",
                    "41dc38988945fcb44faf2ef72d0061289ef8efd8",
                    "4f71e72bde0018f555c5adcce062e005",
                    Some(
                        "3803a0727eeb0ade441e0ec107161ded2d4\
                         25ec0d102f21f51bf2cf9947c7ec4aa72795b2f69b\
                         041596e8817d0a3c16f8fadeb",
                    ),
                ),
                (
                    "ebc753e5422b377d3cb64b58ffa41b61",
                    "2e1821efaced9acf1f241c9b",
                    "069567190554e9ab2b50a4e1fbf9c147340a5025\
                     fdbd201929834eaf6532325899ccb9f401823e04b\
                     05817243d2142a3589878",
                    "b9673412fd4f88ba0e920f46dd6438ff791d8eef",
                    "534d9234d2351cf30e565de47baece0b",
                    Some(
                        "39077edb35e9c5a4b1e4c2a6b9bb1fce77f\
                         00f5023af40333d6d699014c2bcf4209c18353a18\
                         017f5b36bfc00b1f6dcb7ed485",
                    ),
                ),
                (
                    "52bdbbf9cf477f187ec010589cb39d58",
                    "d3be36d3393134951d324b31",
                    "700188da144fa692cf46e4a8499510a53d90903c\
                     967f7f13e8a1bd8151a74adc4fe63e32b992760b3\
                     a5f99e9a47838867000a9",
                    "93c4fc6a4135f54d640b0c976bf755a06a292c33",
                    "8ca4e38aa3dfa6b1d0297021ccf3ea5f",
                    None, // FAIL
                ),
            ],
        ),
        // test_group_4
        (
            (128, 96, 408, 720, 128),
            &[
                (
                    "da2bb7d581493d692380c77105590201",
                    "44aa3e7856ca279d2eb020c6",
                    "9290d430c9e89c37f0446dbd620c9a6b\
                     34b1274aeb6f911f75867efcf95b6feda\
                     69f1af4ee16c761b3c9aeac3da03aa9889c88",
                    "4cd171b23bddb3a53cdf959d5c1710b4\
                     81eb3785a90eb20a2345ee00d0bb7868c\
                     367ab12e6f4dd1dee72af4eee1d197777\
                     d1d6499cc541f34edbf45cda6ef90b3c0\
                     24f9272d72ec1909fb8fba7db88a4d6f7\
                     d3d925980f9f9f72",
                    "9e3ac938d3eb0cadd6f5c9e35d22ba38",
                    Some(
                        "9bbf4c1a2742f6ac80cb4e8a052\
                         e4a8f4f07c43602361355b717381edf9f\
                         abd4cb7e3ad65dbd1378b196ac270588d\
                         d0621f642",
                    ),
                ),
                (
                    "d74e4958717a9d5c0e235b76a926cae8",
                    "0b7471141e0c70b1995fd7b1",
                    "e701c57d2330bf066f9ff8cf3ca4343c\
                     afe4894651cd199bdaaa681ba486b4a65\
                     c5a22b0f1420be29ea547d42c713bc6af66aa",
                    "4a42b7aae8c245c6f1598a395316e4b8\
                     484dbd6e64648d5e302021b1d3fa0a38f\
                     46e22bd9c8080b863dc0016482538a856\
                     2a4bd0ba84edbe2697c76fd039527ac17\
                     9ec5506cf34a6039312774cedebf4961f\
                     3978b14a26509f96",
                    "e192c23cb036f0b31592989119eed55d",
                    Some(
                        "840d9fb95e32559fb3602e48590\
                         280a172ca36d9b49ab69510f5bd552bfa\
                         b7a306f85ff0a34bc305b88b804c60b90add594a17",
                    ),
                ),
                (
                    "1986310c725ac94ecfe6422e75fc3ee7",
                    "93ec4214fa8e6dc4e3afc775",
                    "b178ec72f85a311ac4168f42a4b2c231\
                     13fbea4b85f4b9dabb74e143eb1b8b0a3\
                     61e0243edfd365b90d5b325950df0ada058f9",
                    "e80b88e62c49c958b5e0b8b54f532d9f\
                     f6aa84c8a40132e93e55b59fc24e8decf\
                     28463139f155d1e8ce4ee76aaeefcd245\
                     baa0fc519f83a5fb9ad9aa40c4b211260\
                     13f576c4272c2cb136c8fd091cc4539877a5d1e72d607f960",
                    "8b347853f11d75e81e8a95010be81f17",
                    None, // FAIL
                ),
            ],
        ),
        // test_group_5
        (
            (128, 96, 104, 0, 128),
            &[
                (
                    "387218b246c1a8257748b56980e50c94",
                    "dd7e014198672be39f95b69d",
                    "cdba9e73eaf3d38eceb2b04a8d",
                    "",
                    "ecf90f4a47c9c626d6fb2c765d201556",
                    Some("48f5b426baca03064554cc2b30"),
                ),
                (
                    "294de463721e359863887c820524b3d4",
                    "3338b35c9d57a5d28190e8c9",
                    "2f46634e74b8e4c89812ac83b9",
                    "",
                    "dabd506764e68b82a7e720aa18da0abe",
                    Some("46a2e55c8e264df211bd112685"),
                ),
                (
                    "28ead7fd2179e0d12aa6d5d88c58c2dc",
                    "5055347f18b4d5add0ae5c41",
                    "142d8210c3fb84774cdbd0447a",
                    "",
                    "5fd321d9cdb01952dc85f034736c2a7d",
                    Some("3b95b981086ee73cc4d0cc1422"),
                ),
                (
                    "7d7b6c988137b8d470c57bf674a09c87",
                    "9edf2aa970d016ac962e1fd8",
                    "a85b66c3cb5eab91d5bdc8bc0e",
                    "",
                    "dc054efc01f3afd21d9c2484819f569a",
                    None, // FAIL
                ),
            ],
        ),
    ];

    const chacha_20_poly_1305_encrypt_test_groups: &[
        // key, pt, iv, fixed, aad, ct
        (&str, &str, &str, &str, &str, &str)
    ] = &[
        (
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173\
            73206f66202739393a204966204920636f756c64206f6666657220796f75206f6\
            e6c79206f6e652074697020666f7220746865206675747572652c2073756e7363\
            7265656e20776f756c642062652069742e",
            "4041424344454647",
            "07000000",
            "50515253c0c1c2c3c4c5c6c7",
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
            3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b369\
            2ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3f\
            f4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecb",  // "d0600691" truncated
        )
    ];

    const chacha_20_poly_1305_decrypt_test_groups: &[
        // key, iv, fixed, aad, ct, pt
        (&str, &str, &str, &str, &str, Option<&str>)
    ] = &[
        (
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "4041424344454647",
            "07000000",
            "50515253c0c1c2c3c4c5c6c7",
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
            3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b369\
            2ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3f\
            f4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecb",  // "d0600691" truncated
            Some("4c616469657320616e642047656e746c656d656e206f662074686520636\
            c617373206f66202739393a204966204920636f756c64206f6666657220796f75\
            206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756\
            e73637265656e20776f756c642062652069742e")
        ),
        // Modify the ciphertext (Poly1305 authenticator).
        (
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "4041424344454647",
            "07000000",
            "50515253c0c1c2c3c4c5c6c7",
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
            3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b369\
            2ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3f\
            f4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecc",  // "d0600691" truncated
            None,
        ),
        // Modify the associated data.
        (
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "4041424344454647",
            "07000000",
            "60515253c0c1c2c3c4c5c6c7",
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
            3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b369\
            2ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3f\
            f4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecb",  // "d0600691" truncated
            None,
        )
    ];

    #[test]
    fn aes_128_gcm_12_encrypter_encrypt() {
        for &((key_len, iv_len, pt_len, aad_len, tag_len), test_group) in aes_128_gcm_12_encrypt_test_groups {
            for &(key, iv, pt, aad, ct, tag) in test_group {
                let key = hex::decode(key).unwrap();
                let iv = hex::decode(iv).unwrap();
                let pt = hex::decode(pt).unwrap();
                let aad = hex::decode(aad).unwrap();
                let ct = hex::decode(ct).unwrap();
                let tag = hex::decode(tag).unwrap();

                assert_eq!(key.len() * 8, key_len);
                assert_eq!(iv.len() * 8, iv_len);
                assert_eq!(pt.len() * 8, pt_len);
                assert_eq!(aad.len() * 8, aad_len);
                assert_eq!(ct.len() * 8, pt_len);
                assert_eq!(tag.len() * 8, tag_len);

                assert!(tag.len() > kAuthTagSize);

                let encrypter = Aes128Gcm12Encrypter::new(&key, b"");
                let cipher_text = encrypter.encrypt(&iv, &aad, &pt).unwrap();

                assert_eq!(&cipher_text[..ct.len()], ct.as_slice());
                assert_eq!(&cipher_text[ct.len()..], &tag[..kAuthTagSize]);
            }
        }
    }

    #[test]
    fn aes_128_gcm_12_decrypter_decrypt() {
        for &((key_len, iv_len, pt_len, aad_len, tag_len), test_group) in aes_128_gcm_12_decrypt_test_groups {
            for &(key, iv, ct, aad, tag, pt) in test_group {
                let key = hex::decode(key).unwrap();
                let iv = hex::decode(iv).unwrap();
                let aad = hex::decode(aad).unwrap();
                let ct = hex::decode(ct).unwrap();
                let tag = hex::decode(tag).unwrap();
                let pt = pt.map(|pt| hex::decode(pt).unwrap());

                assert_eq!(key.len() * 8, key_len);
                assert_eq!(iv.len() * 8, iv_len);
                assert_eq!(aad.len() * 8, aad_len);
                assert_eq!(ct.len() * 8, pt_len);
                assert_eq!(tag.len() * 8, tag_len);

                if let Some(ref pt) = pt {
                    assert_eq!(pt.len() * 8, pt_len);
                }

                let (nonce_prefix, packet_number) = iv.split_at(iv.len() - mem::size_of::<QuicPacketNumber>());
                let packet_number = NativeEndian::read_u64(packet_number);

                let mut cipher_text = ct.to_vec();

                cipher_text.extend_from_slice(&tag[..kAuthTagSize]);

                let decrypter = Aes128Gcm12Decrypter::new(&key, nonce_prefix);
                let plain_text = decrypter.decrypt_packet(
                    QuicVersion::QUIC_VERSION_41,
                    packet_number,
                    &aad,
                    &cipher_text,
                );

                if let Some(ref pt) = pt {
                    assert_eq!(plain_text.unwrap(), pt);
                } else {
                    assert!(plain_text.is_err());
                }
            }
        }
    }

    #[test]
    fn chacha_20_poly_1305_encrypter_encrypt() {
        for &(key, pt, iv, fixed, aad, ct) in chacha_20_poly_1305_encrypt_test_groups {
            let key = hex::decode(key).unwrap();
            let pt = hex::decode(pt).unwrap();
            let iv = hex::decode(iv).unwrap();
            let fixed = hex::decode(fixed).unwrap();
            let aad = hex::decode(aad).unwrap();
            let ct = hex::decode(ct).unwrap();

            let encrypter = ChaCha20Poly1305Encrypter::new(&key, b"");
            let nonce = fixed.into_iter().chain(iv.into_iter()).collect::<Vec<u8>>();
            let cipher_text = encrypter.encrypt(&nonce, &aad, &pt).unwrap();

            assert_eq!(ct.len() - pt.len(), kAuthTagSize);
            assert_eq!(cipher_text.len() - pt.len(), kAuthTagSize);
            assert_eq!(cipher_text, &ct);
        }
    }

    #[test]
    fn chacha_20_poly_1305_encrypter_decrypt() {
        for &(key, iv, fixed, aad, ct, pt) in chacha_20_poly_1305_decrypt_test_groups {
            let key = hex::decode(key).unwrap();
            let iv = hex::decode(iv).unwrap();
            let fixed = hex::decode(fixed).unwrap();
            let aad = hex::decode(aad).unwrap();
            let ct = hex::decode(ct).unwrap();
            let pt = pt.map(|pt| hex::decode(pt).unwrap());

            let mut nonce = fixed;

            nonce.extend_from_slice(&iv);

            let (nonce_prefix, packet_number) = nonce.split_at(nonce.len() - mem::size_of::<QuicPacketNumber>());
            let packet_number = NativeEndian::read_u64(packet_number);

            let decrypter = ChaCha20Poly1305Decrypter::new(&key, &nonce_prefix);
            let plain_text = decrypter.decrypt_packet(QuicVersion::QUIC_VERSION_41, packet_number, &aad, &ct);

            if let Some(ref pt) = pt {
                assert_eq!(plain_text.unwrap(), pt);
            } else {
                assert!(plain_text.is_err());
            }
        }
    }
}
