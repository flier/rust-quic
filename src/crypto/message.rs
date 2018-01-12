#![allow(non_upper_case_globals)]
use std::collections::HashMap;
use std::mem;
use std::str;

use byteorder::{ByteOrder, LittleEndian};
use failure::{Error, Fail};
use nom::{IResult, Needed, le_u16, le_u32};

use errors::QuicError;
use types::{quic_tag, QuicTag};

/// Max number of entries in a message.
const kMaxEntries: usize = 128;

/// An intermediate format of a handshake message
/// that's convenient for a `CryptoFramer` to serialize from or parse into.
#[derive(Clone, Debug, PartialEq)]
pub struct CryptoHandshakeMessage<'a> {
    tag: QuicTag,
    values: HashMap<QuicTag, &'a [u8]>,
}

impl<'a> CryptoHandshakeMessage<'a> {
    pub fn parse(input: &'a [u8]) -> Result<(&'a [u8], CryptoHandshakeMessage<'a>), Error> {
        match parse_crypto_handshake_message(input) {
            IResult::Done(remaining, (tag, entries)) => {
                let mut values = HashMap::new();
                let mut last_tag = None;
                let mut last_offset = 0;

                for (tag, offset) in entries {
                    match last_tag {
                        Some(last_tag) if tag == last_tag => {
                            bail!(QuicError::DuplicateTag(tag));
                        }
                        Some(last_tag) if tag < last_tag => {
                            bail!(QuicError::TagOutOfOrder(tag));
                        }
                        _ => {}
                    }

                    if offset < last_offset {
                        bail!(QuicError::OffsetOutOfOrder(offset));
                    }

                    let size = offset - last_offset;

                    if size > remaining.len() {
                        bail!(QuicError::IncompletePacket(Needed::Size(offset)).context("handshake message payload."));
                    }

                    values.insert(tag, &remaining[last_offset..offset]);

                    last_tag = Some(tag);
                    last_offset = offset;
                }

                Ok((
                    &remaining[last_offset..],
                    CryptoHandshakeMessage { tag, values },
                ))
            }
            IResult::Incomplete(needed) => {
                bail!(QuicError::from(needed).context("incomplete crypto handshake message."))
            }
            IResult::Error(err) => bail!(QuicError::from(err).context("unable to crypto handshake message.")),
        }
    }

    pub fn tag(&self) -> QuicTag {
        self.tag
    }

    pub fn contains(&self, tag: QuicTag) -> bool {
        self.values.contains_key(&tag)
    }

    pub fn get_bytes(&self, tag: QuicTag) -> Option<&[u8]> {
        self.values.get(&tag).cloned()
    }

    pub fn get_str(&self, tag: QuicTag) -> Option<&str> {
        self.values
            .get(&tag)
            .map(|s| unsafe { str::from_utf8_unchecked(s) })
    }

    pub fn get_u32(&self, tag: QuicTag) -> Result<u32, Error> {
        self.get_pod(tag, LittleEndian::read_u32)
    }

    pub fn get_u64(&self, tag: QuicTag) -> Result<u64, Error> {
        self.get_pod(tag, LittleEndian::read_u64)
    }

    fn get_pod<T, F>(&self, tag: QuicTag, read: F) -> Result<T, Error>
    where
        F: FnOnce(&[u8]) -> T,
    {
        if let Some(value) = self.values.get(&tag) {
            if value.len() == mem::size_of::<T>() {
                Ok(read(value))
            } else {
                bail!(QuicError::InvalidParam(tag))
            }
        } else {
            bail!(QuicError::ParamNotFound(tag))
        }
    }
}

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    parse_crypto_handshake_message<(QuicTag, Vec<(QuicTag, usize)>)>,
    do_parse!(
        tag: quic_tag >>
        num_entries: verify!(map!(le_u16, |n| n as usize), |n| n < kMaxEntries) >>
        padding: take!(2) >>
        entries: many_m_n!(num_entries, num_entries, tuple!(quic_tag, map!(le_u32, |n| n as usize))) >>
        (
            tag, entries
        )
    )
);

#[cfg(test)]
mod tests {
    use std::iter::FromIterator;

    use super::*;

    #[test]
    fn parse_message() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        let input = &[
            // tag
            0x33, 0x77, 0xAA, 0xFF,
            // num entries
            0x02, 0x00,
            // padding
            0x00, 0x00,
            // tag 1
            0x78, 0x56, 0x34, 0x12,
            // end offset 1
            0x06, 0x00, 0x00, 0x00,
            // tag 2
            0x79, 0x56, 0x34, 0x12,
            // end offset 2
            0x0b, 0x00, 0x00, 0x00,
            // value 1
            b'a', b'b', b'c', b'd', b'e', b'f',
            // value 2
            b'g', b'h', b'i', b'j', b'k',
        ];

        assert_eq!(
            CryptoHandshakeMessage::parse(input).unwrap(),
            (
                &b""[..],
                CryptoHandshakeMessage {
                    tag: QuicTag(0xFFAA7733),
                    values: HashMap::from_iter(vec![
                        (QuicTag(0x12345678), &b"abcdef"[..]),
                        (QuicTag(0x12345679), &b"ghijk"[..]),
                    ]),
                }
            )
        );
    }
}
