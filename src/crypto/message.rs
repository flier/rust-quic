#![allow(non_upper_case_globals)]

use failure::{Error, Fail};
use nom::{IResult, Needed, le_u16, le_u32};

use errors::QuicError;
use tag::{quic_tag, QuicTag};

/// Max number of entries in a message.
const kMaxEntries: usize = 128;

/// An intermediate format of a handshake message
/// that's convenient for a CryptoFramer to serialize from or parse into.
#[derive(Clone, Debug, PartialEq)]
pub struct CryptoHandshakeMessage<'a> {
    pub tag: QuicTag,
    pub values: Vec<(QuicTag, &'a [u8])>,
}

impl<'a> CryptoHandshakeMessage<'a> {
    pub fn parse(input: &'a [u8]) -> Result<(&'a [u8], CryptoHandshakeMessage<'a>), Error> {
        match parse_crypto_handshake_message(input) {
            IResult::Done(remaining, (tag, entries)) => {
                let mut values = vec![];
                let mut last_tag = None;
                let mut last_offset = 0;

                for (tag, offset) in entries {
                    match last_tag {
                        Some(last_tag) if tag == last_tag => {
                            bail!("duplicate tag: {}", tag);
                        }
                        Some(last_tag) if tag < last_tag => {
                            bail!("tag {} out of order", tag);
                        }
                        _ => {}
                    }

                    if offset < last_offset {
                        bail!("offset {} out of order", offset);
                    }

                    let size = offset - last_offset;

                    if size > remaining.len() {
                        bail!(
                            QuicError::IncompletePacket(Needed::Size(offset))
                                .context("incomplete crypto handshake message payload.")
                        );
                    }

                    values.push((tag, &remaining[last_offset..offset]));

                    last_tag = Some(tag);
                    last_offset = offset;
                }

                Ok((
                    &remaining[last_offset..],
                    CryptoHandshakeMessage { tag, values },
                ))
            }
            IResult::Incomplete(needed) => {
                bail!(QuicError::IncompletePacket(needed).context("incomplete crypto handshake message."))
            }
            IResult::Error(err) => bail!(QuicError::InvalidPacket(err).context("unable to crypto handshake message.")),
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
            (tag, entries)
        )
    )
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
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
                    values: vec![
                        (QuicTag(0x12345678), b"abcdef"),
                        (QuicTag(0x12345679), b"ghijk"),
                    ],
                }
            )
        );
    }
}
