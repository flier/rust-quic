use std::mem;
use std::slice;
use std::str::FromStr;

use byteorder::{ByteOrder, LittleEndian};
use failure::Error;
use nom::le_u32;

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct QuicTag(u32);

impl QuicTag {
    pub fn new(s: &[u8]) -> Self {
        QuicTag(LittleEndian::read_u32(s))
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(mem::transmute(&self.0), 4) }
    }
}

impl From<u32> for QuicTag {
    fn from(n: u32) -> Self {
        QuicTag(n)
    }
}

impl From<QuicTag> for u32 {
    fn from(tag: QuicTag) -> u32 {
        tag.0
    }
}

impl FromStr for QuicTag {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() < 4 {
            bail!("incomplete tag, {}", s)
        }

        Ok(QuicTag(LittleEndian::read_u32(s.as_bytes())))
    }
}

named!(pub quic_tag<QuicTag>, map!(le_u32, QuicTag));

#[cfg(test)]
mod tests {
    use nom::IResult;

    use super::*;

    #[test]
    fn test_quic_tag() {
        let exmp = QuicTag(0x504d5845);

        assert_eq!(quic_tag(b"EXMP"), IResult::Done(&b""[..], exmp));

        assert_eq!(exmp, QuicTag::new(b"EXMP"));
        assert_eq!(exmp.as_bytes(), b"EXMP");

        assert_eq!(u32::from(exmp), 0x504d5845);
        assert_eq!(exmp, 0x504d5845.into());

        assert_eq!("EXMP".parse::<QuicTag>().unwrap(), exmp);
    }
}
