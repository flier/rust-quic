use std::fmt;
use std::iter;
use std::mem;
use std::slice;
use std::str;
use std::str::FromStr;

use byteorder::{ByteOrder, LittleEndian};
use failure::Error;
use nom::le_u32;

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Hash)]
pub struct QuicTag(pub u32);

impl QuicTag {
    pub fn new(s: &[u8]) -> Self {
        let bytes = s.iter()
            .cloned()
            .chain(iter::repeat(0))
            .take(4)
            .collect::<Vec<u8>>();

        QuicTag(LittleEndian::read_u32(&bytes))
    }

    pub fn size() -> usize {
        mem::size_of::<u32>()
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(&self.0 as *const u32 as *const u8, 4) }
    }

    pub fn as_str(&self) -> &str {
        unsafe { str::from_utf8_unchecked(self.as_bytes()) }.trim_matches(|b| b == '\0')
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
        Ok(QuicTag::new(s.as_bytes()))
    }
}

impl fmt::Display for QuicTag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl fmt::Debug for QuicTag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "QuicTag({})", self.as_str())
    }
}

#[macro_export]
macro_rules! quic_tag {
    ($s:expr) => {
        $crate::types::QuicTag(
            (($s[3] as u32) << 24) +
            (($s[2] as u32) << 16) +
            (($s[1] as u32) << 8) +
             ($s[0] as u32))
    };
}

named!(pub quic_tag<QuicTag>, map!(le_u32, QuicTag));

#[cfg(test)]
mod tests {
    use nom::IResult;

    use super::*;

    #[test]
    fn tag() {
        let exmp = QuicTag(0x504d5845);

        assert_eq!(exmp, quic_tag!(b"EXMP"));
        assert_eq!(exmp.as_bytes(), b"EXMP");
        assert_eq!(exmp.as_str(), "EXMP");

        assert_eq!(quic_tag(b"EXMP"), IResult::Done(&b""[..], exmp));

        assert_eq!(u32::from(exmp), 0x504d5845);
        assert_eq!(exmp, 0x504d5845.into());

        assert_eq!("EXMP".parse::<QuicTag>().unwrap(), exmp);

        let exp = QuicTag(0x505845);

        assert_eq!(exp, QuicTag::new(b"EXP\0"));
        assert_eq!(exp.as_bytes(), b"EXP\0");
        assert_eq!(exp.as_str(), "EXP");
    }
}
