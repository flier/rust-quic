#![allow(dead_code, non_upper_case_globals)]
use std::hash::{BuildHasherDefault, Hasher};

use extprim::u128::u128;

pub const kPrime: u128 = u128!(309485009821345068724781371);
pub const kOffset: u128 = u128!(144066263297769815596495629667062367629);

fn fnv0<T>(data: T) -> u128
where
    T: AsRef<[u8]>,
{
    fnv1(u128::zero(), data)
}

fn fnv1<T>(uhash: u128, data: T) -> u128
where
    T: AsRef<[u8]>,
{
    data.as_ref().iter().fold(uhash, |hash, &b| {
        hash.wrapping_mul(kPrime) ^ u128::new(u64::from(b))
    })
}

pub fn fnv1a<T>(uhash: u128, data: T) -> u128
where
    T: AsRef<[u8]>,
{
    data.as_ref().iter().fold(uhash, |hash, &b| {
        (hash ^ u128::new(u64::from(b))).wrapping_mul(kPrime)
    })
}

pub struct FnvHasher(u128);

impl Default for FnvHasher {
    #[inline]
    fn default() -> FnvHasher {
        FnvHasher(kOffset)
    }
}

impl FnvHasher {
    /// Create an FNV hasher starting with a state corresponding to the hash `key`.
    #[inline]
    pub fn with_key(key: u128) -> FnvHasher {
        FnvHasher(key)
    }

    #[inline]
    pub fn hash(&self) -> u128 {
        self.0
    }
}

impl Hasher for FnvHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0.low64()
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        self.0 = fnv1a(self.0, bytes)
    }
}

/// A builder for default FNV hashers.
pub type FnvBuildHasher = BuildHasherDefault<FnvHasher>;

#[cfg(test)]
mod tests {
    use std::hash::Hash;

    use super::*;

    #[test]
    fn fnv0_hash() {
        assert_eq!(fnv0(b"chongo <Landon Curt Noll> /\\../\\"), kOffset);
    }

    #[test]
    fn fnv1_hash() {
        assert_eq!(
            fnv1(
                kOffset,
                &[
                    0x20, 0x28, 0x4e, 0x43, 0x40, 0x55, 0x6f, 0x99, 0x25, 0x1b, 0x89, 0xf4, 0xa8, 0x18, 0xec, 0x76,
                    0xc0,
                ][..]
            ),
            u128!(0)
        );
    }

    #[test]
    fn fnv1a_hash() {
        assert_eq!(
            fnv1a(kOffset, b""),
            u128!(0x6c62272e07bb014262b821756295c58d)
        );
        assert_eq!(
            fnv1a(kOffset, b"a"),
            u128!(0xd228cb696f1a8caf78912b704e4a8964)
        );
        assert_eq!(
            fnv1a(kOffset, b"foobar"),
            u128!(0x343e1662793c64bf6f0d3597ba446f18)
        );
    }

    #[test]
    fn fnv_hasher() {
        let mut hasher = FnvHasher::default();

        (b"hello").hash(&mut hasher);

        assert_eq!(hasher.hash(), u128!(0x2e5b502d462502fc5e5dcb2c452ccbb8));
        assert_eq!(
            fnv1a(kOffset, b"\x05\0\0\0\0\0\0\0hello"),
            u128!(0x2e5b502d462502fc5e5dcb2c452ccbb8)
        );
    }
}
