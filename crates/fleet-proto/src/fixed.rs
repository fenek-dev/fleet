//! Serde for `[u8; N]` of any N as a fixed tuple (no length prefix in postcard).
//! serde's built-in array impls stop at 32; this matches their wire format.

use core::fmt;
use serde::de::{Error, SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserializer, Serializer};

pub fn serialize<S: Serializer, const N: usize>(bytes: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
    let mut t = s.serialize_tuple(N)?;
    for b in bytes {
        t.serialize_element(b)?;
    }
    t.end()
}

pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<[u8; N], D::Error> {
    struct V<const N: usize>;
    impl<'de, const N: usize> Visitor<'de> for V<N> {
        type Value = [u8; N];
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{N} bytes")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<[u8; N], A::Error> {
            let mut out = [0u8; N];
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::invalid_length(i, &self))?;
            }
            Ok(out)
        }
    }
    d.deserialize_tuple(N, V::<N>)
}
