//! Extensible tagged enum encoding shared by `Op`, `Payload` and `Event`
//! (design §6.2).
//!
//! On the wire a value is the postcard tuple `(tag: u16 varint, payload: bytes)`,
//! where `payload` is the postcard encoding of the variant's fields. A receiver
//! that does not know `tag` skips the payload and yields the type's `Unknown`
//! variant, so the enclosing frame still decodes.

use crate::DecodeError;
use core::fmt;
use serde::de::{self, Error as _, SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Implemented by every tagged wire enum.
pub(crate) trait Tagged: Sized {
    const EXPECTING: &'static str;
    fn wire_tag(&self) -> u16;
    /// Postcard encoding of the variant's fields (empty for unit variants and
    /// `Unknown`).
    fn wire_payload(&self) -> Vec<u8>;
    /// Unknown tags must map to the `Unknown` variant, never to an error.
    fn from_wire(tag: u16, payload: &[u8]) -> Result<Self, DecodeError>;
}

/// `value` if `payload` is empty (unit variants).
pub(crate) fn unit<T>(value: T, payload: &[u8]) -> Result<T, DecodeError> {
    if payload.is_empty() {
        Ok(value)
    } else {
        Err(DecodeError::TrailingBytes(payload.len()))
    }
}

pub(crate) struct Bytes<'a>(pub &'a [u8]);

impl Serialize for Bytes<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(self.0)
    }
}

struct ByteBuf(Vec<u8>);

impl<'de> Deserialize<'de> for ByteBuf {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = ByteBuf;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("variant payload bytes")
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<ByteBuf, E> {
                Ok(ByteBuf(v.to_vec()))
            }
            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<ByteBuf, E> {
                Ok(ByteBuf(v))
            }
        }
        d.deserialize_bytes(V)
    }
}

pub(crate) fn serialize<T: Tagged, S: Serializer>(value: &T, s: S) -> Result<S::Ok, S::Error> {
    let payload = value.wire_payload();
    let mut t = s.serialize_tuple(2)?;
    t.serialize_element(&value.wire_tag())?;
    t.serialize_element(&Bytes(&payload))?;
    t.end()
}

pub(crate) fn deserialize<'de, T: Tagged, D: Deserializer<'de>>(d: D) -> Result<T, D::Error> {
    struct V<T>(core::marker::PhantomData<T>);
    impl<'de, T: Tagged> Visitor<'de> for V<T> {
        type Value = T;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str(T::EXPECTING)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<T, A::Error> {
            let tag: u16 = seq
                .next_element()?
                .ok_or_else(|| A::Error::invalid_length(0, &self))?;
            let payload: ByteBuf = seq
                .next_element()?
                .ok_or_else(|| A::Error::invalid_length(1, &self))?;
            T::from_wire(tag, &payload.0).map_err(A::Error::custom)
        }
    }
    d.deserialize_tuple(2, V::<T>(core::marker::PhantomData))
}

/// Implements `Serialize`/`Deserialize` through [`Tagged`].
macro_rules! tagged_serde {
    ($t:ty) => {
        impl serde::Serialize for $t {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                $crate::tagged::serialize(self, s)
            }
        }
        impl<'de> serde::Deserialize<'de> for $t {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                $crate::tagged::deserialize(d)
            }
        }
    };
}
pub(crate) use tagged_serde;
