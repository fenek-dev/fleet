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

/// Deepest nesting of tagged values (e.g. `Payload::ChangePending` holding
/// a `Payload`, `SignedEvents` holding `Event`s). Decoding recurses, so
/// without a bound a hostile frame of nested values could exhaust the
/// stack.
const MAX_NESTING: u8 = 8;

thread_local! {
    static DEPTH: core::cell::Cell<u8> = const { core::cell::Cell::new(0) };
}

/// One level of tagged nesting, released on drop.
struct Nesting;

impl Nesting {
    fn enter() -> Option<Nesting> {
        DEPTH.with(|d| {
            (d.get() < MAX_NESTING).then(|| {
                d.set(d.get() + 1);
                Nesting
            })
        })
    }
}

impl Drop for Nesting {
    fn drop(&mut self) {
        DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

pub(crate) fn deserialize<'de, T: Tagged, D: Deserializer<'de>>(d: D) -> Result<T, D::Error> {
    let _level =
        Nesting::enter().ok_or_else(|| D::Error::custom("tagged values nested too deep"))?;
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

/// Declares a tagged wire enum (`Op`, `Payload`, `Event`) from a catalog.
///
/// Each variant is unit, `Name(binding: Type)` or `Name { field: Type, .. }`,
/// followed by `= CONST(tag, "name")`. Generates the tag module (`CONST`s,
/// `ALL`, `NAMES`), the enum plus an `Unknown { tag }` variant, `tag()`,
/// `name()`, `is_known_tag()`, `payload()` and the [`Tagged`] impl. The
/// payload is the postcard tuple of the variant's fields in order, so a
/// one-field variant encodes exactly like its field.
macro_rules! tagged_enum {
    (
        $(#[$em:meta])*
        pub enum $E:ident, tags = $tagmod:ident, expecting = $exp:literal {
            $(
                $(#[$m:meta])*
                $V:ident
                $( ( $tv:ident : $T:ty ) )?
                $( { $( $(#[$fm:meta])* $f:ident : $ft:ty ),* $(,)? } )?
                = $TAG:ident ( $num:literal, $name:literal )
            ),* $(,)?
        }
    ) => {
        /// Wire tags. Explicit constants; never reorder or reuse.
        pub mod $tagmod {
            $( pub const $TAG: u16 = $num; )*
            /// Every known tag, in catalog order.
            pub const ALL: &[u16] = &[$($num),*];
            /// Name of every known variant, in the same order as [`ALL`].
            pub const NAMES: &[&str] = &[$($name),*];
        }

        $(#[$em])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum $E {
            $(
                $(#[$m])*
                $V $( ($T) )? $( { $( $(#[$fm])* $f : $ft ),* } )?,
            )*
            /// A tag this build doesn't know. Never acted on; serializes with
            /// an empty payload.
            Unknown { tag: u16 },
        }

        impl $E {
            pub fn tag(&self) -> u16 {
                match self {
                    $( $E::$V { .. } => $tagmod::$TAG, )*
                    $E::Unknown { tag } => *tag,
                }
            }

            /// Catalog name (`"unknown"` for [`Self::Unknown`]).
            pub fn name(&self) -> &'static str {
                match self {
                    $( $E::$V { .. } => $name, )*
                    $E::Unknown { .. } => "unknown",
                }
            }

            /// Whether this build has a variant for `tag`.
            pub fn is_known_tag(tag: u16) -> bool {
                $tagmod::ALL.contains(&tag)
            }

            /// Postcard encoding of the variant's fields.
            pub(crate) fn payload(&self) -> Vec<u8> {
                match self {
                    $(
                        $E::$V $( ($tv) )? $( { $($f),* } )? =>
                            $crate::encode(&( $($tv,)? $($($f,)*)? )),
                    )*
                    $E::Unknown { .. } => Vec::new(),
                }
            }
        }

        impl $crate::tagged::Tagged for $E {
            const EXPECTING: &'static str = $exp;

            fn wire_tag(&self) -> u16 {
                self.tag()
            }

            fn wire_payload(&self) -> Vec<u8> {
                self.payload()
            }

            #[allow(clippy::let_unit_value)]
            fn from_wire(tag: u16, payload: &[u8]) -> Result<Self, $crate::DecodeError> {
                Ok(match tag {
                    $(
                        $tagmod::$TAG => {
                            let ( $($tv,)? $($($f,)*)? ): ( $($T,)? $($($ft,)*)? ) =
                                $crate::decode(payload)?;
                            $E::$V $( ($tv) )? $( { $($f),* } )?
                        }
                    )*
                    tag => $E::Unknown { tag },
                })
            }
        }

        $crate::tagged::tagged_serde!($E);
    };
}
pub(crate) use tagged_enum;
