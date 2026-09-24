//! Public keys and signatures as fixed-size byte newtypes.
//!
//! Only the encoding is checked here; point validation is fleet-crypto's job.

use core::fmt;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

/// P-256 public key, SEC1 **compressed** (33 bytes, prefix 0x02 or 0x03).
/// Compressed matches CryptoKit's `compressedRepresentation` and halves roster size.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct P256Public(pub [u8; 33]);

impl P256Public {
    pub fn new(bytes: [u8; 33]) -> Option<Self> {
        matches!(bytes[0], 0x02 | 0x03).then_some(Self(bytes))
    }
}

impl Serialize for P256Public {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        crate::fixed::serialize(&self.0, s)
    }
}

impl<'de> Deserialize<'de> for P256Public {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes: [u8; 33] = crate::fixed::deserialize(d)?;
        Self::new(bytes).ok_or_else(|| D::Error::custom("P-256 key is not SEC1 compressed"))
    }
}

/// Ed25519 public key (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ed25519Public(pub [u8; 32]);

/// X25519 public key (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct X25519Public(pub [u8; 32]);

/// 64-byte signature: raw `r ‖ s` (low-S) for P-256, `R ‖ S` for Ed25519.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature(pub [u8; 64]);

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        crate::fixed::serialize(&self.0, s)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        crate::fixed::deserialize(d).map(Self)
    }
}

macro_rules! hex_debug {
    ($($t:ident),*) => {$(
        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, concat!(stringify!($t), "({})"), hex::encode(self.0))
            }
        }
    )*};
}
hex_debug!(P256Public, Ed25519Public, X25519Public, Signature);

/// Which of a device's keys signed (design §5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyKind {
    Device,
    Monitor,
    Recovery,
}
