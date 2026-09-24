//! Strict postcard framing helpers.

use serde::{Serialize, de::DeserializeOwned};

/// Largest application frame (design §6.1). Bigger payloads use streams.
pub const MAX_FRAME: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("frame of {0} bytes exceeds MAX_FRAME")]
    TooLarge(usize),
    #[error("{0} trailing bytes after value")]
    TrailingBytes(usize),
    #[error("malformed encoding: {0}")]
    Malformed(postcard::Error),
}

/// Encodes a value with postcard.
///
/// Serialization of fleet-proto types cannot fail (no unsized sequences, no
/// maps), so this panics only on a bug in a type's `Serialize` impl.
pub fn encode<T: Serialize + ?Sized>(value: &T) -> Vec<u8> {
    postcard::to_allocvec(value).expect("fleet-proto types always serialize")
}

/// Decodes exactly one value. Rejects oversize input and trailing bytes.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DecodeError> {
    if bytes.len() > MAX_FRAME {
        return Err(DecodeError::TooLarge(bytes.len()));
    }
    let (value, rest) = postcard::take_from_bytes(bytes).map_err(DecodeError::Malformed)?;
    if !rest.is_empty() {
        return Err(DecodeError::TrailingBytes(rest.len()));
    }
    Ok(value)
}
