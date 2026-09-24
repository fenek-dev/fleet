//! Fleet wire protocol types shared by the agent and the Mac core.
//!
//! Wire types live in versioned modules (`v1`, later `v2`, ...) because postcard
//! is positional: a struct never changes within a protocol version (design §6.2).
//! The current version is re-exported at the crate root.
#![forbid(unsafe_code)]

pub mod chunk;
pub mod codec;
pub mod domain;
mod fixed;
mod tagged;
pub mod v1;

pub use codec::{DecodeError, MAX_FRAME, decode, encode};
pub use v1::*;

/// Protocol version implemented by the `v1` module.
pub const PROTO_VERSION: u16 = 1;
