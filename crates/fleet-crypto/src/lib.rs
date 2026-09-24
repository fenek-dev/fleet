//! Noise sessions, envelope signing/verification and recovery key derivation.
//!
//! Everything here is pure: no I/O, no clocks (callers pass `now_ms`), no
//! storage (replay state goes through [`verify::ReplayStore`]).
#![forbid(unsafe_code)]

pub mod approval;
mod error;
pub mod merkle;
pub mod noise;
pub mod receipt;
pub mod recovery;
pub mod roster;
pub mod sig;
pub mod verify;

pub use error::Error;
/// Re-exported so callers can hold key material for this crate's APIs
/// (e.g. `noise::StaticKeypair::from_bytes`) without their own dependency.
pub use zeroize::Zeroizing;

/// BLAKE3 of `bytes`.
pub fn blake3(bytes: &[u8]) -> fleet_proto::Hash32 {
    *::blake3::hash(bytes).as_bytes()
}

/// Fills `buf` from the OS CSPRNG.
pub fn random_bytes(buf: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(buf).map_err(|_| Error::Rng)
}

#[cfg(test)]
pub(crate) mod testutil;
