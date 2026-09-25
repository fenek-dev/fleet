//! AES-GCM with a random 96-bit nonce (sync records, design §7.6) and the
//! fixed-nonce form HPKE needs (RFC 9180 single-shot, sequence 0).
//!
//! Random nonces: a sync key encrypts at most a few hundred thousand records
//! over its life (it is rotated on every revocation), far below the 2^32
//! messages NIST SP 800-38D allows per key with random 96-bit nonces.

use crate::{Error, random_bytes};
use aes_gcm::aead::{Aead as _, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// Encrypts with `key` under `nonce`. `key` is 16 (AES-128) or 32 (AES-256)
/// bytes.
pub fn seal_with_nonce(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    pt: &[u8],
) -> Result<Vec<u8>, Error> {
    let n = Nonce::from(*nonce);
    let payload = Payload { msg: pt, aad };
    match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .map_err(|_| Error::BadKey)?
            .encrypt(&n, payload),
        32 => Aes256Gcm::new_from_slice(key)
            .map_err(|_| Error::BadKey)?
            .encrypt(&n, payload),
        _ => return Err(Error::BadKey),
    }
    .map_err(|_| Error::TooLarge(pt.len()))
}

pub fn open_with_nonce(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, Error> {
    let n = Nonce::from(*nonce);
    let payload = Payload { msg: ct, aad };
    match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .map_err(|_| Error::BadKey)?
            .decrypt(&n, payload),
        32 => Aes256Gcm::new_from_slice(key)
            .map_err(|_| Error::BadKey)?
            .decrypt(&n, payload),
        _ => return Err(Error::BadKey),
    }
    .map_err(|_| Error::Decrypt)
}

/// AES-256-GCM with a fresh random nonce: `nonce ‖ ciphertext ‖ tag`.
pub fn seal(key: &[u8; 32], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, Error> {
    let mut nonce = [0u8; NONCE_LEN];
    random_bytes(&mut nonce)?;
    let ct = seal_with_nonce(key, &nonce, aad, pt)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Opens [`seal`]'s output.
pub fn open(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, Error> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Decrypt);
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::Decrypt)?;
    open_with_nonce(key, &nonce, aad, ct)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper() {
        let key = [7u8; 32];
        let s = seal(&key, b"name", b"hello").unwrap();
        assert_eq!(open(&key, b"name", &s).unwrap(), b"hello");
        assert!(open(&key, b"other", &s).is_err(), "aad is bound");
        assert!(open(&[8u8; 32], b"name", &s).is_err());
        let mut bad = s.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(open(&key, b"name", &bad).is_err());
        assert!(open(&key, b"name", &s[..20]).is_err());
        assert_ne!(seal(&key, b"name", b"hello").unwrap(), s, "fresh nonce");
    }
}
