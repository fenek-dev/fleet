//! Signatures: P-256 ECDSA (SHA-256, raw `r ‖ s`, low-S only) and Ed25519
//! (`verify_strict`). Design §6.2 and §6.4 "Signature encoding".

use crate::{Error, random_bytes};
use ed25519_dalek::Signer as _;
use fleet_proto::{Ed25519Public, P256Public, Signature};
use p256::ecdsa::signature::Verifier as _;
use zeroize::Zeroizing;

/// Length of every signature on the wire.
pub const SIG_LEN: usize = 64;

/// A P-256 signing key. On the Mac the Secure Enclave implements this through
/// a UniFFI callback into Swift; private keys never enter Rust (rule 7).
///
/// Implementations may return a high-S signature (CryptoKit does not
/// normalize); every caller in this crate normalizes with [`p256_normalize`].
pub trait Signer {
    fn public(&self) -> P256Public;
    fn sign(&self, msg: &[u8]) -> Result<Signature, Error>;
}

/// Signs with `signer` and returns the low-S form.
pub fn p256_sign(signer: &(impl Signer + ?Sized), msg: &[u8]) -> Result<Signature, Error> {
    p256_normalize(&signer.sign(msg)?)
}

/// Converts a raw `r ‖ s` signature to low-S form. Rejects zero scalars.
pub fn p256_normalize(sig: &Signature) -> Result<Signature, Error> {
    let parsed = p256::ecdsa::Signature::from_slice(&sig.0).map_err(|_| Error::BadSignature)?;
    Ok(to_raw(&parsed.normalize_s()))
}

fn to_raw(sig: &p256::ecdsa::Signature) -> Signature {
    let mut out = [0u8; SIG_LEN];
    out.copy_from_slice(&sig.to_bytes());
    Signature(out)
}

/// Parses and validates a compressed SEC1 P-256 point.
pub fn p256_key(key: &P256Public) -> Result<p256::ecdsa::VerifyingKey, Error> {
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.0).map_err(|_| Error::BadKey)
}

/// Uncompressed SEC1 encoding (`0x04 ‖ x ‖ y`), as OpenSSH's
/// `ecdsa-sha2-nistp256` key blob needs.
pub fn p256_uncompressed(key: &P256Public) -> Result<[u8; 65], Error> {
    let point = p256_key(key)?.to_sec1_point(false);
    point.as_bytes().try_into().map_err(|_| Error::BadKey)
}

/// Verifies a P-256 signature over `msg` (hashed with SHA-256).
/// Rejects high-S signatures: `(r, n−s)` must not verify as a second copy.
pub fn p256_verify(key: &P256Public, msg: &[u8], sig: &Signature) -> Result<(), Error> {
    let vk = p256_key(key)?;
    let parsed = p256::ecdsa::Signature::from_slice(&sig.0).map_err(|_| Error::BadSignature)?;
    if to_raw(&parsed.normalize_s()) != *sig {
        return Err(Error::BadSignature);
    }
    vk.verify(msg, &parsed).map_err(|_| Error::BadSignature)
}

/// Like [`p256_verify`] for an untyped buffer; anything but 64 bytes fails.
pub fn p256_verify_slice(key: &P256Public, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    let sig: [u8; SIG_LEN] = sig.try_into().map_err(|_| Error::BadSignature)?;
    p256_verify(key, msg, &Signature(sig))
}

/// Strict Ed25519 verification (rejects small-order points and non-canonical S).
pub fn ed25519_verify(key: &Ed25519Public, msg: &[u8], sig: &Signature) -> Result<(), Error> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&key.0).map_err(|_| Error::BadKey)?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig.0);
    vk.verify_strict(msg, &sig).map_err(|_| Error::BadSignature)
}

/// Software P-256 key for tests, development and `fleetctl` without an enclave.
/// The secret scalar is zeroized on drop (by `p256`).
pub struct SoftwareP256Signer {
    key: p256::ecdsa::SigningKey,
}

impl SoftwareP256Signer {
    pub fn generate() -> Result<Self, Error> {
        loop {
            let mut bytes = Zeroizing::new([0u8; 32]);
            random_bytes(bytes.as_mut())?;
            // Fails only for 0 or ≥ n (probability ~2^-32).
            if let Ok(s) = Self::from_bytes(&bytes) {
                return Ok(s);
            }
        }
    }

    /// From a big-endian scalar in `[1, n)`.
    pub fn from_bytes(secret: &[u8; 32]) -> Result<Self, Error> {
        let key = p256::ecdsa::SigningKey::from_slice(secret).map_err(|_| Error::BadKey)?;
        Ok(Self { key })
    }
}

impl Signer for SoftwareP256Signer {
    fn public(&self) -> P256Public {
        let point = self.key.verifying_key().to_sec1_point(true);
        let bytes: [u8; 33] = point
            .as_bytes()
            .try_into()
            .expect("compressed point is 33 bytes");
        P256Public(bytes)
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        let sig: p256::ecdsa::Signature = self.key.try_sign(msg).map_err(|_| Error::Signer)?;
        Ok(to_raw(&sig.normalize_s()))
    }
}

/// Ed25519 key: agent signing key, recovery keys. Zeroized on drop.
pub struct Ed25519Signer {
    key: ed25519_dalek::SigningKey,
}

impl Ed25519Signer {
    pub fn generate() -> Result<Self, Error> {
        let mut seed = Zeroizing::new([0u8; 32]);
        random_bytes(seed.as_mut())?;
        Ok(Self::from_seed(&seed))
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: ed25519_dalek::SigningKey::from_bytes(seed),
        }
    }

    /// The 32-byte seed, for persisting the agent key (`0600 root`).
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.key.to_bytes())
    }

    pub fn public(&self) -> Ed25519Public {
        Ed25519Public(self.key.verifying_key().to_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.key.sign(msg).to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{malleate, p256_signer};

    #[test]
    fn p256_roundtrip_and_low_s() {
        let s = p256_signer(1);
        let sig = s.sign(b"hello").unwrap();
        p256_verify(&s.public(), b"hello", &sig).unwrap();
        assert!(p256_verify(&s.public(), b"hellO", &sig).is_err());
        let high = malleate(&sig);
        assert_ne!(high, sig);
        // The high-S twin is mathematically valid but must be rejected...
        assert!(p256_verify(&s.public(), b"hello", &high).is_err());
        // ...and normalizing it yields the original.
        assert_eq!(p256_normalize(&high).unwrap(), sig);
    }

    #[test]
    fn p256_rejects_tampered_and_wrong_length() {
        let s = p256_signer(2);
        let sig = s.sign(b"m").unwrap();
        let mut bad = sig;
        bad.0[5] ^= 1;
        assert!(p256_verify(&s.public(), b"m", &bad).is_err());
        assert!(p256_verify_slice(&s.public(), b"m", &sig.0[..63]).is_err());
        let mut long = sig.0.to_vec();
        long.push(0);
        assert!(p256_verify_slice(&s.public(), b"m", &long).is_err());
        assert!(p256_verify_slice(&s.public(), b"m", &sig.0).is_ok());
        assert!(p256_verify(&s.public(), b"m", &Signature([0; 64])).is_err());
    }

    #[test]
    fn p256_rejects_invalid_key() {
        let mut key = [0xffu8; 33];
        key[0] = 0x02; // x ≥ p is not a field element
        let sig = p256_signer(3).sign(b"m").unwrap();
        assert!(matches!(
            p256_verify(&P256Public(key), b"m", &sig),
            Err(Error::BadKey)
        ));
    }

    #[test]
    fn ed25519_roundtrip() {
        let k = Ed25519Signer::from_seed(&[7; 32]);
        let sig = k.sign(b"x");
        ed25519_verify(&k.public(), b"x", &sig).unwrap();
        let mut bad = sig;
        bad.0[0] ^= 1;
        assert!(ed25519_verify(&k.public(), b"x", &bad).is_err());
        assert_eq!(Ed25519Signer::from_seed(&k.seed()).public(), k.public());
    }
}
