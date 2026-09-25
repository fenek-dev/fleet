//! HPKE (RFC 9180), base mode, single-shot: sealing the sync key to a Mac's
//! Secure Enclave key-agreement key (DHKEM(P-256), design §5.12) and to the
//! recovery escrow key (DHKEM(X25519), design §5.11).
//!
//! Suites: KEM `0x0010` DHKEM(P-256, HKDF-SHA256) or `0x0020`
//! DHKEM(X25519, HKDF-SHA256); KDF `0x0001` HKDF-SHA256; AEAD `0x0002`
//! AES-256-GCM (Fleet's choice) or `0x0001` AES-128-GCM (kept for the RFC
//! test vectors). Only sequence number 0 is used (one message per context).
//!
//! The P-256 recipient's private key lives in the Secure Enclave, so opening
//! goes through [`P256Recipient`]: Swift computes the ECDH shared x-coordinate
//! (`sharedSecretFromKeyAgreement`) and only that crosses. CryptoKit's own
//! HPKE isn't used because the Rust core owns the formats and tests.

use crate::aead;
use crate::{Error, random_bytes};
use fleet_proto::X25519Public;
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::ToSec1Point as _;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const KEM_P256: u16 = 0x0010;
pub const KEM_X25519: u16 = 0x0020;
pub const KDF_HKDF_SHA256: u16 = 0x0001;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadId {
    Aes128Gcm = 0x0001,
    Aes256Gcm = 0x0002,
}

impl AeadId {
    fn key_len(self) -> usize {
        match self {
            AeadId::Aes128Gcm => 16,
            AeadId::Aes256Gcm => 32,
        }
    }
}

/// `enc ‖ ct` of one sealed message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    pub enc: Vec<u8>,
    pub ct: Vec<u8>,
}

/// A P-256 key-agreement private key held elsewhere (Secure Enclave).
pub trait P256Recipient {
    /// Uncompressed SEC1 public key (`0x04 ‖ x ‖ y`).
    fn public(&self) -> [u8; 65];
    /// ECDH with `peer` (uncompressed SEC1): the shared x-coordinate.
    fn agree(&self, peer: &[u8; 65]) -> Result<Zeroizing<[u8; 32]>, Error>;
}

/// Software P-256 recipient (tests, and a Mac without a Secure Enclave in
/// DEBUG development builds).
pub struct SoftwareP256Recipient {
    secret: p256::SecretKey,
}

impl SoftwareP256Recipient {
    pub fn generate() -> Result<Self, Error> {
        loop {
            let mut b = Zeroizing::new([0u8; 32]);
            random_bytes(b.as_mut())?;
            if let Ok(s) = Self::from_bytes(&b) {
                return Ok(s);
            }
        }
    }

    pub fn from_bytes(secret: &[u8; 32]) -> Result<Self, Error> {
        let secret = p256::SecretKey::from_slice(secret).map_err(|_| Error::BadKey)?;
        Ok(Self { secret })
    }
}

impl P256Recipient for SoftwareP256Recipient {
    fn public(&self) -> [u8; 65] {
        let p = self.secret.public_key().to_sec1_point(false);
        p.as_bytes()
            .try_into()
            .expect("uncompressed point is 65 bytes")
    }

    fn agree(&self, peer: &[u8; 65]) -> Result<Zeroizing<[u8; 32]>, Error> {
        p256_dh(&self.secret, peer)
    }
}

fn p256_dh(secret: &p256::SecretKey, peer: &[u8; 65]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let pk = p256::PublicKey::from_sec1_bytes(peer).map_err(|_| Error::BadKey)?;
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), pk.as_affine());
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(shared.raw_secret_bytes());
    Ok(out)
}

/// Validates an uncompressed P-256 public key.
pub fn p256_check_public(pk: &[u8]) -> Result<[u8; 65], Error> {
    let arr: [u8; 65] = pk.try_into().map_err(|_| Error::BadKey)?;
    if arr[0] != 4 {
        return Err(Error::BadKey);
    }
    p256::PublicKey::from_sec1_bytes(&arr).map_err(|_| Error::BadKey)?;
    Ok(arr)
}

// ---- labeled KDF (RFC 9180 §4) ----

fn kem_suite(kem: u16) -> Vec<u8> {
    let mut s = b"KEM".to_vec();
    s.extend_from_slice(&kem.to_be_bytes());
    s
}

fn hpke_suite(kem: u16, aead: AeadId) -> Vec<u8> {
    let mut s = b"HPKE".to_vec();
    s.extend_from_slice(&kem.to_be_bytes());
    s.extend_from_slice(&KDF_HKDF_SHA256.to_be_bytes());
    s.extend_from_slice(&(aead as u16).to_be_bytes());
    s
}

fn labeled_extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut labeled = Zeroizing::new(Vec::with_capacity(
        7 + suite.len() + label.len() + ikm.len(),
    ));
    labeled.extend_from_slice(b"HPKE-v1");
    labeled.extend_from_slice(suite);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(ikm);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &labeled);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&prk);
    out
}

fn labeled_expand(
    suite: &[u8],
    prk: &[u8; 32],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| Error::Kdf)?;
    let l = u16::try_from(len).map_err(|_| Error::Kdf)?.to_be_bytes();
    let mut out = Zeroizing::new(vec![0u8; len]);
    hk.expand_multi_info(&[&l, b"HPKE-v1", suite, label, info], &mut out)
        .map_err(|_| Error::Kdf)?;
    Ok(out)
}

fn extract_and_expand(
    kem: u16,
    dh: &[u8],
    kem_context: &[u8],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let suite = kem_suite(kem);
    let prk = labeled_extract(&suite, b"", b"eae_prk", dh);
    let okm = labeled_expand(&suite, &prk, b"shared_secret", kem_context, 32)?;
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&okm);
    Ok(out)
}

/// Base-mode key schedule: `(key, base_nonce)`.
fn key_schedule(
    kem: u16,
    aead: AeadId,
    shared: &[u8; 32],
    info: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, [u8; 12]), Error> {
    let suite = hpke_suite(kem, aead);
    let psk_id_hash = labeled_extract(&suite, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(&suite, b"", b"info_hash", info);
    let mut ctx = vec![0u8]; // mode_base
    ctx.extend_from_slice(psk_id_hash.as_ref());
    ctx.extend_from_slice(info_hash.as_ref());
    let secret = labeled_extract(&suite, shared, b"secret", b"");
    let key = labeled_expand(&suite, &secret, b"key", &ctx, aead.key_len())?;
    let nonce = labeled_expand(&suite, &secret, b"base_nonce", &ctx, 12)?;
    let mut n = [0u8; 12];
    n.copy_from_slice(&nonce);
    Ok((key, n))
}

// ---- P-256 ----

fn seal_p256_with(
    eph: &p256::SecretKey,
    pk_r: &[u8; 65],
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
    aead_id: AeadId,
) -> Result<Sealed, Error> {
    let enc: [u8; 65] = eph
        .public_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .map_err(|_| Error::BadKey)?;
    let dh = p256_dh(eph, pk_r)?;
    let mut kem_ctx = enc.to_vec();
    kem_ctx.extend_from_slice(pk_r);
    let shared = extract_and_expand(KEM_P256, dh.as_ref(), &kem_ctx)?;
    let (key, nonce) = key_schedule(KEM_P256, aead_id, &shared, info)?;
    let ct = aead::seal_with_nonce(&key, &nonce, aad, pt)?;
    Ok(Sealed {
        enc: enc.to_vec(),
        ct,
    })
}

/// Seals `pt` to the P-256 key `pk_r` (uncompressed SEC1).
pub fn seal_p256(pk_r: &[u8], info: &[u8], aad: &[u8], pt: &[u8]) -> Result<Sealed, Error> {
    let pk_r = p256_check_public(pk_r)?;
    let eph = SoftwareP256Recipient::generate()?;
    seal_p256_with(&eph.secret, &pk_r, info, aad, pt, AeadId::Aes256Gcm)
}

pub fn open_p256(
    recipient: &dyn P256Recipient,
    sealed: &Sealed,
    info: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    open_p256_with(recipient, sealed, info, aad, AeadId::Aes256Gcm)
}

fn open_p256_with(
    recipient: &dyn P256Recipient,
    sealed: &Sealed,
    info: &[u8],
    aad: &[u8],
    aead_id: AeadId,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let enc = p256_check_public(&sealed.enc)?;
    let dh = recipient.agree(&enc)?;
    let mut kem_ctx = enc.to_vec();
    kem_ctx.extend_from_slice(&recipient.public());
    let shared = extract_and_expand(KEM_P256, dh.as_ref(), &kem_ctx)?;
    let (key, nonce) = key_schedule(KEM_P256, aead_id, &shared, info)?;
    aead::open_with_nonce(&key, &nonce, aad, &sealed.ct).map(Zeroizing::new)
}

// ---- X25519 ----

fn x25519_dh(
    secret: &x25519_dalek::StaticSecret,
    peer: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(*peer));
    let out = Zeroizing::new(shared.to_bytes());
    // RFC 9180 §7.1.4: reject the all-zero output (small-order peer).
    if out.iter().all(|b| *b == 0) {
        return Err(Error::BadKey);
    }
    Ok(out)
}

fn seal_x25519_with(
    eph: &x25519_dalek::StaticSecret,
    pk_r: &X25519Public,
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
    aead_id: AeadId,
) -> Result<Sealed, Error> {
    let enc = x25519_dalek::PublicKey::from(eph).to_bytes();
    let dh = x25519_dh(eph, &pk_r.0)?;
    let mut kem_ctx = enc.to_vec();
    kem_ctx.extend_from_slice(&pk_r.0);
    let shared = extract_and_expand(KEM_X25519, dh.as_ref(), &kem_ctx)?;
    let (key, nonce) = key_schedule(KEM_X25519, aead_id, &shared, info)?;
    let ct = aead::seal_with_nonce(&key, &nonce, aad, pt)?;
    Ok(Sealed {
        enc: enc.to_vec(),
        ct,
    })
}

/// Seals `pt` to an X25519 key (the recovery escrow key).
pub fn seal_x25519(
    pk_r: &X25519Public,
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<Sealed, Error> {
    let mut b = Zeroizing::new([0u8; 32]);
    random_bytes(b.as_mut())?;
    let eph = x25519_dalek::StaticSecret::from(*b);
    seal_x25519_with(&eph, pk_r, info, aad, pt, AeadId::Aes256Gcm)
}

/// Opens with the X25519 secret (`secret` zeroized by the caller).
pub fn open_x25519(
    secret: &Zeroizing<[u8; 32]>,
    sealed: &Sealed,
    info: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    open_x25519_with(secret, sealed, info, aad, AeadId::Aes256Gcm)
}

fn open_x25519_with(
    secret: &Zeroizing<[u8; 32]>,
    sealed: &Sealed,
    info: &[u8],
    aad: &[u8],
    aead_id: AeadId,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let enc: [u8; 32] = sealed
        .enc
        .as_slice()
        .try_into()
        .map_err(|_| Error::BadKey)?;
    let sk = x25519_dalek::StaticSecret::from(**secret);
    let pk_r = x25519_dalek::PublicKey::from(&sk).to_bytes();
    let dh = x25519_dh(&sk, &enc)?;
    let mut kem_ctx = enc.to_vec();
    kem_ctx.extend_from_slice(&pk_r);
    let shared = extract_and_expand(KEM_X25519, dh.as_ref(), &kem_ctx)?;
    let (key, nonce) = key_schedule(KEM_X25519, aead_id, &shared, info)?;
    aead::open_with_nonce(&key, &nonce, aad, &sealed.ct).map(Zeroizing::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s.split_whitespace().collect::<String>()).unwrap()
    }
    fn a32(s: &str) -> [u8; 32] {
        h(s).try_into().unwrap()
    }

    const INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
    const PT: &str = "4265617574792069732074727574682c20747275746820626561757479";
    const AAD0: &str = "436f756e742d30";

    /// RFC 9180 A.1.1 (X25519, HKDF-SHA256, AES-128-GCM), sequence 0.
    #[test]
    fn rfc9180_x25519_vector() {
        let sk_e = x25519_dalek::StaticSecret::from(a32(
            "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
        ));
        let sk_r = Zeroizing::new(a32(
            "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
        ));
        let pk_r = X25519Public(a32(
            "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
        ));
        let s =
            seal_x25519_with(&sk_e, &pk_r, &h(INFO), &h(AAD0), &h(PT), AeadId::Aes128Gcm).unwrap();
        assert_eq!(
            s.enc,
            h("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")
        );
        assert_eq!(
            s.ct,
            h(
                "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9
               6d8770ac83d07bea87e13c512a"
            )
        );
        let pt = open_x25519_with(&sk_r, &s, &h(INFO), &h(AAD0), AeadId::Aes128Gcm).unwrap();
        assert_eq!(*pt, h(PT));
    }

    /// RFC 9180 A.3.1 (P-256, HKDF-SHA256, AES-128-GCM), sequence 0.
    #[test]
    fn rfc9180_p256_vector() {
        let sk_e = p256::SecretKey::from_slice(&h(
            "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb",
        ))
        .unwrap();
        let r = SoftwareP256Recipient::from_bytes(&a32(
            "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2",
        ))
        .unwrap();
        let pk_r = h(
            "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f70
                      6a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0",
        );
        assert_eq!(r.public().to_vec(), pk_r);
        let s = seal_p256_with(
            &sk_e,
            &pk_r.clone().try_into().unwrap(),
            &h(INFO),
            &h(AAD0),
            &h(PT),
            AeadId::Aes128Gcm,
        )
        .unwrap();
        assert_eq!(
            s.enc,
            h(
                "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325
               ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4"
            )
        );
        assert_eq!(
            s.ct,
            h(
                "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f
               9076ac232e3ab2523f39513434"
            )
        );
        let pt = open_p256_with(&r, &s, &h(INFO), &h(AAD0), AeadId::Aes128Gcm).unwrap();
        assert_eq!(*pt, h(PT));
    }

    #[test]
    fn aes256_roundtrips_and_binds_info_and_aad() {
        let r = SoftwareP256Recipient::generate().unwrap();
        let s = seal_p256(&r.public(), b"info", b"aad", b"sync key").unwrap();
        assert_eq!(*open_p256(&r, &s, b"info", b"aad").unwrap(), b"sync key");
        assert!(open_p256(&r, &s, b"other", b"aad").is_err());
        assert!(open_p256(&r, &s, b"info", b"x").is_err());
        let other = SoftwareP256Recipient::generate().unwrap();
        assert!(open_p256(&other, &s, b"info", b"aad").is_err());
        assert!(seal_p256(&[4u8; 65], b"", b"", b"").is_err(), "not a point");

        let sk = Zeroizing::new([9u8; 32]);
        let pk = X25519Public(
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*sk)).to_bytes(),
        );
        let s = seal_x25519(&pk, b"i", b"a", b"k").unwrap();
        assert_eq!(*open_x25519(&sk, &s, b"i", b"a").unwrap(), b"k");
        assert!(open_x25519(&Zeroizing::new([8u8; 32]), &s, b"i", b"a").is_err());
        assert!(
            seal_x25519(&X25519Public([0; 32]), b"", b"", b"").is_err(),
            "small order"
        );
    }
}
