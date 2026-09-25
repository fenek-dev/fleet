//! Recovery code (design §5.11): 24 BIP-39 words → Argon2id → HKDF-SHA256 →
//! recovery signing key, recovery SSH key (Ed25519) and escrow key (X25519).

use crate::noise::StaticKeypair;
use crate::sig::Ed25519Signer;
use crate::{Error, random_bytes};
use fleet_proto::{Ed25519Public, X25519Public};
use hkdf::Hkdf;
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

pub const SALT_PREFIX: &[u8] = b"fleet-recovery-v1";
pub const INFO_SIGN: &[u8] = b"fleet/recovery-sign/v1";
pub const INFO_SSH: &[u8] = b"fleet/recovery-ssh/v1";
pub const INFO_ESCROW: &[u8] = b"fleet/recovery-escrow/v1";
/// Default recovery delay without a passphrase (§5.3).
pub const DEFAULT_DELAY_S: u32 = 72 * 3600;

/// Argon2id cost. Injectable so tests can use tiny parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// m = 256 MiB, t = 3, p = 1.
    pub const PRODUCTION: KdfParams = KdfParams {
        m_kib: 256 * 1024,
        t: 3,
        p: 1,
    };
}

/// `recovery_delay_s` for a new code: 0 only with a **strong** passphrase
/// ([`passphrase_is_strong`]), 72 h otherwise. A weak passphrase is still
/// mixed into the derivation; it just doesn't earn the zero delay, because
/// paper plus a guessable passphrase must not beat a veto.
pub fn delay_for(passphrase: &str) -> u32 {
    if passphrase_is_strong(passphrase) {
        0
    } else {
        DEFAULT_DELAY_S
    }
}

/// Minimum length (in characters) of a mixed-class passphrase.
pub const STRONG_MIN_CHARS: usize = 12;
/// Minimum character classes (lowercase, uppercase, digit, other).
pub const STRONG_MIN_CLASSES: usize = 3;
/// Minimum words of a passphrase made of words.
pub const STRONG_MIN_WORDS: usize = 5;
/// Minimum letters per counted word.
pub const STRONG_MIN_WORD_LEN: usize = 3;

/// Simple, documented strength estimate aiming at ~60 bits (design §5.11).
/// On the NFKD-normalized, trimmed passphrase, either:
///
/// - at least [`STRONG_MIN_CHARS`] characters from at least
///   [`STRONG_MIN_CLASSES`] of {lowercase, uppercase, digit, other}
///   (12 × log2(~60) ≈ 70 bits for random choices; people choose worse,
///   hence the margin), or
/// - at least [`STRONG_MIN_WORDS`] distinct words of at least
///   [`STRONG_MIN_WORD_LEN`] letters, separated by spaces, `-`, `_` or `.`
///   (5 diceware words ≈ 64 bits).
///
/// This is a floor against "password1"-style input, not a guarantee.
pub fn passphrase_is_strong(passphrase: &str) -> bool {
    let norm = nfkd(passphrase);
    let p = norm.trim();
    let chars = p.chars().count();
    let classes = [
        p.chars().any(|c| c.is_lowercase()),
        p.chars().any(|c| c.is_uppercase()),
        p.chars().any(|c| c.is_numeric()),
        p.chars().any(|c| !c.is_alphanumeric()),
    ]
    .iter()
    .filter(|&&b| b)
    .count();
    if chars >= STRONG_MIN_CHARS && classes >= STRONG_MIN_CLASSES {
        return true;
    }
    let mut words: Vec<Zeroizing<String>> = Vec::new();
    for w in p.split(|c: char| c.is_whitespace() || matches!(c, '-' | '_' | '.')) {
        if w.chars().filter(|c| c.is_alphabetic()).count() >= STRONG_MIN_WORD_LEN {
            let w = Zeroizing::new(w.to_lowercase());
            if !words.iter().any(|x| **x == *w) {
                words.push(w);
            }
        }
    }
    words.len() >= STRONG_MIN_WORDS
}

/// 256-bit recovery entropy, shown as 24 words. Zeroized on drop.
pub struct RecoveryCode {
    entropy: Zeroizing<[u8; 32]>,
}

impl RecoveryCode {
    pub fn generate() -> Result<Self, Error> {
        let mut entropy = Zeroizing::new([0u8; 32]);
        random_bytes(entropy.as_mut())?;
        Ok(Self { entropy })
    }

    pub fn from_entropy(entropy: &[u8; 32]) -> Self {
        Self {
            entropy: Zeroizing::new(*entropy),
        }
    }

    /// Parses 24 English BIP-39 words (checksum checked). Unicode (NFKD),
    /// whitespace and case are normalized.
    pub fn parse(words: &str) -> Result<Self, Error> {
        let nfkd = nfkd(words);
        // Built in place in one pre-sized zeroizing buffer: no per-word
        // `String`s or `Vec` of words left behind unzeroized. Lowercasing
        // grows a char by at most 3x in UTF-8 bytes.
        let mut normalized = Zeroizing::new(String::with_capacity(nfkd.len() * 3));
        for w in nfkd.split_whitespace() {
            if !normalized.is_empty() {
                normalized.push(' ');
            }
            normalized.extend(w.chars().flat_map(char::to_lowercase));
        }
        let m = bip39::Mnemonic::parse_normalized(&normalized).map_err(|_| Error::Mnemonic)?;
        let (bytes, len) = m.to_entropy_array();
        let bytes = Zeroizing::new(bytes);
        if len != 32 {
            return Err(Error::Mnemonic);
        }
        let mut entropy = Zeroizing::new([0u8; 32]);
        entropy.copy_from_slice(&bytes[..32]);
        Ok(Self { entropy })
    }

    /// The 24 words, space-separated.
    pub fn phrase(&self) -> Zeroizing<String> {
        let m = bip39::Mnemonic::from_entropy(self.entropy.as_ref()).expect("32 bytes is valid");
        Zeroizing::new(m.to_string())
    }

    pub fn entropy(&self) -> &[u8; 32] {
        &self.entropy
    }

    /// Derives the recovery keys. Slow with production parameters.
    pub fn derive(&self, passphrase: &str, params: KdfParams) -> Result<RecoveryKeys, Error> {
        derive_keys(&self.entropy, passphrase, params)
    }
}

/// Unicode NFKD (as BIP-39 does), so the same passphrase typed on different
/// keyboards or OSes (composed vs decomposed accents) derives the same keys.
fn nfkd(s: &str) -> Zeroizing<String> {
    // Reserve up front so growth rarely leaves unzeroized copies behind.
    let mut out = Zeroizing::new(String::with_capacity(s.len() * 4));
    out.extend(s.nfkd());
    out
}

/// Public halves, as installed in the roster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryPublics {
    pub recovery_key: Ed25519Public,
    pub recovery_ssh_key: Ed25519Public,
    pub recovery_escrow_key: X25519Public,
}

/// Recovery private keys (in memory only; zeroized on drop).
pub struct RecoveryKeys {
    pub sign: Ed25519Signer,
    pub ssh: Ed25519Signer,
    pub escrow: StaticKeypair,
}

impl RecoveryKeys {
    pub fn publics(&self) -> RecoveryPublics {
        RecoveryPublics {
            recovery_key: self.sign.public(),
            recovery_ssh_key: self.ssh.public(),
            recovery_escrow_key: self.escrow.public(),
        }
    }
}

/// `seed = Argon2id(entropy, salt = SALT_PREFIX ‖ NFKD(passphrase))`, then one
/// HKDF-SHA256 expansion per key (no HKDF salt, `info` per §5.11).
///
/// Seed, PRK and every OKM live in `Zeroizing` buffers. The `hkdf` crate has
/// no zeroize support, so the HMAC state inside the `Hkdf` value (derived
/// from the PRK) is not wiped on drop; it lives only for this call.
pub fn derive_keys(
    entropy: &[u8; 32],
    passphrase: &str,
    params: KdfParams,
) -> Result<RecoveryKeys, Error> {
    let passphrase = nfkd(passphrase);
    let seed = argon2_seed(entropy, passphrase.as_bytes(), params)?;
    let prk = {
        let (mut out, _) = Hkdf::<Sha256>::extract(None, seed.as_ref());
        let mut prk = Zeroizing::new([0u8; 32]);
        prk.copy_from_slice(&out);
        zeroize::Zeroize::zeroize(&mut out[..]);
        prk
    };
    let hk = Hkdf::<Sha256>::from_prk(prk.as_ref()).map_err(|_| Error::Kdf)?;
    let expand = |info: &[u8]| -> Result<Zeroizing<[u8; 32]>, Error> {
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(info, okm.as_mut()).map_err(|_| Error::Kdf)?;
        Ok(okm)
    };
    let (sign, ssh, escrow) = (expand(INFO_SIGN)?, expand(INFO_SSH)?, expand(INFO_ESCROW)?);
    Ok(RecoveryKeys {
        sign: Ed25519Signer::from_seed(&sign),
        ssh: Ed25519Signer::from_seed(&ssh),
        escrow: StaticKeypair::from_bytes(&escrow),
    })
}

fn argon2_seed(
    entropy: &[u8; 32],
    passphrase: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let p =
        argon2::Params::new(params.m_kib, params.t, params.p, Some(32)).map_err(|_| Error::Kdf)?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p);
    let mut salt = Zeroizing::new(Vec::with_capacity(SALT_PREFIX.len() + passphrase.len()));
    salt.extend_from_slice(SALT_PREFIX);
    salt.extend_from_slice(passphrase);
    let mut seed = Zeroizing::new([0u8; 32]);
    a.hash_password_into(entropy, &salt, seed.as_mut())
        .map_err(|_| Error::Kdf)?;
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TINY: KdfParams = KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    };

    #[test]
    fn bip39_known_vector_and_roundtrip() {
        let zero = RecoveryCode::from_entropy(&[0; 32]);
        let phrase = zero.phrase();
        let words: Vec<_> = phrase.split(' ').collect();
        assert_eq!(words.len(), 24);
        assert!(words[..23].iter().all(|w| *w == "abandon"));
        assert_eq!(words[23], "art");

        let c = RecoveryCode::generate().unwrap();
        let back = RecoveryCode::parse(&format!("  {}  ", c.phrase().to_uppercase())).unwrap();
        assert_eq!(back.entropy(), c.entropy());
    }

    #[test]
    fn bip39_rejects_bad_input() {
        let phrase = RecoveryCode::from_entropy(&[0; 32]).phrase();
        let bad_checksum = phrase.replace("art", "abandon");
        assert!(RecoveryCode::parse(&bad_checksum).is_err());
        let twelve = ["abandon"; 11].join(" ") + " about";
        assert!(
            RecoveryCode::parse(&twelve).is_err(),
            "12 words is not a recovery code"
        );
        assert!(RecoveryCode::parse("not words at all").is_err());
    }

    #[test]
    fn derivation_is_deterministic_and_passphrase_sensitive() {
        let c = RecoveryCode::from_entropy(&[5; 32]);
        let a = c.derive("", TINY).unwrap().publics();
        let b = c.derive("", TINY).unwrap().publics();
        let p = c.derive("hunter2", TINY).unwrap().publics();
        assert_eq!(a, b);
        assert_ne!(a, p);
        assert_ne!(a.recovery_key, a.recovery_ssh_key);
        assert_eq!(delay_for(""), DEFAULT_DELAY_S);
        assert_eq!(delay_for("x"), DEFAULT_DELAY_S);
        assert_eq!(delay_for("Tr0ub4dor&3xyz"), 0);
    }

    #[test]
    fn passphrase_strength() {
        for weak in [
            "",
            "hunter2",
            "password1234",          // 2 classes
            "   Ab1   ",             // short after trim
            "correct horse battery", // 3 words
            "aa bb cc dd ee ff",     // words too short
            "cat cat cat cat cat",   // not distinct
        ] {
            assert!(!passphrase_is_strong(weak), "{weak:?}");
            assert_eq!(delay_for(weak), DEFAULT_DELAY_S);
        }
        for strong in [
            "Password1234",
            "correct horse battery staple zebra",
            "correct-horse-battery-staple-zebra",
            "  mañana: 12 Äpfel!  ",
        ] {
            assert!(passphrase_is_strong(strong), "{strong:?}");
            assert_eq!(delay_for(strong), 0);
        }
    }

    #[test]
    fn passphrase_is_nfkd_normalized() {
        let c = RecoveryCode::from_entropy(&[5; 32]);
        let composed = "caf\u{e9} \u{212b}ngstr\u{f6}m"; // é, Å (angstrom sign), ö
        let decomposed = "cafe\u{301} A\u{30a}ngstro\u{308}m";
        assert_ne!(composed.as_bytes(), decomposed.as_bytes());
        let a = c.derive(composed, TINY).unwrap().publics();
        let b = c.derive(decomposed, TINY).unwrap().publics();
        assert_eq!(a, b);
        assert_ne!(a, c.derive("cafe Angstrom", TINY).unwrap().publics());
    }
}
