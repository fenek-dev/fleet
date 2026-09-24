//! OpenSSH public keys for `authorized_keys.set` (design §5.9).

use super::{ArgError, ensure, line_ok};
use core::fmt;
use core::str::FromStr;
use serde::{Deserialize, Serialize};

/// Accepted key algorithms. No RSA, no DSA, no certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SshKeyAlgo {
    EcdsaP256,
    Ed25519,
    SkEcdsaP256,
    SkEd25519,
}

impl SshKeyAlgo {
    pub const ALL: [SshKeyAlgo; 4] = [
        SshKeyAlgo::EcdsaP256,
        SshKeyAlgo::Ed25519,
        SshKeyAlgo::SkEcdsaP256,
        SshKeyAlgo::SkEd25519,
    ];

    pub fn name(self) -> &'static str {
        match self {
            SshKeyAlgo::EcdsaP256 => "ecdsa-sha2-nistp256",
            SshKeyAlgo::Ed25519 => "ssh-ed25519",
            SshKeyAlgo::SkEcdsaP256 => "sk-ecdsa-sha2-nistp256@openssh.com",
            SshKeyAlgo::SkEd25519 => "sk-ssh-ed25519@openssh.com",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.name() == s)
    }
}

/// A public key line without options: `algo base64 [comment]`. The blob's
/// SSH wire structure must match `algo` exactly. The comment is one line of
/// at most 256 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawKey", into = "RawKey")]
pub struct SshPublicKey {
    algo: SshKeyAlgo,
    blob: Vec<u8>,
    comment: String,
}

#[derive(Serialize, Deserialize)]
struct RawKey {
    algo: SshKeyAlgo,
    blob: Vec<u8>,
    comment: String,
}

/// Reads one SSH `string` (u32 BE length + bytes).
fn take<'a>(b: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (len, rest) = b.split_first_chunk::<4>()?;
    let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
    if rest.len() < len {
        return None;
    }
    let (s, rest) = rest.split_at(len);
    *b = rest;
    Some(s)
}

fn blob_ok(algo: SshKeyAlgo, blob: &[u8]) -> bool {
    let mut b = blob;
    let mut next = || take(&mut b);
    let shape = match algo {
        SshKeyAlgo::Ed25519 | SshKeyAlgo::SkEd25519 => {
            next() == Some(algo.name().as_bytes()) && next().is_some_and(|k| k.len() == 32)
        }
        SshKeyAlgo::EcdsaP256 | SshKeyAlgo::SkEcdsaP256 => {
            next() == Some(algo.name().as_bytes())
                && next() == Some(b"nistp256")
                && next().is_some_and(|q| q.len() == 65 && q[0] == 4)
        }
    };
    let app = match algo {
        SshKeyAlgo::SkEd25519 | SshKeyAlgo::SkEcdsaP256 => {
            next().is_some_and(|a| a.starts_with(b"ssh:") && a.len() <= 256)
        }
        _ => true,
    };
    shape && app && b.is_empty()
}

impl SshPublicKey {
    pub const MAX_BLOB: usize = 1024;

    pub fn new(algo: SshKeyAlgo, blob: Vec<u8>, comment: String) -> Result<Self, ArgError> {
        ensure(
            blob.len() <= Self::MAX_BLOB && blob_ok(algo, &blob),
            "ssh public key",
        )?;
        ensure(line_ok(&comment, 0, 256), "ssh key comment")?;
        Ok(Self {
            algo,
            blob,
            comment,
        })
    }

    pub fn algo(&self) -> SshKeyAlgo {
        self.algo
    }

    pub fn blob(&self) -> &[u8] {
        &self.blob
    }

    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// `algo base64 comment` (comment omitted when empty).
    pub fn to_line(&self) -> String {
        let mut s = format!("{} {}", self.algo.name(), base64_encode(&self.blob));
        if !self.comment.is_empty() {
            s.push(' ');
            s.push_str(&self.comment);
        }
        s
    }
}

impl FromStr for SshPublicKey {
    type Err = ArgError;
    /// Parses `algo base64 [comment]`. Lines with options are rejected.
    fn from_str(line: &str) -> Result<Self, ArgError> {
        let bad = ArgError::Invalid("ssh public key");
        let line = line.trim();
        let (algo, rest) = line.split_once(' ').ok_or(bad)?;
        let algo = SshKeyAlgo::from_name(algo).ok_or(bad)?;
        let (b64, comment) = rest.split_once(' ').unwrap_or((rest, ""));
        let blob = base64_decode(b64).ok_or(bad)?;
        Self::new(algo, blob, comment.trim().to_owned())
    }
}

impl fmt::Display for SshPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.to_line())
    }
}

impl TryFrom<RawKey> for SshPublicKey {
    type Error = ArgError;
    fn try_from(r: RawKey) -> Result<Self, ArgError> {
        Self::new(r.algo, r.blob, r.comment)
    }
}

impl From<SshPublicKey> for RawKey {
    fn from(k: SshPublicKey) -> Self {
        RawKey {
            algo: k.algo,
            blob: k.blob,
            comment: k.comment,
        }
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(B64[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Strict standard base64 with padding; rejects non-canonical trailing bits.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.as_bytes();
    if s.is_empty() || !s.len().is_multiple_of(4) {
        return None;
    }
    let pad = s.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return None;
    }
    let body = &s[..s.len() - pad];
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0;
    for &c in body {
        let v = B64.iter().position(|&x| x == c)?;
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // Leftover bits must be zero padding.
    (acc == 0).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ssh_string(out: &mut Vec<u8>, s: &[u8]) {
        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
        out.extend_from_slice(s);
    }

    fn ed25519_blob(k: [u8; 32]) -> Vec<u8> {
        let mut b = Vec::new();
        ssh_string(&mut b, b"ssh-ed25519");
        ssh_string(&mut b, &k);
        b
    }

    fn p256_blob(algo: SshKeyAlgo, x: [u8; 64], app: Option<&[u8]>) -> Vec<u8> {
        let mut b = Vec::new();
        ssh_string(&mut b, algo.name().as_bytes());
        ssh_string(&mut b, b"nistp256");
        let mut q = vec![4];
        q.extend_from_slice(&x);
        ssh_string(&mut b, &q);
        if let Some(a) = app {
            ssh_string(&mut b, a);
        }
        b
    }

    #[test]
    fn examples() {
        // RFC 4648 test vectors.
        for (plain, enc) in [
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(plain.as_bytes()), enc);
            assert_eq!(base64_decode(enc).unwrap(), plain.as_bytes());
        }
        let b64 = base64_encode(&ed25519_blob([0x11; 32]));
        assert!(b64.starts_with("AAAAC3NzaC1lZDI1NTE5AAAAI"));
        let line = format!("ssh-ed25519 {b64} ops@laptop");
        let k: SshPublicKey = line.parse().unwrap();
        assert_eq!(k.algo(), SshKeyAlgo::Ed25519);
        assert_eq!(k.blob(), ed25519_blob([0x11; 32]));
        assert_eq!(k.comment(), "ops@laptop");
        assert_eq!(k.to_line(), line);

        let ecdsa_b64 = base64_encode(&p256_blob(SshKeyAlgo::EcdsaP256, [7; 64], None));
        for bad in [
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ== x".to_owned(),
            "ssh-dss AAAA".to_owned(),
            // ed25519 name with an ecdsa-shaped blob
            format!("ssh-ed25519 {ecdsa_b64}"),
            // options are not accepted
            format!("command=\"x\" ssh-ed25519 {b64}"),
            "ssh-ed25519 !!!!".to_owned(),
            "ssh-ed25519".to_owned(),
        ] {
            assert!(bad.parse::<SshPublicKey>().is_err(), "{bad}");
        }
        assert!(
            format!("ecdsa-sha2-nistp256 {ecdsa_b64}")
                .parse::<SshPublicKey>()
                .is_ok()
        );
        let blob = p256_blob(SshKeyAlgo::EcdsaP256, [7; 64], None);
        assert!(SshPublicKey::new(SshKeyAlgo::EcdsaP256, blob.clone(), String::new()).is_ok());
        assert!(SshPublicKey::new(SshKeyAlgo::SkEcdsaP256, blob, String::new()).is_err());
        let sk = p256_blob(SshKeyAlgo::SkEcdsaP256, [7; 64], Some(b"ssh:"));
        assert!(SshPublicKey::new(SshKeyAlgo::SkEcdsaP256, sk, "yubikey".into()).is_ok());
        let sk_bad_app = p256_blob(SshKeyAlgo::SkEcdsaP256, [7; 64], Some(b"web:"));
        assert!(SshPublicKey::new(SshKeyAlgo::SkEcdsaP256, sk_bad_app, String::new()).is_err());
        let mut trailing = ed25519_blob([1; 32]);
        trailing.push(0);
        assert!(SshPublicKey::new(SshKeyAlgo::Ed25519, trailing, String::new()).is_err());
        assert!(
            SshPublicKey::new(SshKeyAlgo::Ed25519, ed25519_blob([1; 32]), "a\nb".into()).is_err()
        );

        // Non-canonical trailing bits and bad padding.
        assert_eq!(base64_decode("QQ=="), Some(b"A".to_vec()));
        assert_eq!(base64_decode("QR=="), None);
        assert_eq!(base64_decode("Q==="), None);
        assert_eq!(base64_decode("QQ="), None);
    }

    proptest! {
        #[test]
        fn base64_roundtrip(data in prop::collection::vec(any::<u8>(), 1..200)) {
            prop_assert_eq!(base64_decode(&base64_encode(&data)), Some(data));
        }

        #[test]
        fn ed25519_accepts(k in any::<[u8; 32]>(), comment in "[ -~]{0,64}") {
            let key = SshPublicKey::new(SshKeyAlgo::Ed25519, ed25519_blob(k), comment.trim().into()).unwrap();
            let back: SshPublicKey = key.to_line().parse().unwrap();
            prop_assert_eq!(&back, &key);
            let wire: SshPublicKey = crate::decode(&crate::encode(&key)).unwrap();
            prop_assert_eq!(wire, key);
        }

        #[test]
        fn wrong_length_rejected(k in prop::collection::vec(any::<u8>(), 0..64)) {
            prop_assume!(k.len() != 32);
            let mut b = Vec::new();
            ssh_string(&mut b, b"ssh-ed25519");
            ssh_string(&mut b, &k);
            prop_assert!(SshPublicKey::new(SshKeyAlgo::Ed25519, b, String::new()).is_err());
        }
    }
}
