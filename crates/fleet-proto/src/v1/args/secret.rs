//! Secret-bearing arguments: never printed, never audited in full.

use super::ArgError;
use serde::{Deserialize, Serialize};

/// Prefix of the audit form of a [`SudoPasswordHash`]: `$blake3$` plus 64
/// lowercase hex digits of BLAKE3 over the crypt(3) string.
const REDACTED_PREFIX: &str = "$blake3$";

/// crypt(3) hash of a sudo password, made on the Mac (yescrypt `$y$` or
/// sha512-crypt `$6$`; 20–256 bytes of `[A-Za-z0-9./$=]`). Never plaintext.
///
/// Also decodes the **redacted** form audit entries store instead
/// ([`Self::redacted`], `$blake3$<hex>`), so a mirrored audit entry still
/// decodes; `Op::check_args` refuses it in a command. `Debug` never prints
/// the hash and there is no `Display`.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SudoPasswordHash(String);

fn crypt_ok(s: &str) -> bool {
    (20..=256).contains(&s.len())
        && (s.starts_with("$y$") || s.starts_with("$6$"))
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"./$=".contains(&b))
}

fn redacted_ok(s: &str) -> bool {
    s.strip_prefix(REDACTED_PREFIX).is_some_and(|h| {
        h.len() == 64
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

impl SudoPasswordHash {
    /// A crypt(3) hash or the redacted audit form.
    pub fn new(s: impl Into<String>) -> Result<Self, ArgError> {
        let s = s.into();
        if crypt_ok(&s) || redacted_ok(&s) {
            Ok(Self(s))
        } else {
            Err(ArgError::Invalid("sudo password hash"))
        }
    }

    /// A crypt(3) hash only (profile TOML, handlers).
    pub fn crypt(s: impl Into<String>) -> Result<Self, ArgError> {
        let h = Self::new(s)?;
        if h.is_redacted() {
            return Err(ArgError::Invalid("sudo password hash"));
        }
        Ok(h)
    }

    /// The audit form: `$blake3$` + hex(BLAKE3(hash)). Idempotent.
    pub fn redacted(&self) -> Self {
        if self.is_redacted() {
            return self.clone();
        }
        let h = blake3::hash(self.0.as_bytes());
        Self(format!("{REDACTED_PREFIX}{}", hex::encode(h.as_bytes())))
    }

    pub fn is_redacted(&self) -> bool {
        self.0.starts_with(REDACTED_PREFIX)
    }

    /// The hash itself, for `chpasswd --encrypted` stdin only.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for SudoPasswordHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SudoPasswordHash(redacted)")
    }
}

impl TryFrom<String> for SudoPasswordHash {
    type Error = ArgError;
    fn try_from(s: String) -> Result<Self, ArgError> {
        Self::new(s)
    }
}

impl From<SudoPasswordHash> for String {
    fn from(v: SudoPasswordHash) -> String {
        v.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::args::testutil::{roundtrip, wire_rejects};

    const Y: &str = "$y$j9T$abcdefghijklmnop$ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./ab";
    const SIX: &str = "$6$saltsalt$0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJ./";

    #[test]
    fn accepts_crypt_formats() {
        for h in [Y, SIX] {
            let v = SudoPasswordHash::crypt(h).unwrap();
            assert_eq!(v.expose(), h);
            assert!(!v.is_redacted());
            roundtrip(&v);
        }
    }

    #[test]
    fn rejects_plaintext_and_other_schemes() {
        for bad in [
            "hunter2",
            "$1$md5md5$0123456789abcdefghij",
            "$2b$10$0123456789abcdefghijk",
            "$y$short",
            "$y$j9T$with space and more characters",
            "$6$salt$line\nbreak0123456789abcdef",
            &format!("$6${}", "a".repeat(260)),
            "$blake3$00",
            &format!("$blake3${}", "A".repeat(64)),
        ] {
            assert!(SudoPasswordHash::new(bad).is_err(), "{bad:?}");
            assert!(wire_rejects::<SudoPasswordHash>(bad), "{bad:?}");
        }
    }

    #[test]
    fn redaction_is_a_blake3_and_never_crypt() {
        let h = SudoPasswordHash::crypt(Y).unwrap();
        let r = h.redacted();
        assert!(r.is_redacted());
        assert!(!r.expose().contains("j9T"));
        assert_eq!(
            r.expose(),
            format!(
                "$blake3${}",
                hex::encode(blake3::hash(Y.as_bytes()).as_bytes())
            )
        );
        assert_eq!(r.redacted(), r);
        roundtrip(&r);
        assert!(SudoPasswordHash::crypt(r.expose()).is_err());
    }

    #[test]
    fn debug_never_prints_the_hash() {
        let h = SudoPasswordHash::crypt(Y).unwrap();
        assert!(!format!("{h:?}").contains("j9T"));
    }
}
