//! The one-time server password (design §10.1, "one-time password setup").
//!
//! Typed once in Add server, used to add this Mac's SSH key and to answer
//! `sudo` during the agent install, never stored. [`SecretString`] zeroizes
//! on drop and prints as `<redacted>` in `Debug` and `Display`; it has no
//! `Clone`, `Serialize` or `PartialEq`, so it can't end up in a log, cache
//! row, sync record or progress event by accident.

use fleet_crypto::Zeroizing;

/// Longest password accepted (sshd and sudo allow far less in practice).
pub const MAX_PASSWORD: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SecretError {
    #[error("the password is empty")]
    Empty,
    #[error("the password is too long")]
    TooLong,
    #[error("the password is not valid UTF-8")]
    NotUtf8,
    /// A newline would end the line `sudo -S` reads; NUL can't be sent.
    #[error("the password may not contain a line break or NUL")]
    ControlChar,
}

/// A password in memory that is wiped when dropped.
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Takes ownership of `bytes` (wiped here even on error).
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, SecretError> {
        let bytes = Zeroizing::new(bytes);
        if bytes.is_empty() {
            return Err(SecretError::Empty);
        }
        if bytes.len() > MAX_PASSWORD {
            return Err(SecretError::TooLong);
        }
        if bytes.iter().any(|b| matches!(b, b'\n' | b'\r' | 0)) {
            return Err(SecretError::ControlChar);
        }
        let s = std::str::from_utf8(&bytes).map_err(|_| SecretError::NotUtf8)?;
        Ok(Self(Zeroizing::new(s.to_owned())))
    }

    pub fn from_string(s: String) -> Result<Self, SecretError> {
        Self::from_bytes(s.into_bytes())
    }

    /// The secret text. Callers must not log it or put it on a command line.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// `password\n`, the line `sudo -S` reads from stdin (wiped on drop).
    pub fn sudo_stdin(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Zeroizing::new(Vec::with_capacity(self.0.len() + 1));
        v.extend_from_slice(self.0.as_bytes());
        v.push(b'\n');
        v
    }

    /// Server output `raw` made displayable: the password scrubbed on the
    /// **whole** buffer (before any trimming or truncation). If the capture
    /// was cut (`truncated`) and its end could be the start of the
    /// password (a prefix of 4+ bytes), the text is withheld entirely: the
    /// rest of the password was dropped and can't be scrubbed. Exact bytes
    /// only; other encodings of the password are not recognised.
    pub fn scrub_capture(&self, raw: &[u8], truncated: bool) -> String {
        let pw = self.0.as_bytes();
        if truncated {
            let max = pw.len().saturating_sub(1).min(raw.len());
            if (4..=max).any(|n| raw.ends_with(&pw[..n])) {
                return "<server output withheld>".into();
            }
        }
        self.scrub(&String::from_utf8_lossy(raw))
    }

    /// `text` with every occurrence of the password replaced, for any
    /// server text that is about to be shown (defense in depth).
    pub fn scrub(&self, text: &str) -> String {
        text.replace(self.expose(), "<redacted>")
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

impl std::fmt::Display for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacted_in_debug_and_display() {
        let s = SecretString::from_string("hunter2hunter2".into()).unwrap();
        assert_eq!(format!("{s}"), "<redacted>");
        assert!(!format!("{s:?}").contains("hunter2"));
        assert!(!format!("{:?}", Some(&s)).contains("hunter2"));
        assert_eq!(s.expose(), "hunter2hunter2");
    }

    #[test]
    fn validation() {
        assert_eq!(
            SecretString::from_bytes(vec![]).unwrap_err(),
            SecretError::Empty
        );
        for bad in ["a\nb", "a\rb", "a\0b"] {
            assert_eq!(
                SecretString::from_string(bad.into()).unwrap_err(),
                SecretError::ControlChar
            );
        }
        assert_eq!(
            SecretString::from_bytes(vec![0xff, 0xfe]).unwrap_err(),
            SecretError::NotUtf8
        );
        assert_eq!(
            SecretString::from_bytes(vec![b'a'; MAX_PASSWORD + 1]).unwrap_err(),
            SecretError::TooLong
        );
        // Spaces and symbols are fine.
        assert!(SecretString::from_string("p@ss w0rd'\"$".into()).is_ok());
    }

    #[test]
    fn capture_scrub_handles_cut_passwords() {
        let s = SecretString::from_string("abcdefgh".into()).unwrap();
        assert_eq!(s.scrub_capture(b"x abcdefgh y", false), "x <redacted> y");
        // Cut mid-password: withheld; cut elsewhere: shown.
        assert_eq!(s.scrub_capture(b"err abcde", true), "<server output withheld>");
        assert_eq!(s.scrub_capture(b"err abc", true), "err abc");
        assert_eq!(s.scrub_capture(b"err ok", true), "err ok");
        // Not truncated: a trailing prefix is just text.
        assert_eq!(s.scrub_capture(b"err abcde", false), "err abcde");
    }

    #[test]
    fn stdin_line_and_scrub() {
        let s = SecretString::from_string("pw-1".into()).unwrap();
        assert_eq!(&s.sudo_stdin()[..], b"pw-1\n");
        assert_eq!(s.scrub("sudo said pw-1 twice pw-1"), "sudo said <redacted> twice <redacted>");
    }
}
