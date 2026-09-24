//! Identifiers and validated strings.

use core::fmt;
use core::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    #[error("identifier has wrong format")]
    Format,
    #[error("string longer than {0} bytes")]
    TooLong(usize),
    #[error("string contains control characters")]
    Control,
}

/// 16-byte random id. Binary on the wire; `<prefix><32 hex>` in TOML/text.
macro_rules! id16 {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct $name(pub [u8; 16]);

        impl $name {
            pub const PREFIX: &'static str = $prefix;
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{}{}", $prefix, hex::encode(self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                fmt::Display::fmt(self, f)
            }
        }

        impl FromStr for $name {
            type Err = IdError;
            fn from_str(s: &str) -> Result<Self, IdError> {
                let hex = s.strip_prefix($prefix).ok_or(IdError::Format)?;
                let mut out = [0u8; 16];
                hex::decode_to_slice(hex, &mut out).map_err(|_| IdError::Format)?;
                Ok(Self(out))
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                if s.is_human_readable() {
                    s.collect_str(self)
                } else {
                    self.0.serialize(s)
                }
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                if d.is_human_readable() {
                    let s = String::deserialize(d)?;
                    s.parse().map_err(D::Error::custom)
                } else {
                    <[u8; 16]>::deserialize(d).map(Self)
                }
            }
        }
    };
}

id16!(DeviceId, "d_");
id16!(FleetId, "f_");

/// Server identifier, `^srv_[a-z0-9]{6,32}$`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ServerId(String);

impl ServerId {
    pub const PREFIX: &'static str = "srv_";

    pub fn new(s: impl Into<String>) -> Result<Self, IdError> {
        let s = s.into();
        let body = s.strip_prefix(Self::PREFIX).ok_or(IdError::Format)?;
        let ok_len = (6..=32).contains(&body.len());
        let ok_chars = body
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        if ok_len && ok_chars {
            Ok(Self(s))
        } else {
            Err(IdError::Format)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ServerId {
    type Error = IdError;
    fn try_from(s: String) -> Result<Self, IdError> {
        Self::new(s)
    }
}

impl From<ServerId> for String {
    fn from(id: ServerId) -> String {
        id.0
    }
}

impl fmt::Display for ServerId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ServerId {
    type Err = IdError;
    fn from_str(s: &str) -> Result<Self, IdError> {
        Self::new(s)
    }
}

/// UTF-8 string of at most `N` bytes with no control characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BoundedString<const N: usize>(String);

impl<const N: usize> BoundedString<N> {
    pub fn new(s: impl Into<String>) -> Result<Self, IdError> {
        let s = s.into();
        if s.len() > N {
            return Err(IdError::TooLong(N));
        }
        if s.chars().any(char::is_control) {
            return Err(IdError::Control);
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<const N: usize> fmt::Display for BoundedString<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<const N: usize> Serialize for BoundedString<N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de, const N: usize> Deserialize<'de> for BoundedString<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(d)?).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_id_validation() {
        assert!(ServerId::new("srv_7f3a9c").is_ok());
        assert!(ServerId::new("srv_abc12").is_err()); // too short
        assert!(ServerId::new("srv_ABCDEF").is_err());
        assert!(ServerId::new("srv_abc-def").is_err());
        assert!(ServerId::new(format!("srv_{}", "a".repeat(33))).is_err());
        assert!(ServerId::new("xsrv_abcdef").is_err());
    }

    #[test]
    fn id_text_form() {
        let id = FleetId([0xab; 16]);
        let s = id.to_string();
        assert_eq!(s, format!("f_{}", "ab".repeat(16)));
        assert_eq!(s.parse::<FleetId>().unwrap(), id);
        assert!(s.parse::<DeviceId>().is_err());
    }

    #[test]
    fn bounded_string() {
        assert!(BoundedString::<4>::new("abcd").is_ok());
        assert!(BoundedString::<4>::new("abcde").is_err());
        assert!(BoundedString::<8>::new("a\nb").is_err());
    }
}
