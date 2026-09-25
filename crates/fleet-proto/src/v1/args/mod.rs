//! Validated argument types for typed operations (design §4.2).
//!
//! Every type here validates in its constructor **and** on deserialize, so a
//! decoded `Op` never holds a malformed scalar argument. Collection sizes and
//! cross-field rules are checked by [`crate::Op::check_args`].
//!
//! These types are for Mac → agent arguments only. Results coming back from a
//! server use plain strings (security rule 6: server data is untrusted, and a
//! strict type there would turn an odd unit or path name into a decode error).

mod compose;
mod docker;
mod firewall;
mod names;
mod net;
mod path;
mod query;
mod sched;
mod secret;
mod ssh;
mod text;

pub use compose::ComposeFile;
pub use docker::{ComposeProject, ContainerId, ContainerName, ContainerRef, ImageRef, VolumeName};
pub use firewall::{FirewallMode, FirewallRule, FirewallRuleSet, FwAction, FwChain, RateLimit};
pub use names::{
    DebPackageName, DebVersion, GameName, GameTemplateId, GroupName, PRIVILEGED_GROUPS, UnitName,
    UserName,
};
pub use net::{Cidr, Endpoint, Port, PortRange, Protocol, WgKey, WgPeer};
pub use path::{AbsPath, AllowedPath};
pub use query::{JournalQuery, Priority, SearchQuery, TimeRange};
pub use sched::{CronSpec, Nice, Pid, Signal};
pub use secret::SudoPasswordHash;
pub use ssh::{SshKeyAlgo, SshPublicKey};
pub use std::net::IpAddr;
pub use text::{
    CheckId, CronCommand, FwComment, GrepPattern, HttpPath, JournalCursor, Label, ModuleId,
    ProfileToml, RconCommand, RuleId, SearchTerm, ShellCommand,
};

use super::ErrorCode;

/// Argument validation failure. Maps to [`ErrorCode::InvalidArgument`] on
/// the wire; the `&'static str` names the argument type for Mac-side
/// messages and tests only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ArgError {
    #[error("invalid {0}")]
    Invalid(&'static str),
    #[error("too many {0}")]
    TooMany(&'static str),
    #[error("path not under an allowed root")]
    NotAllowed,
}

impl From<ArgError> for ErrorCode {
    fn from(_: ArgError) -> ErrorCode {
        ErrorCode::InvalidArgument
    }
}

/// `Ok` if `items.len() <= max`.
pub(crate) fn at_most<T>(items: &[T], max: usize, what: &'static str) -> Result<(), ArgError> {
    if items.len() <= max {
        Ok(())
    } else {
        Err(ArgError::TooMany(what))
    }
}

/// `Ok` if `ok`.
pub(crate) fn ensure(ok: bool, what: &'static str) -> Result<(), ArgError> {
    if ok {
        Ok(())
    } else {
        Err(ArgError::Invalid(what))
    }
}

/// Single-line text: at most `max` bytes, no control characters.
pub(crate) fn line_ok(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len()) && !s.chars().any(char::is_control)
}

/// Multi-line text: at most `max` bytes, no control characters except `\n`
/// and `\t`.
pub(crate) fn text_ok(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len()) && !s.chars().any(|c| c.is_control() && c != '\n' && c != '\t')
}

/// Lowercase slug: `^[a-z0-9][a-z0-9._-]{0,max-1}$`.
pub(crate) fn slug_ok(s: &str, max: usize) -> bool {
    let b = s.as_bytes();
    (1..=max).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(&c))
}

/// Declares a `String` newtype validated by `check` in `new`, `FromStr` and
/// `Deserialize`.
macro_rules! validated_string {
    ($(#[$m:meta])* $name:ident, $what:literal, $check:expr) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn new(s: impl Into<String>) -> Result<Self, $crate::v1::args::ArgError> {
                let s = s.into();
                let check: fn(&str) -> bool = $check;
                if check(&s) {
                    Ok(Self(s))
                } else {
                    Err($crate::v1::args::ArgError::Invalid($what))
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = $crate::v1::args::ArgError;
            fn try_from(s: String) -> Result<Self, Self::Error> {
                Self::new(s)
            }
        }

        impl From<$name> for String {
            fn from(v: $name) -> String {
                v.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl core::str::FromStr for $name {
            type Err = $crate::v1::args::ArgError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s)
            }
        }
    };
}
pub(crate) use validated_string;

#[cfg(test)]
pub(crate) mod testutil {
    use serde::{Serialize, de::DeserializeOwned};

    /// Postcard roundtrip must preserve the value.
    pub fn roundtrip<T: Serialize + DeserializeOwned + PartialEq + core::fmt::Debug>(v: &T) {
        let back: T = crate::decode(&crate::encode(v)).unwrap();
        assert_eq!(&back, v);
    }

    /// A rejected string must also be rejected when decoded from the wire.
    pub fn wire_rejects<T: DeserializeOwned>(s: &str) -> bool {
        crate::decode::<T>(&crate::encode(s)).is_err()
    }
}
