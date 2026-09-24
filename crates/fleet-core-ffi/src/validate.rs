//! Argument validation for values Swift passes in. Everything that ends up
//! in an SSH target or the cache is checked here, not in the UI.

use crate::types::FleetError;
use fleet_proto::ServerId;

fn invalid(field: &str) -> FleetError {
    FleetError::InvalidArgument {
        field: field.to_string(),
    }
}

/// Display name: 1–64 chars, no control characters, not blank.
pub fn name(s: &str, field: &str) -> Result<String, FleetError> {
    let t = s.trim();
    let n = t.chars().count();
    if (1..=64).contains(&n) && !t.chars().any(char::is_control) {
        Ok(t.to_string())
    } else {
        Err(invalid(field))
    }
}

/// DNS name, IPv4 or bare IPv6 literal: 1–253 bytes of `[A-Za-z0-9.:-]`,
/// not starting with `-` (never parsed as an option anywhere).
pub fn host(s: &str) -> Result<String, FleetError> {
    let ok = (1..=253).contains(&s.len())
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'-'));
    if ok {
        Ok(s.to_string())
    } else {
        Err(invalid("host"))
    }
}

pub fn port(p: u16) -> Result<u16, FleetError> {
    if p == 0 { Err(invalid("port")) } else { Ok(p) }
}

/// Debian's default `NAME_REGEX`: `^[a-z][-a-z0-9_]{0,31}$` (plus `_` first).
pub fn user(s: &str) -> Result<String, FleetError> {
    let mut b = s.bytes();
    let first = b
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c == b'_');
    let rest = b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_');
    if first && rest && s.len() <= 32 {
        Ok(s.to_string())
    } else {
        Err(invalid("user"))
    }
}

/// Tags: 1–32 of `[a-z0-9-]`; at most 16 per server; deduplicated.
pub fn tags(v: &[String]) -> Result<Vec<String>, FleetError> {
    if v.len() > 16 {
        return Err(invalid("tags"));
    }
    let mut out: Vec<String> = Vec::with_capacity(v.len());
    for t in v {
        let ok = (1..=32).contains(&t.len())
            && t.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
        if !ok {
            return Err(invalid("tags"));
        }
        if !out.contains(t) {
            out.push(t.clone());
        }
    }
    Ok(out)
}

pub fn server_id(s: &str) -> Result<ServerId, FleetError> {
    ServerId::new(s).map_err(|_| invalid("server_id"))
}

/// Group ids are ours: `grp_` + 12 of `[a-z0-9]`.
pub fn group_id(s: &str) -> Result<String, FleetError> {
    let ok = s.strip_prefix("grp_").is_some_and(|b| {
        (6..=32).contains(&b.len())
            && b.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    });
    if ok {
        Ok(s.to_string())
    } else {
        Err(invalid("group_id"))
    }
}

/// `prefix` + 12 random `[a-z0-9]`.
pub fn random_id(prefix: &str) -> Result<String, FleetError> {
    const ALPHABET: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut buf = [0u8; 12];
    fleet_crypto::random_bytes(&mut buf).map_err(|_| FleetError::Internal {
        message: "rng".into(),
    })?;
    let body: String = buf
        .iter()
        .map(|b| ALPHABET[usize::from(*b) % ALPHABET.len()] as char)
        .collect();
    Ok(format!("{prefix}{body}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        for ok in ["web-04", "203.0.113.14", "2001:db8::1", "a.example.com"] {
            assert!(host(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "-oProxyCommand=x",
            "a b",
            "a;b",
            "a/b",
            "h\n",
            &"a".repeat(254),
        ] {
            assert!(host(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn users() {
        for ok in ["root", "deploy", "_svc", "a-b_c9"] {
            assert!(user(ok).is_ok(), "{ok}");
        }
        for bad in ["", "Root", "9x", "-x", "a b", "a$", &"a".repeat(33)] {
            assert!(user(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn names_ports_tags() {
        assert_eq!(name("  web-04 ", "name").unwrap(), "web-04");
        assert!(name("   ", "name").is_err());
        assert!(name("a\u{7}", "name").is_err());
        assert!(name(&"x".repeat(65), "name").is_err());
        assert!(port(0).is_err());
        assert_eq!(port(22).unwrap(), 22);
        assert_eq!(
            tags(&["web".into(), "web".into(), "eu-1".into()]).unwrap(),
            vec!["web".to_string(), "eu-1".to_string()]
        );
        assert!(tags(&["Web".into()]).is_err());
        assert!(tags(&[String::new()]).is_err());
    }

    #[test]
    fn ids() {
        let s = random_id("srv_").unwrap();
        assert!(server_id(&s).is_ok());
        let g = random_id("grp_").unwrap();
        assert!(group_id(&g).is_ok());
        assert!(group_id("grp_AB").is_err());
        assert!(server_id("srv_x").is_err());
    }
}
