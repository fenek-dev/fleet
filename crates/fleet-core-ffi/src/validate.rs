//! Argument validation for values Swift passes in. Everything that ends up
//! in an SSH target or the cache is checked here, not in the UI.

use crate::types::FleetError;
use fleet_core::ssh::SshTarget;
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

/// `user@host:port[,…]` (first hop first, like `ssh -J`; port optional,
/// default 22; at most 4 hops) as a nested jump chain (first hop
/// innermost). Empty means direct.
pub fn proxy_jump(s: Option<&str>) -> Result<Option<Box<SshTarget>>, FleetError> {
    let s = s.map(str::trim).unwrap_or("");
    if s.is_empty() {
        return Ok(None);
    }
    let hops: Vec<&str> = s.split(',').map(str::trim).collect();
    if hops.len() > 4 {
        return Err(invalid("proxy_jump"));
    }
    let mut chain: Option<SshTarget> = None;
    for hop in hops {
        let (u, rest) = hop.split_once('@').ok_or_else(|| invalid("proxy_jump"))?;
        let (h, p) = match rest.rsplit_once(':') {
            // A bare IPv6 literal has colons of its own: needs the port.
            Some((h, p)) if !h.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
                (h, p.parse::<u16>().map_err(|_| invalid("proxy_jump"))?)
            }
            _ => (rest, 22),
        };
        let mut t = SshTarget::new(
            host(h).map_err(|_| invalid("proxy_jump"))?,
            port(p).map_err(|_| invalid("proxy_jump"))?,
            user(u).map_err(|_| invalid("proxy_jump"))?,
        );
        t.proxy_jump = chain.take().map(Box::new);
        chain = Some(t);
    }
    Ok(chain.map(Box::new))
}

/// Absolute local path (a file the operator picked in the app).
pub fn local_path(s: &str) -> Result<std::path::PathBuf, FleetError> {
    let p = std::path::PathBuf::from(s);
    if p.is_absolute() && !s.contains('\0') && s.len() <= 4096 {
        Ok(p)
    } else {
        Err(invalid("local_path"))
    }
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

    #[test]
    fn jumps() {
        assert_eq!(proxy_jump(None).unwrap(), None);
        assert_eq!(proxy_jump(Some("  ")).unwrap(), None);
        let j = proxy_jump(Some("ops@bastion:2222,deploy@10.0.0.2"))
            .unwrap()
            .unwrap();
        // Last listed hop is outermost; the first hop is innermost.
        assert_eq!(
            (j.user.as_str(), j.host.as_str(), j.port),
            ("deploy", "10.0.0.2", 22)
        );
        let first = j.proxy_jump.as_ref().unwrap();
        assert_eq!(
            (first.user.as_str(), first.host.as_str(), first.port),
            ("ops", "bastion", 2222)
        );
        for bad in [
            "bastion",
            "ops@-oProxyCommand=x",
            "a@b,c@d,e@f,g@h,i@j",
            "ops@h:0",
            "Ops@h",
        ] {
            assert!(proxy_jump(Some(bad)).is_err(), "{bad}");
        }
        assert!(local_path("/Users/x/fleet-agent.deb").is_ok());
        assert!(local_path("relative").is_err());
    }
}
