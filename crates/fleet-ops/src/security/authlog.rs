//! Parser for `sshd` / `sshd-session` journal messages (design §4.6, §4.7).
//!
//! Pure and allocation-light: `&str` in, [`AuthEvent`] out, never panics
//! (proptested, and the entry point for a `cargo-fuzz` target). Every
//! token comes from the network (user names are attacker-chosen), so
//! nothing is trusted beyond "parses as an IP address".

use fleet_proto::payload::LoginMethod;
use std::net::IpAddr;

/// Longest user name kept (Linux allows 32; attackers send more).
pub const MAX_USER: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthKind {
    /// `Accepted <method> for <user> from <ip> port <n> ssh2[: <alg> SHA256:<fp>]`
    Accepted {
        method: LoginMethod,
        fingerprint: Option<String>,
    },
    /// `Failed <method> for [invalid user ]<user> from <ip> …`
    Failed {
        method: LoginMethod,
        invalid_user: bool,
    },
    /// `Invalid user <user> from <ip> port <n>`
    InvalidUser,
    /// Pre-authentication disconnects, timeouts, negotiation failures and
    /// `maximum authentication attempts exceeded`.
    Preauth,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthEvent {
    pub kind: AuthKind,
    pub user: Option<String>,
    pub addr: IpAddr,
    pub port: Option<u16>,
}

impl AuthEvent {
    /// Counts towards a brute-force ban. `Failed publickey` does not:
    /// clients offer every key in their agent, and each rejected one is
    /// logged at `LogLevel VERBOSE`.
    pub fn is_failure(&self) -> bool {
        match &self.kind {
            AuthKind::Accepted { .. } => false,
            AuthKind::Failed { method, .. } => *method != LoginMethod::PublicKey,
            AuthKind::InvalidUser | AuthKind::Preauth => true,
        }
    }
}

fn method(s: &str) -> LoginMethod {
    match s {
        "publickey" => LoginMethod::PublicKey,
        "password" => LoginMethod::Password,
        s if s.starts_with("keyboard-interactive") => LoginMethod::KeyboardInteractive,
        _ => LoginMethod::Other,
    }
}

fn user(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.chars().take(MAX_USER).collect())
}

fn ip(s: &str) -> Option<IpAddr> {
    s.parse().ok()
}

/// `<ip> port <n>…` → address and port.
fn ip_port(rest: &str) -> Option<(IpAddr, Option<u16>)> {
    let mut it = rest.split(' ');
    let addr = ip(it.next()?)?;
    let port = match (it.next(), it.next()) {
        (Some("port"), Some(p)) => p
            .trim_end_matches([':', ','])
            .split(':')
            .next()?
            .parse()
            .ok(),
        _ => None,
    };
    Some((addr, port))
}

/// Splits `… for <user> from <ip> port …` on the **last** ` from `: the
/// user name is attacker-controlled and may itself contain " from ".
fn user_from(rest: &str) -> Option<(&str, &str)> {
    let i = rest.rfind(" from ")?;
    Some((&rest[..i], &rest[i + 6..]))
}

/// Same for forms without `from`: `<user> <ip> port <n>` (last ` <ip> port`).
fn user_then_ip(rest: &str) -> Option<(Option<String>, IpAddr, Option<u16>)> {
    let i = rest.rfind(" port ")?;
    let head = &rest[..i];
    let j = head.rfind(' ')?;
    let addr = ip(&head[j + 1..])?;
    let (_, port) = ip_port(&rest[j + 1..])?;
    Some((user(&head[..j]), addr, port))
}

fn fingerprint(tail: &str) -> Option<String> {
    let i = tail.find("SHA256:")?;
    let fp: String = tail[i..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '+' | '/' | '='))
        .take(64)
        .collect();
    (fp.len() > 7).then_some(fp)
}

/// Parses one sshd message (the journal `MESSAGE`). `None` for everything
/// that is not an authentication event with a source address.
pub fn parse_sshd(msg: &str) -> Option<AuthEvent> {
    let msg = msg.trim();
    let msg = msg.strip_prefix("error: ").unwrap_or(msg);
    let preauth = msg.ends_with("[preauth]");
    let msg = msg.trim_end_matches("[preauth]").trim_end();

    if let Some(rest) = msg.strip_prefix("Accepted ") {
        let (m, rest) = rest.split_once(" for ")?;
        let (u, tail) = user_from(rest)?;
        let (addr, port) = ip_port(tail)?;
        return Some(AuthEvent {
            kind: AuthKind::Accepted {
                method: method(m),
                fingerprint: fingerprint(tail),
            },
            user: user(u),
            addr,
            port,
        });
    }
    if let Some(rest) = msg.strip_prefix("Failed ") {
        let (m, rest) = rest.split_once(" for ")?;
        let (u, tail) = user_from(rest)?;
        let (invalid_user, u) = match u.strip_prefix("invalid user ") {
            Some(u) => (true, u),
            None => (false, u),
        };
        let (addr, port) = ip_port(tail)?;
        return Some(AuthEvent {
            kind: AuthKind::Failed {
                method: method(m),
                invalid_user,
            },
            user: user(u),
            addr,
            port,
        });
    }
    if let Some(rest) = msg.strip_prefix("Invalid user ") {
        let (u, tail) = user_from(rest)?;
        let (addr, port) = ip_port(tail)?;
        return Some(AuthEvent {
            kind: AuthKind::InvalidUser,
            user: user(u),
            addr,
            port,
        });
    }
    if let Some(rest) = msg.strip_prefix("maximum authentication attempts exceeded for ") {
        let (u, tail) = user_from(rest)?;
        let u = u.strip_prefix("invalid user ").unwrap_or(u);
        let (addr, port) = ip_port(tail)?;
        return Some(preauth_event(user(u), addr, port));
    }
    // Remaining forms only count before authentication: after a session
    // "Connection closed by <ip>" is a normal logout.
    let pre_forms: [(&str, bool); 5] = [
        ("Connection closed by ", true),
        ("Disconnected from ", true),
        ("Connection reset by ", true),
        ("Received disconnect from ", false),
        ("Timeout before authentication for ", false),
    ];
    for (prefix, may_have_user) in pre_forms {
        let Some(rest) = msg.strip_prefix(prefix) else {
            continue;
        };
        if !preauth && !prefix.starts_with("Timeout") {
            return None;
        }
        let rest = rest.strip_prefix("connection from ").unwrap_or(rest);
        if may_have_user {
            for who in ["authenticating user ", "invalid user ", "user "] {
                if let Some(r) = rest.strip_prefix(who) {
                    let (u, addr, port) = user_then_ip(r)?;
                    return Some(preauth_event(u, addr, port));
                }
            }
        }
        let (addr, port) = ip_port(rest)?;
        return Some(preauth_event(None, addr, port));
    }
    // Scanners that never finish the handshake.
    for prefix in [
        "Did not receive identification string from ",
        "Unable to negotiate with ",
        "banner exchange: Connection from ",
        "kex_exchange_identification: Connection closed by remote host from ",
    ] {
        if let Some(rest) = msg.strip_prefix(prefix) {
            let (addr, port) = ip_port(rest.trim_end_matches(':'))?;
            return Some(preauth_event(None, addr, port));
        }
    }
    None
}

fn preauth_event(user: Option<String>, addr: IpAddr, port: Option<u16>) -> AuthEvent {
    AuthEvent {
        kind: AuthKind::Preauth,
        user,
        addr,
        port,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn p(s: &str) -> AuthEvent {
        parse_sshd(s).unwrap_or_else(|| panic!("no parse: {s}"))
    }

    #[test]
    fn accepted_with_fingerprint() {
        let e = p(
            "Accepted publickey for alice from 203.0.113.9 port 50022 ssh2: ED25519 SHA256:AbCdEf0123456789+/xyz",
        );
        assert_eq!(e.user.as_deref(), Some("alice"));
        assert_eq!(e.addr.to_string(), "203.0.113.9");
        assert_eq!(e.port, Some(50022));
        assert_eq!(
            e.kind,
            AuthKind::Accepted {
                method: LoginMethod::PublicKey,
                fingerprint: Some("SHA256:AbCdEf0123456789+/xyz".into())
            }
        );
        assert!(!e.is_failure());
        let e = p("Accepted keyboard-interactive/pam for bob from 2001:db8::1 port 2 ssh2");
        assert!(matches!(
            e.kind,
            AuthKind::Accepted {
                method: LoginMethod::KeyboardInteractive,
                fingerprint: None
            }
        ));
        assert_eq!(e.addr.to_string(), "2001:db8::1");
    }

    #[test]
    fn failures() {
        let e = p("Failed password for invalid user admin from 198.51.100.7 port 4242 ssh2");
        assert_eq!(
            e.kind,
            AuthKind::Failed {
                method: LoginMethod::Password,
                invalid_user: true
            }
        );
        assert_eq!(e.user.as_deref(), Some("admin"));
        assert!(e.is_failure());
        let e = p("Failed publickey for root from 198.51.100.7 port 1 ssh2: RSA SHA256:x");
        assert!(!e.is_failure());
        let e = p("Invalid user oracle from 198.51.100.7 port 33");
        assert_eq!(
            (e.kind.clone(), e.user.as_deref()),
            (AuthKind::InvalidUser, Some("oracle"))
        );
        // An attacker-chosen user name containing " from <ip>".
        let e = p("Invalid user x from 10.0.0.1 port 1 from 198.51.100.7 port 33");
        assert_eq!(e.addr.to_string(), "198.51.100.7");
        let e = p(
            "error: maximum authentication attempts exceeded for root from 192.0.2.1 port 5 ssh2 [preauth]",
        );
        assert_eq!(e.kind, AuthKind::Preauth);
        assert_eq!(e.user.as_deref(), Some("root"));
    }

    #[test]
    fn preauth_forms() {
        for (m, user) in [
            ("Connection closed by 192.0.2.1 port 22 [preauth]", None),
            (
                "Connection closed by authenticating user root 192.0.2.1 port 22 [preauth]",
                Some("root"),
            ),
            (
                "Disconnected from invalid user test 192.0.2.1 port 22 [preauth]",
                Some("test"),
            ),
            (
                "Received disconnect from 192.0.2.1 port 22:11: Bye Bye [preauth]",
                None,
            ),
            ("Connection reset by 192.0.2.1 port 22 [preauth]", None),
            (
                "Did not receive identification string from 192.0.2.1 port 22",
                None,
            ),
            (
                "Unable to negotiate with 192.0.2.1 port 22: no matching key exchange method found.",
                None,
            ),
            (
                "banner exchange: Connection from 192.0.2.1 port 22: invalid format",
                None,
            ),
            (
                "Timeout before authentication for connection from 192.0.2.1 to 10.0.0.2, pid = 7",
                None,
            ),
        ] {
            let e = p(m);
            assert_eq!(e.kind, AuthKind::Preauth, "{m}");
            assert_eq!(e.addr.to_string(), "192.0.2.1", "{m}");
            assert_eq!(e.user.as_deref(), user, "{m}");
        }
        // After a session these are normal logouts.
        assert_eq!(parse_sshd("Connection closed by 192.0.2.1 port 22"), None);
        assert_eq!(
            parse_sshd("Disconnected from user alice 192.0.2.1 port 22"),
            None
        );
        assert_eq!(parse_sshd("Server listening on :: port 22."), None);
        assert_eq!(
            parse_sshd("Accepted password for x from not-an-ip port 1"),
            None
        );
    }

    proptest! {
        #[test]
        fn never_panics(s in "\\PC*") {
            let _ = parse_sshd(&s);
        }

        #[test]
        fn never_panics_near_grammar(
            head in prop::sample::select(vec![
                "Accepted publickey for ", "Failed password for invalid user ", "Invalid user ",
                "Connection closed by authenticating user ", "Disconnected from ", "Received disconnect from ",
                "maximum authentication attempts exceeded for ", "Unable to negotiate with ",
            ]),
            mid in "[ a-z0-9.:/\\[\\]]{0,40}",
            tail in prop::sample::select(vec!["", " port 22", " from 1.2.3.4 port 99 ssh2", " [preauth]", " 1.2.3.4 port 1 [preauth]"]),
        ) {
            let s = format!("{head}{mid}{tail}");
            if let Some(e) = parse_sshd(&s) {
                prop_assert!(e.user.as_ref().is_none_or(|u| u.chars().count() <= MAX_USER));
            }
        }
    }
}
