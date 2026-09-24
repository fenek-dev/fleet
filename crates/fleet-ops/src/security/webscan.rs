//! Web scanner detection (design §4.7) from JSON access-log lines written
//! by Caddy (`http.log.access`) or nginx (`log_format … escape=json`, the
//! web role's format). Pure; every field is attacker-influenced.

use serde_json::Value;
use std::net::IpAddr;

/// One request, as far as the detector cares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessHit {
    pub ip: IpAddr,
    /// Lower-cased path without the query string.
    pub path: String,
    pub status: u16,
}

/// Paths only scanners ask for on a server that doesn't serve them.
/// Matched as substrings of the lower-cased path, and only on 4xx answers
/// (a real WordPress site answers `/wp-login.php` with 200).
pub const SCANNER_PATTERNS: &[&str] = &[
    "/.env",
    "/.git/",
    "/.svn/",
    "/.aws/",
    "/.ds_store",
    "/wp-login.php",
    "/wp-admin",
    "/xmlrpc.php",
    "/phpmyadmin",
    "/pma/",
    "/vendor/phpunit",
    "/cgi-bin/",
    "/boaform",
    "/hnap1",
    "/actuator/",
    "/config.php",
    "/setup.php",
    "/shell.php",
    "/.well-known/security.txt~",
    "/owa/auth",
    "/solr/admin",
    "/console/login",
    "/manager/html",
];

fn str_at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter().try_fold(v, |v, k| v.get(k))?.as_str()
}

fn status_of(v: &Value) -> Option<u16> {
    match v.get("status")? {
        Value::Number(n) => n.as_u64().and_then(|n| u16::try_from(n).ok()),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Parses a Caddy or nginx JSON access line. `None` if it isn't one.
pub fn parse_access_line(line: &[u8]) -> Option<AccessHit> {
    if line.len() > 64 * 1024 {
        return None;
    }
    let v: Value = serde_json::from_slice(line).ok()?;
    let ip = str_at(&v, &["request", "client_ip"])
        .or_else(|| str_at(&v, &["request", "remote_ip"]))
        .or_else(|| str_at(&v, &["remote_addr"]))
        .or_else(|| str_at(&v, &["client_ip"]))?
        .parse()
        .ok()?;
    let uri = str_at(&v, &["request", "uri"])
        .or_else(|| str_at(&v, &["request_uri"]))
        .or_else(|| str_at(&v, &["uri"]))?;
    let path = uri.split(['?', '#']).next().unwrap_or("");
    Some(AccessHit {
        ip,
        path: path
            .chars()
            .take(2048)
            .collect::<String>()
            .to_ascii_lowercase(),
        status: status_of(&v)?,
    })
}

/// Whether this request looks like a vulnerability scan.
pub fn is_scanner_probe(hit: &AccessHit) -> bool {
    (400..500).contains(&hit.status) && SCANNER_PATTERNS.iter().any(|p| hit.path.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn caddy_and_nginx() {
        let caddy = br#"{"level":"info","ts":1700000000.1,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"10.0.0.1","client_ip":"198.51.100.4","method":"GET","host":"x","uri":"/.ENV?x=1"},"status":404}"#;
        let h = parse_access_line(caddy).unwrap();
        assert_eq!(
            (h.ip.to_string().as_str(), h.path.as_str(), h.status),
            ("198.51.100.4", "/.env", 404)
        );
        assert!(is_scanner_probe(&h));
        let nginx = br#"{"time":"2023-11-14T22:13:20+00:00","remote_addr":"2001:db8::5","request_uri":"/wp-login.php","status":"200"}"#;
        let h = parse_access_line(nginx).unwrap();
        assert_eq!(h.status, 200);
        assert!(!is_scanner_probe(&h), "a 200 is a real site");
        let ok = br#"{"remote_addr":"192.0.2.1","request_uri":"/index.html","status":404}"#;
        assert!(!is_scanner_probe(&parse_access_line(ok).unwrap()));
        assert!(
            parse_access_line(br#"{"remote_addr":"nope","request_uri":"/","status":1}"#).is_none()
        );
        assert!(parse_access_line(b"127.0.0.1 - - [x] \"GET / HTTP/1.1\" 200").is_none());
    }

    proptest! {
        #[test]
        fn never_panics(b in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse_access_line(&b);
        }
    }
}
