//! `certs.list` (design §2.4): TLS certificates found under configured
//! glob patterns (Let's Encrypt, Caddy), parsed with `x509-parser`; plus
//! the expiry detector (§4.5). Only the leaf (first PEM block) of each
//! file is reported; private keys are never read (patterns name
//! certificate files only, and non-`CERTIFICATE` blocks are skipped).

use crate::ctx::SysCtx;
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput};
use fleet_proto::payload::{CertInfo, Certs};
use fleet_proto::{Event, Op, Payload};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use x509_parser::extensions::GeneralName;
use x509_parser::pem::Pem;

/// Default search patterns. `*` matches within one path component.
pub const DEFAULT_PATTERNS: &[&str] = &[
    "/etc/letsencrypt/live/*/cert.pem",
    "/var/lib/caddy/.local/share/caddy/certificates/*/*/*.crt",
];
pub const MAX_FILES: usize = 1_000;
pub const MAX_CERT_FILE: u64 = 1 << 20;
const MAX_SUBJECTS: usize = 100;
/// Default warning horizon for `cert.expiring`.
pub const WARN_BEFORE_MS: u64 = 14 * 86_400_000;

fn component_matches(pat: &str, name: &str) -> bool {
    if name.starts_with('.') && !pat.starts_with('.') {
        return false;
    }
    match pat.split_once('*') {
        None => pat == name,
        Some((pre, post)) => {
            name.len() >= pre.len() + post.len() && name.starts_with(pre) && name.ends_with(post)
        }
    }
}

/// Expands one pattern under the context root. Symlinks are followed
/// (Let's Encrypt's `live/` links into `archive/`) but every result must
/// resolve inside the root.
pub fn expand(ctx: &SysCtx, pattern: &str) -> Vec<(String, PathBuf)> {
    let Ok(root) = ctx.root().canonicalize() else {
        return Vec::new();
    };
    let mut level: Vec<(String, PathBuf)> = vec![(String::new(), ctx.root().to_path_buf())];
    for comp in pattern.split('/').filter(|c| !c.is_empty()) {
        let mut next = Vec::new();
        for (abs, dir) in &level {
            if comp.contains('*') {
                let Ok(rd) = std::fs::read_dir(dir) else {
                    continue;
                };
                for e in rd.flatten() {
                    let Some(name) = e.file_name().to_str().map(str::to_owned) else {
                        continue;
                    };
                    if component_matches(comp, &name) {
                        next.push((format!("{abs}/{name}"), dir.join(&name)));
                    }
                }
            } else if comp != "." && comp != ".." {
                next.push((format!("{abs}/{comp}"), dir.join(comp)));
            }
            if next.len() > MAX_FILES {
                break;
            }
        }
        next.sort();
        next.truncate(MAX_FILES);
        level = next;
    }
    level
        .into_iter()
        .filter(|(_, p)| {
            p.canonicalize()
                .is_ok_and(|c| c.starts_with(&root) && c.is_file())
        })
        .collect()
}

fn read_capped(p: &Path) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    std::fs::File::open(p)
        .ok()?
        .take(MAX_CERT_FILE)
        .read_to_end(&mut buf)
        .ok()?;
    Some(buf)
}

fn ms(ts: i64) -> u64 {
    u64::try_from(ts).unwrap_or(0).saturating_mul(1000)
}

/// Parses the first certificate of a PEM file.
pub fn parse_pem(source: &str, data: &[u8]) -> Option<CertInfo> {
    let pem: Pem = Pem::iter_from_buffer(data)
        .take(16)
        .filter_map(Result::ok)
        .find(|p| p.label == "CERTIFICATE")?;
    let cert = pem.parse_x509().ok()?;
    let mut subjects: Vec<String> = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for n in &san.value.general_names {
            match n {
                GeneralName::DNSName(d) => subjects.push((*d).chars().take(256).collect()),
                GeneralName::IPAddress(b) => {
                    let ip = match b.len() {
                        4 => <[u8; 4]>::try_from(*b).ok().map(std::net::IpAddr::from),
                        16 => <[u8; 16]>::try_from(*b).ok().map(std::net::IpAddr::from),
                        _ => None,
                    };
                    subjects.extend(ip.map(|i| i.to_string()));
                }
                _ => {}
            }
            if subjects.len() >= MAX_SUBJECTS {
                break;
            }
        }
    }
    if subjects.is_empty() {
        subjects.extend(
            cert.subject()
                .iter_common_name()
                .filter_map(|a| a.as_str().ok())
                .map(|s| s.chars().take(256).collect()),
        );
    }
    let v = cert.validity();
    Some(CertInfo {
        source: source.to_owned(),
        subjects,
        issuer: cert.issuer().to_string().chars().take(512).collect(),
        not_before_ms: ms(v.not_before.timestamp()),
        not_after_ms: ms(v.not_after.timestamp()),
        sha256: Sha256::digest(&pem.contents).into(),
    })
}

pub fn collect(ctx: &SysCtx, patterns: &[String]) -> Certs {
    let mut certs = Vec::new();
    for pat in patterns {
        for (abs, path) in expand(ctx, pat) {
            if certs.len() >= MAX_FILES {
                break;
            }
            if let Some(c) = read_capped(&path).and_then(|d| parse_pem(&abs, &d)) {
                certs.push(c);
            }
        }
    }
    Certs { certs }
}

/// `certs.list`.
pub struct CertsHandler {
    patterns: Vec<String>,
}

impl Default for CertsHandler {
    fn default() -> Self {
        Self::new(DEFAULT_PATTERNS.iter().map(|s| (*s).to_owned()).collect())
    }
}

impl CertsHandler {
    pub fn new(patterns: Vec<String>) -> Self {
        Self { patterns }
    }
}

impl OpHandler for CertsHandler {
    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        _op: &'a Op,
        _meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            Ok(OpOutput::Payload(Payload::Certs(collect(
                ctx,
                &self.patterns,
            ))))
        })
    }
}

/// Emits `cert.expiring` once per (source, notAfter) inside the horizon;
/// a renewed certificate (new notAfter) re-arms it.
pub struct CertWatcher {
    warn_before_ms: u64,
    notified: BTreeSet<(String, u64)>,
}

impl Default for CertWatcher {
    fn default() -> Self {
        Self::new(WARN_BEFORE_MS)
    }
}

impl CertWatcher {
    pub fn new(warn_before_ms: u64) -> Self {
        Self {
            warn_before_ms,
            notified: BTreeSet::new(),
        }
    }

    pub fn observe(&mut self, certs: &Certs, now_ms: u64) -> Vec<Event> {
        let live: BTreeSet<(String, u64)> = certs
            .certs
            .iter()
            .map(|c| (c.source.clone(), c.not_after_ms))
            .collect();
        self.notified.retain(|k| live.contains(k));
        certs
            .certs
            .iter()
            .filter(|c| c.not_after_ms <= now_ms.saturating_add(self.warn_before_ms))
            .filter(|c| self.notified.insert((c.source.clone(), c.not_after_ms)))
            .map(|c| Event::CertExpiring {
                source: c.source.clone(),
                subject: c.subjects.first().cloned().unwrap_or_default(),
                not_after_ms: c.not_after_ms,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FakeRunner;
    use crate::test_util::ctx_at;
    use std::rc::Rc;

    const PEM: &[u8] = include_bytes!("../../tests/fixtures/cert.pem");

    #[test]
    fn parses_fixture() {
        let c = parse_pem("/x", PEM).unwrap();
        assert_eq!(c.subjects, ["example.com", "www.example.com", "192.0.2.1"]);
        assert!(c.issuer.contains("CN=example.com"), "{}", c.issuer);
        assert_eq!(c.not_after_ms - c.not_before_ms, 30 * 86_400_000);
        assert_eq!(c.sha256[..2], [0x7a, 0x3c]);
        assert!(
            parse_pem(
                "/x",
                b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
            )
            .is_none()
        );
        assert!(parse_pem("/x", b"junk").is_none());
    }

    #[test]
    fn scans_patterns_and_warns_once() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::create_dir_all(d.join("etc/letsencrypt/archive/a.example")).unwrap();
        std::fs::create_dir_all(d.join("etc/letsencrypt/live/a.example")).unwrap();
        std::fs::create_dir_all(d.join("etc/letsencrypt/live/escape")).unwrap();
        std::fs::write(d.join("etc/letsencrypt/archive/a.example/cert1.pem"), PEM).unwrap();
        std::os::unix::fs::symlink(
            "../../archive/a.example/cert1.pem",
            d.join("etc/letsencrypt/live/a.example/cert.pem"),
        )
        .unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), PEM).unwrap();
        std::os::unix::fs::symlink(
            outside.path(),
            d.join("etc/letsencrypt/live/escape/cert.pem"),
        )
        .unwrap();
        let caddy = d.join("var/lib/caddy/.local/share/caddy/certificates/acme-v02/b.example");
        std::fs::create_dir_all(&caddy).unwrap();
        std::fs::write(caddy.join("b.example.crt"), PEM).unwrap();
        std::fs::write(
            caddy.join("b.example.key"),
            "-----BEGIN EC PRIVATE KEY-----",
        )
        .unwrap();

        let ctx = ctx_at(d, Rc::new(FakeRunner::new()));
        let certs = collect(&ctx, &CertsHandler::default().patterns);
        let sources: Vec<&str> = certs.certs.iter().map(|c| c.source.as_str()).collect();
        assert_eq!(
            sources,
            [
                "/etc/letsencrypt/live/a.example/cert.pem",
                "/var/lib/caddy/.local/share/caddy/certificates/acme-v02/b.example/b.example.crt"
            ]
        );

        let mut w = CertWatcher::default();
        let na = certs.certs[0].not_after_ms;
        assert!(w.observe(&certs, na - 20 * 86_400_000).is_empty());
        let ev = w.observe(&certs, na - 10 * 86_400_000);
        assert_eq!(ev.len(), 2);
        assert!(matches!(&ev[0], Event::CertExpiring { subject, .. } if subject == "example.com"));
        assert!(w.observe(&certs, na - 9 * 86_400_000).is_empty());
    }

    #[test]
    fn component_glob() {
        assert!(component_matches("*.crt", "a.crt"));
        assert!(!component_matches("*.crt", "a.key"));
        assert!(!component_matches("*", ".hidden"));
        assert!(component_matches(".local", ".local"));
        assert!(!component_matches("ab*ba", "aba"));
    }
}
