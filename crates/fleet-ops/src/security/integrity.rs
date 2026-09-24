//! `integrity.status` (design §2.4): BLAKE3 hashes plus mode/owner of a
//! list of critical files, compared with a baseline that exec stores
//! (through [`BaselineStore`]). The first run with no baseline records
//! one and reports no violations.
//!
//! Package upgrades legitimately change binaries on the list; re-baselining
//! after `dpkg` runs is exec's job (not wired yet).

use crate::ctx::SysCtx;
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput};
use fleet_proto::payload::{IntegrityKind, IntegrityStatus, IntegrityViolation};
use fleet_proto::{Event, Op, Payload};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::rc::Rc;

/// Files whose change means compromise or a serious misconfiguration.
pub const DEFAULT_CRITICAL: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/pam.d/common-auth",
    "/etc/pam.d/sshd",
    "/etc/pam.d/sudo",
    "/etc/ld.so.preload",
    "/etc/crontab",
    "/root/.ssh/authorized_keys",
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/passwd",
    "/usr/bin/login",
    "/usr/sbin/sshd",
    "/usr/lib/fleet/fleet-agent",
];
/// Bytes hashed per file at most (the rest counts as unchanged).
pub const MAX_HASH_BYTES: u64 = 256 << 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileState {
    pub hash: [u8; 32],
    /// Permission bits and file type (`st_mode`).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

/// Path → state; `None` = absent when recorded.
pub type Baseline = BTreeMap<String, Option<FileState>>;

pub fn file_state(ctx: &SysCtx, abs: &str) -> Option<FileState> {
    let p = ctx.path(abs)?;
    let f = std::fs::File::open(p).ok()?;
    let m = f.metadata().ok()?;
    if !m.is_file() {
        return None;
    }
    let mut h = blake3::Hasher::new();
    let mut r = f.take(MAX_HASH_BYTES);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = r.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(FileState {
        hash: *h.finalize().as_bytes(),
        mode: m.mode(),
        uid: m.uid(),
        gid: m.gid(),
    })
}

pub fn snapshot(ctx: &SysCtx, paths: &[String]) -> Baseline {
    paths
        .iter()
        .map(|p| (p.clone(), file_state(ctx, p)))
        .collect()
}

/// Differences between a baseline and the current snapshot. Paths only in
/// `current` (list grew) are not violations.
pub fn compare(baseline: &Baseline, current: &Baseline, now_ms: u64) -> Vec<IntegrityViolation> {
    let mut out = Vec::new();
    for (path, cur) in current {
        let Some(base) = baseline.get(path) else {
            continue;
        };
        let kind = match (base, cur) {
            (None, None) => continue,
            (Some(_), None) => IntegrityKind::Missing,
            (None, Some(_)) => IntegrityKind::Added,
            (Some(b), Some(c)) if b.hash != c.hash => IntegrityKind::Modified,
            (Some(b), Some(c)) if (b.mode, b.uid, b.gid) != (c.mode, c.uid, c.gid) => {
                IntegrityKind::PermissionsChanged
            }
            _ => continue,
        };
        out.push(IntegrityViolation {
            path: path.clone(),
            kind,
            detected_ms: now_ms,
        });
    }
    out
}

/// Where exec keeps the baseline (its redb store in production).
pub trait BaselineStore {
    fn load(&self) -> Option<Baseline>;
    fn save(&self, b: &Baseline) -> Result<(), OpError>;
}

#[derive(Default)]
pub struct MemoryBaselineStore(RefCell<Option<Baseline>>);

impl BaselineStore for MemoryBaselineStore {
    fn load(&self) -> Option<Baseline> {
        self.0.borrow().clone()
    }

    fn save(&self, b: &Baseline) -> Result<(), OpError> {
        *self.0.borrow_mut() = Some(b.clone());
        Ok(())
    }
}

/// `integrity.status`.
pub struct IntegrityHandler {
    store: Rc<dyn BaselineStore>,
    paths: Vec<String>,
}

impl IntegrityHandler {
    pub fn new(store: Rc<dyn BaselineStore>, paths: Vec<String>) -> Self {
        Self { store, paths }
    }

    pub fn with_defaults(store: Rc<dyn BaselineStore>) -> Self {
        Self::new(
            store,
            DEFAULT_CRITICAL.iter().map(|s| (*s).to_owned()).collect(),
        )
    }

    pub fn status(&self, ctx: &SysCtx, now_ms: u64) -> Result<IntegrityStatus, OpError> {
        let current = snapshot(ctx, &self.paths);
        let baseline = match self.store.load() {
            Some(b) => b,
            None => {
                self.store.save(&current)?;
                current.clone()
            }
        };
        Ok(IntegrityStatus {
            checked_ms: now_ms,
            files_checked: current.values().filter(|s| s.is_some()).count() as u64,
            violations: compare(&baseline, &current, now_ms),
        })
    }
}

impl OpHandler for IntegrityHandler {
    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        _op: &'a Op,
        meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            Ok(OpOutput::Payload(Payload::IntegrityStatus(
                self.status(ctx, meta.now_ms)?,
            )))
        })
    }
}

/// Emits `integrity.violation` once per (path, kind) until it clears.
#[derive(Default)]
pub struct IntegrityWatcher {
    reported: BTreeSet<(String, u8)>,
}

impl IntegrityWatcher {
    pub fn observe(&mut self, violations: &[IntegrityViolation]) -> Vec<Event> {
        let cur: BTreeSet<(String, u8)> = violations
            .iter()
            .map(|v| (v.path.clone(), v.kind as u8))
            .collect();
        let events = violations
            .iter()
            .filter(|v| !self.reported.contains(&(v.path.clone(), v.kind as u8)))
            .map(|v| Event::IntegrityViolation {
                path: v.path.clone(),
                kind: v.kind,
            })
            .collect();
        self.reported = cur;
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FakeRunner;
    use crate::test_util::{block, ctx_at, meta};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn baseline_then_violations() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::create_dir_all(d.join("etc")).unwrap();
        for f in ["passwd", "shadow", "group"] {
            std::fs::write(d.join("etc").join(f), f).unwrap();
        }
        let ctx = ctx_at(d, Rc::new(FakeRunner::new()));
        let paths: Vec<String> = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/group",
            "/etc/ld.so.preload",
        ]
        .map(String::from)
        .to_vec();
        let store = Rc::new(MemoryBaselineStore::default());
        let h = IntegrityHandler::new(store.clone(), paths);
        let OpOutput::Payload(Payload::IntegrityStatus(s)) =
            block(h.handle(&ctx, &Op::IntegrityStatus, &meta())).unwrap()
        else {
            panic!()
        };
        assert_eq!((s.files_checked, s.violations.len()), (3, 0));
        assert!(store.load().is_some());

        std::fs::write(d.join("etc/passwd"), "evil").unwrap();
        std::fs::remove_file(d.join("etc/shadow")).unwrap();
        std::fs::set_permissions(d.join("etc/group"), std::fs::Permissions::from_mode(0o666))
            .unwrap();
        std::fs::write(d.join("etc/ld.so.preload"), "/tmp/x.so").unwrap();
        let s = h.status(&ctx, 7).unwrap();
        let kinds: Vec<(&str, IntegrityKind)> = s
            .violations
            .iter()
            .map(|v| (v.path.as_str(), v.kind))
            .collect();
        assert_eq!(
            kinds,
            [
                ("/etc/group", IntegrityKind::PermissionsChanged),
                ("/etc/ld.so.preload", IntegrityKind::Added),
                ("/etc/passwd", IntegrityKind::Modified),
                ("/etc/shadow", IntegrityKind::Missing),
            ]
        );

        let mut w = IntegrityWatcher::default();
        assert_eq!(w.observe(&s.violations).len(), 4);
        assert!(w.observe(&s.violations).is_empty());
        assert!(w.observe(&[]).is_empty());
        assert_eq!(w.observe(&s.violations[..1]).len(), 1);
    }
}
