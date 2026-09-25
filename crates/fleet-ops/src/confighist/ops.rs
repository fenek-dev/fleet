//! `config.*` operations.
//!
//! - `config.history{path?, range, limit}`: newest first; one file's
//!   versions, or every file's in the time range.
//! - `config.diff{path, from, to?}`: unified diff of two versions (`to:
//!   None` = the file now). Secret versions answer a hash-only summary,
//!   binary or unstored content a size/hash summary with `binary: true`.
//! - `config.rollback{path, version}`: restores a kept version atomically
//!   (mode and owner of the current file kept), recorded as a new version
//!   attributed to this operation. Protected paths are Elevated by the
//!   catalog's tier; Fleet-owned paths and `/etc/fleet` are refused;
//!   secrets (no content) and deletions can't be restored. Not an
//!   auto-revert op: a rollback is undone by rolling back again.
//! - `config.paths.get` / `config.paths.set` (versioned). Tracking a path
//!   outside `/etc`, `/srv`, `/opt`, `/usr/local/etc` is Elevated.

use super::content::{self, as_text};
use super::diff::unified;
use super::rules::{PathRules, under_operator_roots};
use super::write::{Perms, replace};
use super::{ConfigTracker, OperatorPaths, VersionRecord, store_err, to_version};
use crate::ctx::SysCtx;
use crate::files::walk::open_file;
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, Registry};
use fleet_proto::args::{AbsPath, TimeRange};
use fleet_proto::op::tag;
use fleet_proto::payload::{ConfigDiff, ConfigHistory, ConfigPaths, ConfigVersion};
use fleet_proto::{ErrorCode, Hash32, Op, Payload};
use std::rc::Rc;

pub const TAGS: [u16; 5] = [
    tag::CONFIG_HISTORY,
    tag::CONFIG_DIFF,
    tag::CONFIG_ROLLBACK,
    tag::CONFIG_PATHS_GET,
    tag::CONFIG_PATHS_SET,
];

/// Bytes of history rows per answer (paths dominate; the frame is 1 MiB).
const MAX_HISTORY_BYTES: usize = 768 * 1024;

pub struct ConfigOps(pub Rc<ConfigTracker>);

impl ConfigOps {
    pub fn register(tracker: Rc<ConfigTracker>, r: &mut Registry) {
        let h: Rc<dyn OpHandler> = Rc::new(Self(tracker));
        for t in TAGS {
            r.register(t, h.clone());
        }
    }

    fn history(
        &self,
        path: Option<&AbsPath>,
        range: TimeRange,
        limit: u32,
    ) -> Result<ConfigHistory, OpError> {
        let store = self.0.store();
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        let (since, until) = (
            range.since_ms.unwrap_or(0),
            range.until_ms.unwrap_or(u64::MAX),
        );
        let in_range = |t: u64| t >= since && t < until;
        let mut versions: Vec<ConfigVersion> = Vec::new();
        let mut truncated = false;
        let mut bytes = 0usize;
        let mut push = |v: ConfigVersion, versions: &mut Vec<ConfigVersion>| -> bool {
            bytes += v.path.len() + 96;
            if versions.len() >= limit || bytes > MAX_HISTORY_BYTES {
                return false;
            }
            versions.push(v);
            true
        };
        match path {
            Some(p) => {
                let all = store.versions(p.as_str()).map_err(store_err)?;
                for (ver, rec) in all.iter().rev().filter(|(_, r)| in_range(r.time_ms)) {
                    if !push(to_version(p.as_str(), *ver, rec), &mut versions) {
                        truncated = true;
                        break;
                    }
                }
            }
            None => {
                let mut rows: Vec<(String, u64)> = Vec::new();
                store
                    .timeline(since, until, true, &mut |_, p, v| {
                        if rows.len() > limit {
                            return false;
                        }
                        rows.push((p.to_owned(), v));
                        true
                    })
                    .map_err(store_err)?;
                for (p, v) in rows {
                    let Some(rec) = store.record(&p, v).map_err(store_err)? else {
                        continue;
                    };
                    if !push(to_version(&p, v, &rec), &mut versions) {
                        truncated = true;
                        break;
                    }
                }
            }
        }
        Ok(ConfigHistory {
            versions,
            truncated,
        })
    }

    fn record(&self, path: &str, version: u64) -> Result<VersionRecord, OpError> {
        self.0
            .store()
            .record(path, version)
            .map_err(store_err)?
            .ok_or_else(|| OpError::new(ErrorCode::NotFound))
    }

    /// Kept content of a version (`None`: secret, unstored or corrupt).
    fn content_of(&self, rec: &VersionRecord) -> Result<Option<Vec<u8>>, OpError> {
        if rec.deleted {
            return Ok(Some(Vec::new()));
        }
        if rec.secret || !rec.has_content() {
            return Ok(None);
        }
        let Some(blob) = self.0.store().blob(&rec.hash).map_err(store_err)? else {
            return Ok(None);
        };
        Ok(content::decompress(&blob, &rec.hash))
    }

    fn diff(
        &self,
        ctx: &SysCtx,
        path: &AbsPath,
        from: u64,
        to: Option<u64>,
    ) -> Result<ConfigDiff, OpError> {
        let p = path.as_str();
        let rules = self.0.rules();
        let a = self.record(p, from)?;
        // (hash, size, secret, content, label)
        let (b_hash, b_size, b_secret, b_data, b_label) = match to {
            Some(v) => {
                let b = self.record(p, v)?;
                let data = self.content_of(&b)?;
                (b.hash, b.size, b.secret, data, format!("b{p}@v{v}"))
            }
            None => current(ctx, p, rules.is_secret(p))?,
        };
        let secret = a.secret || b_secret || rules.is_secret(p);
        let summary = |kind: &str| {
            format!(
                "{kind} {p}: v{from} {} ({} bytes) -> {b_label} {} ({b_size} bytes)\n",
                hex32(&a.hash),
                a.size,
                hex32(&b_hash),
            )
        };
        let mk = |unified: String, binary: bool| ConfigDiff {
            path: p.to_owned(),
            from,
            to,
            unified,
            binary,
        };
        if secret {
            // Hash-only: never content, not even from the live file.
            return Ok(mk(summary("secret"), false));
        }
        if a.hash == b_hash && !a.deleted {
            return Ok(mk(String::new(), false));
        }
        let a_data = self.content_of(&a)?;
        let (Some(a_data), Some(b_data)) = (a_data, b_data) else {
            return Ok(mk(summary("content not kept:"), true));
        };
        match (as_text(&a_data), as_text(&b_data)) {
            (Some(old), Some(new)) => Ok(mk(
                unified(old, new, &format!("a{p}@v{from}"), &b_label),
                false,
            )),
            _ => Ok(mk(summary("binary"), true)),
        }
    }

    /// Checks everything `config.rollback` needs without writing.
    fn rollback_plan(&self, path: &AbsPath, version: u64) -> Result<VersionRecord, OpError> {
        let bad = |d: &'static str| OpError::new(ErrorCode::InvalidArgument).with_detail(d);
        if !PathRules::rollback_allowed(path) {
            return Err(bad("fleet path"));
        }
        let rules = self.0.rules();
        if !rules.is_tracked(path.as_str()) {
            return Err(bad("path not tracked"));
        }
        let rec = self.record(path.as_str(), version)?;
        if rec.secret || rules.is_secret(path.as_str()) {
            return Err(bad("secret: content not kept"));
        }
        if rec.deleted {
            return Err(bad("version is a deletion"));
        }
        if !rec.has_content() {
            return Err(OpError::new(ErrorCode::NotFound).with_detail("content not kept"));
        }
        Ok(rec)
    }

    fn rollback(
        &self,
        ctx: &SysCtx,
        path: &AbsPath,
        version: u64,
        meta: &OpMeta,
    ) -> Result<ConfigHistory, OpError> {
        let seq = meta
            .audit_seq
            .ok_or_else(|| OpError::internal("rollback without audit seq"))?;
        let rec = self.rollback_plan(path, version)?;
        let data = self
            .content_of(&rec)?
            .ok_or_else(|| OpError::internal("stored content missing or corrupt"))?;
        let fallback = Perms {
            mode: rec.mode,
            uid: rec.uid,
            gid: rec.gid,
        };
        replace(ctx, path.as_str(), &data, fallback, seq)
            .map_err(|e| crate::files::walk::io_err(e, "rollback write"))?;
        let v = self
            .0
            .note_write(ctx, path.as_str(), tag::CONFIG_ROLLBACK, seq)?;
        let versions = match v {
            Some(v) => vec![v],
            // Content already equal: nothing new to record.
            None => {
                let st = self.0.store().file(path.as_str()).map_err(store_err)?;
                match st {
                    Some(st) => {
                        let r = self.record(path.as_str(), st.version)?;
                        vec![to_version(path.as_str(), st.version, &r)]
                    }
                    None => Vec::new(),
                }
            }
        };
        Ok(ConfigHistory {
            versions,
            truncated: false,
        })
    }

    fn paths(&self) -> ConfigPaths {
        let r = self.0.rules();
        ConfigPaths {
            builtin_tracked: PathRules::builtin_tracked(),
            builtin_secret: PathRules::builtin_secret(),
            tracked: r.operator.tracked.clone(),
            secret: r.operator.secret.clone(),
            version: r.operator.version,
        }
    }

    /// `config.paths.set` tracking a path outside
    /// [`OPERATOR_ROOTS`](super::rules::OPERATOR_ROOTS) needs
    /// a root-key approval ([`OpHandler::requires_elevated`]); checked here
    /// too, so a handler reached without exec's escalation step refuses.
    fn check_paths_roots(op: &Op, meta: &OpMeta) -> Result<(), OpError> {
        if paths_set_escalates(op) && (meta.approval.is_none() || meta.command.approval.is_none()) {
            return Err(OpError::new(ErrorCode::ApprovalRequired)
                .with_detail("tracked path outside /etc, /srv, /opt, /usr/local/etc"));
        }
        Ok(())
    }

    fn check_paths_version(&self, meta: &OpMeta) -> Result<u64, OpError> {
        let current = self.0.rules().operator.version;
        if meta.command.body.expected_version != Some(current) {
            return Err(ErrorCode::VersionConflict { current }.into());
        }
        Ok(current)
    }
}

/// Whether `op` is a `config.paths.set` tracking a rule outside
/// [`OPERATOR_ROOTS`](super::rules::OPERATOR_ROOTS).
pub fn paths_set_escalates(op: &Op) -> bool {
    matches!(op, Op::ConfigPathsSet { tracked, .. }
        if tracked.iter().any(|p| !under_operator_roots(p.as_str())))
}

/// The live file for a diff: (hash, size, secret, content, label).
#[allow(clippy::type_complexity)]
fn current(
    ctx: &SysCtx,
    p: &str,
    secret_path: bool,
) -> Result<(Hash32, u64, bool, Option<Vec<u8>>, String), OpError> {
    let label = format!("b{p}@now");
    match open_file(ctx, p) {
        Ok((f, m)) => {
            let o = content::observe(f, m, !secret_path, p)
                .map_err(|e| crate::files::walk::io_err(e, "read"))?;
            let secret = secret_path || o.secret;
            Ok((o.hash, m.size, secret, o.data, label))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((
            [0; 32],
            0,
            secret_path,
            Some(Vec::new()),
            format!("b{p}@deleted"),
        )),
        Err(e) => Err(crate::files::walk::io_err(e, "open")),
    }
}

fn hex32(h: &Hash32) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

impl OpHandler for ConfigOps {
    fn validate(&self, _ctx: &SysCtx, op: &Op, meta: &OpMeta) -> Result<(), OpError> {
        op.check_args().map_err(ErrorCode::from)?;
        match op {
            Op::ConfigHistory { .. } | Op::ConfigDiff { .. } | Op::ConfigPathsGet => Ok(()),
            Op::ConfigRollback { path, version } => self.rollback_plan(path, *version).map(|_| ()),
            Op::ConfigPathsSet { .. } => {
                Self::check_paths_roots(op, meta)?;
                self.check_paths_version(meta).map(|_| ())
            }
            _ => Err(ErrorCode::Unsupported.into()),
        }
    }

    fn requires_elevated(&self, _ctx: &SysCtx, op: &Op, _meta: &OpMeta) -> Result<bool, OpError> {
        Ok(paths_set_escalates(op))
    }

    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        op: &'a Op,
        meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            let p = match op {
                Op::ConfigHistory { path, range, limit } => {
                    Payload::ConfigHistory(self.history(path.as_ref(), *range, *limit)?)
                }
                Op::ConfigDiff { path, from, to } => {
                    Payload::ConfigDiff(self.diff(ctx, path, *from, *to)?)
                }
                Op::ConfigRollback { path, version } => {
                    Payload::ConfigHistory(self.rollback(ctx, path, *version, meta)?)
                }
                Op::ConfigPathsGet => Payload::ConfigPaths(self.paths()),
                Op::ConfigPathsSet { tracked, secret } => {
                    Self::check_paths_roots(op, meta)?;
                    let current = self.check_paths_version(meta)?;
                    self.0.set_operator_paths(OperatorPaths {
                        tracked: tracked.iter().map(|p| p.as_str().to_owned()).collect(),
                        secret: secret.iter().map(|p| p.as_str().to_owned()).collect(),
                        version: current + 1,
                    })?;
                    Payload::ConfigPaths(self.paths())
                }
                _ => return Err(ErrorCode::Unsupported.into()),
            };
            Ok(OpOutput::Payload(p))
        })
    }
}
