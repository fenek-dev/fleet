//! Auto-revert for `profile.apply` (`ChangeKind::Profile`, design §4.10).
//!
//! The snapshot, taken by exec before the handler runs, holds every file
//! the in-scope modules may write (content and mode, or absence), the
//! firewall table when `firewall.baseline` is in scope, and the reload
//! commands that make restored files take effect (`sshd -t` + reload,
//! `sysctl --system`, …). Restoring writes the files back, restores the
//! table, then runs the reloads, trying every step even when one fails.
//! Package installs, unit enables and users created are not undone: they
//! can't lock the operator out, and the next plan shows them.

use crate::engine;
use crate::exec::{remove_file, run_checked_blocking, write_file};
use crate::module::{Cmd, FileSnap, read_file};
use crate::modules::{SYSTEMCTL, kernel, ssh, system};
use fleet_ops::firewall::FirewallRevert;
use fleet_ops::handler::OpError;
use fleet_ops::{Revertible, SysCtx};
use fleet_proto::Op;
use serde::{Deserialize, Serialize};

/// Programs a snapshot's reload list may name (anything else is refused
/// on restore).
pub const RELOAD_PROGRAMS: &[&str] = &[SYSTEMCTL, ssh::SSHD, kernel::SYSCTL, system::AUGENRULES];

const SNAPSHOT_V1: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub files: Vec<FileSnap>,
    /// Encoded `fleet_ops::firewall::Snapshot`.
    pub firewall: Option<Vec<u8>>,
    pub reload: Vec<(String, Vec<String>)>,
}

impl Snapshot {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = vec![SNAPSHOT_V1];
        v.extend(fleet_proto::encode(self));
        v
    }

    pub fn decode(b: &[u8]) -> Result<Self, OpError> {
        match b.split_first() {
            Some((&SNAPSHOT_V1, rest)) => fleet_proto::decode(rest)
                .map_err(|_| OpError::internal("profile snapshot: undecodable")),
            _ => Err(OpError::internal("profile snapshot: unknown version")),
        }
    }
}

/// What a profile apply of `spec` may touch, as found now.
pub fn take(sys: &SysCtx, op: &Op) -> Result<Snapshot, OpError> {
    let Op::ProfileApply { spec, .. } = op else {
        return Err(OpError::internal("profile snapshot of another op"));
    };
    let p = crate::profile::resolve(spec, sys)?;
    let mut files: Vec<FileSnap> = Vec::new();
    let mut reload: Vec<(String, Vec<String>)> = Vec::new();
    let mut firewall = None;
    for m in engine::modules_of(&p) {
        if !p.in_scope(m.id()) || p.is_skipped(m.id()) {
            continue;
        }
        for path in m.paths(&p) {
            if !files.iter().any(|f| f.path == path) {
                files.push(FileSnap {
                    prior: read_file(sys, &path)?,
                    path,
                });
            }
        }
        for c in m.reload(&p) {
            let entry = (c.program.to_owned(), c.args);
            if !reload.contains(&entry) {
                reload.push(entry);
            }
        }
        if m.id() == "firewall.baseline" {
            firewall = Some(FirewallRevert::take_snapshot(sys)?.encode());
        }
    }
    Ok(Snapshot {
        files,
        firewall,
        reload,
    })
}

/// Puts a snapshot back; every step is tried, the first error returned.
pub fn restore(sys: &SysCtx, snap: &Snapshot) -> Result<(), OpError> {
    let mut first: Option<OpError> = None;
    let mut keep = |r: Result<(), OpError>| {
        if let Err(e) = r
            && first.is_none()
        {
            first = Some(e);
        }
    };
    for f in snap.files.iter().rev() {
        keep(match &f.prior {
            Some((bytes, mode)) => write_file(sys, &f.path, bytes, *mode),
            None => remove_file(sys, &f.path),
        });
    }
    if let Some(fw) = &snap.firewall {
        keep(FirewallRevert.restore(sys, fw));
    }
    for (program, args) in &snap.reload {
        let Some(p) = RELOAD_PROGRAMS.iter().find(|p| **p == program.as_str()) else {
            keep(Err(OpError::internal(format!("snapshot names {program}"))));
            continue;
        };
        keep(run_checked_blocking(sys, &Cmd::new(p, args.iter().cloned())).map(drop));
    }
    first.map_or(Ok(()), Err)
}

/// The `Revertible` registered for `ChangeKind::Profile`.
#[derive(Default)]
pub struct ProfileRevert;

impl Revertible for ProfileRevert {
    fn snapshot(&self, ctx: &SysCtx, op: &Op) -> Result<Vec<u8>, OpError> {
        Ok(take(ctx, op)?.encode())
    }

    fn restore(&self, ctx: &SysCtx, snapshot: &[u8]) -> Result<(), OpError> {
        restore(ctx, &Snapshot::decode(snapshot)?)
    }
}
