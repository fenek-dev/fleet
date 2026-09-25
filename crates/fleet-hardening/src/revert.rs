//! Auto-revert for `profile.apply` (`ChangeKind::Profile`, design §4.10).
//!
//! The snapshot, taken by exec before the handler runs, holds every file
//! the in-scope modules of the op's phase may write (content and mode, or
//! absence), the firewall table and its model version when
//! `firewall.baseline` is in scope, and each module's reload group: its
//! validators followed by its reloads (`sshd -t` then the ssh reload,
//! `sysctl --system`, …). Restoring writes the files back, restores the
//! table, then runs the groups: within a group the first failure skips
//! the rest (a restored `sshd_config` that fails `sshd -t` is never
//! reloaded; the error is reported), and every group is tried.
//!
//! The firewall part is restored only while the table is still what the
//! profile apply left: the handler reports the table's model version
//! after the apply as the change's `new_version`, and a different current
//! version (known) skips the table, keeping the newer rules. Exec also
//! claims `ChangeKind::Firewall` for such a change, so no
//! `firewall.apply` can run while it is pending.
//!
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
const SNAPSHOT_V2: u8 = 2;

/// One argv (program from [`RELOAD_PROGRAMS`]).
pub type ReloadCmd = (String, Vec<String>);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub files: Vec<FileSnap>,
    /// Encoded `fleet_ops::firewall::Snapshot`.
    pub firewall: Option<Vec<u8>>,
    /// The table's model version when snapshotted (`None`: unknown or
    /// firewall not in scope). A table still at this version needs no
    /// restore.
    pub firewall_version: Option<u64>,
    /// Per module: validators, then reloads. The first failing command
    /// skips the rest of its group.
    pub reload: Vec<Vec<ReloadCmd>>,
}

/// Snapshots written by agents before reload groups.
#[derive(Deserialize)]
struct SnapshotV1 {
    files: Vec<FileSnap>,
    firewall: Option<Vec<u8>>,
    reload: Vec<ReloadCmd>,
}

/// A flat V1 reload list as groups: `sshd -t` belongs to the command
/// after it; everything else stands alone.
fn groups_of_v1(flat: Vec<ReloadCmd>) -> Vec<Vec<ReloadCmd>> {
    let mut out: Vec<Vec<ReloadCmd>> = Vec::new();
    let mut open = false;
    for c in flat {
        let validator = c.0 == ssh::SSHD && c.1 == ["-t"];
        match out.last_mut() {
            Some(g) if open => g.push(c),
            _ => out.push(vec![c]),
        }
        open = validator;
    }
    out
}

impl Snapshot {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = vec![SNAPSHOT_V2];
        v.extend(fleet_proto::encode(self));
        v
    }

    pub fn decode(b: &[u8]) -> Result<Self, OpError> {
        let bad = |_| OpError::internal("profile snapshot: undecodable");
        match b.split_first() {
            Some((&SNAPSHOT_V2, rest)) => fleet_proto::decode(rest).map_err(bad),
            Some((&SNAPSHOT_V1, rest)) => {
                let v1: SnapshotV1 = fleet_proto::decode(rest).map_err(bad)?;
                Ok(Self {
                    files: v1.files,
                    firewall: v1.firewall,
                    firewall_version: None,
                    reload: groups_of_v1(v1.reload),
                })
            }
            _ => Err(OpError::internal("profile snapshot: unknown version")),
        }
    }
}

/// What a profile apply of `spec` may touch, as found now.
pub fn take(sys: &SysCtx, op: &Op) -> Result<Snapshot, OpError> {
    let Op::ProfileApply { spec, phase, .. } = op else {
        return Err(OpError::internal("profile snapshot of another op"));
    };
    let p = crate::profile::resolve(spec, sys)?;
    let mut files: Vec<FileSnap> = Vec::new();
    let mut reload: Vec<Vec<ReloadCmd>> = Vec::new();
    let mut firewall = None;
    let mut firewall_version = None;
    for m in engine::modules_of(&p) {
        // Only what this phase runs: a revert must not roll back (or
        // reload for) modules another phase applied meanwhile.
        if !engine::runs(&p, m.as_ref(), *phase) || p.is_skipped(m.id()) {
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
        let group: Vec<ReloadCmd> = m
            .reload(&p)
            .into_iter()
            .map(|c| (c.program.to_owned(), c.args))
            .collect();
        if !group.is_empty() && !reload.contains(&group) {
            reload.push(group);
        }
        if m.id() == "firewall.baseline" {
            let snap = FirewallRevert::take_snapshot(sys)?;
            firewall_version = match &snap {
                fleet_ops::firewall::Snapshot::Model(set) => {
                    Some(fleet_ops::firewall::model::version(set))
                }
                fleet_ops::firewall::Snapshot::Absent => {
                    Some(fleet_ops::firewall::model::ABSENT_VERSION)
                }
                fleet_ops::firewall::Snapshot::Raw(_) => None,
            };
            firewall = Some(snap.encode());
        }
    }
    Ok(Snapshot {
        files,
        firewall,
        firewall_version,
        reload,
    })
}

/// Whether the firewall part of a snapshot should be put back, given the
/// change's `new_version` (the table's version right after the apply)
/// and the table's version now (`None`: unknown).
pub fn restore_firewall(snap: &Snapshot, new_version: Option<u64>, now: Option<u64>) -> bool {
    match (now, snap.firewall_version, new_version) {
        // Already the snapshotted table.
        (Some(n), Some(before), _) if n == before => false,
        // Changed since the apply: keep the newer table.
        (Some(n), _, Some(after)) if n != after => false,
        // Unknown, or still what the apply left: restore (lockout-safe).
        _ => true,
    }
}

/// Puts a snapshot back; every part is tried, the first error returned.
pub fn restore(sys: &SysCtx, snap: &Snapshot, new_version: Option<u64>) -> Result<(), OpError> {
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
        if restore_firewall(snap, new_version, FirewallRevert::current_version(sys)) {
            keep(FirewallRevert.restore(sys, fw));
        } else {
            eprintln!("profile revert: firewall table changed since the apply; kept");
        }
    }
    for group in &snap.reload {
        for (program, args) in group {
            let Some(p) = RELOAD_PROGRAMS.iter().find(|p| **p == program.as_str()) else {
                keep(Err(OpError::internal(format!("snapshot names {program}"))));
                break;
            };
            if let Err(e) = run_checked_blocking(sys, &Cmd::new(p, args.iter().cloned())) {
                // A validator failed (e.g. `sshd -t` of the restored
                // files): don't reload a config the daemon would reject.
                keep(Err(OpError::internal(format!(
                    "reload skipped: {}",
                    e.detail().unwrap_or(program)
                ))));
                break;
            }
        }
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
        restore(ctx, &Snapshot::decode(snapshot)?, None)
    }

    fn restore_versioned(
        &self,
        ctx: &SysCtx,
        snapshot: &[u8],
        new_version: Option<u64>,
    ) -> Result<(), OpError> {
        restore(ctx, &Snapshot::decode(snapshot)?, new_version)
    }
}
