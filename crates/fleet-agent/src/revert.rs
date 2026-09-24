//! Auto-revert (design §4.10): the `revert <id>` mode and timer arming.
//!
//! Timers are independent transient systemd units, so an exec crash can't
//! cancel a revert. Commands are fixed binary paths plus argument vectors;
//! nothing here builds a shell string.

use crate::paths::{AGENT_BIN, SYSTEMCTL, SYSTEMD_RUN};
use crate::pending::{ChangeId, ChangeKind, PendingDir, PendingError, RevertedMarker};

/// A fixed program plus arguments. Never passed through a shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedCommand {
    pub program: &'static str,
    pub args: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("spawn {0}: {1}")]
    Spawn(&'static str, std::io::Error),
    #[error("{0} exited with {1:?}")]
    Status(&'static str, Option<i32>),
}

/// Runs fixed commands. Tests substitute a recorder.
pub trait Runner {
    fn run(&self, cmd: &FixedCommand) -> Result<(), RunError>;
}

/// Executes via `std::process::Command` (argv, no shell).
pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, cmd: &FixedCommand) -> Result<(), RunError> {
        let status = std::process::Command::new(cmd.program)
            .args(&cmd.args)
            .env_clear()
            .stdin(std::process::Stdio::null())
            .status()
            .map_err(|e| RunError::Spawn(cmd.program, e))?;
        if status.success() {
            Ok(())
        } else {
            Err(RunError::Status(cmd.program, status.code()))
        }
    }
}

pub fn unit_name(id: ChangeId) -> String {
    format!("fleet-revert-{id}")
}

/// `systemd-run --on-active=<secs> --unit=fleet-revert-<id> <agent> revert <id>`.
pub fn timer_command(id: ChangeId, secs: u32) -> FixedCommand {
    FixedCommand {
        program: SYSTEMD_RUN,
        args: vec![
            format!("--on-active={secs}"),
            format!("--unit={}", unit_name(id)),
            AGENT_BIN.to_owned(),
            "revert".to_owned(),
            id.to_hex(),
        ],
    }
}

/// `systemctl stop fleet-revert-<id>.timer` (on `change.confirm`).
pub fn disarm_command(id: ChangeId) -> FixedCommand {
    FixedCommand {
        program: SYSTEMCTL,
        args: vec!["stop".to_owned(), format!("{}.timer", unit_name(id))],
    }
}

pub fn arm_timer(runner: &dyn Runner, id: ChangeId, secs: u32) -> Result<(), RunError> {
    runner.run(&timer_command(id, secs))
}

pub fn disarm_timer(runner: &dyn Runner, id: ChangeId) -> Result<(), RunError> {
    runner.run(&disarm_command(id))
}

/// Restores a snapshot.
pub trait Revert {
    fn revert(&self, kind: ChangeKind, snapshot: &[u8]) -> Result<(), RevertError>;
}

#[derive(Debug, thiserror::Error)]
#[error("revert of {0:?} failed")]
pub struct RevertError(pub ChangeKind);

/// Production reverter: dispatches by kind to the `fleet_ops::Revertible`
/// modules in `Reverters::with_generic()` (the same set exec snapshots
/// with). A kind without a module fails, so the revert is audited as
/// `Failed` rather than falsely claiming the snapshot was restored.
pub struct RegistryRevert {
    pub reverters: fleet_ops::Reverters,
    pub ctx: fleet_ops::SysCtx,
}

impl RegistryRevert {
    pub fn system() -> Self {
        Self {
            reverters: fleet_ops::Reverters::with_generic(),
            ctx: fleet_ops::SysCtx::system(),
        }
    }
}

impl Revert for RegistryRevert {
    fn revert(&self, kind: ChangeKind, snapshot: &[u8]) -> Result<(), RevertError> {
        self.reverters
            .restore(&self.ctx, kind, snapshot)
            .map_err(|e| {
                if e.detail().is_some() {
                    eprintln!("fleet-agent revert {kind:?}: {e}");
                }
                RevertError(kind)
            })
    }
}

/// Always fails (tests; a kind nothing can restore).
pub struct UnavailableRevert;

impl Revert for UnavailableRevert {
    fn revert(&self, kind: ChangeKind, _: &[u8]) -> Result<(), RevertError> {
        Err(RevertError(kind))
    }
}

/// Always succeeds. Unit tests only; integration tests define their own.
#[cfg(test)]
pub struct NoopRevert;

#[cfg(test)]
impl Revert for NoopRevert {
    fn revert(&self, _: ChangeKind, _: &[u8]) -> Result<(), RevertError> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevertOutcome {
    /// Snapshot restored; marker written for exec.
    Reverted,
    /// Restore failed; pending file removed anyway so the timer can't loop.
    Failed,
    /// Already confirmed or reverted.
    NotPending,
}

/// The body of `fleet-agent revert <id>` (and of exec's own deadline
/// check). Touches only the pending files, never redb (exec holds its
/// lock): claims `pending/<id>.bin` (see `pending`), restores, writes
/// `reverted/<id>.bin`, then deletes the claimed file. Exec audits the
/// marker (`Actor::System`, `Outcome::Reverted`).
pub fn run_revert(
    dir: &PendingDir,
    id: ChangeId,
    reverter: &dyn Revert,
    now_ms: u64,
) -> Result<RevertOutcome, PendingError> {
    if !dir.claim(id)? {
        return Ok(RevertOutcome::NotPending);
    }
    finish_claimed(dir, id, reverter, now_ms)
}

/// Restores a change this process claimed (or, at exec startup, one whose
/// revert crashed after claiming).
pub fn finish_claimed(
    dir: &PendingDir,
    id: ChangeId,
    reverter: &dyn Revert,
    now_ms: u64,
) -> Result<RevertOutcome, PendingError> {
    let Some(change) = dir.get_claimed(id)? else {
        return Ok(RevertOutcome::NotPending);
    };
    let restored = reverter.revert(change.kind, &change.snapshot).is_ok();
    // Marker first, then delete: a crash in between leaves both, and exec
    // at startup skips re-reverting a change that already has a marker.
    dir.write_marker(
        id,
        &RevertedMarker {
            kind: change.kind,
            origin_audit_seq: change.audit_seq,
            restored,
            time_ms: now_ms,
        },
    )?;
    dir.remove_claimed(id)?;
    Ok(if restored {
        RevertOutcome::Reverted
    } else {
        RevertOutcome::Failed
    })
}
