//! Auto-revert (design §4.10): the `revert <id>` mode and timer arming.
//!
//! Timers are independent transient systemd units, so an exec crash can't
//! cancel a revert. They run through `fleet_ops::CommandRunner` (fixed
//! binary paths plus argument vectors, cleared environment, a short
//! timeout); nothing here builds a shell string.
//!
//! Two timers per change: a **guard** (`fleet-revert-<id>-guard`) armed
//! before the handler runs, covering an exec crash mid-apply, and the
//! **confirm** timer (`fleet-revert-<id>`) armed once the apply finished,
//! so the whole confirm window starts then. The guard fires no earlier than
//! the confirm deadline could, so it is harmless if stopping it fails.

use crate::paths::{AGENT_BIN, AGENT_PREV_BIN, SYSTEMCTL, SYSTEMD_RUN};
use crate::pending::{ChangeId, ChangeKind, PendingDir, PendingError, RevertedMarker};
use fleet_ops::{CommandRunner, CommandSpec, RunError, SysCtx};
use std::time::Duration;

/// `systemd-run`/`systemctl` must answer within this.
pub const TIMER_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum TimerError {
    #[error("{0}: {1}")]
    Run(&'static str, RunError),
    #[error("{0} exited with {1:?}")]
    Status(&'static str, Option<i32>),
}

pub fn unit_name(id: ChangeId) -> String {
    format!("fleet-revert-{id}")
}

pub fn guard_unit_name(id: ChangeId) -> String {
    format!("fleet-revert-{id}-guard")
}

/// The binary a revert timer of `kind` runs: the previous build for an
/// agent update (the new one may not even start), else the installed one.
pub fn revert_bin(kind: ChangeKind) -> &'static str {
    match kind {
        ChangeKind::AgentUpdate => AGENT_PREV_BIN,
        _ => AGENT_BIN,
    }
}

fn timer_spec(unit: String, id: ChangeId, secs: u32, bin: &'static str) -> CommandSpec {
    CommandSpec::new(SYSTEMD_RUN)
        .args([
            format!("--on-active={secs}"),
            // Default accuracy is a minute: far too coarse for a 60 s window.
            "--timer-property=AccuracySec=1s".to_owned(),
            format!("--unit={unit}"),
            bin.to_owned(),
            "revert".to_owned(),
            id.to_hex(),
        ])
        .timeout(TIMER_COMMAND_TIMEOUT)
}

/// `systemd-run --on-active=<secs> --timer-property=AccuracySec=1s
/// --unit=fleet-revert-<id> <agent> revert <id>`.
pub fn timer_command(id: ChangeId, secs: u32) -> CommandSpec {
    timer_spec(unit_name(id), id, secs, AGENT_BIN)
}

/// The guard timer: same command, its own unit.
pub fn guard_command(id: ChangeId, secs: u32) -> CommandSpec {
    timer_spec(guard_unit_name(id), id, secs, AGENT_BIN)
}

/// [`timer_command`] running [`revert_bin`] of `kind`.
pub fn timer_command_for(id: ChangeId, secs: u32, kind: ChangeKind) -> CommandSpec {
    timer_spec(unit_name(id), id, secs, revert_bin(kind))
}

/// [`guard_command`] running [`revert_bin`] of `kind`.
pub fn guard_command_for(id: ChangeId, secs: u32, kind: ChangeKind) -> CommandSpec {
    timer_spec(guard_unit_name(id), id, secs, revert_bin(kind))
}

/// `systemctl stop fleet-revert-<id>.timer fleet-revert-<id>-guard.timer`.
pub fn disarm_command(id: ChangeId) -> CommandSpec {
    CommandSpec::new(SYSTEMCTL)
        .args([
            "stop".to_owned(),
            format!("{}.timer", unit_name(id)),
            format!("{}.timer", guard_unit_name(id)),
        ])
        .timeout(TIMER_COMMAND_TIMEOUT)
}

/// Stops only the guard (after the confirm timer is armed).
pub fn disarm_guard_command(id: ChangeId) -> CommandSpec {
    CommandSpec::new(SYSTEMCTL)
        .args(["stop".to_owned(), format!("{}.timer", guard_unit_name(id))])
        .timeout(TIMER_COMMAND_TIMEOUT)
}

/// Runs `spec` synchronously (a few ms normally, bounded by its timeout).
pub fn run_fixed(runner: &dyn CommandRunner, spec: CommandSpec) -> Result<(), TimerError> {
    let program = spec.program;
    let out = runner
        .run_blocking(spec)
        .map_err(|e| TimerError::Run(program, e))?;
    if out.success() {
        Ok(())
    } else {
        Err(TimerError::Status(program, out.code))
    }
}

pub fn arm_timer(runner: &dyn CommandRunner, id: ChangeId, secs: u32) -> Result<(), TimerError> {
    run_fixed(runner, timer_command(id, secs))
}

pub fn arm_guard(runner: &dyn CommandRunner, id: ChangeId, secs: u32) -> Result<(), TimerError> {
    run_fixed(runner, guard_command(id, secs))
}

/// `systemctl stop` exits 5 when a named unit isn't loaded: the guard is
/// normally stopped already once the confirm timer is armed, and a fired
/// timer is gone. Stopping still happens for the units that are loaded, so
/// "not loaded" is the disarmed state, not an error.
const SYSTEMCTL_NOT_LOADED: i32 = 5;

fn stop_units(runner: &dyn CommandRunner, spec: CommandSpec) -> Result<(), TimerError> {
    match run_fixed(runner, spec) {
        Err(TimerError::Status(_, Some(SYSTEMCTL_NOT_LOADED))) => Ok(()),
        r => r,
    }
}

pub fn disarm_timer(runner: &dyn CommandRunner, id: ChangeId) -> Result<(), TimerError> {
    stop_units(runner, disarm_command(id))
}

pub fn disarm_guard(runner: &dyn CommandRunner, id: ChangeId) -> Result<(), TimerError> {
    stop_units(runner, disarm_guard_command(id))
}

/// [`run_fixed`] through the async runner: exec's single-threaded runtime
/// keeps serving while `systemd-run`/`systemctl` run.
pub async fn run_fixed_async(
    runner: &dyn CommandRunner,
    spec: CommandSpec,
) -> Result<(), TimerError> {
    let program = spec.program;
    let out = runner
        .run(spec)
        .await
        .map_err(|e| TimerError::Run(program, e))?;
    if out.success() {
        Ok(())
    } else {
        Err(TimerError::Status(program, out.code))
    }
}

async fn stop_units_async(runner: &dyn CommandRunner, spec: CommandSpec) -> Result<(), TimerError> {
    match run_fixed_async(runner, spec).await {
        Err(TimerError::Status(_, Some(SYSTEMCTL_NOT_LOADED))) => Ok(()),
        r => r,
    }
}

/// Async [`arm_timer`] (exec).
pub async fn arm_timer_async(
    runner: &dyn CommandRunner,
    id: ChangeId,
    secs: u32,
) -> Result<(), TimerError> {
    run_fixed_async(runner, timer_command(id, secs)).await
}

/// Async [`arm_guard`] (exec).
pub async fn arm_guard_async(
    runner: &dyn CommandRunner,
    id: ChangeId,
    secs: u32,
) -> Result<(), TimerError> {
    run_fixed_async(runner, guard_command(id, secs)).await
}

/// [`arm_timer_async`] for a change of `kind` ([`revert_bin`]).
pub async fn arm_timer_for_async(
    runner: &dyn CommandRunner,
    id: ChangeId,
    secs: u32,
    kind: ChangeKind,
) -> Result<(), TimerError> {
    run_fixed_async(runner, timer_command_for(id, secs, kind)).await
}

/// [`arm_guard_async`] for a change of `kind` ([`revert_bin`]).
pub async fn arm_guard_for_async(
    runner: &dyn CommandRunner,
    id: ChangeId,
    secs: u32,
    kind: ChangeKind,
) -> Result<(), TimerError> {
    run_fixed_async(runner, guard_command_for(id, secs, kind)).await
}

/// Async [`disarm_timer`] (exec).
pub async fn disarm_timer_async(
    runner: &dyn CommandRunner,
    id: ChangeId,
) -> Result<(), TimerError> {
    stop_units_async(runner, disarm_command(id)).await
}

/// Async [`disarm_guard`] (exec).
pub async fn disarm_guard_async(
    runner: &dyn CommandRunner,
    id: ChangeId,
) -> Result<(), TimerError> {
    stop_units_async(runner, disarm_guard_command(id)).await
}

/// Builds the production reverter on a blocking-pool thread. Snapshot
/// modules touch files and run `nft`/`sshd -t`/`systemctl` synchronously
/// (the `Revertible` contract), so exec runs them there, each with its own
/// `SysCtx` and `SystemRunner` (neither is `Send`), instead of blocking its
/// single-threaded runtime.
pub type OffloadReverter = std::sync::Arc<dyn Fn() -> RegistryRevert + Send + Sync>;

/// The production [`OffloadReverter`]: [`RegistryRevert::system`].
pub fn system_offload() -> OffloadReverter {
    std::sync::Arc::new(RegistryRevert::system)
}

/// [`system_offload`] with the agent's own modules for `paths`
/// ([`RegistryRevert::for_paths`]).
pub fn offload_for(paths: &crate::paths::Paths) -> OffloadReverter {
    let paths = paths.clone();
    std::sync::Arc::new(move || RegistryRevert::for_paths(&paths))
}

/// Every restore module: `fleet_hardening::reverters()` plus the agent's
/// own, which need its paths: agent updates (`update::UpdateRevert`) and
/// uninstall's SSH restore (`uninstall::SshRestoreRevert`).
pub fn agent_reverters(
    paths: &crate::paths::Paths,
    mode: crate::userkeys::UserKeysMode,
) -> fleet_ops::Reverters {
    let mut r = fleet_hardening::reverters();
    r.register(
        ChangeKind::AgentUpdate,
        std::rc::Rc::new(crate::update::UpdateRevert {
            paths: paths.clone(),
        }),
    );
    r.register(
        ChangeKind::Ssh,
        std::rc::Rc::new(crate::uninstall::SshRestoreRevert {
            paths: paths.clone(),
            mode,
        }),
    );
    r
}

/// Restores a snapshot.
pub trait Revert {
    /// `new_version` is what the change's handler reported after applying
    /// (`None`: failed or none), for modules that restore a part only while
    /// it is unchanged (`Revertible::restore_versioned`).
    fn revert(
        &self,
        kind: ChangeKind,
        snapshot: &[u8],
        new_version: Option<u64>,
    ) -> Result<(), RevertError>;

    /// The version the state of `kind` has now, if it can be read (the
    /// snapshot tells which object, e.g. the user for authorized keys).
    /// A revert restores only while this still equals the change's
    /// `new_version`; `None` (unknown) restores.
    fn current_version(&self, _kind: ChangeKind, _snapshot: &[u8]) -> Option<u64> {
        None
    }
}

#[derive(Debug, thiserror::Error)]
#[error("revert of {0:?} failed")]
pub struct RevertError(pub ChangeKind);

/// Production reverter: dispatches by kind to the `fleet_ops::Revertible`
/// modules in `fleet_hardening::reverters()` (generic ones plus the
/// profile module; the same set exec snapshots with). A kind without a module fails, so the revert is audited as
/// `Failed` rather than falsely claiming the snapshot was restored.
pub struct RegistryRevert {
    pub reverters: fleet_ops::Reverters,
    pub ctx: SysCtx,
    /// Read current versions ([`probe_version`]) before restoring.
    probe: bool,
}

impl RegistryRevert {
    /// Restores without reading versions first (tests, custom modules).
    pub fn new(reverters: fleet_ops::Reverters, ctx: SysCtx) -> Self {
        Self {
            reverters,
            ctx,
            probe: false,
        }
    }

    pub fn system() -> Self {
        Self::for_paths(&crate::paths::Paths::system())
    }

    /// Production modules ([`agent_reverters`]) for the agent at `paths`.
    pub fn for_paths(paths: &crate::paths::Paths) -> Self {
        Self {
            reverters: agent_reverters(paths, crate::userkeys::UserKeysMode::AsUser),
            ctx: SysCtx::system(),
            probe: true,
        }
    }
}

impl Revert for RegistryRevert {
    fn revert(
        &self,
        kind: ChangeKind,
        snapshot: &[u8],
        new_version: Option<u64>,
    ) -> Result<(), RevertError> {
        self.reverters
            .restore_versioned(&self.ctx, kind, snapshot, new_version)
            .map_err(|e| {
                if e.detail().is_some() {
                    eprintln!("fleet-agent revert {kind:?}: {e}");
                }
                RevertError(kind)
            })
    }

    fn current_version(&self, kind: ChangeKind, snapshot: &[u8]) -> Option<u64> {
        self.probe
            .then(|| probe_version(&self.ctx, kind, snapshot))
            .flatten()
    }
}

/// Current version of the state a `kind` snapshot covers, in the same
/// terms the handler reported as `new_version`: the firewall model version
/// (`firewall.get`), the extra-section version of the snapshot's user
/// (`authorized_keys.get`). `None` when unknown (an unparsable firewall
/// table, other kinds): the revert then restores, the lockout-safe side.
pub fn probe_version(ctx: &SysCtx, kind: ChangeKind, snapshot: &[u8]) -> Option<u64> {
    use fleet_ops::firewall::{FirewallRevert, Snapshot, model};
    match kind {
        ChangeKind::Firewall => match FirewallRevert::take_snapshot(ctx).ok()? {
            Snapshot::Model(set) => Some(model::version(&set)),
            Snapshot::Absent => Some(model::ABSENT_VERSION),
            Snapshot::Raw(_) => None,
        },
        ChangeKind::AuthorizedKeys => {
            let (&n, rest) = snapshot.split_first()?;
            let user = std::str::from_utf8(rest.get(..usize::from(n))?).ok()?;
            fleet_ops::users::authorized_keys::get(ctx, user)
                .ok()
                .map(|k| k.version)
        }
        _ => None,
    }
}

/// Always fails (tests; a kind nothing can restore).
pub struct UnavailableRevert;

impl Revert for UnavailableRevert {
    fn revert(&self, kind: ChangeKind, _: &[u8], _: Option<u64>) -> Result<(), RevertError> {
        Err(RevertError(kind))
    }
}

/// Always succeeds. Unit tests only; integration tests define their own.
#[cfg(test)]
pub struct NoopRevert;

#[cfg(test)]
impl Revert for NoopRevert {
    fn revert(&self, _: ChangeKind, _: &[u8], _: Option<u64>) -> Result<(), RevertError> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevertOutcome {
    /// Snapshot restored; marker written for exec.
    Reverted,
    /// Restore failed; pending file removed anyway so the timer can't loop.
    Failed,
    /// The state changed again after this change (its version is no longer
    /// the change's `new_version`): kept as it is, audited as a conflict.
    Kept {
        /// The version the state has now (from the restore's own check).
        current: u64,
    },
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
/// revert crashed after claiming) — unless its state has moved on since
/// (version check, see [`Revert::current_version`]).
pub fn finish_claimed(
    dir: &PendingDir,
    id: ChangeId,
    reverter: &dyn Revert,
    now_ms: u64,
) -> Result<RevertOutcome, PendingError> {
    let Some(change) = dir.get_claimed(id)? else {
        return Ok(RevertOutcome::NotPending);
    };
    let conflict = match (
        change.origin.new_version,
        reverter.current_version(change.kind, &change.snapshot),
    ) {
        (Some(want), Some(now)) if want != now => Some(now),
        _ => None,
    };
    let restored = conflict.is_none()
        && reverter
            .revert(change.kind, &change.snapshot, change.origin.new_version)
            .is_ok();
    // Marker first, then delete: a crash in between leaves both, and exec
    // at startup skips re-reverting a change that already has a marker.
    dir.write_marker(
        id,
        &RevertedMarker {
            kind: change.kind,
            origin_audit_seq: change.audit_seq,
            restored,
            time_ms: now_ms,
            conflict,
        },
    )?;
    dir.remove_claimed(id)?;
    Ok(match (restored, conflict) {
        (true, _) => RevertOutcome::Reverted,
        (false, Some(current)) => RevertOutcome::Kept { current },
        (false, None) => RevertOutcome::Failed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_ops::{CommandOutput, FakeRunner};

    fn exit(code: i32) -> Result<CommandOutput, RunError> {
        Ok(CommandOutput {
            code: Some(code),
            stdout: Vec::new(),
            stderr: Vec::new(),
            truncated: false,
        })
    }

    /// Seen on Debian 12: the guard was stopped once the confirm timer was
    /// armed, so confirming stops a unit that is no longer loaded.
    #[test]
    fn disarm_tolerates_units_already_gone_only() {
        let id = ChangeId([7; 16]);
        let (t, g) = (
            format!("{}.timer", unit_name(id)),
            format!("{}.timer", guard_unit_name(id)),
        );
        let r = FakeRunner::new();
        r.expect(SYSTEMCTL, &["stop", &t, &g], exit(SYSTEMCTL_NOT_LOADED));
        r.expect(SYSTEMCTL, &["stop", &g], exit(SYSTEMCTL_NOT_LOADED));
        r.expect(SYSTEMCTL, &["stop", &t, &g], exit(1));
        assert!(disarm_timer(&r, id).is_ok());
        assert!(disarm_guard(&r, id).is_ok());
        assert!(matches!(
            disarm_timer(&r, id),
            Err(TimerError::Status(_, Some(1)))
        ));
    }
}
