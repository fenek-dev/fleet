//! The auto-revert protocol around an admitted op (design §4.10).
//!
//! Per change kind, at most one change is applying or pending (admission
//! answers `Busy` otherwise, `Exec::kind_busy`), and the kind's lock is
//! held from the snapshot through the apply. Order:
//!
//! 1. snapshot; write `pending/<id>.bin` marked `applying`, with the guard
//!    deadline (apply timeout + confirm window);
//! 2. arm the guard timer (no timer, no apply);
//! 3. run the handler, abandoned after `apply_timeout` (well below the
//!    confirm window): on failure or timeout restore at once and stop the
//!    timers;
//! 4. rewrite the pending file (only if still pending: never resurrect a
//!    claimed change) with the confirm deadline, `new_version`, and the
//!    connection counter a confirm must exceed;
//! 5. arm the confirm timer for the full window, stop the guard;
//! 6. answer `ChangePending { change, inner }`, `inner` being the
//!    handler's own result (e.g. `ProfileApplied`).
//!
//! While `applying`, maintenance doesn't revert it and `change.confirm` is
//! refused; a crash mid-apply is reverted at startup.
//!
//! Nothing here blocks exec's single-threaded runtime: timers go through
//! the async runner, and snapshots and restores (synchronous `Revertible`
//! code: files, `nft`, `sshd -t`, `systemctl`) run on the blocking pool
//! with their own `SysCtx` when `ExecConfig::offload` is set.

use super::{Admitted, Exec, Session, log, log_op_error};
use crate::now_ms;
use crate::pending::{ChangeId, ChangeKind, ChangeOrigin, PendingChange, PendingError};
use crate::revert::{self, RevertOutcome};
use fleet_ops::{OpOutput, Revertible};
use fleet_proto::{ErrorCode, Op, Payload};
use std::rc::Rc;

/// Guard timer margin beyond apply timeout + confirm window.
const GUARD_SLACK_S: u32 = 30;

/// `changes.list` / `ChangePending` view of a pending change.
pub(super) fn wire_pending(id: ChangeId, c: &PendingChange) -> fleet_proto::payload::PendingChange {
    fleet_proto::payload::PendingChange {
        change_id: id.0,
        kind: c.kind,
        op_tag: c.origin.op_tag,
        created_ms: c.origin.created_ms,
        deadline_ms: c.deadline_ms,
        new_version: c.origin.new_version,
    }
}

/// What the handler answered, split into the pending change's
/// `new_version` and the result the `ChangePending` carries: a handler's
/// own `ChangePending` gives its version and inner result; any other
/// payload (`ProfileApplied`, …) is the inner result itself; `Empty`
/// carries nothing.
fn handler_result(change: &mut PendingChange, p: Payload) -> Option<Box<Payload>> {
    match p {
        Payload::ChangePending { change: c, inner } => {
            change.origin.new_version = c.new_version;
            // Never nest a pending change in a pending change.
            inner.filter(|i| !matches!(**i, Payload::ChangePending { .. }))
        }
        Payload::Empty => None,
        other => Some(Box::new(other)),
    }
}

impl Exec {
    fn kind_lock(&self, kind: ChangeKind) -> Rc<tokio::sync::Mutex<()>> {
        self.kind_locks
            .borrow_mut()
            .entry(kind)
            .or_default()
            .clone()
    }

    /// `Revertible::snapshot` of `op`: on the blocking pool with the
    /// offload reverter's own modules and context, or inline with `r`.
    async fn snapshot(
        &self,
        kind: ChangeKind,
        r: &dyn Revertible,
        op: &Op,
    ) -> Result<Vec<u8>, fleet_ops::OpError> {
        let Some(f) = self.offload.clone() else {
            return r.snapshot(&self.ctx, op);
        };
        let op = op.clone();
        tokio::task::spawn_blocking(move || {
            let rr = f();
            rr.reverters
                .get(kind)
                .ok_or(fleet_ops::OpError::new(ErrorCode::Unsupported))?
                .snapshot(&rr.ctx, &op)
        })
        .await
        .map_err(|_| fleet_ops::OpError::internal("snapshot task failed"))?
    }

    /// Claims and restores change `id` (`revert::run_revert`) off the
    /// runtime when offloading, else inline with the configured reverter.
    pub(super) async fn revert_change(&self, id: ChangeId) -> Result<RevertOutcome, PendingError> {
        let dir = self.st.borrow().pending_dir.clone();
        match self.offload.clone() {
            Some(f) => {
                tokio::task::spawn_blocking(move || revert::run_revert(&dir, id, &f(), now_ms()))
                    .await
                    .unwrap_or_else(|_| Err(PendingError::Io(std::io::ErrorKind::Other.into())))
            }
            None => {
                let st = self.st.borrow();
                revert::run_revert(&dir, id, st.reverter.as_ref(), now_ms())
            }
        }
    }

    /// `change.revert`: the timer's restore, now. Claiming (an atomic
    /// rename) makes it exclusive with the timers and with maintenance, so
    /// exactly one restore runs; the loser of a race with a timer that
    /// reverted the change a moment earlier answers success too (the
    /// change is reverted either way), and a change already confirmed or
    /// long gone is `NotFound`. The origin op's audit entry and the
    /// `change.reverted` event come from the marker, exactly as for a
    /// timer's revert.
    pub(super) async fn revert_now(&self, id: ChangeId) -> Result<Payload, ErrorCode> {
        {
            let mut st = self.st.borrow_mut();
            // Still applying, or maintenance already restoring it: retry.
            if st.applying.contains(&id) || !st.reverting.insert(id) {
                return Err(ErrorCode::Busy);
            }
        }
        let outcome = self.revert_change(id).await;
        self.st.borrow_mut().reverted(id);
        let outcome = outcome.map_err(|e| {
            log("revert change", e);
            ErrorCode::Internal
        })?;
        // Everything up to the disarm await is synchronous, so maintenance
        // can't consume the marker in between: a conflict's version comes
        // from the restore's own outcome, and whether a timer beat us to
        // it from the marker it left.
        let (timers, dir) = {
            let st = self.st.borrow();
            (st.timers.clone(), st.pending_dir.clone())
        };
        let already = outcome == RevertOutcome::NotPending
            && dir
                .markers()
                .ok()
                .is_some_and(|m| m.iter().any(|(i, mk)| *i == id && mk.restored));
        // Audit and announce now rather than at the next maintenance tick.
        self.st.borrow_mut().process_markers(now_ms());
        if outcome != RevertOutcome::NotPending
            && let Err(e) = revert::disarm_timer_async(timers.as_ref(), id).await
        {
            // Harmless: the timer's revert finds nothing to claim.
            log("disarm revert timers", e);
        }
        match outcome {
            RevertOutcome::Reverted => Ok(Payload::Empty),
            RevertOutcome::NotPending if already => Ok(Payload::Empty),
            RevertOutcome::NotPending => Err(ErrorCode::NotFound),
            RevertOutcome::Kept { current } => Err(ErrorCode::VersionConflict { current }),
            RevertOutcome::Failed => Err(ErrorCode::Internal),
        }
    }

    /// Restores a change whose apply failed and stops its timers. If the
    /// restore itself fails, the guard timer still reverts it later.
    async fn abort_change(&self, id: ChangeId) {
        match self.revert_change(id).await {
            Ok(_) => {
                let timers = self.st.borrow().timers.clone();
                if let Err(e) = revert::disarm_timer_async(timers.as_ref(), id).await {
                    log("disarm revert timers", e);
                }
            }
            Err(e) => log("revert failed change", e),
        }
    }

    /// Runs `a` under the auto-revert protocol (module docs). Answers
    /// `Payload::ChangePending`, with the handler's own result inside.
    pub(super) async fn apply_reverting(
        &self,
        a: &Admitted,
        session: Session,
        kind: ChangeKind,
        r: &dyn Revertible,
    ) -> Result<Payload, ErrorCode> {
        let lock = self.kind_lock(kind);
        let _held = lock.lock().await;
        let op = &a.meta.command.body.op;
        let fail = |e: fleet_ops::OpError| {
            log_op_error(op.name(), &e);
            e.code()
        };
        let snapshot = self.snapshot(kind, r, op).await.map_err(fail)?;
        let mut raw = [0u8; 16];
        fleet_crypto::random_bytes(&mut raw).map_err(|_| ErrorCode::Internal)?;
        let id = ChangeId(raw);
        // An agent update's window is the health window after its restart
        // (design §10.2), not the policy's.
        let window = if kind == ChangeKind::AgentUpdate {
            crate::update::CONFIRM_WINDOW_S
        } else {
            self.st.borrow().policy.safety.auto_revert_seconds.max(1)
        };
        let apply_secs = u32::try_from(self.apply_timeout.as_secs()).unwrap_or(u32::MAX);
        // Never before the confirm deadline (apply end + window), with
        // slack for the bookkeeping after the handler returns.
        let guard_secs = window
            .saturating_add(apply_secs.max(1))
            .saturating_add(GUARD_SLACK_S);
        let created = now_ms();
        let mut change = PendingChange {
            kind,
            origin: ChangeOrigin {
                device_id: a.meta.command.device_id,
                session: session.id,
                op_tag: op.tag(),
                created_ms: created,
                new_version: None,
                run_id: self.st.borrow().run_id,
                applied_conn: u64::MAX,
            },
            snapshot,
            deadline_ms: created.saturating_add(u64::from(guard_secs) * 1000),
            audit_seq: a.intent_seq,
            applying: true,
        };
        let timers = {
            let st = self.st.borrow();
            st.pending_dir.insert(id, &change).map_err(|e| {
                log("write pending change", e);
                ErrorCode::Internal
            })?;
            st.timers.clone()
        };
        // Never apply without an independent timer.
        if let Err(e) = revert::arm_guard_for_async(timers.as_ref(), id, guard_secs, kind).await {
            log("arm revert guard timer", e);
            if let Err(e) = self.st.borrow().pending_dir.remove(id) {
                log("remove pending change", e);
            }
            return Err(ErrorCode::Internal);
        }
        self.st.borrow_mut().applying.insert(id);
        let applied = match tokio::time::timeout(
            self.apply_timeout,
            a.handler.handle(&self.ctx, op, &a.meta),
        )
        .await
        {
            Err(_) => {
                log(op.name(), "apply timed out; restoring");
                Err(ErrorCode::Timeout)
            }
            Ok(Ok(OpOutput::Payload(p))) => Ok(p),
            Ok(Ok(OpOutput::Stream(_))) => Err(ErrorCode::Internal),
            Ok(Err(e)) => Err(fail(e)),
        };
        let res = match applied {
            Ok(p) => {
                let inner = handler_result(&mut change, p);
                self.finish_apply(id, &mut change, window)
                    .await
                    .map(|()| inner)
            }
            Err(code) => {
                self.abort_change(id).await;
                Err(code)
            }
        };
        self.st.borrow_mut().applying.remove(&id);
        res.map(|inner| Payload::ChangePending {
            change: wire_pending(id, &change),
            inner,
        })
    }

    /// Steps 4–5: record the result, start the confirm window.
    async fn finish_apply(
        &self,
        id: ChangeId,
        change: &mut PendingChange,
        window: u32,
    ) -> Result<(), ErrorCode> {
        change.applying = false;
        change.origin.applied_conn = self.conns.get();
        change.deadline_ms = now_ms().saturating_add(u64::from(window) * 1000);
        let updated = self.st.borrow().pending_dir.update(id, change);
        match updated {
            Ok(true) => {}
            // Claimed meanwhile (only a lost race with the guard): it was
            // reverted, so the change didn't stick.
            Ok(false) => return Err(ErrorCode::Internal),
            Err(e) => {
                log("update pending change", e);
                self.abort_change(id).await;
                return Err(ErrorCode::Internal);
            }
        }
        let timers = self.st.borrow().timers.clone();
        if let Err(e) = revert::arm_timer_for_async(timers.as_ref(), id, window, change.kind).await
        {
            log("arm revert timer", e);
            self.abort_change(id).await;
            return Err(ErrorCode::Internal);
        }
        // Harmless if it fails: the guard fires after the confirm deadline.
        if let Err(e) = revert::disarm_guard_async(timers.as_ref(), id).await {
            log("stop revert guard timer", e);
        }
        Ok(())
    }
}
