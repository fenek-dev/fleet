//! `fleet-agent exec` (design §4.1, §5.6): the root executor. Trusts nothing
//! from the gate: every command is verified here (signature, roster,
//! freshness, replay, approval, policy, arguments), audited (intent, then
//! result) and answered with a signed receipt — for every command exec could
//! decode, reads and rejections included.
//!
//! Listens on `exec.sock` (`0660 root:fleet-gate` in the `0710
//! root:fleet-gate` directory `/run/fleet-exec`) and accepts only peers whose
//! uid is the gate's (`SO_PEERCRED`). One connection per authenticated gate
//! session plus the gate's control connection; see `ipc` for the message
//! order and [`conn`] for the per-connection tasks. Single-threaded: state
//! lives in one `RefCell` ([`state`]), and command handling never awaits
//! while holding it.
//!
//! Operations are dispatched through a `fleet_ops::Registry`: generic ones
//! come from `fleet-ops`, state-bound ones (roster, policy, veto,
//! `agent.health`, `roster.pending`, `events.query`, `change.confirm`,
//! `changes.list`) from [`ops`], `audit.query` from [`audit_ops`]; the
//! whole production registry is assembled by `build` (its tags:
//! [`registry_tags`]). `StreamOpen` runs the same pipeline and then
//! [`stream`] pumps the handler's `OpStream`. Every admitted command is
//! registered with [`attribution`] (config history) until it ends; the
//! stored policy is re-verified at load ([`policy_check`]).
//!
//! Pipeline per command ([`Exec::admit`], design §5.6): verify → policy
//! (AI rate included) → `Request`/`StreamOpen` matches `Op::is_stream` →
//! `Op::check_args` → `expected_version` present if required → confirm
//! preconditions → handler `validate` → escalation
//! (`OpHandler::requires_elevated` for `Op::may_escalate` ops; Elevated
//! without an approval is `ApprovalRequired`) → stream slot (global,
//! per device, per connection) → one change per kind → commit → intent.
//! Ops with `Op::auto_revert` then run under the auto-revert protocol
//! (§4.10, [`apply`]).

mod apply;
mod attribution;
mod audit_ops;
mod confighist;
mod conn;
mod events;
mod lifecycle;
mod ops;
mod policy_check;
mod sources;
mod sshd;
mod state;
mod stream;
mod telemetry;
mod wiring;

pub use sources::{LazySystemd, SourcesConfig};
pub use sshd::{Login, Logins, ProcessSignaller, Sigterm, SshdTerminator, trusted_entry};
pub use state::{StoredPolicy, load_signing_key};

use crate::now_ms;
use crate::paths::Paths;
use crate::pending::{ChangeKind, PendingChange, PendingError, SessionId};
use crate::revert::{self, RegistryRevert, Revert};
use crate::store::StoreError;
use conn::{Budget, ConnGuard};
use fleet_crypto::receipt::{receipt_for, sign_receipt};
use fleet_crypto::verify::{self, VerifiedCommand};
use fleet_ops::{
    CommandRunner, Invocation, OpHandler, OpMeta, OpOutput, Registry, Reverters, Revertible, SysCtx,
};
use fleet_proto::{
    DeviceId, ErrorCode, Hash32, KeyKind, Op, P256Public, Payload, SignedCommand, SignedReceipt,
    encode,
};
use state::{Refused, State, StateParts};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::rc::Rc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// A gate must send `SessionOpen`/`ControlOpen` within this after connecting.
pub const SESSION_OPEN_TIMEOUT: Duration = Duration::from_secs(30);
/// Concurrent connections from the gate (sessions + control); more are
/// closed on accept.
pub const MAX_CONNECTIONS: usize = 64;
/// Bytes held in reassembly buffers across all connections; a connection
/// that pushes the total over this is closed.
pub const MAX_BUFFERED_BYTES: usize = 32 << 20;
/// Streams one device may run at once (across its sessions).
pub const MAX_STREAMS_PER_DEVICE: u32 = 8;
/// Streams one gate connection may run at once.
pub const MAX_STREAMS_PER_CONNECTION: u32 = 16;
/// Replay-cache and event-log pruning run at most this often.
const PRUNE_EVERY: Duration = Duration::from_secs(60);
/// A pending recovery's remaining delay (and the remaining local recovery
/// grace) is persisted at least this often.
const PENDING_PERSIST_EVERY_MS: u64 = 60_000;
/// Requests of one gate connection running at once; the connection stops
/// reading while all are busy.
const MAX_INFLIGHT_REQUESTS: usize = 16;

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Time left until `deadline` (0 once passed).
fn remaining_ms(deadline: Instant) -> u64 {
    millis(deadline.saturating_duration_since(Instant::now()))
}

/// Ends `sshd` sessions of SSH keys removed from the roster (design §5.3
/// rule 5, §4.6). Production: [`SshdTerminator`].
pub trait SessionTerminator {
    fn end_sessions(&self, removed_ssh_keys: &[P256Public]);
}

/// Does nothing (tests).
pub struct NoopTerminator;

impl SessionTerminator for NoopTerminator {
    fn end_sessions(&self, _: &[P256Public]) {}
}

pub struct ExecConfig {
    pub paths: Paths,
    /// Only this uid may connect to `exec.sock`.
    pub gate_uid: u32,
    pub checkpoint_interval: Duration,
    /// Reverted markers, expired pending changes, recovery delay countdown,
    /// replay and event-log pruning, `authorized_keys` refresh.
    pub maintenance_interval: Duration,
    /// Restores snapshots (deadline passed, crashed reverts, failed
    /// applies). Default: `RegistryRevert::system()`, the same modules the
    /// `revert <id>` process uses.
    pub reverter: Box<dyn Revert>,
    /// Snapshot modules for auto-revert ops, by kind (§4.10). An auto-revert
    /// op whose kind has none is refused with `Unsupported`.
    pub reverters: Reverters,
    /// Where snapshots and restores run: `Some` builds a
    /// [`RegistryRevert`] on the blocking pool for each (production:
    /// [`revert::system_offload`]), so synchronous file, `nft` and
    /// `systemctl` work never blocks the runtime; `None` runs `reverters`
    /// and `reverter` inline (tests with fakes that aren't `Send`).
    pub offload: Option<revert::OffloadReverter>,
    /// Runs `systemd-run`/`systemctl` for auto-revert timers (through the
    /// async runner, `revert::TIMER_COMMAND_TIMEOUT` each).
    pub timers: Rc<dyn CommandRunner>,
    /// `None`: [`SshdTerminator`] over the sshd journal's logins and
    /// `<ctx root>/proc`.
    pub terminator: Option<Box<dyn SessionTerminator>>,
    /// Environment of every operation (root, processes, clock, `/proc`).
    pub ctx: SysCtx,
    /// Registered after the built-in handlers, replacing any with the same
    /// tag (tests; later, optional op families).
    pub handlers: Vec<(u16, Rc<dyn OpHandler>)>,
    /// Longest gap between stream checkpoints while data is flowing.
    pub stream_checkpoint_interval: Duration,
    /// A non-`latest_only` stream whose client can't take a chunk for this
    /// long is ended with `Busy`.
    pub stream_send_timeout: Duration,
    /// Event sources (sshd, systemd, pollers) and their inputs.
    pub sources: SourcesConfig,
    /// How often the database is compacted if it has much unused space
    /// (design §4.4); deferred while requests are running.
    pub compact_interval: Duration,
    /// A compaction deferred this long runs even with requests in flight.
    pub compact_force_after: Duration,
    /// Longest an auto-revert handler may run; it is then abandoned and
    /// the snapshot restored (`Timeout`). Well below the confirm window.
    pub apply_timeout: Duration,
    /// Longest a `profile.apply` without auto-revert (Accounts/System
    /// phase: package installs, role repositories) may run. Its children
    /// run in the op's scope and are killed when it is abandoned
    /// (`Timeout`).
    pub profile_apply_timeout: Duration,
    /// `change.confirm` also needs sshd's journal to show a login with the
    /// confirming device's SSH key since the change was made (§4.10 step
    /// 3), waiting up to this long for the journal to catch up. `None`
    /// skips the check (tests without a journal).
    pub confirm_sshd_login: Option<Duration>,
    /// How `agent.uninstall.prepare` reaches users' `~/.ssh`: as the user
    /// through `setpriv` (production) or in-process (tests).
    pub user_keys: crate::userkeys::UserKeysMode,
}

impl ExecConfig {
    pub fn new(paths: Paths, gate_uid: u32) -> Self {
        Self {
            reverter: Box::new(RegistryRevert::for_paths(&paths)),
            reverters: revert::agent_reverters(&paths, crate::userkeys::UserKeysMode::AsUser),
            offload: Some(revert::offload_for(&paths)),
            paths,
            gate_uid,
            checkpoint_interval: Duration::from_secs(3600),
            maintenance_interval: Duration::from_secs(5),
            timers: Rc::new(fleet_ops::SystemRunner),
            terminator: None,
            ctx: SysCtx::system(),
            handlers: Vec::new(),
            stream_checkpoint_interval: Duration::from_secs(5),
            stream_send_timeout: Duration::from_secs(10),
            sources: SourcesConfig::system(),
            compact_interval: Duration::from_secs(24 * 3600),
            compact_force_after: Duration::from_secs(3 * 24 * 3600),
            apply_timeout: Duration::from_secs(30),
            profile_apply_timeout: Duration::from_secs(30 * 60),
            confirm_sshd_login: Some(Duration::from_secs(5)),
            user_keys: crate::userkeys::UserKeysMode::AsUser,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("pending changes: {0}")]
    Pending(#[from] PendingError),
    #[error("not installed: missing {0}")]
    NotInstalled(&'static str),
    #[error("corrupt state: {0}")]
    Corrupt(&'static str),
}

fn log(what: &str, e: impl std::fmt::Display) {
    eprintln!("fleet-exec: {what}: {e}");
}

/// A command that passed every check; its nonce is consumed and its audit
/// intent written (`meta.audit_seq`).
struct Admitted {
    handler: Rc<dyn OpHandler>,
    meta: OpMeta,
    intent_seq: u64,
    consumed_until: u64,
    /// Auto-revert ops: the snapshot module for their kind, and the kind's
    /// in-flight mark (held until the apply finished).
    revertible: Option<(ChangeKind, Rc<dyn Revertible>, KindSlot)>,
    /// `change.confirm`: the change it confirms.
    confirms: Option<PendingChange>,
    /// Config-history attribution of this op's writes, until it ends.
    _attributed: attribution::OpGuard,
}

/// One gate connection: the key kind the gate authenticated and exec's own
/// ids for it (`change.confirm` must come over a newer one).
#[derive(Debug, Clone, Copy)]
struct Session {
    key: KeyKind,
    id: SessionId,
    /// Exec's connection counter when this one opened (monotonic per run).
    conn: u64,
    /// What the gate reported in `SessionOpen` (untrusted): the device it
    /// authenticated, the bridge mode, and the bridge's client address.
    device: DeviceId,
    recovery: bool,
    client_ip: Option<std::net::IpAddr>,
}

/// An answer, shared with identical commands waiting for it.
type Answer = Rc<(Result<Payload, ErrorCode>, SignedReceipt)>;

/// Shared by every connection: state, dispatch, environment.
struct Exec {
    st: Rc<RefCell<State>>,
    registry: Registry,
    reverters: Reverters,
    /// `ExecConfig::offload`.
    offload: Option<revert::OffloadReverter>,
    ctx: SysCtx,
    /// Streams running across all connections
    /// (`limits.max_stream_sessions`), and per device.
    streams: Cell<u32>,
    device_streams: RefCell<HashMap<DeviceId, u32>>,
    /// Requests running now (compaction waits for idle).
    requests: Cell<u32>,
    checkpoint_every: Duration,
    send_timeout: Duration,
    sources: Rc<sources::Sources>,
    /// Connections opened in this run (`Session::conn`).
    conns: Cell<u64>,
    /// Change kinds with an apply in flight (one change per kind).
    kinds: RefCell<HashSet<ChangeKind>>,
    /// Per-kind lock held from snapshot through apply.
    kind_locks: RefCell<HashMap<ChangeKind, Rc<tokio::sync::Mutex<()>>>>,
    /// Commands (by hash) whose nonce is consumed and whose answer isn't
    /// stored yet: an identical re-forward waits for the original answer.
    inflight: RefCell<HashMap<Hash32, watch::Sender<Option<Answer>>>>,
    apply_timeout: Duration,
    profile_apply_timeout: Duration,
    confirm_sshd_login: Option<Duration>,
    /// Running ops and their announced writes (config history).
    attribution: Rc<attribution::ExecAttribution>,
}

/// Marks the change kinds an op claims as being applied; released on drop.
struct KindSlot {
    kinds: Rc<Exec>,
    claimed: Vec<ChangeKind>,
}

impl Drop for KindSlot {
    fn drop(&mut self) {
        let mut k = self.kinds.kinds.borrow_mut();
        for c in &self.claimed {
            k.remove(c);
        }
    }
}

/// Local log only (details never go on the wire); plain codes are routine.
fn log_op_error(op_name: &str, e: &fleet_ops::OpError) {
    if e.detail().is_some() {
        log(op_name, e);
    }
}

impl Exec {
    /// verify → policy → handler supports/validate → stream slot → commit
    /// → intent (design §5.6). Synchronous: nothing else runs in between.
    /// `conn_streams`: streams the session's connection runs now.
    fn admit(
        self: &Rc<Self>,
        session: Session,
        cmd: &SignedCommand,
        inv: Invocation,
        now: u64,
        conn_streams: u32,
    ) -> Result<Admitted, Refused> {
        let refuse = |code| Refused {
            code,
            consumed_until: None,
        };
        let v = self
            .st
            .borrow()
            .verify(session.key, cmd, now)
            .map_err(refuse)?;
        self.st.borrow().check_policy(&v, now).map_err(refuse)?;
        let op = &v.body.op;
        // Streams only as `StreamOpen`, everything else only as `Request`.
        if op.is_stream() != (inv == Invocation::Stream) {
            return Err(refuse(ErrorCode::Unsupported));
        }
        op.check_args()
            .map_err(|_| refuse(ErrorCode::InvalidArgument))?;
        if op.requires_expected_version() && v.body.expected_version.is_none() {
            return Err(refuse(ErrorCode::InvalidArgument));
        }
        let confirms = self.check_confirm(session, op).map_err(refuse)?;
        let handler = self
            .registry
            .get(op)
            .filter(|h| h.supports(op, inv))
            .ok_or(refuse(ErrorCode::Unsupported))?;
        let revertible = if op.auto_revert() {
            let kind = fleet_ops::revertible::change_kind(op).ok_or(refuse(ErrorCode::Internal))?;
            let r = self
                .reverters
                .get(kind)
                .ok_or(refuse(ErrorCode::Unsupported))?;
            Some((kind, r))
        } else {
            None
        };
        let mut meta = OpMeta {
            command: v,
            approval: cmd.approval.clone(),
            audit_seq: None,
            now_ms: now,
            invocation: inv,
        };
        // Replay entries are consumed only once policy and arguments passed,
        // so a refused command doesn't burn its nonce or approval leaf.
        let op = &meta.command.body.op;
        let op_refused = |e: fleet_ops::OpError| {
            log_op_error(op.name(), &e);
            refuse(e.code())
        };
        handler.validate(&self.ctx, op, &meta).map_err(op_refused)?;
        // Conditional Elevated (design §4.2): the handler decides from facts
        // the arguments don't carry; a verified approval covering this op
        // (checked in `verify`) is then required.
        if op.may_escalate()
            && meta.command.approval.is_none()
            && handler
                .requires_elevated(&self.ctx, op, &meta)
                .map_err(op_refused)?
        {
            return Err(refuse(ErrorCode::ApprovalRequired));
        }
        if inv == Invocation::Stream {
            self.stream_room(meta.command.device_id, conn_streams)
                .map_err(refuse)?;
        }
        // One pending change per kind: a second snapshot would capture the
        // first, unconfirmed change, and the reverts would fight. A profile
        // change that may run `firewall.baseline` holds the firewall too.
        if revertible.is_some() {
            for kind in fleet_ops::revertible::claimed_kinds(op) {
                if self.kind_busy(kind).map_err(refuse)? {
                    return Err(refuse(ErrorCode::Busy));
                }
            }
        }
        let intent_seq = self
            .st
            .borrow_mut()
            .commit_intent(&meta.command, cmd, now)?;
        meta.audit_seq = Some(intent_seq);
        let attributed = self.attribution.begin(&meta.command.body.op, intent_seq);
        let revertible = revertible.map(|(kind, r)| {
            let claimed = fleet_ops::revertible::claimed_kinds(op);
            self.kinds.borrow_mut().extend(claimed.iter().copied());
            let slot = KindSlot {
                kinds: self.clone(),
                claimed,
            };
            (kind, r, slot)
        });
        Ok(Admitted {
            handler,
            consumed_until: meta.command.nonce_expires_at_ms,
            meta,
            intent_seq,
            revertible,
            confirms,
            _attributed: attributed,
        })
    }

    /// Stream caps: global (`limits.max_stream_sessions`), per device,
    /// per connection.
    fn stream_room(&self, device: DeviceId, conn_streams: u32) -> Result<(), ErrorCode> {
        let global = self.st.borrow().policy.limits.max_stream_sessions;
        let per_device = self
            .device_streams
            .borrow()
            .get(&device)
            .copied()
            .unwrap_or(0);
        if self.streams.get() >= global
            || per_device >= MAX_STREAMS_PER_DEVICE
            || conn_streams >= MAX_STREAMS_PER_CONNECTION
        {
            return Err(ErrorCode::Busy);
        }
        Ok(())
    }

    /// `change.confirm` preconditions (design §4.10 step 3): the change has
    /// finished applying, and the confirm comes over a connection opened
    /// after that (a new one proves access still works).
    fn check_confirm(&self, session: Session, op: &Op) -> Result<Option<PendingChange>, ErrorCode> {
        let st = self.st.borrow();
        let Some(c) = st.pending_change(op)? else {
            return Ok(None);
        };
        if let Op::ChangeConfirm { change_id } = op
            && (c.applying || st.applying.contains(&crate::pending::ChangeId(*change_id)))
        {
            return Err(ErrorCode::Busy);
        }
        let same_run = c.origin.run_id == st.run_id;
        if c.origin.session == session.id || (same_run && session.conn <= c.origin.applied_conn) {
            return Err(ErrorCode::PolicyDenied);
        }
        Ok(Some(c))
    }

    /// A change of `kind` is being applied, pending or being reverted.
    fn kind_busy(&self, kind: ChangeKind) -> Result<bool, ErrorCode> {
        if self.kinds.borrow().contains(&kind) {
            return Ok(true);
        }
        let entries = self.st.borrow().pending_dir.scan().map_err(|e| {
            log("scan pending", e);
            ErrorCode::Internal
        })?;
        // A pending profile change may hold the firewall table too (its
        // revert restores it): conservatively, any pending profile change
        // blocks firewall changes.
        Ok(entries.iter().any(|e| {
            e.value.as_ref().is_none_or(|c| {
                c.kind == kind || (kind == ChangeKind::Firewall && c.kind == ChangeKind::Profile)
            })
        }))
    }

    /// Runs an admitted request: plain ops through their handler, auto-revert
    /// ops through [`Self::apply_reverting`].
    async fn execute(&self, a: &Admitted, session: Session) -> Result<Payload, ErrorCode> {
        let op = &a.meta.command.body.op;
        if let Some((kind, r, _)) = &a.revertible {
            return self.apply_reverting(a, session, *kind, r.as_ref()).await;
        }
        if let Some(c) = &a.confirms {
            self.await_sshd_login(a.meta.command.device_id, c.origin.created_ms)
                .await?;
        }
        // dpkg changes made while this runs are Fleet's own: their files
        // are re-baselined for integrity when it ends (design §4.7).
        let _pkg = matches!(
            op,
            Op::PkgInstall { .. } | Op::PkgUpgrade { .. } | Op::PkgRemove { .. }
        )
        .then(|| self.sources.fleet_pkg_op());
        let run = a.handler.handle(&self.ctx, op, &a.meta);
        let out = if matches!(op, Op::ProfileApply { .. }) {
            // Accounts/System phases (auto-revert ones never get here):
            // long, but bounded; dropping the future kills its children.
            match tokio::time::timeout(self.profile_apply_timeout, run).await {
                Ok(r) => r,
                Err(_) => {
                    log(op.name(), "apply timed out");
                    return Err(ErrorCode::Timeout);
                }
            }
        } else {
            run.await
        };
        match out {
            Ok(OpOutput::Payload(p)) => Ok(p),
            Ok(OpOutput::Stream(_)) => Err(ErrorCode::Internal),
            Err(e) => {
                log_op_error(op.name(), &e);
                Err(e.code())
            }
        }
    }

    /// `change.confirm`: sshd's journal must show `device` logging in with
    /// its device SSH key at or after `since_ms` — the new connection the
    /// confirm travels over. Waits a little for the journal to catch up.
    async fn await_sshd_login(&self, device: DeviceId, since_ms: u64) -> Result<(), ErrorCode> {
        let Some(wait) = self.confirm_sshd_login else {
            return Ok(());
        };
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let seen = self
                .sources
                .ssh_logins
                .borrow()
                .device_login_since(device, since_ms);
            if seen {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(ErrorCode::PolicyDenied);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// One `Request`. Every answer is receipted, rejections included
    /// (`audit_seq` `None` before the intent).
    ///
    /// The answer to a command that consumed its nonce is kept (as long as
    /// the nonce) and returned again, unchanged, for the identical command:
    /// a gate that drops the reply and re-forwards the command gets the
    /// original result and receipt, never a signed `Replay` failure for a
    /// command that did run — also while it is still running (it waits).
    async fn request(
        self: &Rc<Self>,
        session: Session,
        cmd: &SignedCommand,
    ) -> (Result<Payload, ErrorCode>, SignedReceipt) {
        let hash = verify::command_hash(cmd);
        let running = self
            .inflight
            .borrow()
            .get(&hash)
            .map(watch::Sender::subscribe);
        if let Some(mut rx) = running
            && let Ok(v) = rx.wait_for(Option::is_some).await
            && let Some(a) = v.as_ref()
        {
            return (a.0.clone(), a.1.clone());
        }
        if let Some(original) = self.st.borrow().stored_response(&hash) {
            return original;
        }
        let now = now_ms();
        let _busy = Busy::new(&self.requests);
        let (result, audit_seq, consumed_until) =
            match self.admit(session, cmd, Invocation::Request, now, 0) {
                Err(r) => (Err(r.code), None, r.consumed_until),
                Ok(a) => {
                    self.inflight
                        .borrow_mut()
                        .insert(hash, watch::channel(None).0);
                    self.learn_hint(session, &a.meta.command);
                    let result = self.execute(&a, session).await;
                    let status = result.as_ref().map(drop).map_err(|c| *c);
                    match self.st.borrow_mut().audit_result(a.intent_seq, status) {
                        Some(seq) => (result, Some(seq), Some(a.consumed_until)),
                        None => (
                            Err(ErrorCode::Internal),
                            Some(a.intent_seq),
                            Some(a.consumed_until),
                        ),
                    }
                }
            };
        let receipt = {
            let st = self.st.borrow();
            let receipt = sign_receipt(
                receipt_for(st.server_id.clone(), hash, audit_seq, &result, now_ms()),
                &st.signer,
            );
            if let Some(expires) = consumed_until
                && let Err(e) =
                    st.store
                        .replay()
                        .put_response(&hash, expires, &encode(&(&result, &receipt)))
            {
                // A later replay then gets `Replay`, which the Mac reads as
                // "outcome unknown".
                log("store response", e);
            }
            receipt
        };
        if let Some(tx) = self.inflight.borrow_mut().remove(&hash) {
            tx.send_replace(Some(Rc::new((result.clone(), receipt.clone()))));
        }
        (result, receipt)
    }

    /// Ban-exemption learning, session side (design §4.7): a command exec
    /// itself verified, from the device the gate reported for this normal
    /// (non-recovery) session, whose bridge sent a client address. The
    /// address is still only a hint; [`sources::Correlator`] learns it only
    /// if sshd's journal shows that device's key accepted from it.
    fn learn_hint(&self, session: Session, v: &VerifiedCommand) {
        if let Some(ip) = session.client_ip
            && !session.recovery
            && v.key != KeyKind::Recovery
            && v.device_id == session.device
        {
            self.sources.session_verified(ip, v.device_id);
        }
    }
}

/// Counts a running request for as long as it lives.
struct Busy<'a>(&'a Cell<u32>);

impl<'a> Busy<'a> {
    fn new(c: &'a Cell<u32>) -> Self {
        c.set(c.get() + 1);
        Self(c)
    }
}

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.set(self.0.get().saturating_sub(1));
    }
}

/// Daily compaction bookkeeping (design §4.4).
#[derive(Default)]
struct CompactState {
    /// Due since (monotonic); `None` when not due.
    due_since: Cell<Option<Instant>>,
    running: Cell<bool>,
}

/// Starts a compaction on the blocking pool when one is due and exec is
/// idle (no request running), or when it was deferred longer than
/// `force_after`. Streams don't hold it back: they only touch the database
/// between items, and wait for it like everyone else.
fn maybe_compact(exec: &Rc<Exec>, c: &Rc<CompactState>, force_after: Duration) {
    let Some(since) = c.due_since.get() else {
        return;
    };
    if c.running.get() || (exec.requests.get() > 0 && since.elapsed() < force_after) {
        return;
    }
    c.running.set(true);
    let compactor = exec.st.borrow().store.compactor();
    let c = c.clone();
    tokio::task::spawn_local(async move {
        let started = Instant::now();
        let res =
            tokio::task::spawn_blocking(move || compactor.compact(crate::store::COMPACT_MIN_FREE))
                .await;
        let done = match res {
            Ok(r) => State::compacted(r, started.elapsed()),
            Err(e) => {
                log("database compaction", e);
                true
            }
        };
        if done {
            c.due_since.set(None);
        }
        c.running.set(false);
    });
}

/// The production registry and the parts that feed its handlers.
struct Built {
    registry: Registry,
    bus: Rc<events::EventBus>,
    tel: Rc<fleet_ops::telemetry::Telemetry>,
    sources: Rc<sources::Sources>,
    config: Option<Rc<fleet_ops::confighist::ConfigTracker>>,
    wired: wiring::Wired,
    attribution: Rc<attribution::ExecAttribution>,
}

/// Every handler exec dispatches to (design §4.2): generic `fleet-ops`
/// ones, hardening, state-bound ops, telemetry, sources, config history,
/// the wired families, agent lifecycle, then `extra` (tests) replacing any
/// of them.
#[allow(clippy::too_many_arguments)]
fn build(
    st: &Rc<RefCell<State>>,
    ctx: &SysCtx,
    paths: &Paths,
    sources_cfg: SourcesConfig,
    ssh_logins: Rc<RefCell<Logins>>,
    user_keys: crate::userkeys::UserKeysMode,
    extra: Vec<(u16, Rc<dyn OpHandler>)>,
) -> Built {
    let mut registry = Registry::with_generic();
    fleet_hardening::register(&mut registry);
    let state_ops: Rc<dyn OpHandler> = Rc::new(ops::StateOps(st.clone()));
    for tag in ops::TAGS {
        registry.register(tag, state_ops.clone());
    }
    let change_ops: Rc<dyn OpHandler> = Rc::new(ops::ChangeOps(st.clone()));
    for tag in ops::CHANGE_TAGS {
        registry.register(tag, change_ops.clone());
    }
    let audit_ops: Rc<dyn OpHandler> = Rc::new(audit_ops::AuditOps(st.clone()));
    for tag in audit_ops::TAGS {
        registry.register(tag, audit_ops.clone());
    }
    let bus = events::EventBus::new(st.clone(), ctx.clock.clone());
    let tel = telemetry::start(st, ctx, &mut registry, &bus);
    let sources = sources::Sources::new(st, ctx, bus.clone(), sources_cfg, ssh_logins);
    sources.register(&mut registry);
    let attribution = Rc::new(attribution::ExecAttribution::default());
    let config = confighist::start(st, &mut registry, &bus, attribution.clone());
    let wired = wiring::start(st, paths, &mut registry, &bus, &tel);
    lifecycle::register(st, &mut registry, user_keys);
    for (tag, h) in extra {
        registry.register(tag, h);
    }
    Built {
        registry,
        bus,
        tel,
        sources,
        config,
        wired,
        attribution,
    }
}

/// Tags of the production registry exec would build for `cfg` (the
/// catalog-coverage test, design §4.2). Loads the installed state like
/// `run` does, but starts nothing; exec must not be running.
#[doc(hidden)]
pub fn registry_tags(mut cfg: ExecConfig) -> Result<Vec<u16>, ExecError> {
    let ssh_logins = Rc::new(RefCell::new(Logins::default()));
    let terminator = cfg.terminator.take().unwrap_or_else(|| Box::new(NoopTerminator));
    let state = State::load(StateParts {
        paths: cfg.paths.clone(),
        reverter: cfg.reverter,
        timers: cfg.timers,
        terminator,
    })?;
    let st = Rc::new(RefCell::new(state));
    let b = build(
        &st,
        &cfg.ctx,
        &cfg.paths,
        cfg.sources,
        ssh_logins,
        cfg.user_keys,
        std::mem::take(&mut cfg.handlers),
    );
    Ok(b.registry.tags().collect())
}

/// Runs exec until `shutdown` completes. The store is closed on return.
pub async fn run(mut cfg: ExecConfig, shutdown: impl Future<Output = ()>) -> Result<(), ExecError> {
    let paths = cfg.paths.clone();
    let gate_uid = cfg.gate_uid;
    let (cp_every, maint_every) = (cfg.checkpoint_interval, cfg.maintenance_interval);
    let ctx = cfg.ctx.clone();
    let extra = std::mem::take(&mut cfg.handlers);
    let reverters = std::mem::take(&mut cfg.reverters);
    let offload = cfg.offload.take();
    let (checkpoint_every, send_timeout) =
        (cfg.stream_checkpoint_interval, cfg.stream_send_timeout);
    let (compact_every, compact_force_after) = (cfg.compact_interval, cfg.compact_force_after);
    let sources_cfg = std::mem::replace(&mut cfg.sources, SourcesConfig::system());
    let background = sources_cfg.enabled;
    let ssh_logins = Rc::new(RefCell::new(Logins::default()));
    let terminator = cfg.terminator.take().unwrap_or_else(|| {
        Box::new(SshdTerminator {
            logins: ssh_logins.clone(),
            proc_root: ctx.root().join("proc"),
            signaller: Box::new(Sigterm),
        })
    });
    let (apply_timeout, profile_apply_timeout, confirm_sshd_login) = (
        cfg.apply_timeout,
        cfg.profile_apply_timeout,
        cfg.confirm_sshd_login,
    );
    let user_keys = cfg.user_keys;
    let mut state = State::load(StateParts {
        paths: cfg.paths,
        reverter: cfg.reverter,
        timers: cfg.timers,
        terminator,
    })?;
    let rearm = state.startup(now_ms())?;

    let listener = conn::bind_exec_socket(&paths)?;
    crate::notify::notify("READY=1");

    let st = Rc::new(RefCell::new(state));
    let Built {
        registry,
        bus,
        tel,
        sources,
        config,
        wired,
        attribution,
    } = build(&st, &ctx, &paths, sources_cfg, ssh_logins, user_keys, extra);
    let exec = Rc::new(Exec {
        st: st.clone(),
        registry,
        reverters,
        offload,
        ctx,
        streams: Cell::new(0),
        device_streams: RefCell::default(),
        requests: Cell::new(0),
        checkpoint_every,
        send_timeout,
        sources: sources.clone(),
        conns: Cell::new(0),
        kinds: RefCell::default(),
        kind_locks: RefCell::default(),
        inflight: RefCell::default(),
        apply_timeout,
        profile_apply_timeout,
        confirm_sshd_login,
        attribution,
    });
    let budget = Rc::new(Budget::default());
    let compaction = Rc::new(CompactState::default());
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            {
                // Confirm timers of changes still pending (dropped by a
                // reboot). Fails harmlessly if a timer survived (exec
                // restart); maintenance reverts on the deadline regardless.
                let timers = st.borrow().timers.clone();
                for (id, secs, kind) in rearm {
                    if let Err(e) =
                        revert::arm_timer_for_async(timers.as_ref(), id, secs, kind).await
                    {
                        log(&format!("re-arm revert timer {id}"), e);
                    }
                }
            }
            tokio::task::spawn_local(tel.clone().run(exec.ctx.clone()));
            sources.spawn();
            if background {
                wired.spawn(&exec.ctx);
            }
            if let Some(c) = config {
                tokio::task::spawn_local(confighist::run(c, exec.ctx.clone()));
            }
            tokio::pin!(shutdown);
            let mut maint = tokio::time::interval(maint_every);
            let mut cp = tokio::time::interval(cp_every);
            let mut compact = tokio::time::interval(compact_every);
            compact.reset(); // not at startup
            let wd_every = crate::notify::watchdog_interval();
            let mut wd = tokio::time::interval(wd_every.unwrap_or(Duration::from_secs(3600)));
            loop {
                tokio::select! {
                    r = listener.accept() => {
                        if let Ok((stream, _)) = r {
                            if budget.conns.get() >= MAX_CONNECTIONS {
                                continue; // dropped: closes the stream
                            }
                            budget.conns.set(budget.conns.get() + 1);
                            let guard = ConnGuard::new(budget.clone());
                            let exec = exec.clone();
                            tokio::task::spawn_local(async move {
                                let _ = conn::connection(stream, exec, gate_uid, &guard).await;
                            });
                        }
                    }
                    _ = maint.tick() => {
                        let due = st.borrow_mut().maintenance(now_ms());
                        for id in due {
                            // Off the main loop: the restore may take a
                            // while (files, nft, reloads).
                            let exec = exec.clone();
                            tokio::task::spawn_local(async move {
                                if let Err(e) = exec.revert_change(id).await {
                                    log(&format!("revert {id}"), e);
                                }
                                exec.st.borrow_mut().reverted(id);
                            });
                        }
                        bus.flush();
                        maybe_compact(&exec, &compaction, compact_force_after);
                    }
                    _ = compact.tick() => {
                        if compaction.due_since.get().is_none() {
                            compaction.due_since.set(Some(Instant::now()));
                        }
                    }
                    _ = cp.tick() => st.borrow().checkpoint(now_ms()),
                    _ = wd.tick(), if wd_every.is_some() => crate::notify::notify("WATCHDOG=1"),
                    () = &mut shutdown => break,
                }
            }
        })
        .await;
    // Last words: sources' state, then events still queued on the bus.
    sources.persist();
    tel.flush();
    bus.flush();
    drop((sources, bus, tel, exec, wired));
    // Dropping the LocalSet ends every connection task and with them the
    // last references to the state (and the redb lock). A compaction still
    // running on the blocking pool holds its own handle; the runtime waits
    // for it on shutdown.
    drop(local);
    let _ = std::fs::remove_file(&paths.exec_sock);
    Ok(())
}
