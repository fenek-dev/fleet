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
//! order. Single-threaded: state lives in one `RefCell`, and command handling
//! never awaits while holding it.
//!
//! Operations are dispatched through a `fleet_ops::Registry`: generic ones
//! come from `fleet-ops`, state-bound ones (roster, policy, veto,
//! `agent.health`, `roster.pending`, `change.confirm`, `changes.list`) from
//! [`ops`]. `StreamOpen` runs the same pipeline and then [`stream`] pumps
//! the handler's `OpStream`.
//!
//! Pipeline per command ([`Exec::admit`], design §5.6): verify → policy →
//! `Request`/`StreamOpen` matches `Op::is_stream` → `Op::check_args` →
//! `expected_version` present if required → handler `validate` →
//! escalation (`OpHandler::requires_elevated` for `Op::may_escalate` ops;
//! Elevated without an approval is `ApprovalRequired`) → stream slot →
//! commit → intent. Ops with `Op::auto_revert` then run under the
//! auto-revert protocol (§4.10, [`Exec::apply_reverting`]).

mod ops;
mod stream;

use crate::authorized_keys;
use crate::frame::Reassembler;
use crate::install::GATE_USER;
use crate::ipc::{self, IpcMsg};
use crate::paths::Paths;
use crate::pending::{
    self, ChangeId, ChangeKind, ChangeOrigin, PendingChange, PendingDir, PendingError, SessionId,
};
use crate::revert::{self, RegistryRevert, Revert, Runner, SystemRunner};
use crate::store::{CheckpointSigner, Intent, MetaKey, Store, StoreError};
use crate::{fsutil, now_ms};
use fleet_crypto::receipt::{receipt_for, sign_event, sign_receipt};
use fleet_crypto::roster::{self, PendingRoster, RecoveryClock, next_grace_remaining, roster_hash};
use fleet_crypto::sig::Ed25519Signer;
use fleet_crypto::verify::{self, VerifiedCommand, VerifyCtx};
use fleet_ops::{Invocation, OpHandler, OpMeta, OpOutput, Registry, Reverters, Revertible, SysCtx};
use fleet_proto::chunk::split_frame;
use fleet_proto::policy::AiAccess;
use fleet_proto::{
    Actor, ErrorCode, Event, Hash32, KeyKind, Message, Op, OpSummary, Outcome, P256Public,
    PROTO_VERSION, Payload, PendingRecovery, Policy, RequestId, RootApproval, ServerId, Signature,
    SignedCommand, SignedEvent, SignedReceipt, SignedRoster, Tier, decode, encode,
};
use serde::{Deserialize, Serialize};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::future::Future;
use std::rc::Rc;
use std::time::{Duration, Instant};
use tokio::net::UnixStream;
use tokio::sync::{Semaphore, broadcast, mpsc, oneshot, watch};

/// A gate must send `SessionOpen`/`ControlOpen` within this after connecting.
pub const SESSION_OPEN_TIMEOUT: Duration = Duration::from_secs(30);
/// Concurrent connections from the gate (sessions + control); more are
/// closed on accept.
pub const MAX_CONNECTIONS: usize = 64;
/// Bytes held in reassembly buffers across all connections; a connection
/// that pushes the total over this is closed.
pub const MAX_BUFFERED_BYTES: usize = 32 << 20;
/// Replay-cache pruning runs at most this often.
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

/// Ends `sshd` sessions of devices removed from the roster, matched by SSH
/// key (design §5.3 rule 5, §4.6). Stub for now: the real implementation
/// needs the login-source tracking of §4.6.
pub trait SessionTerminator {
    fn end_sessions(&self, removed_ssh_keys: &[P256Public]);
}

/// Does nothing (see [`SessionTerminator`]).
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
    /// replay pruning, `authorized_keys` refresh.
    pub maintenance_interval: Duration,
    /// Restores snapshots (deadline passed, crashed reverts, failed
    /// applies). Default: `RegistryRevert::system()`, the same modules the
    /// `revert <id>` process uses.
    pub reverter: Box<dyn Revert>,
    /// Snapshot modules for auto-revert ops, by kind (§4.10). An auto-revert
    /// op whose kind has none is refused with `Unsupported`.
    pub reverters: Reverters,
    /// Arms auto-revert timers again at startup (§4.10).
    pub runner: Box<dyn Runner>,
    pub terminator: Box<dyn SessionTerminator>,
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
}

impl ExecConfig {
    pub fn new(paths: Paths, gate_uid: u32) -> Self {
        Self {
            paths,
            gate_uid,
            checkpoint_interval: Duration::from_secs(3600),
            maintenance_interval: Duration::from_secs(5),
            reverter: Box::new(RegistryRevert::system()),
            reverters: Reverters::with_generic(),
            runner: Box::new(SystemRunner),
            terminator: Box::new(NoopTerminator),
            ctx: SysCtx::system(),
            handlers: Vec::new(),
            stream_checkpoint_interval: Duration::from_secs(5),
            stream_send_timeout: Duration::from_secs(10),
        }
    }
}

/// `MetaKey::Policy`: the TOML as received and the approval it carried
/// (none for the policy given to `install`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPolicy {
    pub toml: String,
    pub approval: Option<RootApproval>,
}

/// `MetaKey::PendingRecovery`. The delay is kept as time *remaining*,
/// counted down with the monotonic clock (design §5.3): changing the wall
/// clock can't hurry an activation, and downtime doesn't count.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredPending {
    roster: SignedRoster,
    hash: Hash32,
    submitted_at_ms: u64,
    remaining_ms: u64,
    grace_until_ms: Option<u64>,
}

/// A pending recovery roster and its countdown.
#[derive(Debug, Clone)]
struct PendingState {
    roster: SignedRoster,
    hash: Hash32,
    submitted_at_ms: u64,
    remaining_ms: u64,
    /// `remaining_ms` as last persisted.
    persisted_ms: u64,
    /// The local recovery-grace end at submission, in the frame of
    /// `submitted_at_ms` (`RecoveryClock::local_grace_until_ms`); activation
    /// judges the grace window as it was then.
    grace_until_ms: Option<u64>,
}

impl PendingState {
    /// The `fleet_crypto` view, with the activation time projected from the
    /// wall clock now (for display, `check_veto` and `activate`).
    fn roster_at(&self, now_ms: u64) -> PendingRoster {
        PendingRoster {
            roster: self.roster.clone(),
            hash: self.hash,
            submitted_at_ms: self.submitted_at_ms,
            activates_at_ms: now_ms.saturating_add(self.remaining_ms),
        }
    }

    fn wire(&self, now_ms: u64) -> PendingRecovery {
        PendingRecovery {
            hash: self.hash,
            activates_at_ms: now_ms.saturating_add(self.remaining_ms),
        }
    }

    fn stored(&self) -> StoredPending {
        StoredPending {
            roster: self.roster.clone(),
            hash: self.hash,
            submitted_at_ms: self.submitted_at_ms,
            remaining_ms: self.remaining_ms,
            grace_until_ms: self.grace_until_ms,
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

/// What every gate connection needs to know; pushed on change.
#[derive(Debug, Clone)]
struct GateView {
    roster: Rc<Vec<u8>>,
    /// End of the local recovery grace (monotonic).
    grace_deadline: Option<Instant>,
    commands_per_minute: u32,
}

impl GateView {
    fn msgs(&self) -> Vec<IpcMsg> {
        vec![
            IpcMsg::RosterUpdate {
                roster: self.roster.as_ref().clone(),
                grace_remaining_ms: self.grace_deadline.map(remaining_ms),
            },
            IpcMsg::Limits {
                commands_per_minute: self.commands_per_minute,
            },
        ]
    }
}

struct AgentKey<'a>(&'a Ed25519Signer);

impl CheckpointSigner for AgentKey<'_> {
    fn sign(&self, msg: &[u8]) -> Signature {
        self.0.sign(msg)
    }
}

struct State {
    store: Store,
    paths: Paths,
    pending_dir: PendingDir,
    server_id: ServerId,
    signer: Ed25519Signer,
    roster: SignedRoster,
    epoch_hashes: Vec<Hash32>,
    /// End of the local recovery grace for `roster.prev_recovery`, counted
    /// on the monotonic clock (design §5.3); persisted as time remaining.
    grace_deadline: Option<Instant>,
    /// Remaining grace as last persisted.
    grace_persisted_ms: u64,
    pending: Option<PendingState>,
    /// Last countdown step of `pending` (monotonic).
    last_tick: Instant,
    last_prune: Option<Instant>,
    policy: Policy,
    admin_user: Option<String>,
    started: Instant,
    /// Random per exec start; binds this run's events (design §6.3).
    run_id: [u8; 16],
    event_seq: u64,
    events: broadcast::Sender<SignedEvent>,
    view: watch::Sender<GateView>,
    reverter: Box<dyn Revert>,
    runner: Box<dyn Runner>,
    terminator: Box<dyn SessionTerminator>,
}

fn meta_decode<T: serde::de::DeserializeOwned>(
    store: &Store,
    key: MetaKey,
    name: &'static str,
) -> Result<Option<T>, ExecError> {
    store
        .meta()
        .get(key)?
        .map(|b| decode(&b).map_err(|_| ExecError::Corrupt(name)))
        .transpose()
}

fn meta_string(store: &Store, key: MetaKey) -> Result<Option<String>, ExecError> {
    store
        .meta()
        .get(key)?
        .map(|b| String::from_utf8(b).map_err(|_| ExecError::Corrupt("utf-8 meta")))
        .transpose()
}

/// Parses a stored policy and checks it belongs to this fleet and server.
fn load_policy(sp: &StoredPolicy, roster: &SignedRoster, server: &ServerId) -> Option<Policy> {
    let p = Policy::from_toml(&sp.toml).ok()?;
    (p.fleet_id == roster.roster.fleet_id && p.server_id == *server).then_some(p)
}

/// Reads the signing seed into a wiped buffer (no symlinks, 32 bytes).
pub fn load_signing_key(paths: &Paths) -> Result<Ed25519Signer, ExecError> {
    let seed = fsutil::read_key32(&paths.signing_key)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::InvalidData => ExecError::Corrupt("signing key"),
            _ => ExecError::Io(e),
        })?
        .ok_or(ExecError::NotInstalled("signing key"))?;
    Ok(Ed25519Signer::from_seed(&seed))
}

fn log(what: &str, e: impl std::fmt::Display) {
    eprintln!("fleet-exec: {what}: {e}");
}

impl State {
    fn load(cfg: ExecConfig) -> Result<Self, ExecError> {
        let store = Store::open(&cfg.paths.state_db)?;
        let roster: SignedRoster = meta_decode(&store, MetaKey::Roster, "roster")?
            .ok_or(ExecError::NotInstalled("roster"))?;
        let server_id =
            meta_string(&store, MetaKey::ServerId)?.ok_or(ExecError::NotInstalled("server id"))?;
        let server_id = ServerId::new(server_id).map_err(|_| ExecError::Corrupt("server id"))?;
        let sp: StoredPolicy = meta_decode(&store, MetaKey::Policy, "policy")?
            .ok_or(ExecError::NotInstalled("policy"))?;
        let policy = load_policy(&sp, &roster, &server_id).ok_or(ExecError::Corrupt("policy"))?;
        let epoch_hashes =
            meta_decode(&store, MetaKey::EpochHashes, "epoch hashes")?.unwrap_or_default();
        // Downtime doesn't count: the countdown resumes where it was saved.
        let grace_ms: Option<u64> =
            meta_decode(&store, MetaKey::GraceRemaining, "grace remaining")?;
        let grace_deadline =
            grace_ms.and_then(|r| Instant::now().checked_add(Duration::from_millis(r)));
        let pending = meta_decode::<StoredPending>(&store, MetaKey::PendingRecovery, "pending")?
            .map(|s| PendingState {
                roster: s.roster,
                hash: s.hash,
                submitted_at_ms: s.submitted_at_ms,
                remaining_ms: s.remaining_ms,
                persisted_ms: s.remaining_ms,
                grace_until_ms: s.grace_until_ms,
            });
        let admin_user = meta_string(&store, MetaKey::AdminUser)?;
        let signer = load_signing_key(&cfg.paths)?;
        let mut run_id = [0u8; 16];
        fleet_crypto::random_bytes(&mut run_id)
            .map_err(|_| ExecError::Io(std::io::Error::other("random run id")))?;
        let view = GateView {
            roster: Rc::new(encode(&roster)),
            grace_deadline,
            commands_per_minute: policy.limits.commands_per_minute,
        };
        Ok(Self {
            store,
            pending_dir: PendingDir::from_paths(&cfg.paths),
            paths: cfg.paths,
            server_id,
            signer,
            roster,
            epoch_hashes,
            grace_deadline,
            grace_persisted_ms: grace_ms.unwrap_or(0),
            pending,
            last_tick: Instant::now(),
            last_prune: None,
            policy,
            admin_user,
            started: Instant::now(),
            run_id,
            event_seq: 0,
            events: broadcast::channel(64).0,
            view: watch::channel(view).0,
            reverter: cfg.reverter,
            runner: cfg.runner,
            terminator: cfg.terminator,
        })
    }

    /// Local recovery grace left (monotonic), `None` if there is none.
    fn grace_remaining(&self) -> Option<u64> {
        self.grace_deadline.map(remaining_ms)
    }

    fn clock(&self, now_ms: u64) -> RecoveryClock {
        RecoveryClock::with_grace_remaining(now_ms, self.grace_remaining())
    }

    /// Persists the remaining grace now and then; drops it once run out.
    fn tick_grace(&mut self) {
        let Some(rem) = self.grace_remaining() else {
            return;
        };
        let (value, done) = if rem == 0 {
            (None, true)
        } else if self.grace_persisted_ms.saturating_sub(rem) >= PENDING_PERSIST_EVERY_MS {
            (Some(encode(&rem)), false)
        } else {
            return;
        };
        match self
            .store
            .meta()
            .update(&[(MetaKey::GraceRemaining, value.as_deref())])
        {
            Ok(()) => {
                self.grace_persisted_ms = rem;
                if done {
                    self.grace_deadline = None;
                }
            }
            Err(e) => log("persist recovery grace", e),
        }
    }

    fn emit(&mut self, event: Event) {
        self.event_seq += 1;
        // No receivers (no gate connected) is fine; events are best-effort
        // until the offline event log exists.
        let signed = sign_event(
            self.server_id.clone(),
            self.run_id,
            self.event_seq,
            now_ms(),
            event,
            &self.signer,
        );
        let _ = self.events.send(signed);
    }

    fn push_view(&self) {
        self.view.send_replace(GateView {
            roster: Rc::new(encode(&self.roster)),
            grace_deadline: self.grace_deadline,
            commands_per_minute: self.policy.limits.commands_per_minute,
        });
    }

    /// Startup: close interrupted intents, recover `pending/` (§4.10 step
    /// 5), audit revert markers, prune replay, refresh authorized_keys.
    /// Per-entry problems are logged and quarantined, never fatal.
    fn startup(&mut self, now: u64) -> Result<(), ExecError> {
        self.store.audit().mark_interrupted_on_start(now)?;
        self.pending_dir.create()?;
        self.recover_pending(now);
        self.process_markers(now);
        self.prune(true);
        self.sync_authorized_keys(now);
        Ok(())
    }

    fn maintenance(&mut self, now: u64) {
        self.revert_expired(now);
        self.process_markers(now);
        self.tick_pending(now);
        self.tick_grace();
        self.prune(false);
        self.sync_authorized_keys(now);
    }

    fn prune(&mut self, force: bool) {
        if !force && self.last_prune.is_some_and(|t| t.elapsed() < PRUNE_EVERY) {
            return;
        }
        self.last_prune = Some(Instant::now());
        if let Err(e) = self.store.replay().prune(now_ms()) {
            log("replay prune", e);
        }
    }

    fn checkpoint(&self, now: u64) {
        let res = self
            .store
            .audit()
            .checkpoint(self.server_id.clone(), now, &AgentKey(&self.signer))
            .and_then(|cp| self.store.meta().set(MetaKey::Checkpoint, &encode(&cp)));
        if let Err(e) = res {
            log("audit checkpoint", e);
        }
    }

    /// Moves an unreadable file aside and audits it (`System`,
    /// `Failed(Internal)`).
    fn quarantine(&mut self, path: &std::path::Path, now: u64) {
        match pending::quarantine(path, &self.paths.quarantine_dir) {
            Ok(dest) => log("quarantined", dest.display()),
            Err(e) => log(&format!("quarantine {}", path.display()), e),
        }
        let op = OpSummary {
            tag: 0,
            args: Vec::new(),
        };
        if let Err(e) =
            self.store
                .audit()
                .append_system(now, [0; 32], op, Outcome::Failed(ErrorCode::Internal))
        {
            log("audit quarantine", e);
        }
    }

    /// Startup pass over `pending/`: finish crashed reverts (`.claimed`),
    /// revert what expired while exec was down, re-arm timers for the rest
    /// (a reboot drops transient timers), quarantine unreadable files.
    fn recover_pending(&mut self, now: u64) {
        let entries = match self.pending_dir.scan() {
            Ok(e) => e,
            Err(e) => return log("scan pending", e),
        };
        for e in entries {
            let Some(change) = &e.value else {
                self.quarantine(&e.path, now);
                continue;
            };
            let has_marker = self.pending_dir.has_marker(e.id);
            let res = if e.claimed {
                if has_marker {
                    // Crashed after writing its marker.
                    self.pending_dir.remove_claimed(e.id).map(drop)
                } else {
                    revert::finish_claimed(&self.pending_dir, e.id, self.reverter.as_ref(), now)
                        .map(drop)
                }
            } else if change.deadline_ms <= now {
                if has_marker {
                    self.pending_dir.remove(e.id).map(drop)
                } else {
                    revert::run_revert(&self.pending_dir, e.id, self.reverter.as_ref(), now)
                        .map(drop)
                }
            } else {
                let secs = (change.deadline_ms - now).div_ceil(1000);
                let secs = u32::try_from(secs).unwrap_or(u32::MAX).max(1);
                // Fails harmlessly if the timer survived (exec restart, no
                // reboot); maintenance reverts on the deadline regardless.
                if let Err(err) = revert::arm_timer(self.runner.as_ref(), e.id, secs) {
                    log(&format!("re-arm revert timer {}", e.id), err);
                }
                Ok(())
            };
            if let Err(err) = res {
                log(&format!("pending change {}", e.id), err);
            }
        }
    }

    /// Belt and braces for lost timers: reverts unclaimed changes whose
    /// deadline passed. Claiming makes this safe against a concurrent timer.
    fn revert_expired(&mut self, now: u64) {
        let Ok(entries) = self.pending_dir.scan() else {
            return;
        };
        for e in entries.into_iter().filter(|e| !e.claimed) {
            match &e.value {
                None => self.quarantine(&e.path, now),
                Some(c) if c.deadline_ms <= now => {
                    if let Err(err) =
                        revert::run_revert(&self.pending_dir, e.id, self.reverter.as_ref(), now)
                    {
                        log(&format!("revert {}", e.id), err);
                    }
                }
                Some(_) => {}
            }
        }
    }

    /// Audits markers left by `revert <id>` and emits `ChangeReverted`.
    fn process_markers(&mut self, now: u64) {
        let markers = match self.pending_dir.scan_markers() {
            Ok(m) => m,
            Err(e) => return log("scan reverted", e),
        };
        for e in markers {
            let Some(m) = &e.value else {
                self.quarantine(&e.path, now);
                continue;
            };
            let audit = self.store.audit();
            let seq = match audit.append_revert(m.origin_audit_seq, now, m.restored) {
                Ok(seq) => seq,
                // Origin entry missing: still record that a revert happened.
                Err(StoreError::NotOpenIntent(_)) => match audit.append_system(
                    now,
                    [0; 32],
                    OpSummary {
                        tag: 0,
                        args: Vec::new(),
                    },
                    if m.restored {
                        Outcome::Reverted
                    } else {
                        Outcome::Failed(ErrorCode::Internal)
                    },
                ) {
                    Ok(seq) => seq,
                    Err(err) => {
                        log("audit revert", err);
                        continue;
                    }
                },
                Err(err) => {
                    log("audit revert", err);
                    continue;
                }
            };
            self.emit(Event::ChangeReverted {
                change_id: e.id.0,
                audit_seq: seq,
            });
            if let Err(err) = self.pending_dir.remove_marker(e.id) {
                log("remove marker", err);
            }
        }
    }

    fn sync_authorized_keys(&self, now: u64) {
        if let Some(user) = &self.admin_user
            && let Err(e) = authorized_keys::sync(
                &self.paths.authorized_keys_dir,
                user,
                &self.roster.roster,
                self.clock(now),
            )
        {
            log("authorized_keys", e);
        }
    }

    fn set_pending(&mut self, p: Option<PendingState>) -> Result<(), StoreError> {
        let bytes = p.as_ref().map(|p| encode(&p.stored()));
        self.store
            .meta()
            .update(&[(MetaKey::PendingRecovery, bytes.as_deref())])?;
        self.pending = p;
        Ok(())
    }

    /// Counts the pending recovery's delay down by the monotonic time since
    /// the last tick; persists now and then; activates at zero.
    fn tick_pending(&mut self, now: u64) {
        let elapsed = u64::try_from(self.last_tick.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_tick = Instant::now();
        let Some(p) = self.pending.as_mut() else {
            return;
        };
        p.remaining_ms = p.remaining_ms.saturating_sub(elapsed);
        if p.remaining_ms == 0 {
            self.activate_due(now);
        } else if p.persisted_ms.saturating_sub(p.remaining_ms) >= PENDING_PERSIST_EVERY_MS {
            let stored = encode(&p.stored());
            match self
                .store
                .meta()
                .update(&[(MetaKey::PendingRecovery, Some(&stored[..]))])
            {
                Ok(()) => p.persisted_ms = p.remaining_ms,
                Err(e) => log("persist pending recovery", e),
            }
        }
    }

    /// Installs an accepted roster: persist, rewrite authorized_keys, end
    /// removed devices' sessions, push to gates, emit `RosterChanged`.
    fn install_roster(&mut self, new: SignedRoster, now: u64) -> Result<(), StoreError> {
        let cur = &self.roster;
        let epoch_changed = new.roster.epoch != cur.roster.epoch;
        let hashes = if epoch_changed {
            Vec::new()
        } else {
            let mut h = self.epoch_hashes.clone();
            h.push(roster_hash(cur));
            h
        };
        let grace = next_grace_remaining(&cur.roster, &new.roster, self.grace_remaining());
        let removed: Vec<P256Public> = cur
            .roster
            .devices
            .iter()
            .filter(|d| {
                new.roster
                    .device(&d.id)
                    .is_none_or(|n| n.ssh_key != d.ssh_key)
            })
            .map(|d| d.ssh_key)
            .collect();
        let (rb, hb, gb) = (encode(&new), encode(&hashes), grace.map(|g| encode(&g)));
        let mut changes = vec![
            (MetaKey::Roster, Some(&rb[..])),
            (MetaKey::EpochHashes, Some(&hb[..])),
            (MetaKey::GraceRemaining, gb.as_deref()),
        ];
        // A pending recovery targets the old epoch; it can never activate.
        if epoch_changed {
            changes.push((MetaKey::PendingRecovery, None));
        }
        self.store.meta().update(&changes)?;
        let (epoch, version) = (new.roster.epoch, new.roster.version);
        self.roster = new;
        self.epoch_hashes = hashes;
        self.grace_deadline =
            grace.and_then(|g| Instant::now().checked_add(Duration::from_millis(g)));
        self.grace_persisted_ms = grace.unwrap_or(0);
        if epoch_changed {
            self.pending = None;
        }
        self.terminator.end_sessions(&removed);
        self.sync_authorized_keys(now);
        self.push_view();
        self.emit(Event::RosterChanged { epoch, version });
        Ok(())
    }

    /// Installs a pending recovery roster whose delay has run out. The audit
    /// entry records what really happened; on any failure the pending entry
    /// is dropped (with `RecoveryVetoed`) so it can't retry forever.
    fn activate_due(&mut self, now: u64) {
        let Some(ps) = self.pending.as_ref() else {
            return;
        };
        if ps.remaining_ms > 0 {
            return;
        }
        let p = ps.roster_at(now);
        let res = roster::activate(&self.roster, &self.epoch_hashes, &p, now, ps.grace_until_ms);
        let op = OpSummary::from(&Op::RosterUpdate {
            roster: Box::new(p.roster.clone()),
        });
        let outcome = match res {
            Ok(()) => match self.install_roster(p.roster.clone(), now) {
                Ok(()) => Outcome::Ok,
                Err(e) => {
                    log("activate pending recovery", e);
                    Outcome::Failed(ErrorCode::Internal)
                }
            },
            Err(e) => Outcome::Failed(e.code()),
        };
        if let Err(e) = self.store.audit().append_system(now, p.hash, op, outcome) {
            log("audit recovery activation", e);
        }
        if outcome != Outcome::Ok {
            if let Err(e) = self.set_pending(None) {
                log("clear pending recovery", e);
                self.pending = None;
            }
            self.emit(Event::RecoveryVetoed { hash: p.hash });
        }
    }

    fn pending_wire(&self, now: u64) -> Option<PendingRecovery> {
        self.pending.as_ref().map(|p| p.wire(now))
    }

    fn hello(&self) -> Message {
        let now = now_ms();
        Message::Hello {
            proto_min: PROTO_VERSION,
            proto_max: PROTO_VERSION,
            agent_version: crate::agent_version(),
            server_id: self.server_id.clone(),
            time_ms: now,
            roster_epoch: self.roster.roster.epoch,
            roster_version: self.roster.roster.version,
            pending_recovery: self.pending_wire(now),
        }
    }

    /// The stored answer to an identical command that already ran.
    fn stored_response(
        &self,
        hash: &Hash32,
    ) -> Option<(Result<Payload, ErrorCode>, SignedReceipt)> {
        match self.store.replay().get_response(hash) {
            Ok(Some(bytes)) => match decode(&bytes) {
                Ok(original) => Some(original),
                // Falls through to verification, which answers `Replay`.
                Err(e) => {
                    log("stored response", e);
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                log("stored response", e);
                None
            }
        }
    }

    fn verify(
        &self,
        session: KeyKind,
        cmd: &SignedCommand,
        now: u64,
    ) -> Result<VerifiedCommand, ErrorCode> {
        let ctx = VerifyCtx {
            roster: &self.roster.roster,
            server_id: &self.server_id,
            now_ms: now,
            skew_ms: verify::DEFAULT_SKEW_MS,
            max_ttl_ms: verify::DEFAULT_MAX_TTL_MS,
            // Asserted by the gate; it can only narrow what the command's
            // own key kind already permits.
            session_key_kind: session,
            grace_remaining_ms: self.grace_remaining(),
        };
        verify::verify_command(cmd, &ctx, &self.store.replay()).map_err(|e| e.code())
    }

    /// Consumes the replay entries, then appends the audit intent; returns
    /// its seq.
    fn commit_intent(
        &mut self,
        v: &VerifiedCommand,
        cmd: &SignedCommand,
        now: u64,
    ) -> Result<u64, Refused> {
        v.commit(&mut self.store.replay()).map_err(|e| Refused {
            code: e.code(),
            consumed_until: None,
        })?;
        let intent = Intent {
            time_ms: now,
            actor: v.body.actor.clone(),
            device_id: v.device_id,
            command_hash: v.command_hash,
            signature: cmd.signature,
            op: OpSummary::from(&v.body.op),
        };
        self.store
            .audit()
            .append_intent(intent)
            .map_err(|_| Refused {
                code: ErrorCode::Internal,
                consumed_until: Some(v.nonce_expires_at_ms),
            })
    }

    /// Appends the result entry; `None` if that failed (the change, if any,
    /// happened, but startup will mark the intent Interrupted).
    fn audit_result(&mut self, intent_seq: u64, status: Result<(), ErrorCode>) -> Option<u64> {
        let outcome = match status {
            Ok(()) => Outcome::Ok,
            Err(c) => Outcome::Failed(c),
        };
        self.store
            .audit()
            .append_result(intent_seq, now_ms(), outcome)
            .map_err(|e| log("audit result", e))
            .ok()
    }

    /// The pending change `change.confirm` names, if it's still pending.
    fn pending_change(&self, op: &Op) -> Result<Option<PendingChange>, ErrorCode> {
        let Op::ChangeConfirm { change_id } = op else {
            return Ok(None);
        };
        self.pending_dir.get(ChangeId(*change_id)).map_err(|e| {
            log("read pending change", e);
            ErrorCode::Internal
        })
    }

    fn check_policy(&self, v: &VerifiedCommand) -> Result<(), ErrorCode> {
        let op = &v.body.op;
        // `change.confirm` is in the `firewall` group, but it confirms any
        // auto-revert change (mesh, profile, authorized keys, …). The device
        // that made the change may always confirm it (design §5.4): its
        // original command already passed policy, and refusing the confirm
        // would only revert an allowed change.
        let own_change = || {
            self.pending_change(op)
                .ok()
                .flatten()
                .is_some_and(|c| c.origin.device_id == v.device_id)
        };
        if !self.policy.allows_group(op.group()) && !own_change() {
            return Err(ErrorCode::PolicyDenied);
        }
        let tier = self.policy.effective_tier(op);
        // `[elevated] extra` can make an envelope-only op Elevated.
        if tier == Tier::Elevated
            && v.approval.is_none()
            && op.authorization() != fleet_proto::Authorization::SelfSigned
        {
            return Err(ErrorCode::ApprovalRequired);
        }
        if let Actor::Ai { .. } = v.body.actor {
            let ok = match self.policy.actors.ai {
                AiAccess::Full => true,
                AiAccess::ReadOnly => tier == Tier::Read,
                AiAccess::None => false,
            };
            if !ok {
                return Err(ErrorCode::PolicyDenied);
            }
        }
        Ok(())
    }
}

/// A command refused before it ran: the code, and until when its nonce
/// stays recorded if it was consumed.
struct Refused {
    code: ErrorCode,
    consumed_until: Option<u64>,
}

/// A command that passed every check; its nonce is consumed and its audit
/// intent written (`meta.audit_seq`).
struct Admitted {
    handler: Rc<dyn OpHandler>,
    meta: OpMeta,
    intent_seq: u64,
    consumed_until: u64,
    /// Auto-revert ops: the snapshot module for their kind.
    revertible: Option<(ChangeKind, Rc<dyn Revertible>)>,
}

/// One gate connection: the key kind the gate authenticated and exec's own
/// random id for it (`change.confirm` must come over a different one).
#[derive(Debug, Clone, Copy)]
struct Session {
    key: KeyKind,
    id: SessionId,
}

/// Shared by every connection: state, dispatch, environment.
struct Exec {
    st: Rc<RefCell<State>>,
    registry: Registry,
    reverters: Reverters,
    ctx: SysCtx,
    /// Streams running across all connections
    /// (`limits.max_stream_sessions`).
    streams: Cell<u32>,
    checkpoint_every: Duration,
    send_timeout: Duration,
}

/// `changes.list` / `ChangePending` view of a pending change.
fn wire_pending(id: ChangeId, c: &PendingChange) -> fleet_proto::payload::PendingChange {
    fleet_proto::payload::PendingChange {
        change_id: id.0,
        kind: c.kind,
        op_tag: c.origin.op_tag,
        created_ms: c.origin.created_ms,
        deadline_ms: c.deadline_ms,
        new_version: c.origin.new_version,
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
    fn admit(
        &self,
        session: Session,
        cmd: &SignedCommand,
        inv: Invocation,
        now: u64,
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
        self.st.borrow().check_policy(&v).map_err(refuse)?;
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
        // A fresh connection proves access still works (§4.10 step 3).
        if let Some(c) = self.st.borrow().pending_change(op).map_err(refuse)?
            && c.origin.session == session.id
        {
            return Err(refuse(ErrorCode::PolicyDenied));
        }
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
        if inv == Invocation::Stream
            && self.streams.get() >= self.st.borrow().policy.limits.max_stream_sessions
        {
            return Err(refuse(ErrorCode::Busy));
        }
        let intent_seq = self
            .st
            .borrow_mut()
            .commit_intent(&meta.command, cmd, now)?;
        meta.audit_seq = Some(intent_seq);
        Ok(Admitted {
            handler,
            consumed_until: meta.command.nonce_expires_at_ms,
            meta,
            intent_seq,
            revertible,
        })
    }

    /// Runs an admitted request: plain ops through their handler, auto-revert
    /// ops through [`Self::apply_reverting`].
    async fn execute(&self, a: &Admitted, session: Session) -> Result<Payload, ErrorCode> {
        let op = &a.meta.command.body.op;
        if let Some((kind, r)) = &a.revertible {
            return self.apply_reverting(a, session, *kind, r.as_ref()).await;
        }
        match a.handler.handle(&self.ctx, op, &a.meta).await {
            Ok(OpOutput::Payload(p)) => Ok(p),
            Ok(OpOutput::Stream(_)) => Err(ErrorCode::Internal),
            Err(e) => {
                log_op_error(op.name(), &e);
                Err(e.code())
            }
        }
    }

    /// Auto-revert protocol (design §4.10): snapshot, write
    /// `pending/<id>.bin`, arm the independent timer, and only then apply.
    /// Answers `Payload::ChangePending`. If applying fails the snapshot is
    /// restored right away (claimed like any revert, so it's audited as
    /// `Reverted` by the marker pass) and the timer stopped.
    async fn apply_reverting(
        &self,
        a: &Admitted,
        session: Session,
        kind: ChangeKind,
        r: &dyn Revertible,
    ) -> Result<Payload, ErrorCode> {
        let op = &a.meta.command.body.op;
        let fail = |e: fleet_ops::OpError| {
            log_op_error(op.name(), &e);
            e.code()
        };
        let snapshot = r.snapshot(&self.ctx, op).map_err(fail)?;
        let mut raw = [0u8; 16];
        fleet_crypto::random_bytes(&mut raw).map_err(|_| ErrorCode::Internal)?;
        let id = ChangeId(raw);
        let secs = self.st.borrow().policy.safety.auto_revert_seconds.max(1);
        let created = now_ms();
        let mut change = PendingChange {
            kind,
            origin: ChangeOrigin {
                device_id: a.meta.command.device_id,
                session: session.id,
                op_tag: op.tag(),
                created_ms: created,
                new_version: None,
            },
            snapshot,
            deadline_ms: created.saturating_add(u64::from(secs) * 1000),
            audit_seq: a.intent_seq,
        };
        {
            let st = self.st.borrow();
            st.pending_dir.insert(id, &change).map_err(|e| {
                log("write pending change", e);
                ErrorCode::Internal
            })?;
            // Never apply without the independent timer.
            if let Err(e) = revert::arm_timer(st.runner.as_ref(), id, secs) {
                log("arm revert timer", e);
                if let Err(e) = st.pending_dir.remove(id) {
                    log("remove pending change", e);
                }
                return Err(ErrorCode::Internal);
            }
        }
        let applied = match a.handler.handle(&self.ctx, op, &a.meta).await {
            Ok(OpOutput::Payload(p)) => Ok(p),
            Ok(OpOutput::Stream(_)) => Err(ErrorCode::Internal),
            Err(e) => Err(fail(e)),
        };
        let st = self.st.borrow();
        let payload = match applied {
            Ok(p) => p,
            Err(code) => {
                match revert::run_revert(&st.pending_dir, id, st.reverter.as_ref(), now_ms()) {
                    Ok(_) => {
                        if let Err(e) = revert::disarm_timer(st.runner.as_ref(), id) {
                            log("disarm revert timer", e);
                        }
                    }
                    // The timer still reverts at the deadline.
                    Err(e) => log("revert failed change", e),
                }
                return Err(code);
            }
        };
        let new_version = match payload {
            Payload::ChangePending(p) => p.new_version,
            _ => None,
        };
        if new_version.is_some() {
            change.origin.new_version = new_version;
            // Only if still pending: never resurrect a claimed change.
            if matches!(st.pending_dir.get(id), Ok(Some(_)))
                && let Err(e) = st.pending_dir.insert(id, &change)
            {
                log("update pending change", e);
            }
        }
        Ok(Payload::ChangePending(wire_pending(id, &change)))
    }

    /// One `Request`. Every answer is receipted, rejections included
    /// (`audit_seq` `None` before the intent).
    ///
    /// The answer to a command that consumed its nonce is kept (as long as
    /// the nonce) and returned again, unchanged, for the identical command:
    /// a gate that drops the reply and re-forwards the command gets the
    /// original result and receipt, never a signed `Replay` failure for a
    /// command that did run.
    async fn request(
        &self,
        session: Session,
        cmd: &SignedCommand,
    ) -> (Result<Payload, ErrorCode>, SignedReceipt) {
        let hash = verify::command_hash(cmd);
        if let Some(original) = self.st.borrow().stored_response(&hash) {
            return original;
        }
        let now = now_ms();
        let (result, audit_seq, consumed_until) =
            match self.admit(session, cmd, Invocation::Request, now) {
                Err(r) => (Err(r.code), None, r.consumed_until),
                Ok(a) => {
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
        (result, receipt)
    }
}

/// Creates the socket directories and binds `exec.sock` (design §4.1):
/// `/run/fleet-exec` `0710 root:fleet-gate`, a fresh root-only `.tmp` inside
/// it for binding, and the socket `0660 root:fleet-gate` renamed into place.
/// Nothing here resolves a path the gate can write.
fn bind_exec_socket(paths: &Paths) -> Result<tokio::net::UnixListener, ExecError> {
    let gate_gid = if fsutil::current_uid()? == 0 {
        Some(
            fsutil::lookup_gid(&paths.group, GATE_USER)
                .ok_or(ExecError::NotInstalled("group fleet-gate"))?,
        )
    } else {
        None
    };
    fsutil::ensure_dir(&paths.exec_run_dir, 0o710)?;
    if let Some(gid) = gate_gid {
        fsutil::lchown(&paths.exec_run_dir, Some(0), Some(gid))?;
    }
    // Recreated every start: an older layout let the gate write here.
    let tmp = &paths.exec_tmp_dir;
    match std::fs::symlink_metadata(tmp) {
        Ok(m) if m.file_type().is_dir() => std::fs::remove_dir_all(tmp)?,
        Ok(_) => std::fs::remove_file(tmp)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(tmp)?;
    }
    Ok(fsutil::bind_socket(&paths.exec_sock, tmp, 0o660, gate_gid)?)
}

/// Connection count and reassembly bytes across all gate connections.
#[derive(Default)]
struct Budget {
    conns: Cell<usize>,
    bytes: Cell<usize>,
}

/// Releases one connection slot and its buffered bytes on drop.
struct ConnGuard {
    budget: Rc<Budget>,
    bytes: Cell<usize>,
}

impl ConnGuard {
    /// Records this connection's new buffered total; `false` if the global
    /// budget is exceeded.
    fn set_bytes(&self, n: usize) -> bool {
        let total = self.budget.bytes.get() - self.bytes.get() + n;
        self.budget.bytes.set(total);
        self.bytes.set(n);
        total <= MAX_BUFFERED_BYTES
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.budget.conns.set(self.budget.conns.get() - 1);
        self.budget
            .bytes
            .set(self.budget.bytes.get() - self.bytes.get());
    }
}

/// Runs exec until `shutdown` completes. The store is closed on return.
pub async fn run(mut cfg: ExecConfig, shutdown: impl Future<Output = ()>) -> Result<(), ExecError> {
    let paths = cfg.paths.clone();
    let gate_uid = cfg.gate_uid;
    let (cp_every, maint_every) = (cfg.checkpoint_interval, cfg.maintenance_interval);
    let ctx = cfg.ctx.clone();
    let extra = std::mem::take(&mut cfg.handlers);
    let reverters = std::mem::take(&mut cfg.reverters);
    let (checkpoint_every, send_timeout) =
        (cfg.stream_checkpoint_interval, cfg.stream_send_timeout);
    let mut state = State::load(cfg)?;
    state.startup(now_ms())?;

    let listener = bind_exec_socket(&paths)?;
    crate::notify::notify("READY=1");

    let st = Rc::new(RefCell::new(state));
    let mut registry = Registry::with_generic();
    let state_ops: Rc<dyn OpHandler> = Rc::new(ops::StateOps(st.clone()));
    for tag in ops::TAGS {
        registry.register(tag, state_ops.clone());
    }
    let change_ops: Rc<dyn OpHandler> = Rc::new(ops::ChangeOps(st.clone()));
    for tag in ops::CHANGE_TAGS {
        registry.register(tag, change_ops.clone());
    }
    for (tag, h) in extra {
        registry.register(tag, h);
    }
    let exec = Rc::new(Exec {
        st: st.clone(),
        registry,
        reverters,
        ctx,
        streams: Cell::new(0),
        checkpoint_every,
        send_timeout,
    });
    let budget = Rc::new(Budget::default());
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            tokio::pin!(shutdown);
            let mut maint = tokio::time::interval(maint_every);
            let mut cp = tokio::time::interval(cp_every);
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
                            let guard = ConnGuard { budget: budget.clone(), bytes: Cell::new(0) };
                            let exec = exec.clone();
                            tokio::task::spawn_local(async move {
                                let _ = connection(stream, exec, gate_uid, &guard).await;
                            });
                        }
                    }
                    _ = maint.tick() => st.borrow_mut().maintenance(now_ms()),
                    _ = cp.tick() => st.borrow().checkpoint(now_ms()),
                    _ = wd.tick(), if wd_every.is_some() => crate::notify::notify("WATCHDOG=1"),
                    () = &mut shutdown => break,
                }
            }
        })
        .await;
    // Dropping the LocalSet ends every connection task and with them the
    // last references to the state (and the redb lock).
    drop(local);
    let _ = std::fs::remove_file(&paths.exec_sock);
    Ok(())
}

/// Outgoing side of one gate connection, shared by its request and stream
/// tasks: frames messages (exec frame ids, top bit clear) into a bounded
/// queue drained by the connection's single writer.
#[derive(Clone)]
struct Out {
    tx: mpsc::Sender<Vec<IpcMsg>>,
    ids: Rc<Cell<u32>>,
}

impl Out {
    fn frame(&self, msg: &Message) -> Vec<IpcMsg> {
        let id = self.ids.get();
        self.ids.set(id.wrapping_add(1) & !ipc::GATE_FRAME_BIT);
        split_frame(id, &encode(msg))
            .into_iter()
            .map(IpcMsg::Chunk)
            .collect()
    }

    async fn send(&self, msg: &Message) -> Option<()> {
        self.tx.send(self.frame(msg)).await.ok()
    }
}

/// Running streams of one connection: id → (generation, cancel).
type ActiveStreams = Rc<RefCell<HashMap<RequestId, (u64, oneshot::Sender<()>)>>>;

async fn connection(
    stream: UnixStream,
    exec: Rc<Exec>,
    gate_uid: u32,
    guard: &ConnGuard,
) -> Option<()> {
    if stream.peer_cred().ok()?.uid() != gate_uid {
        return None;
    }
    let (mut r, mut w) = stream.into_split();
    let (mut view_rx, mut ev_rx) = {
        let s = exec.st.borrow();
        (s.view.subscribe(), s.events.subscribe())
    };
    let (tx, mut rx) = mpsc::channel::<Vec<IpcMsg>>(16);
    let out = Out {
        tx,
        ids: Rc::new(Cell::new(0)),
    };
    let frame = |msg: &Message| out.frame(msg);

    let init = view_rx.borrow_and_update().msgs();
    for m in &init {
        ipc::write_msg(&mut w, m).await.ok()?;
    }
    let first = tokio::time::timeout(SESSION_OPEN_TIMEOUT, ipc::read_msg(&mut r))
        .await
        .ok()?
        .ok()??;
    let key = match first {
        IpcMsg::SessionOpen { key, .. } => key,
        IpcMsg::ControlOpen => return control(r, w, view_rx).await,
        _ => return None,
    };
    // Exec's own id for this session; the gate can't choose it.
    let mut id = [0u8; 16];
    fleet_crypto::random_bytes(&mut id).ok()?;
    let key = Session { key, id };
    let hello = exec.st.borrow().hello();
    for m in &frame(&hello) {
        ipc::write_msg(&mut w, m).await.ok()?;
    }

    let active: ActiveStreams = Rc::default();
    let inflight = Rc::new(Semaphore::new(MAX_INFLIGHT_REQUESTS));
    let up = async {
        let mut reasm = Reassembler::for_exec();
        let mut generation = 0u64;
        loop {
            let IpcMsg::Chunk(c) = ipc::read_msg(&mut r).await.ok()?? else {
                return None::<()>;
            };
            let done = reasm.push(&c).ok()?;
            if !guard.set_bytes(reasm.buffered()) {
                return None;
            }
            let Some((_, bytes)) = done else {
                continue;
            };
            match decode::<Message>(&bytes).ok()? {
                // Each request runs as its own task, so a long operation
                // doesn't hold up `StreamCancel` or other requests. It runs
                // to completion (and is audited) even if the gate goes away.
                Message::Request { id, cmd } => {
                    // Released by the task (`Rc`: no owned permits).
                    inflight.acquire().await.ok()?.forget();
                    let (exec, out, inflight) = (exec.clone(), out.clone(), inflight.clone());
                    tokio::task::spawn_local(async move {
                        let (result, receipt) = exec.request(key, &cmd).await;
                        let reply = Message::Response {
                            id,
                            result,
                            receipt: Some(receipt),
                        };
                        let _ = out.send(&reply).await;
                        inflight.add_permits(1);
                    });
                }
                Message::StreamOpen { id, cmd } => {
                    if active.borrow().contains_key(&id) {
                        // Client bug; unsigned, nothing was verified.
                        let end = Message::StreamEnd {
                            id,
                            status: Err(ErrorCode::InvalidArgument),
                        };
                        out.send(&end).await?;
                        continue;
                    }
                    generation += 1;
                    let (cancel_tx, cancel_rx) = oneshot::channel();
                    active.borrow_mut().insert(id, (generation, cancel_tx));
                    tokio::task::spawn_local(stream::run(
                        exec.clone(),
                        out.clone(),
                        stream::Handle {
                            active: active.clone(),
                            generation,
                            id,
                            cancel: cancel_rx,
                        },
                        key,
                        cmd,
                    ));
                }
                Message::StreamCancel { id } => {
                    if let Some((_, c)) = active.borrow_mut().remove(&id) {
                        let _ = c.send(());
                    }
                }
                _ => return None,
            }
        }
    };
    let tx = out.tx.clone();
    let down = async {
        loop {
            tokio::select! {
                r = view_rx.changed() => {
                    r.ok()?;
                    let msgs = view_rx.borrow_and_update().msgs();
                    tx.send(msgs).await.ok()?;
                }
                e = ev_rx.recv() => match e {
                    Ok(e) => tx.send(frame(&Message::Event(e))).await.ok()?,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return None::<()>,
                },
            }
        }
    };
    let writer = async {
        while let Some(batch) = rx.recv().await {
            for m in &batch {
                ipc::write_msg(&mut w, m).await.ok()?;
            }
        }
        None::<()>
    };
    tokio::select! {
        _ = up => {},
        _ = down => {},
        _ = writer => {},
    }
    // Dropping the cancel senders ends this connection's streams (each
    // still audits its result).
    active.borrow_mut().clear();
    Some(())
}

/// The gate's control connection: roster/limits updates only, until the
/// gate closes it (anything it sends ends the connection).
async fn control(
    mut r: tokio::net::unix::OwnedReadHalf,
    mut w: tokio::net::unix::OwnedWriteHalf,
    mut view_rx: watch::Receiver<GateView>,
) -> Option<()> {
    // One read for the whole connection (read_msg isn't cancellation-safe).
    let closed = ipc::read_msg(&mut r);
    tokio::pin!(closed);
    loop {
        tokio::select! {
            ch = view_rx.changed() => {
                ch.ok()?;
                let msgs = view_rx.borrow_and_update().msgs();
                for m in &msgs {
                    ipc::write_msg(&mut w, m).await.ok()?;
                }
            }
            _ = &mut closed => return Some(()),
        }
    }
}
