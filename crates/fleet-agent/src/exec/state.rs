//! Exec's persistent state and its maintenance (design §4.4, §4.10, §5.3):
//! roster and recovery countdowns, policy, the audit log, the signed event
//! log, pending auto-revert files, and the per-command checks that need
//! this state (verification, policy, AI rate, commit).

use super::policy_check;
use super::{
    ExecError, PENDING_PERSIST_EVERY_MS, PRUNE_EVERY, SessionTerminator, log, remaining_ms,
};
use crate::authorized_keys;
use crate::ipc::IpcMsg;
use crate::paths::Paths;
use crate::pending::{self, ChangeId, PendingChange, PendingDir};
use crate::revert::{self, Revert};
use crate::store::{
    AUDIT_RETENTION_MS, CheckpointSigner, Compaction, EVENT_RETENTION_MS, Intent,
    MAX_ARCHIVE_ENTRIES, MAX_EVENTS, MetaKey, Store, StoreError,
};

/// Under `exec_dir`: archived audit entries (design §5.8).
pub const AUDIT_ARCHIVE_DIR: &str = "audit-archive";
use crate::{fsutil, now_ms};
use fleet_crypto::receipt::sign_event;
use fleet_crypto::roster::{self, PendingRoster, RecoveryClock, next_grace_remaining, roster_hash};
use fleet_crypto::sig::Ed25519Signer;
use fleet_crypto::verify::{self, VerifiedCommand, VerifyCtx};
use fleet_ops::CommandRunner;
use fleet_proto::payload::SignedEventPage;
use fleet_proto::policy::AiAccess;
use fleet_proto::{
    Actor, DeviceId, ErrorCode, Event, Hash32, KeyKind, MAX_FRAME, Message, Op, OpSummary, Outcome,
    P256Public, PROTO_VERSION, Payload, PendingRecovery, Policy, RootApproval, ServerId, Signature,
    SignedCommand, SignedEvent, SignedReceipt, SignedRoster, Tier, decode, encode,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::rc::Rc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, watch};

/// Largest `events.query` page (encoded events), well inside a frame.
const EVENT_PAGE_BYTES: usize = MAX_FRAME / 2;
/// AI actors tracked for `ai_commands_per_minute` (least recent dropped).
const MAX_AI_ACTORS: usize = 256;
const MINUTE_MS: u64 = 60_000;

/// `MetaKey::Policy`: the TOML as received and the approval it carried
/// (none for the policy given to `install`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPolicy {
    pub toml: String,
    pub approval: Option<RootApproval>,
    /// The command's `expected_version` (part of the approved op digest).
    pub expected_version: Option<u64>,
    /// The roster in force when the policy was accepted, so the approval
    /// can be re-verified at start (design §5.4); `None` for the install
    /// policy and for policies stored before re-verification existed.
    pub roster: Option<SignedRoster>,
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
pub(super) struct PendingState {
    pub(super) roster: SignedRoster,
    pub(super) hash: Hash32,
    pub(super) submitted_at_ms: u64,
    pub(super) remaining_ms: u64,
    /// `remaining_ms` as last persisted.
    pub(super) persisted_ms: u64,
    /// The local recovery-grace end at submission, in the frame of
    /// `submitted_at_ms` (`RecoveryClock::local_grace_until_ms`); activation
    /// judges the grace window as it was then.
    pub(super) grace_until_ms: Option<u64>,
}

impl PendingState {
    /// The `fleet_crypto` view, with the activation time projected from the
    /// wall clock now (for display, `check_veto` and `activate`).
    pub(super) fn roster_at(&self, now_ms: u64) -> PendingRoster {
        PendingRoster {
            roster: self.roster.clone(),
            hash: self.hash,
            submitted_at_ms: self.submitted_at_ms,
            activates_at_ms: now_ms.saturating_add(self.remaining_ms),
        }
    }

    pub(super) fn wire(&self, now_ms: u64) -> PendingRecovery {
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

/// What every gate connection needs to know; pushed on change.
#[derive(Debug, Clone)]
pub(super) struct GateView {
    roster: Rc<Vec<u8>>,
    /// End of the local recovery grace (monotonic).
    grace_deadline: Option<Instant>,
    commands_per_minute: u32,
}

impl GateView {
    pub(super) fn msgs(&self) -> Vec<IpcMsg> {
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

/// A command refused before it ran: the code, and until when its nonce
/// stays recorded if it was consumed.
pub(super) struct Refused {
    pub(super) code: ErrorCode,
    pub(super) consumed_until: Option<u64>,
}

/// What `State::load` takes from the config.
pub(super) struct StateParts {
    pub(super) paths: Paths,
    pub(super) reverter: Box<dyn Revert>,
    pub(super) timers: Rc<dyn CommandRunner>,
    pub(super) terminator: Box<dyn SessionTerminator>,
    pub(super) user_keys: crate::userkeys::UserKeysMode,
}

/// Failed monitor-line syncs (5 s ticks) before an alert is raised.
const MONITOR_SYNC_ALERT_AFTER: u32 = 3;

pub(super) struct State {
    pub(super) store: Store,
    pub(super) paths: Paths,
    pub(super) pending_dir: PendingDir,
    pub(super) server_id: ServerId,
    pub(super) signer: Ed25519Signer,
    pub(super) roster: SignedRoster,
    pub(super) epoch_hashes: Vec<Hash32>,
    /// End of the local recovery grace for `roster.prev_recovery`, counted
    /// on the monotonic clock (design §5.3); persisted as time remaining.
    grace_deadline: Option<Instant>,
    /// Remaining grace as last persisted.
    grace_persisted_ms: u64,
    pub(super) pending: Option<PendingState>,
    /// Last countdown step of `pending` (monotonic).
    last_tick: Instant,
    last_prune: Option<Instant>,
    pub(super) policy: Policy,
    admin_user: Option<String>,
    /// Device lines of the authorized_keys roster section, per roster.
    ak_cache: authorized_keys::DeviceLinesCache,
    /// How the admin's `~/.ssh/authorized_keys` is reached (as the user).
    user_keys: crate::userkeys::UserKeysMode,
    /// `(epoch, version)` whose monitor lines were last pushed there.
    home_monitor_synced: std::cell::Cell<Option<(u32, u64)>>,
    /// Consecutive failed monitor-line syncs (alert after a few).
    home_monitor_failures: std::cell::Cell<u32>,
    pub(super) started: Instant,
    /// Random per exec start; binds this run's events (design §6.3).
    pub(super) run_id: [u8; 16],
    /// This run's ordinal in the event log (key order across restarts).
    event_run: u64,
    event_seq: u64,
    pub(super) events: broadcast::Sender<SignedEvent>,
    pub(super) view: watch::Sender<GateView>,
    pub(super) reverter: Box<dyn Revert>,
    /// Runs `systemd-run`/`systemctl` for revert timers.
    pub(super) timers: Rc<dyn CommandRunner>,
    terminator: Box<dyn SessionTerminator>,
    /// Auto-revert changes whose handler is still running: maintenance
    /// never reverts these, and confirming them is refused.
    pub(super) applying: HashSet<ChangeId>,
    /// Expired changes whose revert maintenance handed to a task (off the
    /// main loop); not handed out again while it runs.
    pub(super) reverting: HashSet<ChangeId>,
    /// Admission times of AI commands in the last minute, per (device,
    /// AI client) (`actors.ai_commands_per_minute`).
    ai_calls: HashMap<(DeviceId, String), VecDeque<u64>>,
    /// The stored policy failed re-verification at load (design §5.4):
    /// `policy` is deny-all; startup raises the critical alert.
    pub(super) policy_rejected: Option<policy_check::PolicyCheckError>,
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

impl State {
    pub(super) fn load(parts: StateParts) -> Result<Self, ExecError> {
        let store = crate::store::schema::open_versioned(&parts.paths.state_db)?;
        let roster: SignedRoster = meta_decode(&store, MetaKey::Roster, "roster")?
            .ok_or(ExecError::NotInstalled("roster"))?;
        let server_id =
            meta_string(&store, MetaKey::ServerId)?.ok_or(ExecError::NotInstalled("server id"))?;
        let server_id = ServerId::new(server_id).map_err(|_| ExecError::Corrupt("server id"))?;
        let sp = store
            .meta()
            .get(MetaKey::Policy)?
            .ok_or(ExecError::NotInstalled("policy"))?;
        let epoch_hashes: Vec<Hash32> =
            meta_decode(&store, MetaKey::EpochHashes, "epoch hashes")?.unwrap_or_default();
        // A policy that doesn't verify isn't enforced; exec still starts
        // (deny-all, critical alert at startup) instead of crash-looping.
        let (policy, policy_rejected) = match policy_check::decode_stored(&sp)
            .ok_or(policy_check::PolicyCheckError::Invalid)
            .and_then(|sp| policy_check::verify_stored(&sp, &roster, &epoch_hashes, &server_id))
        {
            Ok(p) => (p, None),
            Err(e) => {
                log("stored policy rejected", e);
                (policy_check::deny_all(&roster, &server_id), Some(e))
            }
        };
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
        let signer = load_signing_key(&parts.paths)?;
        let mut run_id = [0u8; 16];
        fleet_crypto::random_bytes(&mut run_id)
            .map_err(|_| ExecError::Io(std::io::Error::other("random run id")))?;
        let event_run = store.events().begin_run(&run_id)?;
        let view = GateView {
            roster: Rc::new(encode(&roster)),
            grace_deadline,
            commands_per_minute: policy.limits.commands_per_minute,
        };
        Ok(Self {
            store,
            pending_dir: PendingDir::from_paths(&parts.paths),
            paths: parts.paths,
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
            ak_cache: authorized_keys::DeviceLinesCache::default(),
            user_keys: parts.user_keys,
            home_monitor_synced: std::cell::Cell::new(None),
            home_monitor_failures: std::cell::Cell::new(0),
            started: Instant::now(),
            run_id,
            event_run,
            event_seq: 0,
            events: broadcast::channel(64).0,
            view: watch::channel(view).0,
            reverter: parts.reverter,
            timers: parts.timers,
            terminator: parts.terminator,
            applying: HashSet::new(),
            reverting: HashSet::new(),
            ai_calls: HashMap::new(),
            policy_rejected,
        })
    }

    /// Local recovery grace left (monotonic), `None` if there is none.
    fn grace_remaining(&self) -> Option<u64> {
        self.grace_deadline.map(remaining_ms)
    }

    pub(super) fn clock(&self, now_ms: u64) -> RecoveryClock {
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

    /// Signs the event, appends it to the event log (so Macs that are
    /// offline or lag behind get it with `events.query`) and broadcasts it
    /// to connected gates.
    pub(super) fn emit(&mut self, event: Event) {
        self.event_seq += 1;
        let signed = sign_event(
            self.server_id.clone(),
            self.run_id,
            self.event_seq,
            now_ms(),
            event,
            &self.signer,
        );
        if let Err(e) =
            self.store
                .events()
                .append(self.event_run, signed.seq, signed.time_ms, &encode(&signed))
        {
            log("persist event", e);
        }
        // No receivers (no gate connected) is fine: the log has it.
        let _ = self.events.send(signed);
    }

    /// Seq of the latest event this run emitted (0: none yet).
    pub(super) fn event_seq(&self) -> u64 {
        self.event_seq
    }

    /// `events.query`: signed events after `(since_run_id, since_seq)`.
    pub(super) fn events_after(
        &self,
        since_run_id: Option<[u8; 16]>,
        since_seq: u64,
        limit: u32,
    ) -> Result<SignedEventPage, ErrorCode> {
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        let (rows, more) = self
            .store
            .events()
            .after(since_run_id.as_ref(), since_seq, limit, EVENT_PAGE_BYTES)
            .map_err(|e| {
                log("events query", e);
                ErrorCode::Internal
            })?;
        Ok(SignedEventPage {
            events: rows.iter().filter_map(|r| decode_event(&r.bytes)).collect(),
            more,
        })
    }

    /// This run's events with a seq above `seq` (a lagging connection
    /// catching up from the log).
    pub(super) fn events_since(&self, seq: u64, limit: usize) -> Vec<SignedEvent> {
        match self.store.events().in_run_after(self.event_run, seq, limit) {
            Ok(rows) => rows.iter().filter_map(|r| decode_event(&r.bytes)).collect(),
            Err(e) => {
                log("events catch-up", e);
                Vec::new()
            }
        }
    }

    pub(super) fn push_view(&self) {
        self.view.send_replace(GateView {
            roster: Rc::new(encode(&self.roster)),
            grace_deadline: self.grace_deadline,
            commands_per_minute: self.policy.limits.commands_per_minute,
        });
    }

    /// Startup: close interrupted intents, recover `pending/` (§4.10 step
    /// 5), audit revert markers, prune replay, refresh authorized_keys.
    /// Per-entry problems are logged and quarantined, never fatal.
    /// Returns the confirm timers exec must re-arm (a reboot drops
    /// transient timers).
    pub(super) fn startup(
        &mut self,
        now: u64,
    ) -> Result<Vec<(ChangeId, u32, pending::ChangeKind)>, ExecError> {
        self.store.audit().mark_interrupted_on_start(now)?;
        if self.policy_rejected.is_some() {
            self.emit(Event::AlertFired {
                rule_id: policy_check::REJECTED_RULE.into(),
                severity: fleet_proto::alert::Severity::Critical,
                subject: "policy".into(),
                value: 0,
            });
        }
        self.pending_dir.create()?;
        self.pending_dir.repair_updates()?;
        // Installs from before the marker existed: uninstall.prepare needs
        // the admin user even when no key file lists it (Agent-only).
        if let Some(u) = &self.admin_user {
            crate::uninstall::record_admin(&self.paths, u);
        }
        let rearm = self.recover_pending(now);
        self.process_markers(now);
        self.prune(true);
        self.sync_authorized_keys(now);
        Ok(rearm)
    }

    /// Periodic work; returns expired changes exec must revert (off the
    /// main loop).
    pub(super) fn maintenance(&mut self, now: u64) -> Vec<ChangeId> {
        let due = self.expired(now);
        self.process_markers(now);
        self.tick_pending(now);
        self.tick_grace();
        self.prune(false);
        self.sync_authorized_keys(now);
        due
    }

    fn prune(&mut self, force: bool) {
        if !force && self.last_prune.is_some_and(|t| t.elapsed() < PRUNE_EVERY) {
            return;
        }
        self.last_prune = Some(Instant::now());
        let now = now_ms();
        if let Err(e) = self.store.replay().prune(now) {
            log("replay prune", e);
        }
        let cutoff = now.saturating_sub(EVENT_RETENTION_MS);
        if let Err(e) = self
            .store
            .events()
            .prune(cutoff, MAX_EVENTS, self.event_run)
        {
            log("event log prune", e);
        }
        self.archive_audit(now);
        let old = now.saturating_sub(MINUTE_MS);
        self.ai_calls.retain(|_, q| {
            q.retain(|t| *t > old);
            !q.is_empty()
        });
    }

    /// Moves audit entries older than the retention into an archive file
    /// (design §5.8, `store::audit_archive`); one batch per prune.
    pub(super) fn archive_audit(&self, now: u64) {
        let dir = self.paths.exec_dir.join(AUDIT_ARCHIVE_DIR);
        match self.store.audit().archive_before(
            &dir,
            &self.server_id,
            now.saturating_sub(AUDIT_RETENTION_MS),
            MAX_ARCHIVE_ENTRIES,
        ) {
            Ok(Some(r)) => log(
                "audit archived",
                format!("seq {}..={} into {}", r.from_seq, r.to_seq, r.file),
            ),
            Ok(None) => {}
            Err(e) => log("audit archive", e),
        }
    }

    /// Logs what a compaction did (`true`), or `false` when the database
    /// was in use (try again later).
    pub(super) fn compacted(res: Result<Compaction, StoreError>, took: Duration) -> bool {
        match res {
            Ok(Compaction::Busy) => false,
            Ok(Compaction::Done { before, after }) => {
                log(
                    "database compacted",
                    format!("{before} → {after} bytes in {took:?}"),
                );
                true
            }
            Ok(Compaction::NotNeeded { .. }) => true,
            Err(e) => {
                log("database compaction", e);
                true
            }
        }
    }

    pub(super) fn checkpoint(&self, now: u64) {
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
    /// revert what expired while exec was down or whose apply was cut off
    /// by a crash (`applying`), re-arm confirm timers for the rest (a reboot
    /// drops transient timers), quarantine unreadable files.
    /// Returns the confirm timers to re-arm `(id, seconds)`.
    fn recover_pending(&mut self, now: u64) -> Vec<(ChangeId, u32, pending::ChangeKind)> {
        let mut rearm = Vec::new();
        let entries = match self.pending_dir.scan() {
            Ok(e) => e,
            Err(e) => {
                log("scan pending", e);
                return rearm;
            }
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
            } else if change.applying || change.deadline_ms <= now {
                if has_marker {
                    self.pending_dir.remove(e.id).map(drop)
                } else {
                    revert::run_revert(&self.pending_dir, e.id, self.reverter.as_ref(), now)
                        .map(drop)
                }
            } else {
                let secs = (change.deadline_ms - now).div_ceil(1000);
                let secs = u32::try_from(secs).unwrap_or(u32::MAX).max(1);
                // Armed by exec once its runtime runs (async runner).
                rearm.push((e.id, secs, change.kind));
                Ok(())
            };
            if let Err(err) = res {
                log(&format!("pending change {}", e.id), err);
            }
        }
        rearm
    }

    /// Belt and braces for lost timers: unclaimed changes whose deadline
    /// passed, for exec to revert off the main loop (`Exec::revert_change`;
    /// claiming makes that safe against a concurrent timer). Changes still
    /// being applied are skipped (their apply timeout restores them), and
    /// so are reverts already handed out; the returned ids are marked
    /// `reverting` until [`State::reverted`].
    fn expired(&mut self, now: u64) -> Vec<ChangeId> {
        let Ok(entries) = self.pending_dir.scan() else {
            return Vec::new();
        };
        let mut due = Vec::new();
        for e in entries.into_iter().filter(|e| !e.claimed) {
            if self.applying.contains(&e.id) || self.reverting.contains(&e.id) {
                continue;
            }
            match &e.value {
                None => self.quarantine(&e.path, now),
                Some(c) if c.deadline_ms <= now => {
                    self.reverting.insert(e.id);
                    due.push(e.id);
                }
                Some(_) => {}
            }
        }
        due
    }

    /// A revert handed out by [`State::maintenance`] finished.
    pub(super) fn reverted(&mut self, id: ChangeId) {
        self.reverting.remove(&id);
    }

    /// Audits markers left by `revert <id>` and emits `ChangeReverted`. A
    /// revert skipped because the state changed again since is audited as
    /// `Failed(VersionConflict)` and emits nothing (the change stays).
    pub(super) fn process_markers(&mut self, now: u64) {
        let markers = match self.pending_dir.scan_markers() {
            Ok(m) => m,
            Err(e) => return log("scan reverted", e),
        };
        for e in markers {
            let Some(m) = &e.value else {
                self.quarantine(&e.path, now);
                continue;
            };
            let outcome = match (m.restored, m.conflict) {
                (true, _) => Outcome::Reverted,
                (false, Some(current)) => Outcome::Failed(ErrorCode::VersionConflict { current }),
                (false, None) => Outcome::Failed(ErrorCode::Internal),
            };
            let audit = self.store.audit();
            let seq = match audit.append_revert_outcome(m.origin_audit_seq, now, outcome) {
                Ok(seq) => seq,
                // Origin entry missing: still record that a revert happened.
                Err(StoreError::NotOpenIntent(_)) => match audit.append_system(
                    now,
                    [0; 32],
                    OpSummary {
                        tag: 0,
                        args: Vec::new(),
                    },
                    outcome,
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
            drop(audit);
            if m.conflict.is_none() {
                self.emit(Event::ChangeReverted {
                    change_id: e.id.0,
                    audit_seq: seq,
                });
            }
            if let Err(err) = self.pending_dir.remove_marker(e.id) {
                log("remove marker", err);
            }
        }
    }

    fn sync_authorized_keys(&mut self, now: u64) {
        // Agent-only mode (design §5.4): never write or rewrite the admin's
        // `authorized_keys` file — the operator owns it.
        if self.policy.security == fleet_proto::policy::SecurityMode::AgentOnly {
            return;
        }
        if let Some(user) = &self.admin_user
            && let Err(e) = authorized_keys::sync(
                &self.paths.authorized_keys_dir,
                user,
                &self.roster.roster,
                self.clock(now),
                &self.ak_cache,
            )
        {
            log("authorized_keys", e);
        }
        // While sshd still reads ~/.ssh/authorized_keys (before the §10.1
        // step 5 switchover) the monitor keys must be there too, or a
        // locked app can't open monitor sessions.
        let v = (self.roster.roster.epoch, self.roster.roster.version);
        if let Some(user) = self.admin_user.clone()
            && self.home_monitor_synced.get() != Some(v)
        {
            let users = crate::userkeys::user_keys(self.user_keys, self.timers.as_ref());
            let res = authorized_keys::sync_home_monitor(
                &self.paths,
                &user,
                Some(&self.roster.roster),
                users.as_ref(),
            );
            drop(users);
            const RULE: &str = "monitor-keys-sync";
            match res {
                Ok(()) => {
                    // Cached only on success; a failure retries every tick.
                    self.home_monitor_synced.set(Some(v));
                    if self.home_monitor_failures.replace(0) >= MONITOR_SYNC_ALERT_AFTER {
                        self.emit(Event::AlertCleared {
                            rule_id: RULE.into(),
                            subject: user,
                        });
                    }
                }
                Err(e) => {
                    let n = self.home_monitor_failures.get().saturating_add(1);
                    self.home_monitor_failures.set(n);
                    if n == 1 {
                        log("home monitor keys", &e);
                    }
                    if n == MONITOR_SYNC_ALERT_AFTER {
                        // A revoked device's monitor key may still be
                        // accepted by sshd: tell the operator.
                        self.emit(Event::AlertFired {
                            rule_id: RULE.into(),
                            severity: fleet_proto::alert::Severity::Warning,
                            subject: user,
                            value: u64::from(n),
                        });
                    }
                }
            }
        }
    }

    pub(super) fn set_pending(&mut self, p: Option<PendingState>) -> Result<(), StoreError> {
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

    /// Installs an accepted roster: persist, rewrite authorized_keys, then
    /// end the sshd sessions of removed or replaced SSH keys (device and
    /// monitor), push to gates, emit `RosterChanged`.
    pub(super) fn install_roster(&mut self, new: SignedRoster, now: u64) -> Result<(), StoreError> {
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
        let removed = removed_ssh_keys(&cur.roster, &new.roster);
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
        // Keys out of authorized_keys first, so an ended session can't log
        // straight back in.
        self.sync_authorized_keys(now);
        self.terminator.end_sessions(&removed);
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

    pub(super) fn pending_wire(&self, now: u64) -> Option<PendingRecovery> {
        self.pending.as_ref().map(|p| p.wire(now))
    }

    pub(super) fn hello(&self) -> Message {
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
    pub(super) fn stored_response(
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

    pub(super) fn verify(
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
    /// its seq. Counts an AI command against its actor's rate.
    pub(super) fn commit_intent(
        &mut self,
        v: &VerifiedCommand,
        cmd: &SignedCommand,
        now: u64,
    ) -> Result<u64, Refused> {
        v.commit(&mut self.store.replay()).map_err(|e| Refused {
            code: e.code(),
            consumed_until: None,
        })?;
        if let Some(key) = ai_key(v) {
            if !self.ai_calls.contains_key(&key) && self.ai_calls.len() >= MAX_AI_ACTORS {
                let stalest = self
                    .ai_calls
                    .iter()
                    .min_by_key(|(_, q)| q.back().copied().unwrap_or(0))
                    .map(|(k, _)| k.clone());
                if let Some(k) = stalest {
                    self.ai_calls.remove(&k);
                }
            }
            self.ai_calls.entry(key).or_default().push_back(now);
        }
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
    pub(super) fn audit_result(
        &mut self,
        intent_seq: u64,
        status: Result<(), ErrorCode>,
    ) -> Option<u64> {
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
    pub(super) fn pending_change(&self, op: &Op) -> Result<Option<PendingChange>, ErrorCode> {
        let (Op::ChangeConfirm { change_id } | Op::ChangeRevert { change_id }) = op else {
            return Ok(None);
        };
        self.pending_dir.get(ChangeId(*change_id)).map_err(|e| {
            log("read pending change", e);
            ErrorCode::Internal
        })
    }

    pub(super) fn check_policy(&self, v: &VerifiedCommand, now: u64) -> Result<(), ErrorCode> {
        let op = &v.body.op;
        // Agent-only mode (design §5.4): the operator asked Fleet not to
        // change security on this server. Refused here, before the nonce
        // is consumed, so a retried/re-signed command isn't burned for
        // nothing. Re-read from the live policy on every command: a
        // `policy.update` that switches modes takes effect immediately,
        // no agent restart needed.
        if self.policy.security == fleet_proto::policy::SecurityMode::AgentOnly
            && op.takes_over_security()
        {
            return Err(ErrorCode::PolicyDenied);
        }
        // `change.confirm` and `change.revert` are in the `firewall` group,
        // but they act on any auto-revert change (mesh, profile, authorized
        // keys, …). The device that made the change may always confirm or
        // revert it (design §5.4): its original command already passed
        // policy, and refusing the confirm would only revert an allowed
        // change (and refusing the revert would keep a change the operator
        // wants gone).
        let own_change = || {
            self.pending_change(op)
                .ok()
                .flatten()
                .is_some_and(|c| c.origin.device_id == v.device_id)
        };
        // Under the deny-all fallback (stored policy rejected, design
        // §5.4) the read-only monitor subset stays available, so a Mac can
        // still catch up on events (the `policy.rejected` alert included).
        let fallback_read = self.policy_rejected.is_some() && op.monitor_allowed();
        if !self.policy.allows_group(op.group()) && !own_change() && !fallback_read {
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
            // `actors.ai_commands_per_minute` (design §5.4), counted per
            // device and AI client. `ai_bulk_confirm_above` is enforced by
            // the Mac (a bulk action spans servers).
            let limit = self.policy.actors.ai_commands_per_minute;
            let recent = ai_key(v)
                .and_then(|k| self.ai_calls.get(&k))
                .map_or(0, |q| {
                    q.iter()
                        .filter(|t| now.saturating_sub(**t) < MINUTE_MS)
                        .count()
                });
            if recent >= usize::try_from(limit).unwrap_or(usize::MAX) {
                return Err(ErrorCode::Busy);
            }
        }
        Ok(())
    }
}

/// The rate key of an AI command: its device and AI client name.
fn ai_key(v: &VerifiedCommand) -> Option<(DeviceId, String)> {
    match &v.body.actor {
        Actor::Ai { client, .. } => Some((v.device_id, client.as_str().to_owned())),
        _ => None,
    }
}

fn decode_event(bytes: &[u8]) -> Option<SignedEvent> {
    decode(bytes).map_err(|e| log("stored event", e)).ok()
}

/// SSH keys (device and monitor) of devices removed from the roster, or
/// whose key changed.
pub(super) fn removed_ssh_keys(
    cur: &fleet_proto::Roster,
    new: &fleet_proto::Roster,
) -> Vec<P256Public> {
    let mut out = Vec::new();
    for d in &cur.devices {
        let n = new.device(&d.id);
        if n.is_none_or(|n| n.ssh_key != d.ssh_key) {
            out.push(d.ssh_key);
        }
        if n.is_none_or(|n| n.monitor_ssh_key != d.monitor_ssh_key) {
            out.push(d.monitor_ssh_key);
        }
    }
    // A key still listed for any device stays.
    out.retain(|k| {
        !new.devices
            .iter()
            .any(|d| d.ssh_key == *k || d.monitor_ssh_key == *k)
    });
    out.dedup();
    out
}
