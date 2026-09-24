//! Command verification pipeline (design §5.6), minus policy and argument
//! validation, which exec does next.
//!
//! Order: session key kind → key lookup → signature → body decode → actor →
//! version, fleet and server binding → freshness → op authorization (session
//! mode, approval) → read-only replay check.
//!
//! **Two steps.** [`verify_command`] writes nothing. Exec then checks policy
//! and arguments and only then calls [`VerifiedCommand::commit`], which
//! consumes the nonce and the approval leaf. So a command that policy or
//! argument validation rejects doesn't burn its approval leaf (a Touch ID).
//!
//! **Race:** between `verify_command` and `commit` another command with the
//! same nonce or leaf could pass the read-only check too. `commit` re-checks
//! and fails with `Replay`, but the caller must still serialize
//! verify → policy → commit → audit intent per exec. Exec is single-threaded,
//! so it processes one command at a time through these steps.
//!
//! The signature covers `key ‖ device_id ‖ body`, so `device_id` (the replay
//! key's first half) is authenticated for every key kind, recovery included.

use crate::approval::{self, ApprovalError, ApprovalLeaf};
use crate::{blake3, roster, sig};
use fleet_proto::{
    Actor, Authorization, CommandBody, DeviceId, ErrorCode, Hash32, KeyKind, Op, PROTO_VERSION,
    Roster, ServerId, SignedCommand, encode,
};
use std::collections::HashMap;

pub const DEFAULT_TTL_MS: u32 = 60_000;
pub const DEFAULT_MAX_TTL_MS: u32 = 5 * 60_000;
pub const DEFAULT_SKEW_MS: u64 = 30_000;

/// Persistent replay table. The agent's implementation is redb-backed;
/// entries past their expiry may be pruned.
///
/// `contains_*` are read-only and must fail closed (`true` on a storage
/// error). `check_and_insert_*` record the key until `expires_at_ms` and
/// return `true` if it was **not** seen before, `false` on a replay or a
/// storage error.
pub trait ReplayStore {
    fn contains_nonce(&self, device_id: DeviceId, nonce: [u8; 16]) -> bool;
    fn contains_leaf(&self, approval_id: [u8; 16], leaf: Hash32) -> bool;
    fn check_and_insert_nonce(
        &mut self,
        device_id: DeviceId,
        nonce: [u8; 16],
        expires_at_ms: u64,
    ) -> bool;
    fn check_and_insert_leaf(
        &mut self,
        approval_id: [u8; 16],
        leaf: Hash32,
        expires_at_ms: u64,
    ) -> bool;
}

/// In-memory [`ReplayStore`] for tests and the Mac-side simulator.
#[derive(Debug, Default)]
pub struct MemoryReplayStore {
    nonces: HashMap<(DeviceId, [u8; 16]), u64>,
    leaves: HashMap<([u8; 16], Hash32), u64>,
}

impl MemoryReplayStore {
    /// Drops entries that expired before `now_ms`.
    pub fn prune(&mut self, now_ms: u64) {
        self.nonces.retain(|_, exp| *exp >= now_ms);
        self.leaves.retain(|_, exp| *exp >= now_ms);
    }

    pub fn len(&self) -> usize {
        self.nonces.len() + self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ReplayStore for MemoryReplayStore {
    fn contains_nonce(&self, d: DeviceId, n: [u8; 16]) -> bool {
        self.nonces.contains_key(&(d, n))
    }
    fn contains_leaf(&self, id: [u8; 16], leaf: Hash32) -> bool {
        self.leaves.contains_key(&(id, leaf))
    }
    fn check_and_insert_nonce(&mut self, d: DeviceId, n: [u8; 16], exp: u64) -> bool {
        self.nonces.insert((d, n), exp).is_none()
    }
    fn check_and_insert_leaf(&mut self, id: [u8; 16], leaf: Hash32, exp: u64) -> bool {
        self.leaves.insert((id, leaf), exp).is_none()
    }
}

/// Verifier inputs. `fleet_id` is taken from `roster`.
#[derive(Debug, Clone, Copy)]
pub struct VerifyCtx<'a> {
    pub roster: &'a Roster,
    pub server_id: &'a ServerId,
    pub now_ms: u64,
    pub skew_ms: u64,
    pub max_ttl_ms: u32,
    /// Mode fixed by `DeviceAuth` for this session (design §5.5).
    pub session_key_kind: KeyKind,
    /// Local grace left for the roster's `prev_recovery` (the agent's
    /// monotonic countdown); extends the rotated-out recovery key's window
    /// (see `roster::RecoveryClock`).
    pub grace_remaining_ms: Option<u64>,
}

impl VerifyCtx<'_> {
    pub fn recovery_clock(&self) -> roster::RecoveryClock {
        roster::RecoveryClock::with_grace_remaining(self.now_ms, self.grace_remaining_ms)
    }
}

impl<'a> VerifyCtx<'a> {
    pub fn new(roster: &'a Roster, server_id: &'a ServerId, now_ms: u64, session: KeyKind) -> Self {
        Self {
            roster,
            server_id,
            now_ms,
            skew_ms: DEFAULT_SKEW_MS,
            max_ttl_ms: DEFAULT_MAX_TTL_MS,
            session_key_kind: session,
            grace_remaining_ms: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCommand {
    pub body: CommandBody,
    /// Signed envelope `device_id`. For recovery-key commands it is the
    /// recovering Mac's self-chosen id (not in the roster).
    pub device_id: DeviceId,
    pub key: KeyKind,
    /// Present whenever the command carried an approval (always for
    /// `Authorization::RootApproval` ops). Policy can require it for ops
    /// raised to Elevated via `[elevated] extra`.
    pub approval: Option<ApprovalLeaf>,
    /// BLAKE3 of the `SignedCommand` encoding (receipts, audit).
    pub command_hash: Hash32,
    /// Until when [`VerifiedCommand::commit`] records the nonce
    /// (`issued_at + ttl + skew`).
    pub nonce_expires_at_ms: u64,
}

impl VerifiedCommand {
    /// Consumes the replay entries: the nonce first, then the approval leaf.
    /// Call once policy and argument checks have passed, before the audit
    /// intent. Fails with [`VerifyError::Replay`] (writing nothing) if either
    /// is already recorded; if the leaf insert then fails anyway (race or
    /// storage error), the nonce stays consumed and the command must not run.
    pub fn commit(&self, replay: &mut impl ReplayStore) -> Result<(), VerifyError> {
        let leaf_seen = self
            .approval
            .as_ref()
            .is_some_and(|l| replay.contains_leaf(l.approval_id, l.leaf));
        if leaf_seen || replay.contains_nonce(self.device_id, self.body.nonce) {
            return Err(VerifyError::Replay);
        }
        if !replay.check_and_insert_nonce(self.device_id, self.body.nonce, self.nonce_expires_at_ms)
        {
            return Err(VerifyError::Replay);
        }
        if let Some(l) = &self.approval
            && !replay.check_and_insert_leaf(l.approval_id, l.leaf, l.expires_at_ms)
        {
            return Err(VerifyError::Replay);
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("command key kind does not match the session mode")]
    SessionMismatch,
    #[error("device is not in the current roster")]
    UnknownDevice,
    #[error("signature invalid")]
    Signature,
    #[error("body malformed")]
    Malformed,
    #[error("actor not allowed for this key kind")]
    ActorMismatch,
    #[error("unsupported protocol version {0}")]
    Version(u16),
    #[error("command is for another fleet")]
    WrongFleet,
    #[error("command is for another server")]
    WrongServer,
    #[error("ttl is zero or above the cap")]
    BadTtl,
    #[error("issued_at outside the freshness window")]
    Stale,
    #[error("nonce already used")]
    Replay,
    #[error("operation not allowed for this key kind")]
    KeyNotAllowed,
    #[error("unknown operation")]
    Unsupported,
    #[error("operation requires a root-key approval")]
    ApprovalRequired,
    #[error("approval: {0}")]
    Approval(#[from] ApprovalError),
}

impl VerifyError {
    pub fn code(&self) -> ErrorCode {
        use VerifyError::*;
        match self {
            SessionMismatch | UnknownDevice | ActorMismatch | WrongFleet | WrongServer
            | KeyNotAllowed => ErrorCode::Unauthorized,
            Signature => ErrorCode::SignatureInvalid,
            Malformed => ErrorCode::InvalidArgument,
            Version(_) | Unsupported => ErrorCode::Unsupported,
            BadTtl | Stale => ErrorCode::Stale,
            Replay => ErrorCode::Replay,
            ApprovalRequired => ErrorCode::ApprovalRequired,
            Approval(e) => e.code(),
        }
    }
}

pub fn command_hash(cmd: &SignedCommand) -> Hash32 {
    blake3(&encode(cmd))
}

/// Every check except policy and arguments; writes no replay state (see the
/// module docs). The caller runs policy and argument checks, then
/// [`VerifiedCommand::commit`], before executing.
pub fn verify_command(
    cmd: &SignedCommand,
    ctx: &VerifyCtx<'_>,
    replay: &impl ReplayStore,
) -> Result<VerifiedCommand, VerifyError> {
    // Session mode and key.
    if cmd.key != ctx.session_key_kind {
        return Err(VerifyError::SessionMismatch);
    }
    let msg = SignedCommand::signed_message(cmd.key, &cmd.device_id, &cmd.body);
    match cmd.key {
        KeyKind::Device | KeyKind::Monitor => {
            let dev = ctx
                .roster
                .device(&cmd.device_id)
                .ok_or(VerifyError::UnknownDevice)?;
            let key = if cmd.key == KeyKind::Device {
                &dev.device_key
            } else {
                &dev.monitor_key
            };
            sig::p256_verify(key, &msg, &cmd.signature).map_err(|_| VerifyError::Signature)?;
        }
        KeyKind::Recovery => {
            // Only the rotated-out key inside its grace window, else the
            // current key (design §5.3 rule 6).
            roster::verify_recovery_sig(ctx.roster, ctx.recovery_clock(), &msg, &cmd.signature)
                .map_err(|_| VerifyError::Signature)?;
        }
    }

    // Body, actor and binding.
    let body = cmd.decode_body().map_err(|_| VerifyError::Malformed)?;
    // Recovery-key commands carry exactly `Actor::Recovery`; no Mac command
    // may claim `Recovery` otherwise, nor the agent-only `System`.
    let actor_ok = match body.actor {
        Actor::Recovery => cmd.key == KeyKind::Recovery,
        Actor::System => false,
        _ => cmd.key != KeyKind::Recovery,
    };
    if !actor_ok {
        return Err(VerifyError::ActorMismatch);
    }
    if body.v != PROTO_VERSION {
        return Err(VerifyError::Version(body.v));
    }
    if body.fleet_id != ctx.roster.fleet_id {
        return Err(VerifyError::WrongFleet);
    }
    if body.server_id != *ctx.server_id {
        return Err(VerifyError::WrongServer);
    }

    // Freshness: issued_at − skew ≤ now ≤ issued_at + ttl + skew.
    if body.ttl_ms == 0 || body.ttl_ms > ctx.max_ttl_ms {
        return Err(VerifyError::BadTtl);
    }
    let not_before = body.issued_at_ms.saturating_sub(ctx.skew_ms);
    let not_after = body
        .issued_at_ms
        .saturating_add(u64::from(body.ttl_ms))
        .saturating_add(ctx.skew_ms);
    if ctx.now_ms < not_before || ctx.now_ms > not_after {
        return Err(VerifyError::Stale);
    }

    // Op authorization.
    if matches!(body.op, Op::Unknown { .. }) {
        return Err(VerifyError::Unsupported);
    }
    let allowed = match cmd.key {
        KeyKind::Device => true,
        KeyKind::Monitor => body.op.monitor_allowed(),
        KeyKind::Recovery => body.op.recovery_allowed(),
    };
    if !allowed {
        return Err(VerifyError::KeyNotAllowed);
    }
    let approval = match &cmd.approval {
        Some(a) => Some(approval::verify_approval(
            a,
            ctx.roster,
            ctx.server_id,
            &approval::body_op_digest(&body),
            ctx.now_ms,
        )?),
        None => None,
    };
    if body.op.authorization() == Authorization::RootApproval && approval.is_none() {
        return Err(VerifyError::ApprovalRequired);
    }
    // `Authorization::SelfSigned` (roster.update) passes here; the payload is
    // validated by `roster::evaluate` before anything is installed.

    // Read-only replay check, last. Consumed later by `commit`.
    if replay.contains_nonce(cmd.device_id, body.nonce) {
        return Err(VerifyError::Replay);
    }
    if let Some(leaf) = &approval
        && replay.contains_leaf(leaf.approval_id, leaf.leaf)
    {
        return Err(ApprovalError::LeafReused.into());
    }

    Ok(VerifiedCommand {
        command_hash: command_hash(cmd),
        body,
        device_id: cmd.device_id,
        key: cmd.key,
        approval,
        nonce_expires_at_ms: not_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::{build_approvals, op_digest};
    use crate::roster::{PendingRoster, RosterError, check_veto, roster_hash};
    use crate::testutil::*;
    use fleet_proto::{ApprovalItem, RootApproval};

    fn ctx<'a>(r: &'a Roster, s: &'a ServerId, kind: KeyKind) -> VerifyCtx<'a> {
        VerifyCtx::new(r, s, NOW, kind)
    }

    fn policy_op() -> Op {
        Op::PolicyUpdate {
            policy_toml: "version = 3".into(),
        }
    }

    fn approvals(fx: &Fixture, op: &Op, servers: &[ServerId]) -> Vec<RootApproval> {
        let items: Vec<_> = servers
            .iter()
            .map(|s| ApprovalItem {
                server_id: s.clone(),
                op_digest: op_digest(op, None),
            })
            .collect();
        let m = fx.macs.last().unwrap();
        build_approvals(&m.root, m.id, &fx.approval_params(NOW), &items).unwrap()
    }

    fn err(cmd: &SignedCommand, c: &VerifyCtx<'_>, store: &mut MemoryReplayStore) -> VerifyError {
        let before = store.len();
        let e = verify_command(cmd, c, &*store).unwrap_err();
        assert_eq!(
            store.len(),
            before,
            "rejection must not record replay state"
        );
        e
    }

    /// Verify, then commit (what exec does once policy passes).
    fn accept(
        cmd: &SignedCommand,
        c: &VerifyCtx<'_>,
        store: &mut MemoryReplayStore,
    ) -> VerifiedCommand {
        let v = verify_command(cmd, c, &*store).unwrap();
        v.commit(store).unwrap();
        v
    }

    #[test]
    fn accepts_read_op() {
        let fx = Fixture::new(1);
        let (r, s) = (fx.roster(), server(0));
        let cmd = fx.sign_device(0, &body_for(&s, Op::SystemInfo, NOW));
        let v = verify_command(
            &cmd,
            &ctx(&r, &s, KeyKind::Device),
            &MemoryReplayStore::default(),
        )
        .unwrap();
        assert_eq!(v.body.op, Op::SystemInfo);
        assert_eq!(v.device_id, fx.macs[0].id);
        assert!(v.approval.is_none());
    }

    #[test]
    fn envelope_rejections() {
        let fx = Fixture::new(1);
        let (r, s) = (fx.roster(), server(0));
        let c = ctx(&r, &s, KeyKind::Device);
        let mut st = MemoryReplayStore::default();
        let good = fx.sign_device(0, &body_for(&s, Op::SystemInfo, NOW));

        let mut t = good.clone();
        let last = t.body.len() - 1;
        t.body[last] ^= 1; // expected_version tag flips
        assert!(matches!(err(&t, &c, &mut st), VerifyError::Signature));

        let mut t = good.clone();
        t.signature.0[10] ^= 1;
        assert!(matches!(err(&t, &c, &mut st), VerifyError::Signature));

        let mut t = good.clone();
        t.signature = malleate(&t.signature);
        assert!(
            matches!(err(&t, &c, &mut st), VerifyError::Signature),
            "high-S"
        );

        // Signed by the right key for the wrong kind label.
        let mut t = good.clone();
        t.key = KeyKind::Monitor;
        let cm = ctx(&r, &s, KeyKind::Monitor);
        assert!(matches!(err(&t, &cm, &mut st), VerifyError::Signature));

        // Device-key command in a monitor session.
        assert!(matches!(
            err(&good, &cm, &mut st),
            VerifyError::SessionMismatch
        ));

        // Revoked device.
        let revoked = fx.without(0);
        let cr = ctx(&revoked, &s, KeyKind::Device);
        assert!(matches!(
            err(&good, &cr, &mut st),
            VerifyError::UnknownDevice
        ));

        accept(&good, &c, &mut st);
        assert!(matches!(err(&good, &c, &mut st), VerifyError::Replay));
    }

    #[test]
    fn binding_and_freshness() {
        let fx = Fixture::new(1);
        let (r, s) = (fx.roster(), server(0));
        let c = ctx(&r, &s, KeyKind::Device);
        let mut st = MemoryReplayStore::default();
        let check =
            |b: CommandBody, st: &mut MemoryReplayStore| err(&fx.sign_device(0, &b), &c, st);

        let b = body_for(&server(1), Op::SystemInfo, NOW);
        assert!(matches!(check(b, &mut st), VerifyError::WrongServer));

        let mut b = body_for(&s, Op::SystemInfo, NOW);
        b.fleet_id = fleet_proto::FleetId([0x99; 16]);
        assert!(matches!(check(b, &mut st), VerifyError::WrongFleet));

        let b = body_for(&s, Op::SystemInfo, NOW - 60_000 - 30_000 - 1);
        assert!(matches!(check(b, &mut st), VerifyError::Stale));
        let b = body_for(&s, Op::SystemInfo, NOW + 30_001);
        assert!(matches!(check(b, &mut st), VerifyError::Stale));

        let mut b = body_for(&s, Op::SystemInfo, NOW);
        b.ttl_ms = DEFAULT_MAX_TTL_MS + 1;
        assert!(matches!(check(b, &mut st), VerifyError::BadTtl));
        let mut b = body_for(&s, Op::SystemInfo, NOW);
        b.ttl_ms = 0;
        assert!(matches!(check(b, &mut st), VerifyError::BadTtl));

        let mut b = body_for(&s, Op::SystemInfo, NOW);
        b.v = 2;
        assert!(matches!(check(b, &mut st), VerifyError::Version(2)));

        let b = body_for(&s, Op::Unknown { tag: 777 }, NOW);
        assert!(matches!(check(b, &mut st), VerifyError::Unsupported));

        // Edges of the window are accepted.
        for at in [NOW - 60_000 - 30_000, NOW + 30_000] {
            let cmd = fx.sign_device(0, &body_for(&s, Op::SystemInfo, at));
            accept(&cmd, &c, &mut st);
        }
    }

    #[test]
    fn monitor_and_recovery_key_limits() {
        let fx = Fixture::new(1);
        let (r, s) = (fx.roster(), server(0));
        let mut st = MemoryReplayStore::default();

        let cm = ctx(&r, &s, KeyKind::Monitor);
        let ok = fx.sign_monitor(0, &body_for(&s, Op::AgentHealth, NOW));
        accept(&ok, &cm, &mut st);
        let op = policy_op();
        let mut change = fx.sign_monitor(0, &body_for(&s, op.clone(), NOW));
        change.approval = Some(approvals(&fx, &op, std::slice::from_ref(&s)).remove(0));
        assert!(matches!(
            err(&change, &cm, &mut st),
            VerifyError::KeyNotAllowed
        ));
        let read = fx.sign_monitor(0, &body_for(&s, Op::SystemInfo, NOW));
        assert!(matches!(
            err(&read, &cm, &mut st),
            VerifyError::KeyNotAllowed
        ));

        let cr = ctx(&r, &s, KeyKind::Recovery);
        let ok = fx.sign_recovery_cmd(&body_for(&s, Op::RosterPending, NOW));
        let v = accept(&ok, &cr, &mut st);
        assert_eq!(v.device_id, RECOVERY_MAC);
        let bad = fx.sign_recovery_cmd(&body_for(&s, op, NOW));
        assert!(matches!(
            err(&bad, &cr, &mut st),
            VerifyError::KeyNotAllowed
        ));

        // device_id is signed: relabeling a recovery command breaks it.
        let mut relabeled = ok.clone();
        relabeled.device_id = DeviceId([0x42; 16]);
        assert!(matches!(
            err(&relabeled, &cr, &mut st),
            VerifyError::Signature
        ));
        assert!(matches!(err(&ok, &cr, &mut st), VerifyError::Replay));
    }

    #[test]
    fn device_id_is_signed() {
        let fx = Fixture::new(2);
        let (r, s) = (fx.roster(), server(0));
        let c = ctx(&r, &s, KeyKind::Device);
        let mut st = MemoryReplayStore::default();
        // Mac 0's signature relabeled as mac 1 (both in the roster).
        let mut t = fx.sign_device(0, &body_for(&s, Op::SystemInfo, NOW));
        t.device_id = fx.macs[1].id;
        assert!(matches!(err(&t, &c, &mut st), VerifyError::Signature));
    }

    #[test]
    fn actor_must_match_key_kind() {
        let fx = Fixture::new(1);
        let (r, s) = (fx.roster(), server(0));
        let mut st = MemoryReplayStore::default();
        let cr = ctx(&r, &s, KeyKind::Recovery);
        let cd = ctx(&r, &s, KeyKind::Device);
        let body = |actor| CommandBody {
            actor,
            ..body_for(&s, Op::RosterPending, NOW)
        };

        // Recovery key without Actor::Recovery.
        let human = sign_recovery_raw(&fx.recovery, RECOVERY_MAC, &body(Actor::Human));
        let e = err(&human, &cr, &mut st);
        assert!(matches!(e, VerifyError::ActorMismatch));
        assert_eq!(e.code(), ErrorCode::Unauthorized);
        // Device key claiming Recovery or System.
        for actor in [Actor::Recovery, Actor::System] {
            let t = fx.sign_device(0, &body(actor));
            assert!(matches!(err(&t, &cd, &mut st), VerifyError::ActorMismatch));
        }
        let sys = sign_recovery_raw(&fx.recovery, RECOVERY_MAC, &body(Actor::System));
        assert!(matches!(
            err(&sys, &cr, &mut st),
            VerifyError::ActorMismatch
        ));
    }

    #[test]
    fn rotated_recovery_key_accepted_inside_grace_window() {
        let fx = Fixture::new(1);
        let s = server(0);
        let mut r = fx.roster();
        r.recovery_key = recovery_signer(66).public();
        r.prev_recovery = Some(fleet_proto::PrevRecovery {
            recovery_key: fx.recovery.public(),
            recovery_ssh_key: fx.genesis.roster.recovery_ssh_key,
            recovery_escrow_key: fx.genesis.roster.recovery_escrow_key,
            recovery_delay_s: 0,
            valid_until_ms: NOW + 1000,
        });
        let mut st = MemoryReplayStore::default();
        let cmd = fx.sign_recovery_cmd(&body_for(&s, Op::RosterPending, NOW));
        accept(&cmd, &ctx(&r, &s, KeyKind::Recovery), &mut st);
        // The rotated-in key is not accepted for recovery inside the window.
        let new = recovery_signer(66);
        let rbody = |at| CommandBody {
            actor: Actor::Recovery,
            ..body_for(&s, Op::RosterPending, at)
        };
        let by_new = sign_recovery_raw(&new, RECOVERY_MAC, &rbody(NOW));
        assert!(matches!(
            err(&by_new, &ctx(&r, &s, KeyKind::Recovery), &mut st),
            VerifyError::Signature
        ));

        let late = NOW + 1000;
        let cmd = fx.sign_recovery_cmd(&body_for(&s, Op::RosterPending, late));
        let mut c = VerifyCtx::new(&r, &s, late, KeyKind::Recovery);
        assert!(matches!(err(&cmd, &c, &mut st), VerifyError::Signature));
        // After the window the new key works.
        let by_new = sign_recovery_raw(&new, RECOVERY_MAC, &rbody(late));
        accept(&by_new, &c, &mut st);
        // The agent saw the rotation recently: its local window is still open.
        c.grace_remaining_ms = Some(roster::RECOVERY_GRACE_MS - 1000);
        accept(&cmd, &c, &mut st);
    }

    #[test]
    fn elevated_requires_valid_unused_approval() {
        let fx = Fixture::new(2);
        let (r, s) = (fx.roster(), server(0));
        let c = ctx(&r, &s, KeyKind::Device);
        let mut st = MemoryReplayStore::default();
        let op = policy_op();
        let apps = approvals(&fx, &op, &[server(0), server(1)]);

        let bare = fx.sign_device(0, &body_for(&s, op.clone(), NOW));
        assert!(matches!(
            err(&bare, &c, &mut st),
            VerifyError::ApprovalRequired
        ));

        // Another server's proof.
        let mut wrong = bare.clone();
        wrong.approval = Some(apps[1].clone());
        assert!(matches!(
            err(&wrong, &c, &mut st),
            VerifyError::Approval(ApprovalError::Proof)
        ));

        // Approval for a different op digest.
        let mut other_op = fx.sign_device(
            0,
            &body_for(
                &s,
                Op::PolicyUpdate {
                    policy_toml: "evil".into(),
                },
                NOW,
            ),
        );
        other_op.approval = Some(apps[0].clone());
        assert!(matches!(
            err(&other_op, &c, &mut st),
            VerifyError::Approval(ApprovalError::Proof)
        ));

        let mut ok = bare.clone();
        ok.approval = Some(apps[0].clone());
        let v = accept(&ok, &c, &mut st);
        assert_eq!(v.approval.unwrap().leaf_index, 0);

        // Fresh envelope, same leaf: rejected, code Replay, and nothing
        // recorded (`err` checks).
        let mut again = fx.sign_device(0, &body_for(&s, op, NOW + 1));
        again.approval = Some(apps[0].clone());
        let e = err(&again, &c, &mut st);
        assert!(matches!(
            e,
            VerifyError::Approval(ApprovalError::LeafReused)
        ));
        assert_eq!(e.code(), ErrorCode::Replay);

        // Expired approval.
        let late = VerifyCtx::new(&r, &s, NOW + 31 * 60_000, KeyKind::Device);
        let mut exp = fx.sign_device(0, &body_for(&s, policy_op(), NOW + 31 * 60_000));
        exp.approval = Some(apps[0].clone());
        assert!(matches!(
            err(&exp, &late, &mut st),
            VerifyError::Approval(ApprovalError::Expired)
        ));

        // Approver removed from the roster.
        let removed = fx.without(1);
        let cr = ctx(&removed, &s, KeyKind::Device);
        let mut orphan = fx.sign_device(0, &body_for(&s, policy_op(), NOW));
        orphan.approval = Some(apps[0].clone());
        assert!(matches!(
            err(&orphan, &cr, &mut st),
            VerifyError::Approval(ApprovalError::SignerUnknown)
        ));
    }

    #[test]
    fn roster_update_is_self_signed() {
        let fx = Fixture::new(1);
        let (r, s) = (fx.roster(), server(0));
        let op = Op::RosterUpdate {
            roster: Box::new(fx.genesis.clone()),
        };
        let cmd = fx.sign_device(0, &body_for(&s, op, NOW));
        verify_command(
            &cmd,
            &ctx(&r, &s, KeyKind::Device),
            &MemoryReplayStore::default(),
        )
        .unwrap();
    }

    #[test]
    fn veto_before_activation() {
        let fx = Fixture::new(2);
        let (r, s) = (fx.roster(), server(0));
        let pending = PendingRoster {
            roster: fx.genesis.clone(),
            hash: roster_hash(&fx.genesis),
            submitted_at_ms: NOW,
            activates_at_ms: NOW + 1000,
        };
        let op = Op::RosterVeto {
            pending_hash: pending.hash,
        };
        let mut cmd = fx.sign_device(0, &body_for(&s, op.clone(), NOW));
        cmd.approval = Some(approvals(&fx, &op, std::slice::from_ref(&s)).remove(0));
        let v = verify_command(
            &cmd,
            &ctx(&r, &s, KeyKind::Device),
            &MemoryReplayStore::default(),
        )
        .unwrap();
        check_veto(&v, &pending, NOW).unwrap();
        assert_eq!(
            check_veto(&v, &pending, NOW + 1000),
            Err(RosterError::VetoMismatch)
        );
        let other = PendingRoster {
            hash: [0; 32],
            ..pending
        };
        assert_eq!(check_veto(&v, &other, NOW), Err(RosterError::VetoMismatch));
    }

    /// Audit F2a #4: replay state is consumed only by `commit`, after policy.
    #[test]
    fn replay_consumed_only_on_commit() {
        let fx = Fixture::new(2);
        let (r, s) = (fx.roster(), server(0));
        let c = ctx(&r, &s, KeyKind::Device);
        let mut st = MemoryReplayStore::default();
        let op = policy_op();
        let apps = approvals(&fx, &op, std::slice::from_ref(&s));
        let mut cmd = fx.sign_device(0, &body_for(&s, op.clone(), NOW));
        cmd.approval = Some(apps[0].clone());

        // Verified but rejected by policy (no commit): nothing consumed, so
        // the same approval can be retried once policy allows it.
        let v = verify_command(&cmd, &c, &st).unwrap();
        assert!(st.is_empty());
        drop(v);
        let v = verify_command(&cmd, &c, &st).unwrap();
        v.commit(&mut st).unwrap();
        assert_eq!(st.len(), 2, "nonce and leaf");
        // Second commit of the same verified command: replay.
        assert!(matches!(v.commit(&mut st), Err(VerifyError::Replay)));
        assert_eq!(st.len(), 2);
        assert!(matches!(err(&cmd, &c, &mut st), VerifyError::Replay));

        // Two envelopes sharing one leaf, both verified before either commits
        // (what serialization in exec prevents): the second commit fails
        // without recording its nonce.
        let mut st = MemoryReplayStore::default();
        let mut a = fx.sign_device(0, &body_for(&s, op.clone(), NOW));
        a.approval = Some(apps[0].clone());
        let mut b = fx.sign_device(1, &body_for(&s, op, NOW + 1));
        b.approval = Some(apps[0].clone());
        let (va, vb) = (
            verify_command(&a, &c, &st).unwrap(),
            verify_command(&b, &c, &st).unwrap(),
        );
        va.commit(&mut st).unwrap();
        assert!(matches!(vb.commit(&mut st), Err(VerifyError::Replay)));
        assert_eq!(st.len(), 2, "b's nonce not recorded");

        // Same nonce, no approval.
        let mut st = MemoryReplayStore::default();
        let read = fx.sign_device(0, &body_for(&s, Op::SystemInfo, NOW));
        let (v1, v2) = (
            verify_command(&read, &c, &st).unwrap(),
            verify_command(&read, &c, &st).unwrap(),
        );
        v1.commit(&mut st).unwrap();
        assert!(matches!(v2.commit(&mut st), Err(VerifyError::Replay)));
        assert_eq!(st.len(), 1);
        assert_eq!(v1.nonce_expires_at_ms, NOW + 60_000 + DEFAULT_SKEW_MS);
    }
}
