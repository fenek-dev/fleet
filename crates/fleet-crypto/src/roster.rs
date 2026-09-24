//! Roster acceptance (design §5.3). Pure state machine: the caller persists
//! rosters, the pending recovery and the hashes of the current epoch.
//!
//! **State the caller keeps:** the current `SignedRoster` and `epoch_hashes`,
//! the hashes of every roster accepted in the current epoch (the current one is
//! always implied). A recovery roster's `prev_hash` may name any of them, so a
//! recovery supersedes every branch after a fork. When an epoch changes, the
//! caller resets `epoch_hashes` to just the new roster's hash.
//!
//! **Recovery-key rotation grace (rule 6).** A normal update that changes any
//! recovery key must record the replaced keys in `prev_recovery`, with
//! `issued_at_ms + RECOVERY_GRACE_MS ≤ valid_until_ms ≤ issued_at_ms +
//! RECOVERY_GRACE_MS + MAX_GRACE_SLACK_MS`. While that window is open **only**
//! the old recovery key signs recovery rosters, recovery commands and
//! recovery `DeviceAuth`; the newly rotated-in key is not accepted for
//! recovery until the window closes. Otherwise a compromised Mac could rotate
//! in its own key (with delay 0) and recover with it at once, locking the real
//! code out. Later normal updates carry `prev_recovery` forward unchanged
//! (dropping it only once expired), and may not rotate again while it is
//! still active.
//!
//! "Recovery settings" are the three keys **and** `recovery_delay_s`: changing
//! the delay alone is a rotation too (it needs the grace record). While the
//! grace window is open a recovery roster waits the **previous** delay (the
//! one the real code was set up with).
//!
//! **Agent clock.** The window is `max(prev.valid_until_ms,
//! local_grace_until_ms)`, where the local end is 72 h after *this agent*
//! accepted the rotating roster ([`RecoveryClock`]). A roster's
//! `issued_at_ms` is chosen by the signing Mac, so an agent that was offline
//! would otherwise receive a rotation whose signed window already closed.
//! The agent counts its 72 h down on the monotonic clock (like a pending
//! recovery's delay) and passes the end projected onto `now_ms`, so a wall
//! clock change can't stretch or cut the local window.

use crate::sig::{self, Ed25519Signer, Signer};
use crate::verify::VerifiedCommand;
use crate::{Error, blake3};
use fleet_proto::{
    DeviceId, Ed25519Public, ErrorCode, Hash32, KeyRef, Op, PrevRecovery, Roster, Signature,
    SignedRoster, X25519Public, encode,
};

/// Minimum lifetime of `prev_recovery` after a rotation (72 h).
pub const RECOVERY_GRACE_MS: u64 = 72 * 3600 * 1000;
/// How far `prev_recovery.valid_until_ms` may exceed `issued_at_ms +
/// RECOVERY_GRACE_MS` (1 h). Bounded because the old key is the *only*
/// recovery key during the window: an open-ended window would disable the
/// new key indefinitely.
pub const MAX_GRACE_SLACK_MS: u64 = 3600 * 1000;
/// How far a roster's `issued_at_ms` may lead the verifier's clock.
pub const MAX_ROSTER_SKEW_MS: u64 = 5 * 60_000;

/// The verifier's view of time for recovery-key grace (rule 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecoveryClock {
    pub now_ms: u64,
    /// End (exclusive) of this agent's local grace window for the current
    /// `prev_recovery`, in the same frame as `now_ms`: the agent projects
    /// its monotonic countdown (see [`next_grace_remaining`]) as
    /// `now_ms + remaining`. `None` on the Mac, when unknown or once the
    /// countdown ran out: only the signed `valid_until_ms` counts.
    pub local_grace_until_ms: Option<u64>,
}

impl RecoveryClock {
    pub fn at(now_ms: u64) -> Self {
        Self {
            now_ms,
            local_grace_until_ms: None,
        }
    }

    /// Clock at `now_ms` with `remaining_ms` of local grace left (`None`:
    /// no local grace).
    pub fn with_grace_remaining(now_ms: u64, remaining_ms: Option<u64>) -> Self {
        Self {
            now_ms,
            local_grace_until_ms: remaining_ms
                .filter(|r| *r > 0)
                .map(|r| now_ms.saturating_add(r)),
        }
    }

    /// End (exclusive) of `prev`'s grace window on this verifier.
    pub fn grace_until(&self, prev: &PrevRecovery) -> u64 {
        prev.valid_until_ms
            .max(self.local_grace_until_ms.unwrap_or(0))
    }

    /// `roster.prev_recovery` if its grace window is open now.
    pub fn active_prev<'r>(&self, roster: &'r Roster) -> Option<&'r PrevRecovery> {
        roster
            .prev_recovery
            .as_ref()
            .filter(|p| self.now_ms < self.grace_until(p))
    }
}

/// The local grace time remaining after installing `new` over `cur`: a full
/// [`RECOVERY_GRACE_MS`] on a rotation, carried while `prev_recovery` is
/// carried forward, cleared when it is dropped. The agent counts it down on
/// the monotonic clock.
pub fn next_grace_remaining(cur: &Roster, new: &Roster, remaining: Option<u64>) -> Option<u64> {
    match &new.prev_recovery {
        None => None,
        Some(p) if cur.prev_recovery.as_ref() == Some(p) => remaining,
        Some(_) => Some(RECOVERY_GRACE_MS),
    }
}

type RecoverySettings = (Ed25519Public, Ed25519Public, X25519Public, u32);

fn settings(r: &Roster) -> RecoverySettings {
    let (k, s, e) = r.recovery_keys();
    (k, s, e, r.recovery_delay_s)
}

fn prev_settings(p: &PrevRecovery) -> RecoverySettings {
    let (k, s, e) = p.recovery_keys();
    (k, s, e, p.recovery_delay_s)
}

/// Recovery delay that applies to a recovery roster submitted under `clock`:
/// the previous roster's delay while the grace window is open (only the
/// previous key can sign then), otherwise the current one.
pub fn effective_recovery_delay_s(roster: &Roster, clock: RecoveryClock) -> u32 {
    match clock.active_prev(roster) {
        Some(p) => p.recovery_delay_s,
        None => roster.recovery_delay_s,
    }
}

/// The one recovery signing key `roster` accepts under `clock`: the
/// rotated-out key while its grace window is open, else the current key.
pub fn recovery_key_at(roster: &Roster, clock: RecoveryClock) -> &Ed25519Public {
    clock
        .active_prev(roster)
        .map_or(&roster.recovery_key, |p| &p.recovery_key)
}

/// Recovery SSH keys `roster` accepts under `clock` (for `authorized_keys`):
/// like [`recovery_key_at`], only the rotated-out key during the window.
pub fn recovery_ssh_keys_at(roster: &Roster, clock: RecoveryClock) -> Vec<Ed25519Public> {
    vec![
        clock
            .active_prev(roster)
            .map_or(roster.recovery_ssh_key, |p| p.recovery_ssh_key),
    ]
}

/// Verifies an Ed25519 signature by the recovery key `roster` accepts under
/// `clock` ([`recovery_key_at`]).
pub fn verify_recovery_sig(
    roster: &Roster,
    clock: RecoveryClock,
    msg: &[u8],
    signature: &Signature,
) -> Result<(), Error> {
    sig::ed25519_verify(recovery_key_at(roster, clock), msg, signature)
        .map_err(|_| Error::BadSignature)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RosterError {
    #[error("roster is for another fleet")]
    WrongFleet,
    #[error("roster from an older epoch")]
    OldEpoch,
    #[error("epoch may only increase by one, through recovery")]
    EpochSkip,
    #[error("version is not current + 1 (normal) or higher (recovery)")]
    BadVersion,
    #[error("prev_hash does not match")]
    PrevHash,
    #[error("signer is not a root key in the current roster")]
    SignerUnknown,
    #[error("wrong kind of signer for this transition")]
    WrongSigner,
    #[error("roster signature invalid")]
    Signature,
    #[error("recovery roster must install a new recovery key")]
    RecoveryKeyReused,
    #[error("recovery roster must clear prev_recovery")]
    RecoveryPrevNotCleared,
    #[error("recovery keys rotated without a prev_recovery grace record for the current keys")]
    RecoveryGrace,
    #[error("prev_recovery must be carried forward unchanged until it expires")]
    PrevRecoveryChanged,
    #[error("recovery keys rotated again while the previous grace window is active")]
    RotationTooSoon,
    #[error("issued_at_ms goes backwards or is in the future")]
    IssuedAt,
    #[error("roster has no devices or duplicate device ids")]
    Malformed,
    #[error("pending recovery is not active yet")]
    NotYetActive,
    #[error("veto does not name the pending recovery, or came too late")]
    VetoMismatch,
    #[error("chain link {index}: {error}")]
    ChainLink {
        index: usize,
        error: Box<RosterError>,
    },
    #[error("a pending recovery must be the last link of a chain")]
    PendingNotLast,
}

impl RosterError {
    pub fn code(&self) -> ErrorCode {
        match self {
            RosterError::Signature => ErrorCode::SignatureInvalid,
            RosterError::OldEpoch | RosterError::BadVersion => ErrorCode::Stale,
            RosterError::SignerUnknown | RosterError::WrongSigner => ErrorCode::Unauthorized,
            RosterError::ChainLink { error, .. } => error.code(),
            _ => ErrorCode::InvalidArgument,
        }
    }
}

/// Outcome of a valid candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RosterDecision {
    /// Install now.
    Accept,
    /// Recovery roster under `recovery_delay_s`: store as pending, raise a
    /// critical event, and install via [`activate`] once the delay passes
    /// without a veto.
    Pending { activates_at_ms: u64 },
}

/// A recovery roster waiting out its delay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRoster {
    pub roster: SignedRoster,
    /// [`roster_hash`] of `roster`; the `roster.veto` argument.
    pub hash: Hash32,
    /// When the agent accepted it as pending. [`activate`] checks the
    /// recovery-key grace window at this time, not at activation.
    pub submitted_at_ms: u64,
    pub activates_at_ms: u64,
}

impl PendingRoster {
    pub fn to_wire(&self) -> fleet_proto::PendingRecovery {
        fleet_proto::PendingRecovery {
            hash: self.hash,
            activates_at_ms: self.activates_at_ms,
        }
    }
}

/// BLAKE3 of the `SignedRoster` encoding (what `prev_hash` refers to).
pub fn roster_hash(signed: &SignedRoster) -> Hash32 {
    blake3(&encode(signed))
}

/// Signs `roster` with a Mac root key.
pub fn sign_root(
    roster: Roster,
    device_id: DeviceId,
    root: &(impl Signer + ?Sized),
) -> Result<SignedRoster, Error> {
    let signature = sig::p256_sign(root, &SignedRoster::signed_message(&roster))?;
    Ok(SignedRoster {
        roster,
        signer: KeyRef::Root(device_id),
        signature,
    })
}

/// Signs `roster` with the recovery key.
pub fn sign_recovery(roster: Roster, recovery: &Ed25519Signer) -> SignedRoster {
    let signature = recovery.sign(&SignedRoster::signed_message(&roster));
    SignedRoster {
        roster,
        signer: KeyRef::Recovery,
        signature,
    }
}

fn check_structure(r: &Roster) -> Result<(), RosterError> {
    let mut ids: Vec<&DeviceId> = r.devices.iter().map(|d| &d.id).collect();
    ids.sort();
    ids.dedup();
    if r.devices.is_empty() || ids.len() != r.devices.len() {
        return Err(RosterError::Malformed);
    }
    Ok(())
}

/// Verifies `candidate`'s signature with a key from `signing_roster`.
/// Recovery signatures must use the previous recovery key while its grace
/// window is open under `clock`, the current one otherwise.
fn check_signature(
    signing_roster: &Roster,
    candidate: &SignedRoster,
    clock: RecoveryClock,
) -> Result<(), RosterError> {
    let msg = SignedRoster::signed_message(&candidate.roster);
    let res = match candidate.signer {
        KeyRef::Root(id) => {
            let dev = signing_roster
                .device(&id)
                .ok_or(RosterError::SignerUnknown)?;
            sig::p256_verify(&dev.root_key, &msg, &candidate.signature)
        }
        KeyRef::Recovery => verify_recovery_sig(signing_roster, clock, &msg, &candidate.signature),
    };
    res.map_err(|_| RosterError::Signature)
}

/// Validates a genesis roster (installed at `fleet-agent install` time, pinned
/// by the operator): epoch 0, version 1, zero `prev_hash`, no
/// `prev_recovery`, `issued_at_ms` not ahead of `now_ms` by more than
/// [`MAX_ROSTER_SKEW_MS`], and self-signed by a root key it lists.
pub fn verify_genesis(genesis: &SignedRoster, now_ms: u64) -> Result<(), RosterError> {
    let r = &genesis.roster;
    check_structure(r)?;
    if r.epoch != 0 {
        return Err(RosterError::EpochSkip);
    }
    if r.version != 1 {
        return Err(RosterError::BadVersion);
    }
    if r.prev_recovery.is_some() {
        return Err(RosterError::Malformed);
    }
    if r.issued_at_ms > now_ms.saturating_add(MAX_ROSTER_SKEW_MS) {
        return Err(RosterError::IssuedAt);
    }
    if r.prev_hash != [0; 32] {
        return Err(RosterError::PrevHash);
    }
    if !matches!(genesis.signer, KeyRef::Root(_)) {
        return Err(RosterError::WrongSigner);
    }
    check_signature(&genesis.roster, genesis, RecoveryClock::at(0))
}

/// Decides whether `candidate` may follow `current` (rules 1, 3, 4, 6).
///
/// `epoch_hashes`: hashes of all rosters accepted in `current`'s epoch; the
/// hash of `current` is implied and need not be listed. `clock` carries the
/// agent's local grace end for `current.prev_recovery`.
pub fn evaluate(
    current: &SignedRoster,
    epoch_hashes: &[Hash32],
    candidate: &SignedRoster,
    clock: RecoveryClock,
) -> Result<RosterDecision, RosterError> {
    evaluate_inner(current, epoch_hashes, candidate, clock)?;
    let delay_s = effective_recovery_delay_s(&current.roster, clock);
    if candidate.signer == KeyRef::Recovery && delay_s > 0 {
        return Ok(RosterDecision::Pending {
            activates_at_ms: clock.now_ms.saturating_add(u64::from(delay_s) * 1000),
        });
    }
    Ok(RosterDecision::Accept)
}

/// `clock.now_ms`: the verifier's clock, or a pending recovery's submission time.
fn evaluate_inner(
    current: &SignedRoster,
    epoch_hashes: &[Hash32],
    candidate: &SignedRoster,
    clock: RecoveryClock,
) -> Result<(), RosterError> {
    let at_ms = clock.now_ms;
    let (cur, new) = (&current.roster, &candidate.roster);
    if new.fleet_id != cur.fleet_id {
        return Err(RosterError::WrongFleet);
    }
    check_structure(new)?;
    if new.epoch < cur.epoch {
        return Err(RosterError::OldEpoch);
    }
    if new.issued_at_ms < cur.issued_at_ms
        || new.issued_at_ms > at_ms.saturating_add(MAX_ROSTER_SKEW_MS)
    {
        return Err(RosterError::IssuedAt);
    }
    if new.epoch == cur.epoch {
        // Rule 1: normal update.
        if candidate.signer == KeyRef::Recovery {
            return Err(RosterError::WrongSigner);
        }
        if Some(new.version) != cur.version.checked_add(1) {
            return Err(RosterError::BadVersion);
        }
        if new.prev_hash != roster_hash(current) {
            return Err(RosterError::PrevHash);
        }
        check_recovery_grace(cur, new, clock)?;
    } else {
        // Rule 3: recovery.
        if Some(new.epoch) != cur.epoch.checked_add(1) {
            return Err(RosterError::EpochSkip);
        }
        if candidate.signer != KeyRef::Recovery {
            return Err(RosterError::WrongSigner);
        }
        if new.version <= cur.version {
            return Err(RosterError::BadVersion);
        }
        if new.prev_hash != roster_hash(current) && !epoch_hashes.contains(&new.prev_hash) {
            return Err(RosterError::PrevHash);
        }
        if new.prev_recovery.is_some() {
            return Err(RosterError::RecoveryPrevNotCleared);
        }
        // Fresh keys: none may repeat the current or the rotated-out set.
        let old = std::iter::once(cur.recovery_keys())
            .chain(cur.prev_recovery.map(|p| p.recovery_keys()));
        for (k, s, e) in old {
            if new.recovery_key == k || new.recovery_ssh_key == s || new.recovery_escrow_key == e {
                return Err(RosterError::RecoveryKeyReused);
            }
        }
    }
    check_signature(cur, candidate, clock)
}

/// Rule 6 for a normal update `cur → new`. Windows are judged on the
/// agent's clock, so Macs should carry `prev_recovery` forward rather than
/// drop it (carrying is always allowed; dropping only once closed here).
fn check_recovery_grace(
    cur: &Roster,
    new: &Roster,
    clock: RecoveryClock,
) -> Result<(), RosterError> {
    let cur_prev_active = clock.active_prev(cur).is_some();
    if settings(new) != settings(cur) {
        // Rotation (keys or delay): one at a time, and the replaced
        // settings stay usable.
        if cur_prev_active {
            return Err(RosterError::RotationTooSoon);
        }
        let min_until = new.issued_at_ms.saturating_add(RECOVERY_GRACE_MS);
        let max_until = min_until.saturating_add(MAX_GRACE_SLACK_MS);
        let grace_ok = new.prev_recovery.is_some_and(|p| {
            prev_settings(&p) == settings(cur)
                && (min_until..=max_until).contains(&p.valid_until_ms)
        });
        if !grace_ok {
            return Err(RosterError::RecoveryGrace);
        }
    } else if new.prev_recovery != cur.prev_recovery {
        // Only allowed change without rotation: dropping an expired record.
        let dropped_expired = new.prev_recovery.is_none() && !cur_prev_active;
        if !dropped_expired {
            return Err(RosterError::PrevRecoveryChanged);
        }
    }
    Ok(())
}

/// Installs a pending recovery once its delay has passed. Re-validates it
/// against the (possibly updated) current roster, ignoring the delay; the
/// recovery-key grace window is judged at `pending.submitted_at_ms`, with
/// `local_grace_until_ms` as the agent projected it at submission (same
/// frame as `submitted_at_ms`).
pub fn activate(
    current: &SignedRoster,
    epoch_hashes: &[Hash32],
    pending: &PendingRoster,
    now_ms: u64,
    local_grace_until_ms: Option<u64>,
) -> Result<(), RosterError> {
    if now_ms < pending.activates_at_ms {
        return Err(RosterError::NotYetActive);
    }
    if roster_hash(&pending.roster) != pending.hash {
        return Err(RosterError::VetoMismatch);
    }
    evaluate_inner(
        current,
        epoch_hashes,
        &pending.roster,
        RecoveryClock {
            now_ms: pending.submitted_at_ms,
            local_grace_until_ms,
        },
    )
}

/// Checks that a verified `roster.veto` command cancels `pending`.
///
/// `verify::verify_command` has already checked the device signature and the
/// root-key approval (signer in the current roster, covering this server and
/// this op). This checks that it carried an approval, names this pending
/// roster, and arrived before activation.
pub fn check_veto(
    verified: &VerifiedCommand,
    pending: &PendingRoster,
    now_ms: u64,
) -> Result<(), RosterError> {
    let Op::RosterVeto { pending_hash } = &verified.body.op else {
        return Err(RosterError::VetoMismatch);
    };
    if verified.approval.is_none()
        || *pending_hash != pending.hash
        || now_ms >= pending.activates_at_ms
    {
        return Err(RosterError::VetoMismatch);
    }
    Ok(())
}

/// Result of [`apply_chain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainOutcome {
    /// Number of leading links to install, in order.
    pub accepted: usize,
    /// Set when the final link is a delayed recovery roster.
    pub pending: Option<PendingRoster>,
    /// Local grace remaining (see [`next_grace_remaining`]) to persist with
    /// the last accepted link.
    pub grace_remaining_ms: Option<u64>,
}

/// Catch-up (rule 2): validates each link in order against the one before.
/// All-or-nothing: any bad link rejects the whole chain. Links at or below
/// the current version (already installed) must not be sent.
pub fn apply_chain(
    current: &SignedRoster,
    epoch_hashes: &[Hash32],
    chain: &[SignedRoster],
    clock: RecoveryClock,
) -> Result<ChainOutcome, RosterError> {
    let now_ms = clock.now_ms;
    let mut clock = clock;
    let mut cur = current;
    let mut hashes = epoch_hashes.to_vec();
    for (index, link) in chain.iter().enumerate() {
        let wrap = |error| RosterError::ChainLink {
            index,
            error: Box::new(error),
        };
        match evaluate(cur, &hashes, link, clock).map_err(wrap)? {
            RosterDecision::Accept => {
                // Same semantics as exec's stored epoch hashes: every
                // roster of the epoch *before* the current one; the current
                // one is implied. So push the roster being replaced.
                if link.roster.epoch != cur.roster.epoch {
                    hashes.clear();
                } else {
                    hashes.push(roster_hash(cur));
                }
                let remaining = clock.local_grace_until_ms.map(|u| u.saturating_sub(now_ms));
                clock = RecoveryClock::with_grace_remaining(
                    now_ms,
                    next_grace_remaining(&cur.roster, &link.roster, remaining),
                );
                cur = link;
            }
            RosterDecision::Pending { activates_at_ms } => {
                if index + 1 != chain.len() {
                    return Err(RosterError::PendingNotLast);
                }
                return Ok(ChainOutcome {
                    accepted: index,
                    pending: Some(PendingRoster {
                        roster: link.clone(),
                        hash: roster_hash(link),
                        submitted_at_ms: now_ms,
                        activates_at_ms,
                    }),
                    grace_remaining_ms: grace_remaining(clock),
                });
            }
        }
    }
    Ok(ChainOutcome {
        accepted: chain.len(),
        pending: None,
        grace_remaining_ms: grace_remaining(clock),
    })
}

fn grace_remaining(clock: RecoveryClock) -> Option<u64> {
    clock
        .local_grace_until_ms
        .map(|u| u.saturating_sub(clock.now_ms))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use fleet_proto::Ed25519Public;

    // Wrappers with a plain clock (no local rotation time) for the older tests.
    fn evaluate(
        c: &SignedRoster,
        h: &[Hash32],
        n: &SignedRoster,
        now: u64,
    ) -> Result<RosterDecision, RosterError> {
        super::evaluate(c, h, n, RecoveryClock::at(now))
    }
    fn apply_chain(
        c: &SignedRoster,
        h: &[Hash32],
        chain: &[SignedRoster],
        now: u64,
    ) -> Result<ChainOutcome, RosterError> {
        super::apply_chain(c, h, chain, RecoveryClock::at(now))
    }
    fn activate(
        c: &SignedRoster,
        h: &[Hash32],
        p: &PendingRoster,
        now: u64,
    ) -> Result<(), RosterError> {
        super::activate(c, h, p, now, None)
    }

    /// Next normal roster signed by mac `by`.
    fn next(
        fx: &Fixture,
        cur: &SignedRoster,
        by: usize,
        edit: impl FnOnce(&mut Roster),
    ) -> SignedRoster {
        let mut r = cur.roster.clone();
        r.version += 1;
        r.prev_hash = roster_hash(cur);
        edit(&mut r);
        sign_root(r, fx.macs[by].id, &fx.macs[by].root).unwrap()
    }

    fn recovery(fx: &Fixture, cur: &SignedRoster, prev: Hash32) -> SignedRoster {
        let mut r = cur.roster.clone();
        r.epoch += 1;
        r.version += 5;
        r.prev_hash = prev;
        r.devices.truncate(1);
        let new = recovery_signer(99);
        r.recovery_key = new.public();
        r.recovery_ssh_key = Ed25519Public([0x51; 32]);
        r.recovery_escrow_key = fleet_proto::X25519Public([0x52; 32]);
        r.prev_recovery = None;
        sign_recovery(r, &fx.recovery)
    }

    #[test]
    fn genesis_and_normal_update() {
        let fx = Fixture::new(2);
        verify_genesis(&fx.genesis, NOW).unwrap();
        let v2 = next(&fx, &fx.genesis, 1, |_| {});
        assert_eq!(
            evaluate(&fx.genesis, &[], &v2, NOW),
            Ok(RosterDecision::Accept)
        );
    }

    #[test]
    fn normal_update_rejections() {
        let fx = Fixture::new(2);
        let g = &fx.genesis;

        let skip = next(&fx, g, 0, |r| r.version += 1);
        assert_eq!(evaluate(g, &[], &skip, NOW), Err(RosterError::BadVersion));

        let wrong_prev = next(&fx, g, 0, |r| r.prev_hash = [1; 32]);
        assert_eq!(
            evaluate(g, &[], &wrong_prev, NOW),
            Err(RosterError::PrevHash)
        );

        // Signed by a P-256 key that isn't anyone's root key.
        let mut r = next(&fx, g, 0, |_| {}).roster;
        r.version = g.roster.version + 1;
        let forged = sign_root(r.clone(), fx.macs[0].id, &fx.macs[0].device).unwrap();
        assert_eq!(evaluate(g, &[], &forged, NOW), Err(RosterError::Signature));
        let stranger = sign_root(
            r.clone(),
            fleet_proto::DeviceId([0xab; 16]),
            &p256_signer(77),
        )
        .unwrap();
        assert_eq!(
            evaluate(g, &[], &stranger, NOW),
            Err(RosterError::SignerUnknown)
        );

        // Recovery key may not sign a same-epoch update.
        let rec_same_epoch = sign_recovery(r, &fx.recovery);
        assert_eq!(
            evaluate(g, &[], &rec_same_epoch, NOW),
            Err(RosterError::WrongSigner)
        );

        // Tampered after signing.
        let mut t = next(&fx, g, 0, |_| {});
        t.roster.devices[0].added_at += 1;
        assert_eq!(evaluate(g, &[], &t, NOW), Err(RosterError::Signature));

        // Older / equal version replay.
        let v2 = next(&fx, g, 0, |_| {});
        assert_eq!(evaluate(&v2, &[], g, NOW), Err(RosterError::BadVersion));
    }

    #[test]
    fn removed_device_cannot_sign() {
        let fx = Fixture::new(2);
        let removed_id = fx.macs[1].id;
        let v2 = next(&fx, &fx.genesis, 0, |r| {
            r.devices.retain(|d| d.id != removed_id)
        });
        evaluate(&fx.genesis, &[], &v2, NOW).unwrap();
        let v3 = next(&fx, &v2, 1, |_| {});
        assert_eq!(
            evaluate(&v2, &[], &v3, NOW),
            Err(RosterError::SignerUnknown)
        );
    }

    #[test]
    fn catch_up_chain_of_three() {
        let fx = Fixture::new(2);
        let v2 = next(&fx, &fx.genesis, 0, |_| {});
        let v3 = next(&fx, &v2, 1, |r| r.devices[0].added_at += 1);
        let v4 = next(&fx, &v3, 0, |_| {});
        let out =
            apply_chain(&fx.genesis, &[], &[v2.clone(), v3.clone(), v4.clone()], NOW).unwrap();
        assert_eq!(
            out,
            ChainOutcome {
                accepted: 3,
                pending: None,
                grace_remaining_ms: None,
            }
        );

        // A broken middle link rejects the whole chain.
        let mut bad = v3;
        bad.signature.0[1] ^= 1;
        let err = apply_chain(&fx.genesis, &[], &[v2, bad, v4], NOW).unwrap_err();
        assert!(matches!(err, RosterError::ChainLink { index: 1, .. }));
    }

    #[test]
    fn chain_recovery_off_original_current_after_catch_up() {
        let fx = Fixture::new(2);
        let g = fx.genesis_with(|r| r.recovery_delay_s = 0);
        let v2 = next(&fx, &g, 0, |_| {});
        let v3 = next(&fx, &v2, 1, |_| {});
        // Recovery forks off the roster that was current before catch-up.
        let rec = recovery(&fx, &v3, roster_hash(&g));
        let out = apply_chain(&g, &[], &[v2.clone(), v3.clone(), rec], NOW).unwrap();
        assert_eq!(out.accepted, 3);
        // And off an intermediate link.
        let rec2 = recovery(&fx, &v3, roster_hash(&v2));
        assert_eq!(
            apply_chain(&g, &[], &[v2, v3, rec2], NOW).unwrap().accepted,
            3
        );
    }

    #[test]
    fn recovery_immediate_with_zero_delay_and_fork() {
        let fx = Fixture::new(2);
        let g = fx.genesis_with(|r| r.recovery_delay_s = 0);
        // Fork: attacker's branch v2 is current; recovery chains off genesis.
        let v2 = next(&fx, &g, 1, |_| {});
        let rec = recovery(&fx, &v2, roster_hash(&g));
        assert_eq!(
            evaluate(&v2, &[roster_hash(&g)], &rec, NOW),
            Ok(RosterDecision::Accept)
        );
        // Without genesis among the epoch's hashes, prev_hash is unknown.
        assert_eq!(evaluate(&v2, &[], &rec, NOW), Err(RosterError::PrevHash));
    }

    #[test]
    fn recovery_rejections() {
        let fx = Fixture::new(1);
        let g = &fx.genesis;
        let h = roster_hash(g);

        // Must install a new recovery key.
        let mut r = recovery(&fx, g, h).roster;
        r.recovery_key = g.roster.recovery_key;
        let same_key = sign_recovery(r, &fx.recovery);
        assert_eq!(
            evaluate(g, &[], &same_key, NOW),
            Err(RosterError::RecoveryKeyReused)
        );

        // Root key can't open a new epoch.
        let r = recovery(&fx, g, h).roster;
        let by_root = sign_root(r.clone(), fx.macs[0].id, &fx.macs[0].root).unwrap();
        assert_eq!(
            evaluate(g, &[], &by_root, NOW),
            Err(RosterError::WrongSigner)
        );

        // Epoch skip.
        let mut r2 = r.clone();
        r2.epoch += 1;
        assert_eq!(
            evaluate(g, &[], &sign_recovery(r2, &fx.recovery), NOW),
            Err(RosterError::EpochSkip)
        );

        // Version must still grow.
        let mut r3 = r;
        r3.version = g.roster.version;
        assert_eq!(
            evaluate(g, &[], &sign_recovery(r3, &fx.recovery), NOW),
            Err(RosterError::BadVersion)
        );
    }

    #[test]
    fn old_epoch_replay_rejected() {
        let fx = Fixture::new(1);
        let g = fx.genesis_with(|r| r.recovery_delay_s = 0);
        let rec = recovery(&fx, &g, roster_hash(&g));
        evaluate(&g, &[], &rec, NOW).unwrap();
        // An epoch-0 roster with a higher version, validly signed by a Mac that
        // is still listed, is refused once epoch 1 is current.
        let mut old = g.roster.clone();
        old.version = rec.roster.version + 1;
        old.prev_hash = roster_hash(&rec);
        let old = sign_root(old, fx.macs[0].id, &fx.macs[0].root).unwrap();
        assert_eq!(evaluate(&rec, &[], &old, NOW), Err(RosterError::OldEpoch));
    }

    #[test]
    fn recovery_pending_then_activation() {
        let fx = Fixture::new(1);
        let g = &fx.genesis;
        let delay_ms = u64::from(g.roster.recovery_delay_s) * 1000;
        assert!(delay_ms > 0);
        let rec = recovery(&fx, g, roster_hash(g));
        let out = apply_chain(g, &[], std::slice::from_ref(&rec), NOW).unwrap();
        assert_eq!(out.accepted, 0);
        let pending = out.pending.unwrap();
        assert_eq!(pending.activates_at_ms, NOW + delay_ms);
        assert_eq!(pending.hash, roster_hash(&rec));

        assert_eq!(
            activate(g, &[], &pending, NOW + delay_ms - 1),
            Err(RosterError::NotYetActive)
        );
        activate(g, &[], &pending, NOW + delay_ms).unwrap();
    }

    const HOUR: u64 = 3600 * 1000;

    /// Normal update by mac 0 that rotates every recovery key to `seed`'s,
    /// with a grace record for the current keys lasting `grace_ms`.
    fn rotate(fx: &Fixture, cur: &SignedRoster, seed: u8, grace_ms: u64) -> SignedRoster {
        let old = cur.roster.clone();
        next(fx, cur, 0, |r| {
            r.recovery_key = recovery_signer(seed).public();
            r.recovery_ssh_key = Ed25519Public([seed; 32]);
            r.recovery_escrow_key = fleet_proto::X25519Public([seed; 32]);
            r.prev_recovery = Some(fleet_proto::PrevRecovery {
                recovery_key: old.recovery_key,
                recovery_ssh_key: old.recovery_ssh_key,
                recovery_escrow_key: old.recovery_escrow_key,
                recovery_delay_s: old.recovery_delay_s,
                valid_until_ms: r.issued_at_ms + grace_ms,
            });
        })
    }

    #[test]
    fn rotation_requires_grace_record() {
        let fx = Fixture::new(1);
        let g = &fx.genesis;
        let no_prev = next(&fx, g, 0, |r| r.recovery_key = recovery_signer(66).public());
        assert_eq!(
            evaluate(g, &[], &no_prev, NOW),
            Err(RosterError::RecoveryGrace)
        );
        let short = rotate(&fx, g, 66, RECOVERY_GRACE_MS - 1);
        assert_eq!(
            evaluate(g, &[], &short, NOW),
            Err(RosterError::RecoveryGrace)
        );
        let mut wrong_keys = rotate(&fx, g, 66, RECOVERY_GRACE_MS).roster;
        wrong_keys.prev_recovery.as_mut().unwrap().recovery_key = Ed25519Public([1; 32]);
        let wrong_keys = sign_root(wrong_keys, fx.macs[0].id, &fx.macs[0].root).unwrap();
        assert_eq!(
            evaluate(g, &[], &wrong_keys, NOW),
            Err(RosterError::RecoveryGrace)
        );
        // Only the SSH key changes: still a rotation.
        let ssh_only = next(&fx, g, 0, |r| r.recovery_ssh_key = Ed25519Public([1; 32]));
        assert_eq!(
            evaluate(g, &[], &ssh_only, NOW),
            Err(RosterError::RecoveryGrace)
        );
        let ok = rotate(&fx, g, 66, RECOVERY_GRACE_MS);
        assert_eq!(evaluate(g, &[], &ok, NOW), Ok(RosterDecision::Accept));
    }

    #[test]
    fn old_recovery_key_recovers_inside_window_only() {
        let fx = Fixture::new(2);
        let g = fx.genesis_with(|r| r.recovery_delay_s = 0);
        // Compromised mac 0 rotates the recovery key away from the real code.
        let hostile = rotate(&fx, &g, 66, RECOVERY_GRACE_MS);
        evaluate(&g, &[], &hostile, NOW).unwrap();
        // The real code (fx.recovery) still recovers inside the window...
        let rec = recovery(&fx, &hostile, roster_hash(&hostile));
        assert_eq!(rec.roster.prev_recovery, None);
        assert_eq!(
            evaluate(&hostile, &[], &rec, NOW + 71 * HOUR),
            Ok(RosterDecision::Accept)
        );
        // ...but not once it has closed.
        assert_eq!(
            evaluate(&hostile, &[], &rec, NOW + RECOVERY_GRACE_MS),
            Err(RosterError::Signature)
        );
        // The new (attacker's) key only after the window.
        let mut r = rec.roster.clone();
        r.recovery_key = recovery_signer(98).public();
        let by_new = sign_recovery(r, &recovery_signer(66));
        assert_eq!(
            evaluate(&hostile, &[], &by_new, NOW + 71 * HOUR),
            Err(RosterError::Signature)
        );
        assert_eq!(
            evaluate(&hostile, &[], &by_new, NOW + RECOVERY_GRACE_MS),
            Ok(RosterDecision::Accept)
        );
    }

    /// Regression (audit F2a #1): a compromised Mac rotates in its own
    /// recovery key with delay 0, then immediately "recovers" with it. The
    /// rotated-in key must not work during the grace window; the real code
    /// (previous key) must, under the previous delay.
    #[test]
    fn rotated_in_key_cannot_recover_during_grace() {
        for real_delay_s in [72 * 3600, 0] {
            let fx = Fixture::new(2);
            let g = fx.genesis_with(|r| r.recovery_delay_s = real_delay_s);
            let hostile = {
                let mut r = rotate(&fx, &g, 66, RECOVERY_GRACE_MS).roster;
                r.recovery_delay_s = 0;
                sign_root(r, fx.macs[0].id, &fx.macs[0].root).unwrap()
            };
            assert_eq!(evaluate(&g, &[], &hostile, NOW), Ok(RosterDecision::Accept));
            let h = roster_hash(&hostile);

            // Attacker's recovery with the rotated-in key: rejected.
            let mut r = recovery(&fx, &hostile, h).roster;
            r.recovery_key = recovery_signer(98).public();
            let attack = sign_recovery(r, &recovery_signer(66));
            for at in [NOW, NOW + HOUR, NOW + RECOVERY_GRACE_MS - 1] {
                assert_eq!(
                    evaluate(&hostile, &[], &attack, at),
                    Err(RosterError::Signature)
                );
                assert_eq!(
                    super::apply_chain(
                        &hostile,
                        &[],
                        std::slice::from_ref(&attack),
                        RecoveryClock::at(at)
                    ),
                    Err(RosterError::ChainLink {
                        index: 0,
                        error: Box::new(RosterError::Signature)
                    })
                );
            }

            // Real code (previous key): accepted, under the previous delay.
            let real = recovery(&fx, &hostile, h);
            let expect = if real_delay_s == 0 {
                RosterDecision::Accept
            } else {
                RosterDecision::Pending {
                    activates_at_ms: NOW + HOUR + u64::from(real_delay_s) * 1000,
                }
            };
            assert_eq!(evaluate(&hostile, &[], &real, NOW + HOUR), Ok(expect));
            assert_eq!(
                effective_recovery_delay_s(&hostile.roster, RecoveryClock::at(NOW + HOUR)),
                real_delay_s
            );
            assert_eq!(
                recovery_key_at(&hostile.roster, RecoveryClock::at(NOW + HOUR)),
                &fx.recovery.public()
            );
            assert_eq!(
                recovery_ssh_keys_at(&hostile.roster, RecoveryClock::at(NOW + HOUR)),
                vec![g.roster.recovery_ssh_key]
            );
        }
    }

    #[test]
    fn grace_valid_until_bounded() {
        let fx = Fixture::new(1);
        let g = &fx.genesis;
        let too_long = rotate(&fx, g, 66, RECOVERY_GRACE_MS + MAX_GRACE_SLACK_MS + 1);
        assert_eq!(
            evaluate(g, &[], &too_long, NOW),
            Err(RosterError::RecoveryGrace)
        );
        let forever = rotate(&fx, g, 66, u64::MAX - NOW);
        assert_eq!(
            evaluate(g, &[], &forever, NOW),
            Err(RosterError::RecoveryGrace)
        );
        for ok in [RECOVERY_GRACE_MS, RECOVERY_GRACE_MS + MAX_GRACE_SLACK_MS] {
            let r = rotate(&fx, g, 66, ok);
            assert_eq!(evaluate(g, &[], &r, NOW), Ok(RosterDecision::Accept));
        }
    }

    #[test]
    fn genesis_bounds() {
        let fx = Fixture::new(1);
        verify_genesis(&fx.genesis, NOW).unwrap();
        let g = fx.genesis_with(|r| r.epoch = 1);
        assert_eq!(verify_genesis(&g, NOW), Err(RosterError::EpochSkip));
        let g = fx.genesis_with(|r| r.version = 2);
        assert_eq!(verify_genesis(&g, NOW), Err(RosterError::BadVersion));
        let g = fx.genesis_with(|r| r.version = 0);
        assert_eq!(verify_genesis(&g, NOW), Err(RosterError::BadVersion));
        let g = fx.genesis_with(|r| {
            r.prev_recovery = Some(fleet_proto::PrevRecovery {
                recovery_key: Ed25519Public([1; 32]),
                recovery_ssh_key: Ed25519Public([2; 32]),
                recovery_escrow_key: fleet_proto::X25519Public([3; 32]),
                recovery_delay_s: 0,
                valid_until_ms: NOW,
            })
        });
        assert_eq!(verify_genesis(&g, NOW), Err(RosterError::Malformed));
        let g = fx.genesis_with(|r| r.issued_at_ms = NOW + MAX_ROSTER_SKEW_MS + 1);
        assert_eq!(verify_genesis(&g, NOW), Err(RosterError::IssuedAt));
        verify_genesis(&g, NOW + 1).unwrap();
        let g = fx.genesis_with(|r| r.prev_hash = [1; 32]);
        assert_eq!(verify_genesis(&g, NOW), Err(RosterError::PrevHash));
        let mut g = fx.genesis.clone();
        g.signature.0[3] ^= 1;
        assert_eq!(verify_genesis(&g, NOW), Err(RosterError::Signature));
    }

    #[test]
    fn pending_recovery_judged_at_submission() {
        let fx = Fixture::new(1);
        let g = &fx.genesis; // 72 h delay
        let hostile = rotate(&fx, g, 66, RECOVERY_GRACE_MS);
        let rec = recovery(&fx, &hostile, roster_hash(&hostile));
        let at = NOW + 70 * HOUR;
        let out = apply_chain(&hostile, &[], std::slice::from_ref(&rec), at).unwrap();
        let pending = out.pending.unwrap();
        assert_eq!(pending.submitted_at_ms, at);
        // Activation lands after the grace window; still valid.
        activate(&hostile, &[], &pending, pending.activates_at_ms).unwrap();
    }

    #[test]
    fn recovery_must_clear_prev_and_use_fresh_keys() {
        let fx = Fixture::new(1);
        let g = fx.genesis_with(|r| r.recovery_delay_s = 0);
        let hostile = rotate(&fx, &g, 66, RECOVERY_GRACE_MS);
        let h = roster_hash(&hostile);

        let mut r = recovery(&fx, &hostile, h).roster;
        r.prev_recovery = hostile.roster.prev_recovery;
        assert_eq!(
            evaluate(&hostile, &[], &sign_recovery(r, &fx.recovery), NOW),
            Err(RosterError::RecoveryPrevNotCleared)
        );
        // Re-installing the rotated-out keys is not fresh.
        let mut r = recovery(&fx, &hostile, h).roster;
        r.recovery_key = g.roster.recovery_key;
        assert_eq!(
            evaluate(&hostile, &[], &sign_recovery(r, &fx.recovery), NOW),
            Err(RosterError::RecoveryKeyReused)
        );
    }

    #[test]
    fn prev_recovery_carried_forward() {
        let fx = Fixture::new(1);
        let g = &fx.genesis;
        let v2 = rotate(&fx, g, 66, RECOVERY_GRACE_MS);
        let until = v2.roster.prev_recovery.unwrap().valid_until_ms;

        let kept = next(&fx, &v2, 0, |_| {});
        assert_eq!(evaluate(&v2, &[], &kept, NOW), Ok(RosterDecision::Accept));

        let dropped = next(&fx, &v2, 0, |r| r.prev_recovery = None);
        assert_eq!(
            evaluate(&v2, &[], &dropped, NOW),
            Err(RosterError::PrevRecoveryChanged)
        );
        assert_eq!(
            evaluate(&v2, &[], &dropped, until),
            Ok(RosterDecision::Accept),
            "may drop once expired"
        );

        let shortened = next(&fx, &v2, 0, |r| {
            r.prev_recovery.as_mut().unwrap().valid_until_ms = NOW
        });
        assert_eq!(
            evaluate(&v2, &[], &shortened, NOW),
            Err(RosterError::PrevRecoveryChanged)
        );

        // No second rotation while the first grace window is active.
        let again = rotate(&fx, &v2, 67, RECOVERY_GRACE_MS);
        assert_eq!(
            evaluate(&v2, &[], &again, NOW),
            Err(RosterError::RotationTooSoon)
        );
        assert_eq!(
            evaluate(&v2, &[], &again, until),
            Ok(RosterDecision::Accept)
        );

        // A roster without prev_recovery may not invent one.
        let invented = next(&fx, g, 0, |r| r.prev_recovery = v2.roster.prev_recovery);
        assert_eq!(
            evaluate(g, &[], &invented, NOW),
            Err(RosterError::PrevRecoveryChanged)
        );
    }

    #[test]
    fn issued_at_monotonic_and_not_future() {
        let fx = Fixture::new(1);
        let g = &fx.genesis;
        let back = next(&fx, g, 0, |r| r.issued_at_ms -= 1);
        assert_eq!(evaluate(g, &[], &back, NOW), Err(RosterError::IssuedAt));
        let future = next(&fx, g, 0, |r| r.issued_at_ms = NOW + MAX_ROSTER_SKEW_MS + 1);
        assert_eq!(evaluate(g, &[], &future, NOW), Err(RosterError::IssuedAt));
        assert_eq!(
            evaluate(g, &[], &future, NOW + 1),
            Ok(RosterDecision::Accept)
        );
    }

    #[test]
    fn pending_must_be_last_in_chain() {
        let fx = Fixture::new(1);
        let g = &fx.genesis;
        let rec = recovery(&fx, g, roster_hash(g));
        let mut after = rec.roster.clone();
        after.version += 1;
        after.prev_hash = roster_hash(&rec);
        let after = sign_root(after, fx.macs[0].id, &fx.macs[0].root).unwrap();
        assert_eq!(
            apply_chain(g, &[], &[rec, after], NOW),
            Err(RosterError::PendingNotLast)
        );
    }

    #[test]
    fn grace_extended_by_agent_clock() {
        let fx = Fixture::new(1);
        let g = fx.genesis_with(|r| r.recovery_delay_s = 0);
        // Rotation signed "at NOW"; this agent only sees it 100 h later, when
        // the signed window has already closed.
        let hostile = rotate(&fx, &g, 66, RECOVERY_GRACE_MS);
        let seen = NOW + 100 * HOUR;
        let accept = RecoveryClock::at(seen);
        assert_eq!(
            super::evaluate(&g, &[], &hostile, accept),
            Ok(RosterDecision::Accept)
        );
        let remaining = next_grace_remaining(&g.roster, &hostile.roster, None);
        assert_eq!(remaining, Some(RECOVERY_GRACE_MS));

        let rec = recovery(&fx, &hostile, roster_hash(&hostile));
        // The agent's countdown, projected onto wall time `now`.
        let local = |now: u64| {
            RecoveryClock::with_grace_remaining(
                now,
                Some((seen + RECOVERY_GRACE_MS).saturating_sub(now)),
            )
        };
        assert_eq!(
            super::evaluate(&hostile, &[], &rec, local(seen + 71 * HOUR)),
            Ok(RosterDecision::Accept)
        );
        assert_eq!(
            super::evaluate(&hostile, &[], &rec, RecoveryClock::at(seen + 71 * HOUR)),
            Err(RosterError::Signature),
            "signed window alone is closed"
        );
        assert_eq!(
            super::evaluate(&hostile, &[], &rec, local(seen + RECOVERY_GRACE_MS)),
            Err(RosterError::Signature)
        );

        // Carrying prev_recovery forward keeps the local time; dropping it
        // is refused while the local window is open; recovery clears it.
        let kept = next(&fx, &hostile, 0, |_| {});
        assert_eq!(
            next_grace_remaining(&hostile.roster, &kept.roster, Some(5)),
            Some(5)
        );
        let dropped = next(&fx, &hostile, 0, |r| r.prev_recovery = None);
        assert_eq!(
            super::evaluate(&hostile, &[], &dropped, local(seen + HOUR)),
            Err(RosterError::PrevRecoveryChanged)
        );
        assert_eq!(
            next_grace_remaining(&hostile.roster, &rec.roster, Some(5)),
            None
        );
        // Chains track it too.
        let out = super::apply_chain(&g, &[], std::slice::from_ref(&hostile), accept).unwrap();
        assert_eq!(out.grace_remaining_ms, Some(RECOVERY_GRACE_MS));
        // A countdown that ran out leaves only the signed window.
        assert_eq!(
            super::evaluate(
                &hostile,
                &[],
                &rec,
                RecoveryClock::with_grace_remaining(seen + HOUR, Some(0))
            ),
            Err(RosterError::Signature)
        );
    }

    /// The local window follows the remaining time the agent counted down,
    /// not the wall clock: a wall clock set back (or forward) neither
    /// stretches nor cuts it.
    #[test]
    fn local_grace_ignores_wall_clock_jumps() {
        let fx = Fixture::new(1);
        let g = fx.genesis_with(|r| r.recovery_delay_s = 0);
        let hostile = rotate(&fx, &g, 66, RECOVERY_GRACE_MS);
        let rec = recovery(&fx, &hostile, roster_hash(&hostile));
        let late = NOW + 200 * HOUR; // signed window closed
        // 1 h of monotonic grace left: open, whatever the wall clock says.
        for wall in [late, late - 100 * HOUR, late + 1000 * HOUR] {
            let c = RecoveryClock::with_grace_remaining(wall, Some(HOUR));
            assert_eq!(
                super::evaluate(&hostile, &[], &rec, c),
                Ok(RosterDecision::Accept),
                "wall {wall}"
            );
            assert_eq!(recovery_key_at(&hostile.roster, c), &fx.recovery.public());
        }
        // Countdown over: closed even with the wall clock set back (still
        // past the signed window).
        let c = RecoveryClock::with_grace_remaining(late - 100 * HOUR, None);
        assert_ne!(recovery_key_at(&hostile.roster, c), &fx.recovery.public());
    }

    #[test]
    fn delay_is_a_recovery_setting() {
        let fx = Fixture::new(1);
        let g = fx.genesis_with(|r| r.recovery_delay_s = 0);
        // Raising the delay alone is a rotation: needs a grace record.
        let raise = next(&fx, &g, 0, |r| r.recovery_delay_s = u32::MAX);
        assert_eq!(
            evaluate(&g, &[], &raise, NOW),
            Err(RosterError::RecoveryGrace)
        );
        // Grace record must carry the old delay.
        let mut wrong = rotate(&fx, &g, 66, RECOVERY_GRACE_MS).roster;
        wrong.prev_recovery.as_mut().unwrap().recovery_delay_s = 5;
        let wrong = sign_root(wrong, fx.macs[0].id, &fx.macs[0].root).unwrap();
        assert_eq!(
            evaluate(&g, &[], &wrong, NOW),
            Err(RosterError::RecoveryGrace)
        );

        // Hostile rotation that also sets a 72 h delay.
        let hostile = {
            let mut r = rotate(&fx, &g, 66, RECOVERY_GRACE_MS).roster;
            r.recovery_delay_s = 72 * 3600;
            sign_root(r, fx.macs[0].id, &fx.macs[0].root).unwrap()
        };
        evaluate(&g, &[], &hostile, NOW).unwrap();
        let rec = recovery(&fx, &hostile, roster_hash(&hostile));
        // Inside the window: the previous delay (0) applies, immediate.
        assert_eq!(
            evaluate(&hostile, &[], &rec, NOW + HOUR),
            Ok(RosterDecision::Accept)
        );
        // After it, the new key's roster waits the full new delay.
        let mut r = rec.roster.clone();
        r.recovery_key = recovery_signer(98).public();
        let by_new = sign_recovery(r, &recovery_signer(66));
        let late = NOW + RECOVERY_GRACE_MS;
        assert_eq!(
            evaluate(&hostile, &[], &by_new, late),
            Ok(RosterDecision::Pending {
                activates_at_ms: late + 72 * HOUR
            })
        );
    }
}
