//! Operations bound to exec's own state (roster, policy, veto,
//! `agent.health`, `roster.pending`), behind the `fleet_ops::OpHandler`
//! trait so exec dispatches every op the same way.
//!
//! `validate` and `handle` both build the [`Plan`]: `handle` runs right
//! after the audit intent without yielding, so it sees the state
//! `validate` checked.

use super::{PendingState, State, StoredPolicy, log};
use fleet_crypto::roster::{self, RosterDecision, roster_hash};
use fleet_ops::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, SysCtx};
use fleet_proto::op::tag;
use fleet_proto::{
    AgentHealth, ErrorCode, Event, Hash32, Op, PROTO_VERSION, Payload, Policy, SignedRoster,
};
use std::cell::RefCell;
use std::rc::Rc;

/// Tags handled by [`StateOps`].
pub(super) const TAGS: [u16; 5] = [
    tag::AGENT_HEALTH,
    tag::ROSTER_UPDATE,
    tag::ROSTER_PENDING,
    tag::ROSTER_VETO,
    tag::POLICY_UPDATE,
];

/// Validated plan for one command; built before the audit intent.
pub(super) enum Plan {
    Health,
    Pending,
    Roster(Box<SignedRoster>, RosterDecision),
    Veto(Hash32),
    Policy(Box<Policy>, StoredPolicy),
}

pub(super) struct StateOps(pub(super) Rc<RefCell<State>>);

impl OpHandler for StateOps {
    fn validate(&self, _ctx: &SysCtx, op: &Op, meta: &OpMeta) -> Result<(), OpError> {
        self.0
            .borrow()
            .prepare(op, meta)
            .map(drop)
            .map_err(OpError::from)
    }

    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        op: &'a Op,
        meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            let mut st = self.0.borrow_mut();
            let plan = st.prepare(op, meta)?;
            st.execute(plan, ctx, meta.now_ms)
                .map(OpOutput::Payload)
                .map_err(OpError::from)
        })
    }
}

impl State {
    /// Argument validation; nothing is changed here.
    pub(super) fn prepare(&self, op: &Op, meta: &OpMeta) -> Result<Plan, ErrorCode> {
        let now = meta.now_ms;
        match op {
            Op::AgentHealth => Ok(Plan::Health),
            Op::RosterPending => Ok(Plan::Pending),
            Op::RosterUpdate { roster: cand } => {
                let d = roster::evaluate(&self.roster, &self.epoch_hashes, cand, self.clock(now))
                    .map_err(|e| e.code())?;
                // One pending recovery at a time (design §5.3): a second
                // submission is refused until the first is vetoed or has
                // activated; it can't displace or restart the countdown.
                if matches!(d, RosterDecision::Pending { .. }) && self.pending.is_some() {
                    return Err(ErrorCode::Busy);
                }
                Ok(Plan::Roster(cand.clone(), d))
            }
            Op::RosterVeto { pending_hash } => {
                let p = self.pending.as_ref().ok_or(ErrorCode::NotFound)?;
                roster::check_veto(&meta.command, &p.roster_at(now), now)
                    .map_err(|_| ErrorCode::InvalidArgument)?;
                Ok(Plan::Veto(*pending_hash))
            }
            Op::PolicyUpdate { policy_toml } => {
                let current = self.policy.version;
                if meta
                    .command
                    .body
                    .expected_version
                    .is_some_and(|e| e != current)
                {
                    return Err(ErrorCode::VersionConflict { current });
                }
                let p = Policy::from_toml(policy_toml).map_err(|_| ErrorCode::InvalidArgument)?;
                if p.fleet_id != self.roster.roster.fleet_id || p.server_id != self.server_id {
                    return Err(ErrorCode::InvalidArgument);
                }
                if p.version <= current {
                    return Err(ErrorCode::VersionConflict { current });
                }
                let stored = StoredPolicy {
                    toml: policy_toml.clone(),
                    approval: meta.approval.clone(),
                };
                Ok(Plan::Policy(Box::new(p), stored))
            }
            _ => Err(ErrorCode::Unsupported),
        }
    }

    pub(super) fn execute(
        &mut self,
        plan: Plan,
        ctx: &SysCtx,
        now: u64,
    ) -> Result<Payload, ErrorCode> {
        let internal = |e: super::StoreError| {
            log("state op", e);
            ErrorCode::Internal
        };
        match plan {
            Plan::Health => Ok(Payload::AgentHealth(self.health(ctx, now))),
            Plan::Pending => Ok(Payload::RosterPending(self.pending_wire(now))),
            Plan::Roster(new, RosterDecision::Accept) => {
                self.install_roster(*new, now).map_err(internal)?;
                Ok(Payload::Empty)
            }
            Plan::Roster(new, RosterDecision::Pending { activates_at_ms }) => {
                let remaining_ms = activates_at_ms.saturating_sub(now);
                let p = PendingState {
                    hash: roster_hash(&new),
                    roster: *new,
                    submitted_at_ms: now,
                    remaining_ms,
                    persisted_ms: remaining_ms,
                    grace_until_ms: self.clock(now).local_grace_until_ms,
                };
                let wire = p.wire(now);
                self.set_pending(Some(p)).map_err(internal)?;
                self.emit(Event::RecoveryPending(wire));
                Ok(Payload::RosterPending(Some(wire)))
            }
            Plan::Veto(hash) => {
                self.set_pending(None).map_err(internal)?;
                self.emit(Event::RecoveryVetoed { hash });
                Ok(Payload::Empty)
            }
            Plan::Policy(p, stored) => {
                self.store
                    .meta()
                    .set(super::MetaKey::Policy, &fleet_proto::encode(&stored))
                    .map_err(internal)?;
                let version = p.version;
                self.policy = *p;
                self.push_view();
                self.emit(Event::PolicyChanged { version });
                Ok(Payload::Empty)
            }
        }
    }

    fn health(&self, ctx: &SysCtx, now: u64) -> AgentHealth {
        AgentHealth {
            agent_version: crate::agent_version(),
            proto_version: PROTO_VERSION,
            uptime_s: self.started.elapsed().as_secs(),
            // The gate's RSS isn't visible from here yet.
            gate_rss_bytes: 0,
            exec_rss_bytes: ctx.procfs.self_rss_bytes().unwrap_or(0),
            audit_seq: self.store.audit().head().map_or(0, |h| h.seq),
            roster_epoch: self.roster.roster.epoch,
            roster_version: self.roster.roster.version,
            policy_version: self.policy.version,
            pending_recovery: self.pending_wire(now),
            run_id: self.run_id,
        }
    }
}
