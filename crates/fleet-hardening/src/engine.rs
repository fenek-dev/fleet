//! Runs a profile's modules: check and score, plan and plan hash, apply
//! in phase order (design §9.1: access, then sshd + firewall, then the
//! rest; the Mac drives the phases with `ProfileSpec::only`).

use crate::facts;
use crate::module::{Change, Ctx, Module, Status};
use crate::modules;
use crate::profile::{self, Resolved};
use fleet_ops::SysCtx;
use fleet_ops::handler::OpError;
use fleet_proto::ErrorCode;
use fleet_proto::alert::Severity;
use fleet_proto::op::ProfileSpec;
use fleet_proto::payload::{ModuleOutcome, ModuleResult};

/// Domain separation of the plan hash.
pub const PLAN_HASH_CONTEXT: &str = "fleet profile plan v1";

/// The profile's modules in apply order: by phase, then profile order.
pub fn modules_of(p: &Resolved) -> Vec<Box<dyn Module>> {
    let mut v: Vec<Box<dyn Module>> = p
        .modules
        .iter()
        .filter_map(|id| modules::by_id(id))
        .collect();
    v.sort_by_key(|m| m.phase());
    v
}

/// Units the facts must cover for this profile.
pub fn units_of(p: &Resolved) -> Vec<String> {
    let mut v: Vec<String> = modules::UNITS.iter().map(|u| (*u).to_owned()).collect();
    for u in &p.settings.disable {
        if !v.contains(u) {
            v.push(u.clone());
        }
    }
    v
}

pub async fn load_resolved(profile: Resolved, sys: &SysCtx, op_id: u64) -> Ctx {
    let facts = facts::gather(sys, &units_of(&profile)).await;
    Ctx {
        sys: sys.clone(),
        profile,
        facts,
        op_id,
        apt_updated: false,
    }
}

pub async fn load(spec: &ProfileSpec, sys: &SysCtx, op_id: u64) -> Result<Ctx, OpError> {
    let p = profile::resolve(spec, sys)?;
    Ok(load_resolved(p, sys, op_id).await)
}

/// One module's audit line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub id: &'static str,
    pub title: &'static str,
    pub weight: u8,
    pub severity: Severity,
    /// `Err`: the check itself failed (detail for the local log).
    pub status: Result<Status, String>,
    /// Turned off by the profile: the reason (exception text or "skipped").
    pub skipped: Option<String>,
    pub fixable: bool,
}

/// `check` of every module in scope.
pub fn check(ctx: &Ctx) -> Vec<Report> {
    modules_of(&ctx.profile)
        .iter()
        .filter(|m| ctx.profile.in_scope(m.id()))
        .map(|m| {
            let id = m.id();
            let skipped = ctx.profile.is_skipped(id).then(|| {
                ctx.profile
                    .exceptions
                    .get(id)
                    .cloned()
                    .unwrap_or_else(|| "skipped by the profile".to_owned())
            });
            let status = if skipped.is_some() {
                Ok(Status::Compliant)
            } else {
                m.check(ctx)
                    .map_err(|e| e.detail().unwrap_or("check failed").to_owned())
            };
            Report {
                id,
                title: m.title(),
                weight: m.weight(),
                severity: m.severity(),
                fixable: matches!(status, Ok(Status::Drifted(_))) && m.fixable(ctx),
                status,
                skipped,
            }
        })
        .collect()
}

/// 0..=100: weighted share of compliant modules. Skipped and
/// not-applicable modules don't count; a pending reboot counts as done.
pub fn score(reports: &[Report]) -> u8 {
    let (mut got, mut total) = (0u32, 0u32);
    for r in reports.iter().filter(|r| r.skipped.is_none()) {
        match &r.status {
            Ok(Status::NotApplicable(_)) => continue,
            Ok(Status::Compliant | Status::PendingReboot(_)) => got += u32::from(r.weight),
            _ => {}
        }
        total += u32::from(r.weight);
    }
    (got * 100)
        .checked_div(total)
        .map_or(100, |s| u8::try_from(s).unwrap_or(100))
}

/// Every change of the in-scope, not-skipped modules, in apply order.
pub fn plan(ctx: &Ctx) -> Result<Vec<Change>, OpError> {
    let mut out = Vec::new();
    for m in modules_of(&ctx.profile) {
        if ctx.profile.in_scope(m.id()) && !ctx.profile.is_skipped(m.id()) {
            out.extend(m.plan(ctx)?);
        }
    }
    Ok(out)
}

/// BLAKE3 (derive-key [`PLAN_HASH_CONTEXT`]) of the postcard-encoded plan:
/// every action with its exact content and argv, so any change in what
/// would run changes the hash.
pub fn plan_hash(plan: &[Change]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(PLAN_HASH_CONTEXT);
    h.update(&fleet_proto::encode(plan));
    *h.finalize().as_bytes()
}

/// Re-plans, refuses unless the plan still hashes to `expected`
/// (`VersionConflict`), then applies module by module. An error stops
/// the apply; exec's auto-revert restores the snapshot.
pub async fn apply(ctx: &mut Ctx, expected: &[u8; 32]) -> Result<Vec<ModuleResult>, OpError> {
    let plan = plan(ctx)?;
    let got = plan_hash(&plan);
    if &got != expected {
        let mut b = [0u8; 8];
        b.copy_from_slice(&got[..8]);
        return Err(ErrorCode::VersionConflict {
            current: u64::from_le_bytes(b),
        }
        .into());
    }
    let mut results = Vec::new();
    for m in modules_of(&ctx.profile) {
        let id = m.id();
        if !ctx.profile.in_scope(id) {
            continue;
        }
        let outcome = if ctx.profile.is_skipped(id) {
            (ModuleOutcome::Skipped, String::new())
        } else if !plan.iter().any(|c| c.module == id) {
            (ModuleOutcome::Unchanged, String::new())
        } else {
            let applied = m.apply(ctx, &plan).await?;
            (ModuleOutcome::Applied, applied.notes.join("; "))
        };
        results.push(ModuleResult {
            id: id.to_owned(),
            outcome: outcome.0,
            detail: outcome.1,
        });
    }
    Ok(results)
}
