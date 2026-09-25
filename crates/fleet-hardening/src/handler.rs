//! `profile.check`, `profile.plan`, `profile.apply` and `audit.run`
//! (design §4.2, §9). `profile.apply` runs under exec's auto-revert
//! protocol (`ChangeKind::Profile`, [`crate::revert::ProfileRevert`]);
//! the handler only applies and answers `ChangePending`.

use crate::engine::{self, Report};
use crate::module::Status;
use crate::profile;
use fleet_ops::SysCtx;
use fleet_ops::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, Registry};
use fleet_proto::alert::Severity;
use fleet_proto::op::tag;
use fleet_proto::payload::{
    AuditFinding, AuditReport, ChangeKind, ModuleCheck, ModuleStatus, PendingChange, PlannedChange,
    ProfileCheck, ProfilePlan,
};
use fleet_proto::{ErrorCode, Op, Payload};
use std::rc::Rc;

const MAX_DETAIL: usize = 1024;

fn clip(s: &str) -> String {
    let mut out: String = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect();
    if out.len() > MAX_DETAIL {
        let mut end = MAX_DETAIL;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
    }
    out
}

/// Wire status and detail. `PendingReboot` has no wire variant yet: it is
/// reported as compliant with a "pending reboot" detail (the change is
/// made; it takes effect at boot).
pub fn wire_status(r: &Report) -> (ModuleStatus, String) {
    if let Some(reason) = &r.skipped {
        return (ModuleStatus::Skipped, clip(reason));
    }
    match &r.status {
        Ok(Status::Compliant) => (ModuleStatus::Compliant, String::new()),
        Ok(Status::Drifted(d)) => (ModuleStatus::Drifted, clip(d)),
        Ok(Status::NotApplicable(d)) => (ModuleStatus::NotApplicable, clip(d)),
        Ok(Status::PendingReboot(d)) => (
            ModuleStatus::Compliant,
            clip(&format!("pending reboot: {d}")),
        ),
        Err(d) => (ModuleStatus::Error, clip(d)),
    }
}

/// Item-level exceptions (not whole modules), shown as accepted.
fn item_exceptions(p: &profile::Resolved) -> impl Iterator<Item = (&String, &String)> {
    p.exceptions
        .iter()
        .filter(|(id, _)| !p.modules.iter().any(|m| m == *id))
}

pub fn profile_check(ctx: &crate::Ctx) -> ProfileCheck {
    let reports = engine::check(ctx);
    let mut modules: Vec<ModuleCheck> = reports
        .iter()
        .map(|r| {
            let (status, detail) = wire_status(r);
            ModuleCheck {
                id: r.id.to_owned(),
                status,
                detail,
            }
        })
        .collect();
    modules.extend(item_exceptions(&ctx.profile).map(|(id, why)| ModuleCheck {
        id: id.clone(),
        status: ModuleStatus::Skipped,
        detail: clip(why),
    }));
    ProfileCheck {
        score: engine::score(&reports),
        modules,
    }
}

pub fn audit_report(ctx: &crate::Ctx) -> AuditReport {
    let reports = engine::check(ctx);
    let mut findings = Vec::new();
    for r in &reports {
        let (status, detail) = wire_status(r);
        if status == ModuleStatus::Compliant && detail.is_empty() {
            continue;
        }
        let title = if detail.is_empty() {
            r.title.to_owned()
        } else {
            clip(&format!("{}: {detail}", r.title))
        };
        findings.push(AuditFinding {
            module: r.id.to_owned(),
            status,
            severity: if r.skipped.is_some() || status == ModuleStatus::Compliant {
                Severity::Info
            } else {
                r.severity
            },
            title,
            fixable: r.fixable,
        });
    }
    findings.extend(item_exceptions(&ctx.profile).map(|(id, why)| AuditFinding {
        module: id.clone(),
        status: ModuleStatus::Skipped,
        severity: Severity::Info,
        title: clip(&format!("accepted exception: {why}")),
        fixable: false,
    }));
    AuditReport {
        score: engine::score(&reports),
        findings,
    }
}

pub fn profile_plan(ctx: &crate::Ctx) -> Result<ProfilePlan, OpError> {
    let plan = engine::plan(ctx)?;
    let remote: Vec<&str> = engine::modules_of(&ctx.profile)
        .iter()
        .filter(|m| m.phase() == crate::Phase::Remote)
        .map(|m| m.id())
        .collect();
    Ok(ProfilePlan {
        plan_hash: engine::plan_hash(&plan),
        changes: plan
            .iter()
            .map(|c| PlannedChange {
                module: c.module.to_owned(),
                description: clip(&c.description),
                diff: c.diff.clone(),
                auto_revert: remote.contains(&c.module),
            })
            .collect(),
    })
}

/// All four ops.
#[derive(Default)]
pub struct ProfileHandler;

impl ProfileHandler {
    async fn run(&self, ctx: &SysCtx, op: &Op, meta: &OpMeta) -> Result<Payload, OpError> {
        let op_id = meta.op_id().unwrap_or(0);
        Ok(match op {
            Op::ProfileCheck(spec) => {
                Payload::ProfileCheck(profile_check(&engine::load(spec, ctx, op_id).await?))
            }
            Op::ProfilePlan(spec) => {
                Payload::ProfilePlan(profile_plan(&engine::load(spec, ctx, op_id).await?)?)
            }
            Op::ProfileApply { spec, plan_hash } => {
                let mut c = engine::load(spec, ctx, op_id).await?;
                engine::apply(&mut c, plan_hash).await?;
                // Exec fills in id, deadline and origin. No version: a
                // profile revert always restores (the lockout-safe side).
                Payload::ChangePending(PendingChange {
                    change_id: [0; 16],
                    kind: ChangeKind::Profile,
                    op_tag: tag::PROFILE_APPLY,
                    created_ms: 0,
                    deadline_ms: 0,
                    new_version: None,
                })
            }
            Op::AuditRun { level } => {
                let mut p = profile::builtin(*level, &[])?;
                p.admin = profile::detect_admin(ctx).map(|name| profile::Admin {
                    name,
                    password_hash: None,
                });
                Payload::AuditReport(audit_report(&engine::load_resolved(p, ctx, op_id).await))
            }
            _ => return Err(ErrorCode::Unsupported.into()),
        })
    }
}

impl OpHandler for ProfileHandler {
    fn validate(&self, ctx: &SysCtx, op: &Op, _meta: &OpMeta) -> Result<(), OpError> {
        match op {
            Op::ProfileCheck(spec) | Op::ProfilePlan(spec) | Op::ProfileApply { spec, .. } => {
                profile::resolve(spec, ctx).map(drop)
            }
            Op::AuditRun { .. } => Ok(()),
            _ => Err(ErrorCode::Unsupported.into()),
        }
    }

    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        op: &'a Op,
        meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move { self.run(ctx, op, meta).await.map(OpOutput::Payload) })
    }
}

pub fn register(r: &mut Registry) {
    let h = Rc::new(ProfileHandler);
    for t in [
        tag::PROFILE_CHECK,
        tag::PROFILE_PLAN,
        tag::PROFILE_APPLY,
        tag::AUDIT_RUN,
    ] {
        r.register(t, h.clone());
    }
}
