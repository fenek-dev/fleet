//! Agent lifecycle ops bound to exec's state (design §10.2, §10.3):
//! `agent.update.stage|commit|rollback`, `agent.uninstall.prepare`,
//! `agent.uninstall`. The file work lives in [`crate::update`] and
//! [`crate::uninstall`]; this checks against the roster and pending
//! changes in force and runs the heavy copies on the blocking pool.
//!
//! `agent.update.commit` and `agent.uninstall.prepare` are auto-revert ops:
//! exec snapshots (`UpdateRevert`, `SshRestoreRevert`), arms the timers and
//! only then calls [`LifecycleOps::handle`].

use super::state::State;
use crate::paths::Paths;
use crate::pending::ChangeKind;
use crate::store::MetaKey;
use crate::uninstall;
use crate::update;
use crate::userkeys::{self, UserKeysMode};
use fleet_ops::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, Registry, SysCtx};
use fleet_proto::op::tag;
use fleet_proto::{ErrorCode, Op, Payload};
use std::cell::RefCell;
use std::rc::Rc;

const TAGS: [u16; 5] = [
    tag::AGENT_UPDATE_STAGE,
    tag::AGENT_UPDATE_COMMIT,
    tag::AGENT_UPDATE_ROLLBACK,
    tag::AGENT_UNINSTALL_PREPARE,
    tag::AGENT_UNINSTALL,
];

pub(super) struct LifecycleOps {
    st: Rc<RefCell<State>>,
    user_keys: UserKeysMode,
}

/// Registers the lifecycle ops and makes sure the SFTP drop directory
/// exists (installs from before it was introduced).
pub(super) fn register(st: &Rc<RefCell<State>>, registry: &mut Registry, user_keys: UserKeysMode) {
    {
        let s = st.borrow();
        let admin = s
            .store
            .meta()
            .get(MetaKey::AdminUser)
            .ok()
            .flatten()
            .and_then(|b| String::from_utf8(b).ok());
        let root = crate::fsutil::current_uid().is_ok_and(|u| u == 0);
        if let Err(e) = update::ensure_incoming(&s.paths, admin.as_deref(), root) {
            super::log("create incoming dir", e);
        }
    }
    let h: Rc<dyn OpHandler> = Rc::new(LifecycleOps {
        st: st.clone(),
        user_keys,
    });
    for t in TAGS {
        registry.register(t, h.clone());
    }
}

fn blocking_err(_: tokio::task::JoinError) -> OpError {
    OpError::internal("lifecycle task failed")
}

impl LifecycleOps {
    fn paths(&self) -> Paths {
        self.st.borrow().paths.clone()
    }

    fn roster(&self) -> fleet_proto::Roster {
        self.st.borrow().roster.roster.clone()
    }

    /// A change of `kind` is pending or applying (its file exists).
    fn pending(&self, kind: ChangeKind) -> Result<bool, OpError> {
        let st = self.st.borrow();
        let list = st
            .pending_dir
            .list()
            .map_err(|e| OpError::internal(format!("pending changes: {e}")))?;
        Ok(list.iter().any(|(_, c)| c.kind == kind))
    }

    async fn restart_later(&self, ctx: &SysCtx, meta: &OpMeta) -> Result<(), OpError> {
        let unit = format!("fleet-agent-restart-{}", meta.audit_seq.unwrap_or(0));
        let out = ctx
            .runner
            .run(update::restart_later(&unit))
            .await
            .map_err(|e| OpError::internal(format!("schedule restart: {e}")))?;
        if !out.success() {
            return Err(OpError::internal("schedule agent restart failed"));
        }
        Ok(())
    }
}

impl OpHandler for LifecycleOps {
    fn validate(&self, _ctx: &SysCtx, op: &Op, _meta: &OpMeta) -> Result<(), OpError> {
        match op {
            Op::AgentUpdateStage {
                manifest,
                staged_path_hash,
            } => {
                update::check_stage(manifest, *staged_path_hash, &self.roster(), update::host())?;
                update::incoming_file(&self.paths(), *staged_path_hash)?;
                Ok(())
            }
            Op::AgentUpdateCommit { version } => {
                update::check_commit(&self.paths(), *version, &self.roster(), update::host())?;
                Ok(())
            }
            Op::AgentUpdateRollback => {
                if self.pending(ChangeKind::AgentUpdate)? {
                    // Its timer (or not confirming) rolls it back.
                    return Err(ErrorCode::Busy.into());
                }
                update::check_rollback(&self.paths())?;
                Ok(())
            }
            Op::AgentUninstallPrepare => Ok(()),
            Op::AgentUninstall { .. } => {
                if self.pending(ChangeKind::Ssh)? {
                    return Err(ErrorCode::Busy.into());
                }
                if uninstall::fleet_keys_active(&self.paths()) {
                    return Err(OpError::new(ErrorCode::PolicyDenied)
                        .with_detail("run and confirm agent.uninstall.prepare first"));
                }
                Ok(())
            }
            _ => Err(ErrorCode::Unsupported.into()),
        }
    }

    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        op: &'a Op,
        meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            let paths = self.paths();
            match op {
                Op::AgentUpdateStage {
                    manifest,
                    staged_path_hash,
                } => {
                    let (m, h, roster) =
                        (manifest.as_ref().clone(), *staged_path_hash, self.roster());
                    tokio::task::spawn_blocking(move || {
                        update::stage(&paths, &m, h, &roster, update::host())
                    })
                    .await
                    .map_err(blocking_err)??;
                }
                Op::AgentUpdateCommit { version } => {
                    let (v, roster) = (*version, self.roster());
                    tokio::task::spawn_blocking(move || {
                        update::commit(&paths, v, &roster, update::host())
                    })
                    .await
                    .map_err(blocking_err)??;
                    // Exec restores (and restarts nothing) if this fails.
                    self.restart_later(ctx, meta).await?;
                }
                Op::AgentUpdateRollback => {
                    tokio::task::spawn_blocking(move || update::rollback(&paths))
                        .await
                        .map_err(blocking_err)??;
                    self.restart_later(ctx, meta).await?;
                }
                Op::AgentUninstallPrepare => {
                    let users = userkeys::user_keys(self.user_keys, ctx.runner.as_ref());
                    uninstall::apply_ssh(&paths, ctx.runner.as_ref(), users.as_ref())?;
                }
                Op::AgentUninstall {
                    keep_audit,
                    remove_firewall,
                } => {
                    let out = ctx
                        .runner
                        .run(uninstall::schedule_spec(*keep_audit, *remove_firewall))
                        .await
                        .map_err(|e| OpError::internal(format!("schedule uninstall: {e}")))?;
                    if !out.success() {
                        return Err(OpError::internal("schedule uninstall failed"));
                    }
                }
                _ => return Err(ErrorCode::Unsupported.into()),
            }
            Ok(OpOutput::Payload(Payload::Empty))
        })
    }
}
