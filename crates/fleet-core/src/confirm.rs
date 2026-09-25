//! A bulk executor that confirms auto-revert changes (design §4.10, §9.1).
//!
//! `firewall.apply`, `authorized_keys.set`, `mesh.*` and `profile.apply`
//! phases with an SSH or firewall module answer `ChangePending`: the change
//! stays only if `change.confirm` arrives over a **later** connection than
//! the one that applied it. The protocol itself (reconnect, retry on
//! `Busy`, one more reconnect on `PolicyDenied`, `NotFound` = reverted,
//! time budget from the change's deadline) lives in [`crate::autorevert`];
//! callers outside bulk use [`crate::autorevert::confirm_pending`] directly.

use crate::manager::{ManagerHandle, RequestOpts};
use fleet_proto::{Actor, Op, ServerId};

/// A bulk executor that confirms every `ChangePending` answer over a
/// fresh connection before reporting success (the bulk sheet, runbooks).
/// A failed confirmation fails that server: the change reverts.
pub struct ConfirmingExecutor {
    pub handle: ManagerHandle,
}

impl crate::bulk::BulkExecutor for ConfirmingExecutor {
    fn execute(
        &self,
        server: ServerId,
        op: Op,
        actor: Actor,
        approval: Option<fleet_proto::RootApproval>,
    ) -> crate::bulk::BoxFut<Result<fleet_proto::Payload, crate::bulk::Failure>> {
        self.execute_with(
            server,
            op,
            actor,
            RequestOpts {
                approval,
                expected_version: None,
            },
        )
    }

    fn execute_with(
        &self,
        server: ServerId,
        op: Op,
        actor: Actor,
        opts: RequestOpts,
    ) -> crate::bulk::BoxFut<Result<fleet_proto::Payload, crate::bulk::Failure>> {
        let h = self.handle.clone();
        Box::pin(async move {
            let reply = h.request_with(&server, op, actor.clone(), opts).await?;
            let p = reply.result.map_err(crate::bulk::Failure::Agent)?;
            if let fleet_proto::Payload::ChangePending { change, .. } = &p {
                crate::autorevert::confirm_pending(&h, &server, change, actor)
                    .await
                    .map_err(|e| {
                        crate::bulk::Failure::Transport(format!(
                            "applied, not confirmed ({e}); reverts"
                        ))
                    })?;
            }
            Ok(p)
        })
    }
}
