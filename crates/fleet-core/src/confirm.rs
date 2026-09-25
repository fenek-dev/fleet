//! Confirming an auto-revert change from a fresh connection (design §4.10,
//! §9.1): entry points for bulk actions, provisioning and MCP.
//!
//! `firewall.apply`, `authorized_keys.set`, `mesh.*` and `profile.apply`
//! phases with an SSH or firewall module answer `ChangePending`: the change
//! stays only if `change.confirm` arrives over a **later** connection than
//! the one that applied it. The protocol itself (reconnect, retry on
//! `Busy`, one more reconnect on `PolicyDenied`, `NotFound` = reverted)
//! lives in [`crate::autorevert`]; this module only wraps it.

pub use crate::autorevert::{ConfirmError, ReconnectError, reconnect_fresh};
use crate::manager::{ManagerHandle, RequestOpts};
use fleet_proto::{Actor, ChangeId, Op, ServerId};
use std::time::Duration;

/// A bulk executor that confirms every `ChangePending` answer over a
/// fresh connection before reporting success (the bulk sheet, runbooks).
/// A failed confirmation fails that server: the change reverts.
pub struct ConfirmingExecutor {
    pub handle: ManagerHandle,
    pub timeout: Duration,
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
        let timeout = self.timeout;
        Box::pin(async move {
            let reply = h.request_with(&server, op, actor.clone(), opts).await?;
            let p = reply.result.map_err(crate::bulk::Failure::Agent)?;
            if let fleet_proto::Payload::ChangePending { change, .. } = &p {
                confirm_on_new_connection(&h, &server, change.change_id, actor, timeout)
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

/// Reconnects `id` and confirms `change` on the new session within
/// `timeout` ([`crate::autorevert::confirm_fresh`]).
pub async fn confirm_on_new_connection(
    h: &ManagerHandle,
    id: &ServerId,
    change: ChangeId,
    actor: Actor,
    timeout: Duration,
) -> Result<(), ConfirmError> {
    crate::autorevert::confirm_fresh(h, id, change, actor, timeout).await
}
