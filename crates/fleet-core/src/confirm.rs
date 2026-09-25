//! Confirming an auto-revert change from a fresh connection (design §4.10,
//! §9.1).
//!
//! `firewall.apply`, `authorized_keys.set`, `mesh.*` and `profile.apply`
//! phases with an SSH or firewall module answer `ChangePending`: the change
//! stays only if `change.confirm` arrives over a **later** connection than
//! the one that applied it (exec refuses a confirm from the same session,
//! `PolicyDenied`). The point is to prove that a new SSH login still works
//! under the changed sshd/firewall, so [`confirm_on_new_connection`] drops
//! the server's connection (a manager reconnect never reuses the SSH
//! transport), waits for the new one to be Ready and sends the confirm on
//! it. If the new login fails the change is simply left to revert.

use crate::manager::{ConnState, ManagerEvent, ManagerHandle, RequestOpts};
use fleet_proto::{Actor, ChangeId, ErrorCode, Op, ServerId};
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfirmError {
    /// The new connection didn't come up: the change will revert.
    #[error("a new connection could not be made: {0}")]
    Reconnect(String),
    #[error("timed out waiting for a new connection")]
    Timeout,
    #[error("the agent refused the confirmation: {0:?}")]
    Agent(ErrorCode),
    #[error("request failed: {0}")]
    Request(String),
}

/// Drops `id`'s connection and waits until a new one is Ready. Fails early
/// when the reconnect hits a fatal failure (host key, SSH key refused).
pub async fn reconnect_fresh(
    h: &ManagerHandle,
    id: &ServerId,
    timeout: Duration,
) -> Result<(), ConfirmError> {
    let mut events = h.subscribe();
    h.reconnect(id);
    let deadline = tokio::time::Instant::now() + timeout;
    let mut left_ready = false;
    loop {
        let ev = tokio::time::timeout_at(deadline, events.recv())
            .await
            .map_err(|_| ConfirmError::Timeout)?;
        match ev {
            Ok(ManagerEvent::State {
                server,
                state,
                failure,
                ..
            }) if &server == id => {
                if state == ConnState::Ready {
                    if left_ready {
                        return Ok(());
                    }
                } else {
                    left_ready = true;
                    if let Some(f) = failure
                        && f.fatal
                    {
                        return Err(ConfirmError::Reconnect(f.message));
                    }
                }
            }
            Ok(_) => {}
            // Missed events: fall back to the state itself (a Ready seen
            // after a lag may be the old link only if nothing happened,
            // which the reconnect rules out).
            Err(RecvError::Lagged(_)) => {
                left_ready = true;
                if h.state(id) == Some(ConnState::Ready) {
                    return Ok(());
                }
            }
            Err(RecvError::Closed) => {
                return Err(ConfirmError::Reconnect("manager stopped".into()));
            }
        }
    }
}

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

/// Reconnects `id` and confirms `change` on the new session. One more
/// reconnect if exec says the confirm came over the applying session.
pub async fn confirm_on_new_connection(
    h: &ManagerHandle,
    id: &ServerId,
    change: ChangeId,
    actor: Actor,
    timeout: Duration,
) -> Result<(), ConfirmError> {
    for attempt in 0..2 {
        reconnect_fresh(h, id, timeout).await?;
        let reply = h
            .request_with(
                id,
                Op::ChangeConfirm { change_id: change },
                actor.clone(),
                RequestOpts::default(),
            )
            .await
            .map_err(|e| ConfirmError::Request(e.to_string()))?;
        match reply.result {
            Ok(_) => return Ok(()),
            Err(ErrorCode::PolicyDenied) if attempt == 0 => continue,
            Err(code) => return Err(ConfirmError::Agent(code)),
        }
    }
    Err(ConfirmError::Agent(ErrorCode::PolicyDenied))
}
