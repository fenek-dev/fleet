//! Mac side of tier escalation (design §4.2, §7.3).
//!
//! `cron.set`, `compose.deploy`, `users.create` and `users.groups.set`
//! (`Op::may_escalate`) become Elevated on the server from facts the
//! arguments don't carry (a privileged user or group, a deny-listed
//! Compose feature). The Mac sends them without a root approval; if exec
//! answers `ApprovalRequired` (nothing ran), the operator is asked for the
//! root key (the Touch ID reason names the op and the servers) and the
//! command is sent once more with the approval. A second refusal is the
//! answer.
//!
//! In a bulk run several servers escalate at about the same time, so
//! [`EscalationBatcher`] gathers the requests that arrive within a short
//! window into one approval (one Touch ID) whose Merkle tree covers them
//! all.

use crate::bulk::{Approver, BulkExecutor, Failure};
use crate::manager::RequestOpts;
use fleet_crypto::approval::op_digest;
use fleet_proto::{Actor, ApprovalItem, ErrorCode, Op, Payload, RootApproval, ServerId};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;

/// How long the first escalation waits for others to join its approval.
pub const DEFAULT_WINDOW: Duration = Duration::from_millis(300);

/// Touch ID reason for escalated commands: the op and (up to three)
/// server names, e.g. `cron.set on srv_a, srv_b and 3 more`.
pub fn escalation_reason(op: &str, servers: &[ServerId]) -> String {
    let shown: Vec<&str> = servers.iter().take(3).map(|s| s.as_str()).collect();
    let more = servers.len().saturating_sub(shown.len());
    let mut s = format!("{op} on {}", shown.join(", "));
    if more > 0 {
        s.push_str(&format!(" and {more} more"));
    }
    s
}

type Waiter = oneshot::Sender<Result<RootApproval, String>>;

struct DrainOnDrop<'a>(&'a Mutex<Vec<(ApprovalItem, Waiter)>>);

impl Drop for DrainOnDrop<'_> {
    fn drop(&mut self) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

/// One root approval for every escalation that arrives within `window`
/// of the first.
pub struct EscalationBatcher {
    approver: Option<Arc<dyn Approver>>,
    op_label: String,
    window: Duration,
    pending: Mutex<Vec<(ApprovalItem, Waiter)>>,
}

impl EscalationBatcher {
    pub fn new(approver: Option<Arc<dyn Approver>>, op_label: &str, window: Duration) -> Arc<Self> {
        Arc::new(Self {
            approver,
            op_label: op_label.to_string(),
            window,
            pending: Mutex::new(Vec::new()),
        })
    }

    /// A root approval for `op` on `server` (with its `expected_version`,
    /// which the approval item covers). The first caller of a batch waits
    /// out the window, then asks the approver once for everyone.
    pub async fn approve(
        &self,
        server: ServerId,
        op: &Op,
        expected_version: Option<u64>,
    ) -> Result<RootApproval, String> {
        let Some(approver) = self.approver.clone() else {
            return Err("no approver".into());
        };
        let item = ApprovalItem {
            server_id: server,
            op_digest: op_digest(op, expected_version),
        };
        let (tx, rx) = oneshot::channel();
        let leader = {
            let mut p = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            p.push((item, tx));
            p.len() == 1
        };
        if leader {
            // A leader dropped mid-window (cancelled run) must not strand
            // the waiters that joined it: they fail instead.
            let guard = DrainOnDrop(&self.pending);
            if !self.window.is_zero() {
                tokio::time::sleep(self.window).await;
            }
            std::mem::forget(guard);
            let batch =
                std::mem::take(&mut *self.pending.lock().unwrap_or_else(|e| e.into_inner()));
            let items: Vec<ApprovalItem> = batch.iter().map(|(i, _)| i.clone()).collect();
            let servers: Vec<ServerId> = items.iter().map(|i| i.server_id.clone()).collect();
            let what = escalation_reason(&self.op_label, &servers);
            let granted = tokio::task::spawn_blocking(move || approver.approve(&what, &items))
                .await
                .map_err(|_| "approval task failed".to_string())
                .and_then(|r| r.map_err(|e| e.to_string()));
            match granted {
                Ok(list) if list.len() == batch.len() => {
                    for ((_, w), a) in batch.into_iter().zip(list) {
                        let _ = w.send(Ok(a));
                    }
                }
                other => {
                    let why = other.err().unwrap_or_else(|| "approval count".into());
                    for (_, w) in batch {
                        let _ = w.send(Err(why.clone()));
                    }
                }
            }
        }
        rx.await.map_err(|_| "approval abandoned".to_string())?
    }
}

/// Sends `op`; on `ApprovalRequired` for a may-escalate op sent without an
/// approval, gets one from `batcher` and sends once more. A refused
/// approval leaves the original `ApprovalRequired` failure.
pub async fn execute_escalating(
    exec: &dyn BulkExecutor,
    batcher: &EscalationBatcher,
    server: ServerId,
    op: Op,
    actor: Actor,
    opts: RequestOpts,
) -> Result<Payload, Failure> {
    let first = exec
        .execute_with(server.clone(), op.clone(), actor.clone(), opts.clone())
        .await;
    match first {
        Err(Failure::Agent(ErrorCode::ApprovalRequired))
            if opts.approval.is_none() && op.may_escalate() =>
        {
            let approval = batcher
                .approve(server.clone(), &op, opts.expected_version)
                .await
                .map_err(|_| Failure::Agent(ErrorCode::ApprovalRequired))?;
            let retry = RequestOpts {
                approval: Some(approval),
                expected_version: opts.expected_version,
            };
            exec.execute_with(server, op, actor, retry).await
        }
        r => r,
    }
}
