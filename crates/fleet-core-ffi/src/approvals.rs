//! Single-server requests with envelope options (design §2.6, §4.2): a
//! known `expected_version`, root approval for Elevated ops, and the
//! escalation retry for may-escalate ops (`fleet_core::escalate`). Server
//! tabs that send `cron.set`, `users.create`, `users.groups.set`,
//! `compose.deploy` or version-checked ops go through
//! [`FleetCore::request_opts`].

use crate::api::FleetCore;
use crate::types::FleetError;
use crate::validate;
use fleet_core::bulk::{BulkExecutor, Failure};
use fleet_core::escalate::{self, EscalationBatcher};
use fleet_core::manager::RequestOpts;
use fleet_core::opspec;
use fleet_crypto::approval::op_digest;
use fleet_proto::{Actor, ApprovalItem, Op, Payload};
use std::sync::Arc;
use std::time::Duration;

pub(crate) fn failure_err(f: Failure) -> FleetError {
    match f {
        Failure::Agent(code) => FleetError::Agent {
            code: format!("{code:?}"),
        },
        Failure::UnknownServer => FleetError::UnknownServer,
        Failure::Locked => FleetError::Locked,
        Failure::Timeout => FleetError::Timeout,
        other => FleetError::Session {
            message: format!("{other:?}"),
        },
    }
}

pub(crate) fn approve_err(e: fleet_core::bulk::ApproveError) -> FleetError {
    match e {
        fleet_core::bulk::ApproveError::Cancelled => FleetError::Cancelled,
        other => FleetError::Session {
            message: other.to_string(),
        },
    }
}

impl FleetCore {
    /// Sends `op` as the operator with `expected_version`: Elevated ops get
    /// one root approval first (Touch ID naming the op and server);
    /// may-escalate ops answered `ApprovalRequired` get one and are sent
    /// once more.
    pub(crate) async fn request_opts(
        self: &Arc<Self>,
        server_id: &str,
        op: Op,
        expected_version: Option<u64>,
    ) -> Result<Payload, FleetError> {
        let id = validate::server_id(server_id)?;
        let (handle, _) = self.running()?;
        let approver = self.root_approver()?;
        let mut opts = RequestOpts {
            approval: None,
            expected_version,
        };
        if opspec::needs_approval(&op) {
            let item = ApprovalItem {
                server_id: id.clone(),
                op_digest: op_digest(&op, expected_version),
            };
            let what = escalate::escalation_reason(op.name(), std::slice::from_ref(&id));
            let a = approver.clone();
            let mut list = crate::fleet_mgmt::blocking("fleet-approve", move || {
                a.approve(&what, &[item]).map_err(approve_err)
            })
            .await?;
            opts.approval = list.pop();
        }
        self.on_core(async move {
            let batcher = EscalationBatcher::new(Some(approver), op.name(), Duration::ZERO);
            let exec: &dyn BulkExecutor = &handle;
            escalate::execute_escalating(exec, &batcher, id, op, Actor::Human, opts)
                .await
                .map_err(failure_err)
        })
        .await
    }
}
