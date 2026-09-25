//! [`OpRunner`]: "send this op to that server" as the fleet-level flows
//! (roster pushes, event catch-up, vetoes) need it. [`ManagerHandle`]
//! implements it; tests use in-process fakes.

use crate::manager::{ManagerHandle, RequestError};
use fleet_proto::{Actor, ErrorCode, Op, Payload, RootApproval, ServerId};
use std::future::Future;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RunError {
    /// Not connected (offline, backing off, removed): try again later.
    #[error("server not reachable")]
    Offline,
    /// Needs a device session; the app is locked.
    #[error("locked")]
    Locked,
    /// Exec answered with this code (receipt verified).
    #[error("agent refused: {0:?}")]
    Agent(ErrorCode),
    /// Session-level failure (no valid receipt, outcome unknown, …).
    #[error("{0}")]
    Other(String),
}

pub trait OpRunner {
    /// The verified payload of `op` on `server`.
    fn run(
        &self,
        server: &ServerId,
        op: Op,
        actor: Actor,
        approval: Option<RootApproval>,
    ) -> impl Future<Output = Result<Payload, RunError>>;
}

impl From<RequestError> for RunError {
    fn from(e: RequestError) -> Self {
        match e {
            RequestError::UnknownServer
            | RequestError::NotReady(_)
            | RequestError::Timeout
            | RequestError::Stopped => RunError::Offline,
            RequestError::Locked => RunError::Locked,
            RequestError::Client(c) => RunError::Other(c.to_string()),
        }
    }
}

impl OpRunner for ManagerHandle {
    async fn run(
        &self,
        server: &ServerId,
        op: Op,
        actor: Actor,
        approval: Option<RootApproval>,
    ) -> Result<Payload, RunError> {
        let reply = self.request(server, op, actor, approval).await?;
        reply.result.map_err(RunError::Agent)
    }
}
