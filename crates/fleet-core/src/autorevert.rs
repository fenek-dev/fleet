//! Mac side of the auto-revert protocol (design §4.10 step 3).
//!
//! An auto-revert op (`Op::auto_revert`) answers `ChangePending`; the
//! change stays only if `change.confirm` arrives over a session opened
//! after the apply finished. [`confirm_fresh`] proves that: it drops the
//! server's managed connection ([`ManagerHandle::reconnect`] opens a new
//! SSH connection and Noise session, never a kept one), waits for Ready
//! and sends the confirm there. Requests queued after `reconnect` are
//! served by the new session (the worker handles the reconnect first).
//!
//! Exec answers `Busy` while the change is still applying (retried),
//! `PolicyDenied` for a session that isn't new enough (one more
//! reconnect), `NotFound` once the timer reverted it.

use crate::manager::{ManagerHandle, RequestError, RequestOpts};
use fleet_proto::op::ChangeId;
use fleet_proto::{Actor, ErrorCode, Op, Payload, ServerId};
use std::time::Duration;

/// Why a change could not be confirmed.
#[derive(Debug, thiserror::Error)]
pub enum ConfirmError {
    /// The revert timer won: the previous state is back.
    #[error("change was reverted")]
    Reverted,
    /// No fresh session came up before the deadline; the timer will revert.
    #[error("no fresh connection before the deadline")]
    NoConnection,
    #[error("agent refused: {0:?}")]
    Agent(ErrorCode),
    #[error(transparent)]
    Request(RequestError),
}

/// Retry pause for `Busy` / not-yet-Ready.
const RETRY: Duration = Duration::from_millis(750);
/// Fresh sessions opened for one confirmation at most.
const MAX_RECONNECTS: u32 = 3;

/// Confirms `change_id` on `id` over a fresh connection. `budget` is the
/// time left before the change's deadline.
pub async fn confirm_fresh(
    handle: &ManagerHandle,
    id: &ServerId,
    change_id: ChangeId,
    actor: Actor,
    budget: Duration,
) -> Result<(), ConfirmError> {
    let until = tokio::time::Instant::now() + budget;
    let mut reconnects = 0;
    let mut need_new = true;
    loop {
        let left = until.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return Err(ConfirmError::NoConnection);
        }
        if need_new {
            if reconnects == MAX_RECONNECTS {
                return Err(ConfirmError::NoConnection);
            }
            reconnects += 1;
            handle.reconnect(id);
            need_new = false;
            // Let the worker tear the old session down before waiting.
            tokio::time::sleep(Duration::from_millis(100)).await;
            handle.wait_ready(id, left).await;
        }
        let res = handle
            .request_with(
                id,
                Op::ChangeConfirm { change_id },
                actor.clone(),
                None,
                RequestOpts::default(),
            )
            .await;
        match classify(res) {
            Step::Done => return Ok(()),
            Step::Fail(e) => return Err(e),
            Step::Retry => tokio::time::sleep(RETRY).await,
            Step::Reconnect => need_new = true,
        }
    }
}

enum Step {
    Done,
    Retry,
    Reconnect,
    Fail(ConfirmError),
}

fn classify(res: Result<crate::session::Reply, RequestError>) -> Step {
    match res {
        Ok(r) => classify_answer(r.result),
        Err(RequestError::NotReady(_) | RequestError::Timeout) => Step::Retry,
        Err(RequestError::Client(_)) => Step::Reconnect,
        Err(e) => Step::Fail(ConfirmError::Request(e)),
    }
}

fn classify_answer(answer: Result<Payload, ErrorCode>) -> Step {
    match answer {
        Ok(_) => Step::Done,
        Err(ErrorCode::NotFound) => Step::Fail(ConfirmError::Reverted),
        Err(ErrorCode::Busy) => Step::Retry,
        Err(ErrorCode::PolicyDenied) => Step::Reconnect,
        Err(c) => Step::Fail(ConfirmError::Agent(c)),
    }
}

/// Milliseconds left until `deadline_ms`, minus a margin for the confirm's
/// own round trip; zero once past.
pub fn budget(deadline_ms: u64, now_ms: u64) -> Duration {
    Duration::from_millis(deadline_ms.saturating_sub(now_ms).saturating_sub(1_000))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_keeps_margin() {
        assert_eq!(budget(10_000, 4_000), Duration::from_millis(5_000));
        assert_eq!(budget(10_000, 9_500), Duration::ZERO);
        assert_eq!(budget(1_000, 5_000), Duration::ZERO);
    }

    #[test]
    fn classifies_answers() {
        assert!(matches!(classify_answer(Ok(Payload::Empty)), Step::Done));
        assert!(matches!(
            classify_answer(Err(ErrorCode::NotFound)),
            Step::Fail(ConfirmError::Reverted)
        ));
        assert!(matches!(classify_answer(Err(ErrorCode::Busy)), Step::Retry));
        assert!(matches!(
            classify_answer(Err(ErrorCode::PolicyDenied)),
            Step::Reconnect
        ));
        assert!(matches!(
            classify_answer(Err(ErrorCode::Internal)),
            Step::Fail(ConfirmError::Agent(ErrorCode::Internal))
        ));
        let not_ready = RequestError::NotReady(crate::manager::ConnState::Connecting);
        assert!(matches!(classify(Err(not_ready)), Step::Retry));
        assert!(matches!(
            classify(Err(RequestError::Stopped)),
            Step::Fail(ConfirmError::Request(RequestError::Stopped))
        ));
    }
}
