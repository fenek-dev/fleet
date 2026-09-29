//! Mac side of the auto-revert protocol (design §4.10 step 3).
//!
//! An auto-revert op (`Op::auto_revert`) answers `ChangePending`; the
//! change stays only if `change.confirm` arrives over a session opened
//! after the apply finished. [`confirm_fresh`] proves that: it drops the
//! server's managed connection ([`ManagerHandle::reconnect`] opens a new
//! SSH connection and Noise session, never a kept one), waits for the new
//! one to be Ready ([`reconnect_fresh`]) and sends the confirm there.
//! Requests queued after `reconnect` are served by the new session (the
//! worker handles the reconnect first). This is the one implementation:
//! [`confirm_pending`] (budget from the change's deadline, capped by
//! [`CONFIRM_TIMEOUT`], skew-adjusted, past deadline = `Reverted`) for
//! bulk, provisioning and MCP; [`crate::confirm`] only adapts it to bulk.
//! A fresh link is recognized by its generation
//! ([`ManagerHandle::link_generation`]), never by a Ready state alone.
//!
//! Exec answers `Busy` while the change is still applying (retried),
//! `PolicyDenied` for a session that isn't new enough (one more
//! reconnect), `NotFound` once the timer reverted it.

use crate::manager::{ConnState, ManagerEvent, ManagerHandle, RequestError, RequestOpts};
use fleet_proto::op::ChangeId;
use fleet_proto::payload::PendingChange;
use fleet_proto::{Actor, ErrorCode, Op, Payload, ServerId};
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;

/// Why a change could not be confirmed.
#[derive(Debug, thiserror::Error)]
pub enum ConfirmError {
    /// The revert timer won: the previous state is back.
    #[error("change was reverted")]
    Reverted,
    /// No fresh session came up before the deadline; the timer will revert.
    #[error("no fresh connection before the deadline")]
    NoConnection,
    /// The new login failed fatally (host key, SSH key refused): the
    /// change will revert.
    #[error("a new connection could not be made: {0}")]
    Reconnect(String),
    #[error("agent refused: {0:?}")]
    Agent(ErrorCode),
    /// Stopped by [`ConfirmRegistry::cancel`] ("Revert now").
    #[error("confirmation cancelled")]
    Cancelled,
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
            need_new = false;
            match reconnect_fresh(handle, id, left).await {
                Ok(()) => {}
                Err(ReconnectError::Timeout) => return Err(ConfirmError::NoConnection),
                Err(ReconnectError::Fatal(m)) => return Err(ConfirmError::Reconnect(m)),
            }
        }
        let res = tokio::time::timeout_at(
            until,
            handle.request_with(
                id,
                Op::ChangeConfirm { change_id },
                actor.clone(),
                RequestOpts::default(),
            ),
        )
        .await
        .map_err(|_| ConfirmError::NoConnection)?;
        match classify(res) {
            Step::Done => return Ok(()),
            Step::Fail(e) => return Err(e),
            Step::Retry => tokio::time::sleep(RETRY).await,
            Step::Reconnect => need_new = true,
        }
    }
}

/// Why [`reconnect_fresh`] gave up.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReconnectError {
    #[error("timed out waiting for a new connection")]
    Timeout,
    /// Fatal connect failure (host key, SSH key refused), or the manager
    /// stopped.
    #[error("a new connection could not be made: {0}")]
    Fatal(String),
}

/// Drops `id`'s connection and waits until a new one is Ready: Ready with
/// a link generation above the one current before the reconnect
/// ([`ManagerHandle::link_generation`]), so neither the old link nor a
/// lagged event stream can pass for a fresh one. Fails early when the
/// reconnect hits a fatal failure.
pub async fn reconnect_fresh(
    h: &ManagerHandle,
    id: &ServerId,
    timeout: Duration,
) -> Result<(), ReconnectError> {
    let mut events = h.subscribe();
    let before = h.link_generation(id).unwrap_or(0);
    h.reconnect(id);
    let deadline = tokio::time::Instant::now() + timeout;
    let fresh = |h: &ManagerHandle| {
        h.state(id) == Some(ConnState::Ready) && h.link_generation(id).unwrap_or(0) > before
    };
    loop {
        let ev = tokio::time::timeout_at(deadline, events.recv())
            .await
            .map_err(|_| ReconnectError::Timeout)?;
        match ev {
            Ok(ManagerEvent::State {
                server,
                state,
                failure,
                ..
            }) if &server == id => {
                if state == ConnState::Ready {
                    if fresh(h) {
                        return Ok(());
                    }
                } else if let Some(f) = failure
                    && f.fatal
                {
                    return Err(ReconnectError::Fatal(f.message));
                }
            }
            Ok(_) => {}
            // Missed events: judge by the link generation itself.
            Err(RecvError::Lagged(_)) => {
                if fresh(h) {
                    return Ok(());
                }
            }
            Err(RecvError::Closed) => {
                return Err(ReconnectError::Fatal("manager stopped".into()));
            }
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

/// Upper bound on one confirmation (reconnect plus confirm), whatever the
/// change's own deadline says.
pub const CONFIRM_TIMEOUT: Duration = Duration::from_secs(45);

/// `deadline_ms` (agent clock) on the Mac clock: minus the skew measured
/// at connect (agent − Mac), when known.
pub fn local_deadline(deadline_ms: u64, skew_ms: Option<i64>) -> u64 {
    match skew_ms {
        Some(s) if s >= 0 => deadline_ms.saturating_sub(s.unsigned_abs()),
        Some(s) => deadline_ms.saturating_add(s.unsigned_abs()),
        None => deadline_ms,
    }
}

/// Time to spend confirming a change due at `deadline_ms` (agent clock):
/// `min(cap, budget)`, or `Reverted` when the deadline has passed (the
/// agent's timer has put the old state back, or is about to).
pub fn confirm_window(
    deadline_ms: u64,
    skew_ms: Option<i64>,
    now_ms: u64,
    cap: Duration,
) -> Result<Duration, ConfirmError> {
    let b = budget(local_deadline(deadline_ms, skew_ms), now_ms);
    if b.is_zero() {
        return Err(ConfirmError::Reverted);
    }
    Ok(b.min(cap))
}

/// The confirmations in flight, at most one per server, so that "Revert
/// now" can stop the automatic one *before* it sends `change.revert`
/// (otherwise a confirm still reconnecting could win the race and keep the
/// change the operator just rejected). `run` registers a confirmation,
/// [`ConfirmRegistry::cancel`] aborts it and returns only once it has been
/// dropped, i.e. after nothing of it can reach the agent any more.
#[derive(Clone, Default)]
pub struct ConfirmRegistry {
    inner: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<ServerId, Running>>>,
}

struct Running {
    token: u64,
    abort: futures_util::future::AbortHandle,
    done: tokio::sync::oneshot::Receiver<()>,
}

/// Runs on drop of the registered confirmation: unregisters it (unless
/// replaced) and tells a waiting `cancel` it is gone.
struct Finished {
    inner: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<ServerId, Running>>>,
    id: ServerId,
    token: u64,
    done: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for Finished {
    fn drop(&mut self) {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if map.get(&self.id).is_some_and(|r| r.token == self.token) {
            map.remove(&self.id);
        }
        drop(map);
        if let Some(tx) = self.done.take() {
            let _ = tx.send(());
        }
    }
}

impl ConfirmRegistry {
    /// Runs `confirmation` as `id`'s registered confirmation; a running one
    /// for the same server is cancelled first. `Err(Cancelled)` when
    /// [`ConfirmRegistry::cancel`] stopped it.
    pub async fn run<F>(&self, id: &ServerId, confirmation: F) -> Result<(), ConfirmError>
    where
        F: std::future::Future<Output = Result<(), ConfirmError>>,
    {
        self.cancel(id).await;
        static TOKENS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let token = TOKENS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (abort, reg) = futures_util::future::AbortHandle::new_pair();
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                id.clone(),
                Running {
                    token,
                    abort,
                    done: rx,
                },
            );
        // Declared before the future, so it drops after it.
        let _finished = Finished {
            inner: self.inner.clone(),
            id: id.clone(),
            token,
            done: Some(tx),
        };
        match futures_util::future::Abortable::new(confirmation, reg).await {
            Ok(r) => r,
            Err(_) => Err(ConfirmError::Cancelled),
        }
    }

    /// Stops `id`'s confirmation, if one runs, and waits until it has been
    /// dropped. Whether one was running.
    pub async fn cancel(&self, id: &ServerId) -> bool {
        let running = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
        let Some(r) = running else { return false };
        r.abort.abort();
        // Resolves (Ok, or Err when the sender is gone) once the
        // confirmation's future has been dropped.
        let _ = r.done.await;
        true
    }
}

/// Confirms a `ChangePending` answer over a fresh connection within the
/// change's own deadline (capped by [`CONFIRM_TIMEOUT`], skew-adjusted).
/// The one entry point for bulk, provisioning and MCP callers.
pub async fn confirm_pending(
    h: &ManagerHandle,
    id: &ServerId,
    change: &PendingChange,
    actor: Actor,
) -> Result<(), ConfirmError> {
    let window = confirm_window(
        change.deadline_ms,
        h.clock_skew_ms(id),
        crate::now_ms(),
        CONFIRM_TIMEOUT,
    )?;
    confirm_fresh(h, id, change.change_id, actor, window).await
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};

    /// Records its drop in `log`, then never finishes by itself.
    struct Pending(Arc<Mutex<Vec<&'static str>>>);
    impl std::future::Future for Pending {
        type Output = Result<(), ConfirmError>;
        fn poll(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            std::task::Poll::Pending
        }
    }
    impl Drop for Pending {
        fn drop(&mut self) {
            // Give a racing `cancel` every chance to run ahead of us.
            self.0.lock().unwrap().push("confirm dropped");
        }
    }

    fn sid() -> ServerId {
        ServerId::new("srv_test01").unwrap()
    }

    /// The race behind "Revert now": the automatic confirmation is still
    /// running (reconnecting). `cancel` returns only after it has been
    /// dropped, so `change.revert` is always sent after nothing of the
    /// confirmation can reach the agent.
    #[tokio::test(flavor = "current_thread")]
    async fn cancel_drops_the_confirmation_before_the_revert_is_sent() {
        let reg = ConfirmRegistry::default();
        let log = Arc::new(Mutex::new(Vec::new()));
        let (r2, l2, id) = (reg.clone(), log.clone(), sid());
        let confirm = tokio::spawn(async move { r2.run(&id, Pending(l2)).await });
        // Let it register and start.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert!(reg.cancel(&sid()).await);
        log.lock().unwrap().push("revert sent");
        assert!(matches!(
            confirm.await.unwrap(),
            Err(ConfirmError::Cancelled)
        ));
        assert_eq!(*log.lock().unwrap(), ["confirm dropped", "revert sent"]);
        // Nothing left to cancel.
        assert!(!reg.cancel(&sid()).await);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn finished_confirmations_unregister_and_new_ones_replace_old() {
        let reg = ConfirmRegistry::default();
        // A confirmation that completes leaves nothing to cancel.
        assert!(reg.run(&sid(), async { Ok(()) }).await.is_ok());
        assert!(!reg.cancel(&sid()).await);
        assert!(matches!(
            reg.run(&sid(), async { Err(ConfirmError::Reverted) }).await,
            Err(ConfirmError::Reverted)
        ));
        assert!(!reg.cancel(&sid()).await);
        // A second run for the same server cancels the first.
        let log = Arc::new(Mutex::new(Vec::new()));
        let (r2, l2, id) = (reg.clone(), log.clone(), sid());
        let first = tokio::spawn(async move { r2.run(&id, Pending(l2)).await });
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        let second = reg.run(&sid(), async { Ok(()) }).await;
        assert!(second.is_ok());
        assert!(matches!(first.await.unwrap(), Err(ConfirmError::Cancelled)));
        assert_eq!(*log.lock().unwrap(), ["confirm dropped"]);
        // Other servers are untouched.
        let other = ServerId::new("srv_test02").unwrap();
        let (r3, l3, o2) = (reg.clone(), log.clone(), other.clone());
        let third = tokio::spawn(async move { r3.run(&o2, Pending(l3)).await });
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert!(!reg.cancel(&sid()).await);
        assert!(reg.cancel(&other).await);
        assert!(matches!(third.await.unwrap(), Err(ConfirmError::Cancelled)));
    }

    #[test]
    fn budget_keeps_margin() {
        assert_eq!(budget(10_000, 4_000), Duration::from_millis(5_000));
        assert_eq!(budget(10_000, 9_500), Duration::ZERO);
        assert_eq!(budget(1_000, 5_000), Duration::ZERO);
    }

    #[test]
    fn confirm_window_caps_skews_and_reverts_past_deadline() {
        let cap = CONFIRM_TIMEOUT;
        // Far deadline: capped.
        assert_eq!(confirm_window(1_000_000, None, 0, cap).unwrap(), cap);
        // Short deadline: its own budget.
        assert_eq!(
            confirm_window(11_000, None, 0, cap).unwrap(),
            Duration::from_secs(10)
        );
        // Agent clock 5 s ahead: the local deadline is 5 s earlier.
        assert_eq!(
            confirm_window(11_000, Some(5_000), 0, cap).unwrap(),
            Duration::from_secs(5)
        );
        // Agent 5 s behind: later.
        assert_eq!(
            confirm_window(11_000, Some(-5_000), 0, cap).unwrap(),
            Duration::from_secs(15)
        );
        // Past the deadline: reverted, not a wait.
        assert!(matches!(
            confirm_window(10_000, None, 20_000, cap),
            Err(ConfirmError::Reverted)
        ));
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
