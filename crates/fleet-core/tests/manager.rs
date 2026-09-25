//! Connection manager with a fake connector (no crypto, no sockets).

use fleet_core::manager::{
    AgentLink, ConnState, ConnectionManager, Connector, LinkCtx, LinkError, ManagerConfig,
    ManagerEvent, ManagerHandle, RequestError, ServeEnd, ServerSpec, SessionKind, backoff_delay,
};
use fleet_core::ssh::{SshError, SshTarget};
use fleet_core::{ClientError, PendingReply, Reply};
use fleet_proto::{
    Actor, Ed25519Public, ErrorCode, Event, Op, Outcome, Receipt, RootApproval, ServerId,
    Signature, SignedReceipt, X25519Public,
};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::LocalSet;
use tokio::time::timeout;

const T: Duration = Duration::from_secs(10);

fn sid(i: usize) -> ServerId {
    ServerId::new(format!("srv_{i:06}")).unwrap()
}

fn spec(i: usize) -> ServerSpec {
    ServerSpec {
        id: sid(i),
        target: SshTarget::new("127.0.0.1", 22, "admin"),
        host_key: None,
        agent_noise: X25519Public([1; 32]),
        agent_signing: Ed25519Public([2; 32]),
    }
}

fn cfg() -> ManagerConfig {
    ManagerConfig {
        backoff_min: Duration::from_millis(5),
        backoff_max: Duration::from_millis(40),
        offline_after: 3,
        request_timeout: Duration::from_secs(5),
        ..Default::default()
    }
}

enum Fail {
    Transient,
    Fatal,
}

#[derive(Default)]
struct Fake {
    /// Per server: failures to produce before succeeding.
    fail_first: RefCell<HashMap<ServerId, (u32, bool)>>,
    attempts: RefCell<HashMap<ServerId, u32>>,
    kinds: RefCell<Vec<(ServerId, SessionKind)>>,
    handshake_delay: Duration,
    inflight: Cell<usize>,
    max_inflight: Cell<usize>,
    /// Senders of each live link's event feed; dropping one breaks the link.
    feeds: RefCell<HashMap<ServerId, mpsc::UnboundedSender<Event>>>,
    sent: SentLog,
}

/// Requests sent with options: (connection attempt, op, expected_version).
type SentLog = std::rc::Rc<RefCell<Vec<(u32, &'static str, Option<u64>)>>>;

impl Fake {
    fn fail(&self, i: usize, n: u32, how: Fail) {
        self.fail_first
            .borrow_mut()
            .insert(sid(i), (n, matches!(how, Fail::Fatal)));
    }
}

struct FakeLink {
    kind: SessionKind,
    events: mpsc::UnboundedReceiver<Event>,
    alive: std::rc::Rc<()>,
    attempt: u32,
    sent: SentLog,
}

fn reply(result: Result<fleet_proto::Payload, ErrorCode>) -> Reply {
    Reply {
        result,
        receipt: SignedReceipt {
            receipt: Receipt {
                server_id: sid(0),
                command_hash: [0; 32],
                audit_seq: None,
                outcome: Outcome::Ok,
                payload_hash: [0; 32],
                time_ms: 0,
            },
            signature: Signature([0; 64]),
        },
    }
}

/// How long the fake link takes to answer `pkg.refresh` (a slow op).
const SLOW: Duration = Duration::from_millis(400);

impl AgentLink for FakeLink {
    async fn start_request(
        &mut self,
        op: Op,
        _: Actor,
        _: Option<RootApproval>,
    ) -> Result<PendingReply, ClientError> {
        // Echo the session kind through the result so tests can see which
        // session served the request.
        let r = reply(match (&op, self.kind) {
            (Op::AgentHealth, SessionKind::Monitor) => Err(ErrorCode::NotFound),
            _ => Ok(fleet_proto::Payload::Empty),
        });
        let (tx, rx) = tokio::sync::oneshot::channel();
        let delay = if matches!(op, Op::PkgRefresh) {
            SLOW
        } else {
            Duration::ZERO
        };
        // Answers arrive later, like responses read off the wire, and only
        // while the link lives (a real session drops its pending replies).
        let alive = std::rc::Rc::downgrade(&self.alive);
        tokio::task::spawn_local(async move {
            tokio::time::sleep(delay).await;
            if alive.upgrade().is_some() {
                let _ = tx.send(Ok(r));
            }
        });
        Ok(rx)
    }

    async fn start_request_with(
        &mut self,
        op: Op,
        actor: Actor,
        approval: Option<RootApproval>,
        expected_version: Option<u64>,
    ) -> Result<PendingReply, ClientError> {
        self.sent
            .borrow_mut()
            .push((self.attempt, op.name(), expected_version));
        self.start_request(op, actor, approval).await
    }

    async fn next_event(&mut self) -> Result<(u64, Event), ClientError> {
        match self.events.recv().await {
            Some(e) => Ok((1, e)),
            None => Err(ClientError::Closed),
        }
    }

    fn take_events(&mut self) -> Vec<(u64, Event)> {
        Vec::new()
    }
}

struct FakeConnector(std::rc::Rc<Fake>);

impl std::ops::Deref for FakeConnector {
    type Target = Fake;
    fn deref(&self) -> &Fake {
        &self.0
    }
}

impl Connector for FakeConnector {
    async fn run(
        &self,
        server: &ServerSpec,
        kind: SessionKind,
        mut ctx: LinkCtx<'_>,
    ) -> Result<ServeEnd, LinkError> {
        self.inflight.set(self.inflight.get() + 1);
        self.max_inflight
            .set(self.max_inflight.get().max(self.inflight.get()));
        tokio::time::sleep(self.handshake_delay).await;
        self.inflight.set(self.inflight.get() - 1);
        ctx.authenticating();
        self.kinds.borrow_mut().push((server.id.clone(), kind));
        let n = {
            let mut a = self.attempts.borrow_mut();
            let n = a.entry(server.id.clone()).or_default();
            *n += 1;
            *n
        };
        if let Some(&(fails, fatal)) = self.fail_first.borrow().get(&server.id)
            && n <= fails
        {
            return Err(if fatal {
                LinkError::Ssh(SshError::AuthRejected)
            } else {
                LinkError::Client(ClientError::Closed)
            });
        }
        let (tx, rx) = mpsc::unbounded_channel();
        self.feeds.borrow_mut().insert(server.id.clone(), tx);
        let mut link = FakeLink {
            kind,
            events: rx,
            alive: std::rc::Rc::new(()),
            attempt: n,
            sent: self.sent.clone(),
        };
        ctx.serve(&mut link).await
    }
}

fn start(fake: std::rc::Rc<Fake>, cfg: ManagerConfig, kind: SessionKind) -> ManagerHandle {
    let (mgr, handle) = ConnectionManager::new(FakeConnector(fake), cfg, kind);
    tokio::task::spawn_local(mgr.run());
    handle
}

async fn wait_state(h: &ManagerHandle, id: &ServerId, want: ConnState) {
    timeout(T, async {
        while h.state(id) != Some(want) {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{id:?} never reached {want:?}, is {:?}", h.state(id)));
}

#[test]
fn backoff_bounds() {
    let c = ManagerConfig::default();
    assert_eq!(backoff_delay(&c, 0, 0), Duration::from_millis(500));
    assert_eq!(
        backoff_delay(&c, 0, u32::MAX),
        Duration::from_secs(1) - Duration::from_nanos(1)
    );
    assert!(backoff_delay(&c, 3, u32::MAX / 2) <= Duration::from_secs(8));
    for a in [6, 10, 40, u32::MAX] {
        let d = backoff_delay(&c, a, u32::MAX);
        assert!(
            d <= Duration::from_secs(60) && d >= Duration::from_secs(59),
            "{d:?}"
        );
        assert_eq!(backoff_delay(&c, a, 0), Duration::from_secs(30));
    }
}

#[tokio::test]
async fn connects_routes_requests_and_fans_out_events() {
    LocalSet::new()
        .run_until(async {
            let fake = std::rc::Rc::new(Fake::default());
            let h = start(fake.clone(), cfg(), SessionKind::Device);
            let mut sub = h.subscribe();
            h.add_server(spec(1));
            // Queued while connecting, served once Ready.
            let r = h
                .request(&sid(1), Op::SystemInfo, Actor::Human, None)
                .await
                .unwrap();
            assert_eq!(r.result, Ok(fleet_proto::Payload::Empty));
            assert_eq!(h.state(&sid(1)), Some(ConnState::Ready));
            let e = h
                .request(&sid(9), Op::SystemInfo, Actor::Human, None)
                .await
                .unwrap_err();
            assert!(matches!(e, RequestError::UnknownServer));

            let ev = Event::PolicyChanged { version: 7 };
            fake.feeds.borrow()[&sid(1)].send(ev.clone()).unwrap();
            let mut states = Vec::new();
            let got = timeout(T, async {
                loop {
                    match sub.recv().await.unwrap() {
                        ManagerEvent::Event { server, event, .. } => break (server, event),
                        ManagerEvent::State { state, .. } => states.push(state),
                        _ => {}
                    }
                }
            })
            .await
            .unwrap();
            assert_eq!(got, (sid(1), ev));
            assert_eq!(
                states,
                vec![
                    ConnState::Connecting,
                    ConnState::Authenticating,
                    ConnState::Ready
                ]
            );

            h.remove_server(&sid(1));
            assert_eq!(h.state(&sid(1)), None);
        })
        .await;
}

#[tokio::test]
async fn transient_failures_back_off_then_recover_and_link_loss_reconnects() {
    LocalSet::new()
        .run_until(async {
            let fake = std::rc::Rc::new(Fake::default());
            fake.fail(1, 4, Fail::Transient);
            let h = start(fake.clone(), cfg(), SessionKind::Device);
            let mut sub = h.subscribe();
            h.add_server(spec(1));
            wait_state(&h, &sid(1), ConnState::Ready).await;
            assert_eq!(fake.attempts.borrow()[&sid(1)], 5);
            let mut seen = Vec::new();
            while let Ok(ManagerEvent::State { state, failure, .. }) = sub.try_recv() {
                if let Some(f) = failure {
                    assert!(!f.fatal);
                    seen.push(state);
                }
            }
            // offline_after = 3.
            assert_eq!(
                seen,
                vec![
                    ConnState::Degraded,
                    ConnState::Degraded,
                    ConnState::Offline,
                    ConnState::Offline
                ]
            );

            // Link drops: Degraded, then back to Ready by itself.
            fake.feeds.borrow_mut().remove(&sid(1));
            timeout(T, async {
                while fake.attempts.borrow()[&sid(1)] < 6 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .unwrap();
            wait_state(&h, &sid(1), ConnState::Ready).await;
            assert_eq!(fake.attempts.borrow()[&sid(1)], 6);
        })
        .await;
}

/// Locked: a refused monitor SSH key (a roster that predates it) parks the
/// server, raises no "removed" alert, and unlocking retries at once. A
/// refused device SSH key does raise it.
#[tokio::test]
async fn monitor_key_refusal_waits_for_unlock_and_removal_alerts() {
    LocalSet::new()
        .run_until(async {
            let fake = std::rc::Rc::new(Fake::default());
            fake.fail(1, 1, Fail::Fatal);
            let h = start(fake.clone(), cfg(), SessionKind::Monitor);
            let mut ev = h.subscribe();
            h.add_server(spec(1));
            wait_state(&h, &sid(1), ConnState::Offline).await;
            h.set_session_kind(SessionKind::Device);
            wait_state(&h, &sid(1), ConnState::Ready).await;
            assert_eq!(
                fake.kinds.borrow().last(),
                Some(&(sid(1), SessionKind::Device))
            );
            let mut removed = 0;
            while let Ok(e) = ev.try_recv() {
                if matches!(
                    e,
                    fleet_core::manager::ManagerEvent::RemovedFromFleet { .. }
                ) {
                    removed += 1;
                }
            }
            assert_eq!(removed, 0);

            fake.fail(2, 1, Fail::Fatal);
            h.add_server(spec(2));
            wait_state(&h, &sid(2), ConnState::Offline).await;
            let mut signed = None;
            while let Ok(e) = ev.try_recv() {
                if let fleet_core::manager::ManagerEvent::RemovedFromFleet { server, signed: s } = e
                {
                    assert_eq!(server, sid(2));
                    signed = Some(s);
                }
            }
            assert_eq!(signed, Some(false), "an SSH refusal is a hint, not signed");
        })
        .await;
}

#[tokio::test]
async fn fatal_failure_blocks_until_reconnect() {
    LocalSet::new()
        .run_until(async {
            let fake = std::rc::Rc::new(Fake::default());
            fake.fail(1, 1, Fail::Fatal);
            let h = start(fake.clone(), cfg(), SessionKind::Device);
            h.add_server(spec(1));
            wait_state(&h, &sid(1), ConnState::Offline).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(fake.attempts.borrow()[&sid(1)], 1, "no automatic retry");
            let e = h
                .request(&sid(1), Op::SystemInfo, Actor::Human, None)
                .await
                .unwrap_err();
            assert!(
                matches!(e, RequestError::NotReady(ConnState::Offline)),
                "{e}"
            );
            h.reconnect(&sid(1));
            wait_state(&h, &sid(1), ConnState::Ready).await;
            assert_eq!(fake.attempts.borrow()[&sid(1)], 2);
        })
        .await;
}

#[tokio::test]
async fn handshakes_are_limited() {
    LocalSet::new()
        .run_until(async {
            let fake = std::rc::Rc::new(Fake {
                handshake_delay: Duration::from_millis(15),
                ..Default::default()
            });
            let h = start(
                fake.clone(),
                ManagerConfig {
                    max_handshakes: 3,
                    ..cfg()
                },
                SessionKind::Monitor,
            );
            for i in 0..12 {
                h.add_server(spec(i));
            }
            for i in 0..12 {
                wait_state(&h, &sid(i), ConnState::Ready).await;
            }
            assert_eq!(fake.max_inflight.get(), 3);
        })
        .await;
}

#[tokio::test]
async fn monitor_session_upgrades_on_unlock() {
    LocalSet::new()
        .run_until(async {
            let fake = std::rc::Rc::new(Fake::default());
            let h = start(fake.clone(), cfg(), SessionKind::Monitor);
            h.add_server(spec(1));
            wait_state(&h, &sid(1), ConnState::Ready).await;
            // Only agent.health goes over a monitor session.
            let e = h
                .request(&sid(1), Op::SystemInfo, Actor::Human, None)
                .await
                .unwrap_err();
            assert!(matches!(e, RequestError::Locked), "{e}");
            let r = h
                .request(&sid(1), Op::AgentHealth, Actor::Human, None)
                .await
                .unwrap();
            assert_eq!(r.result, Err(ErrorCode::NotFound)); // served by the monitor link

            h.set_session_kind(SessionKind::Device);
            timeout(T, async {
                while fake.kinds.borrow().len() < 2 {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
            .await
            .unwrap();
            wait_state(&h, &sid(1), ConnState::Ready).await;
            let r = h
                .request(&sid(1), Op::AgentHealth, Actor::Human, None)
                .await
                .unwrap();
            assert_eq!(r.result, Ok(fleet_proto::Payload::Empty));
            assert_eq!(
                *fake.kinds.borrow(),
                vec![
                    (sid(1), SessionKind::Monitor),
                    (sid(1), SessionKind::Device)
                ]
            );
        })
        .await;
}

#[tokio::test]
async fn slow_requests_run_concurrently_and_never_block_control() {
    LocalSet::new()
        .run_until(async {
            let fake = std::rc::Rc::new(Fake::default());
            let cfg = ManagerConfig {
                max_in_flight: 2,
                ..cfg()
            };
            let h = start(fake.clone(), cfg, SessionKind::Device);
            h.add_server(spec(1));
            wait_state(&h, &sid(1), ConnState::Ready).await;

            // A slow op in flight doesn't hold up a fast one.
            let t0 = std::time::Instant::now();
            let h1 = h.clone();
            let slow = tokio::task::spawn_local(async move {
                h1.request(&sid(1), Op::PkgRefresh, Actor::Human, None)
                    .await
            });
            tokio::task::yield_now().await;
            h.request(&sid(1), Op::SystemInfo, Actor::Human, None)
                .await
                .unwrap();
            assert!(t0.elapsed() < SLOW, "fast request waited for the slow one");
            slow.await.unwrap().unwrap();
            assert!(t0.elapsed() >= SLOW);

            // In-flight cap: 3 slow requests with a cap of 2 take two rounds.
            let t0 = std::time::Instant::now();
            let all: Vec<_> = (0..3)
                .map(|_| {
                    let h = h.clone();
                    tokio::task::spawn_local(async move {
                        h.request(&sid(1), Op::PkgRefresh, Actor::Human, None).await
                    })
                })
                .collect();
            for t in all {
                t.await.unwrap().unwrap();
            }
            let took = t0.elapsed();
            assert!(took >= SLOW * 2 && took < SLOW * 3, "{took:?}");

            // Locking while a slow request is in flight takes effect at
            // once; the request fails instead of blocking the switch.
            let h1 = h.clone();
            let slow = tokio::task::spawn_local(async move {
                h1.request(&sid(1), Op::PkgRefresh, Actor::Human, None)
                    .await
            });
            tokio::time::sleep(Duration::from_millis(20)).await;
            let t0 = std::time::Instant::now();
            h.set_session_kind(SessionKind::Monitor);
            let r = slow.await.unwrap();
            assert!(
                matches!(r, Err(RequestError::NotReady(_))),
                "{:?}",
                r.map(|_| ())
            );
            assert!(t0.elapsed() < SLOW);
            wait_state(&h, &sid(1), ConnState::Ready).await;
            assert_eq!(
                fake.kinds.borrow().last(),
                Some(&(sid(1), SessionKind::Monitor))
            );

            // Removal isn't blocked either.
            h.set_session_kind(SessionKind::Device);
            wait_state(&h, &sid(1), ConnState::Ready).await;
            let h1 = h.clone();
            let slow = tokio::task::spawn_local(async move {
                h1.request(&sid(1), Op::PkgRefresh, Actor::Human, None)
                    .await
            });
            tokio::time::sleep(Duration::from_millis(20)).await;
            let t0 = std::time::Instant::now();
            h.remove_server(&sid(1));
            assert!(slow.await.unwrap().is_err());
            assert!(t0.elapsed() < SLOW);
        })
        .await;
}

#[test]
fn long_ops_get_the_long_timeout() {
    let c = ManagerConfig::default();
    assert_eq!(c.timeout_for(&Op::SystemInfo), c.request_timeout);
    assert_eq!(c.timeout_for(&Op::PkgRefresh), c.long_request_timeout);
    assert!(c.long_request_timeout > c.request_timeout);
}

#[tokio::test]
async fn request_with_carries_expected_version() {
    LocalSet::new()
        .run_until(async {
            let fake = std::rc::Rc::new(Fake::default());
            let h = start(fake.clone(), cfg(), SessionKind::Device);
            h.add_server(spec(1));
            let opts = fleet_core::manager::RequestOpts {
                approval: None,
                expected_version: Some(42),
            };
            h.request_with(&sid(1), Op::FirewallGet, Actor::Human, opts)
                .await
                .unwrap();
            h.request(&sid(1), Op::SystemInfo, Actor::Human, None)
                .await
                .unwrap();
            let sent = fake.sent.borrow().clone();
            assert_eq!(
                sent,
                vec![(1, "firewall.get", Some(42)), (1, "system.info", None)]
            );
        })
        .await;
}

#[tokio::test]
async fn confirm_goes_over_a_new_connection() {
    LocalSet::new()
        .run_until(async {
            let fake = std::rc::Rc::new(Fake::default());
            let h = start(fake.clone(), cfg(), SessionKind::Device);
            h.add_server(spec(1));
            wait_state(&h, &sid(1), ConnState::Ready).await;
            let before = fake.attempts.borrow()[&sid(1)];
            fleet_core::confirm::confirm_on_new_connection(&h, &sid(1), [7; 16], Actor::Human, T)
                .await
                .unwrap();
            let sent = fake.sent.borrow().clone();
            let (attempt, op, _) = *sent.last().unwrap();
            assert_eq!(op, "change.confirm");
            assert!(
                attempt > before,
                "confirm sent on connection {attempt}, applied on {before}"
            );
        })
        .await;
}
