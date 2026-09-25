//! Connection manager (design §3.2, §7.2).
//!
//! One worker per server runs the state machine
//! `Disconnected → Connecting → Authenticating → Ready → Degraded → Offline`:
//!
//! - **Connecting** waits for one of `max_handshakes` (20) permits, so a
//!   waking Mac doesn't open 100 handshakes at once; the permit is released
//!   when the session is Ready.
//! - **Degraded**: the last attempt failed; retrying with exponential
//!   backoff (1–60 s, equal jitter). After `offline_after` consecutive
//!   failures the state is **Offline** (still retrying at the backoff
//!   ceiling). A *fatal* failure (host key changed, agent key mismatch, SSH
//!   key refused, device not authorized) goes Offline and stops retrying
//!   until [`ManagerHandle::reconnect`].
//! - **Session kind**: every worker connects with the current
//!   [`SessionKind`]. Switching Monitor → Device (unlock) or back (lock)
//!   reconnects every Ready server with the new key, without backoff.
//!
//! The transport sits behind [`Connector`]: [`SshConnector`] in the app,
//! in-memory fakes in tests. A connector builds a session and hands it to
//! [`LinkCtx::serve`], which routes requests, fans events out and returns
//! when the link breaks or the manager wants a reconnect.
//!
//! Sessions borrow their signer, and `fleet_crypto::sig::Signer` isn't
//! `Sync`, so sessions aren't `Send`: [`ConnectionManager::run`] and its
//! workers run on one thread (a `tokio::task::LocalSet`; the FFI layer
//! gives the core a current-thread runtime). [`ManagerHandle`] is `Send +
//! Sync` and can be used from anywhere.

use crate::session::{
    ClientError, CommandSigner, Reply, Session, SessionConfig, SessionMode, StreamEvent,
};
use crate::signer::{DeviceSigner, KeyRole, RoleSigner, SignerError};
use crate::ssh::{
    HostKey, HostKeyObservation, P256SshSigner, SshConnection, SshError, SshOptions, SshTarget,
};
use fleet_crypto::noise::StaticKeypair;
use fleet_proto::{
    Actor, DeviceId, Ed25519Public, ErrorCode, Event, FleetId, KeyKind, Op, RequestId,
    RootApproval, ServerId, X25519Public,
};
use std::collections::HashMap;
use std::future::Future;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast, mpsc, oneshot, watch};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    Disconnected,
    Connecting,
    Authenticating,
    Ready,
    /// Last attempt failed; retrying with backoff.
    Degraded,
    /// Unreachable for a while, or blocked by a fatal failure.
    Offline,
}

/// Which key authenticates sessions (design §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    /// Read-only; usable while the app is locked.
    Monitor,
    /// Full session; app unlocked.
    Device,
}

impl SessionKind {
    pub fn key_kind(self) -> KeyKind {
        match self {
            SessionKind::Monitor => KeyKind::Monitor,
            SessionKind::Device => KeyKind::Device,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ManagerConfig {
    /// Concurrent handshakes across all servers (design §3.2: 20).
    pub max_handshakes: usize,
    pub backoff_min: Duration,
    pub backoff_max: Duration,
    /// Consecutive failures before Degraded becomes Offline.
    pub offline_after: u32,
    /// Per request, including time queued while connecting.
    pub request_timeout: Duration,
    /// Queued requests per server.
    pub request_queue: usize,
    /// Broadcast buffer; slow subscribers skip ahead.
    pub event_capacity: usize,
}

impl Default for ManagerConfig {
    fn default() -> Self {
        Self {
            max_handshakes: 20,
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
            offline_after: 5,
            request_timeout: Duration::from_secs(30),
            request_queue: 64,
            event_capacity: 4096,
        }
    }
}

/// Delay before retry number `attempt` (0-based): `min · 2^attempt`
/// capped at `max`, then equal jitter — uniformly in `[d/2, d]` for
/// `jitter` in `0..=u32::MAX`.
pub fn backoff_delay(cfg: &ManagerConfig, attempt: u32, jitter: u32) -> Duration {
    let d = cfg
        .backoff_min
        .saturating_mul(1u32 << attempt.min(20))
        .min(cfg.backoff_max);
    let half = d / 2;
    let extra = (half.as_nanos() * u128::from(jitter)) >> 32;
    half + Duration::from_nanos(extra as u64)
}

fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    // Jitter only; a failed RNG just means no jitter.
    let _ = fleet_crypto::random_bytes(&mut b);
    u32::from_le_bytes(b)
}

/// Why the last attempt failed, for the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub message: String,
    /// No automatic retry; the operator must act (and then reconnect).
    pub fatal: bool,
}

#[derive(Debug, Clone)]
pub enum ManagerEvent {
    State {
        server: ServerId,
        state: ConnState,
        kind: Option<SessionKind>,
        failure: Option<Failure>,
    },
    /// A verified agent event.
    Event {
        server: ServerId,
        seq: u64,
        event: Event,
    },
    /// Connected to a hop without a pinned host key: show the fingerprint,
    /// pin it on confirmation (`Cache::pin_host_key`, then `add_server`).
    HostKeyFirstUse {
        server: ServerId,
        observation: HostKeyObservation,
    },
}

/// What a connector needs to reach one server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSpec {
    pub id: ServerId,
    pub target: SshTarget,
    pub host_key: Option<HostKey>,
    pub agent_noise: X25519Public,
    pub agent_signing: Ed25519Public,
}

#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error(transparent)]
    Ssh(#[from] SshError),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("signer: {0}")]
    Signer(#[from] SignerError),
    #[error("timed out")]
    Timeout,
}

impl LinkError {
    /// Retrying can't help until the operator acts.
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            LinkError::Ssh(SshError::HostKeyChanged { .. } | SshError::AuthRejected)
                | LinkError::Client(
                    ClientError::AgentKeyMismatch
                        | ClientError::WrongServer
                        | ClientError::ProtoVersion { .. }
                        | ClientError::Rejected(
                            ErrorCode::Unauthorized | ErrorCode::SignatureInvalid
                        )
                )
        )
    }
}

/// Why [`LinkCtx::serve`] returned without a link error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeEnd {
    /// Server removed or manager gone.
    Stopped,
    /// Session kind changed: reconnect with the new key now.
    KindChanged,
    /// Reconnect requested, or the spec changed.
    Reconnect,
}

#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    #[error("unknown server")]
    UnknownServer,
    #[error("not connected ({0:?})")]
    NotReady(ConnState),
    /// Needs a device session; the app is locked (monitor session).
    #[error("locked: monitor session")]
    Locked,
    #[error("timed out")]
    Timeout,
    #[error("server removed")]
    Stopped,
    #[error(transparent)]
    Client(ClientError),
}

/// A connected, authenticated agent session as the manager uses it.
pub trait AgentLink {
    fn request(
        &mut self,
        op: Op,
        actor: Actor,
        approval: Option<RootApproval>,
    ) -> impl Future<Output = Result<Reply, ClientError>>;
    /// Must be cancel-safe.
    fn next_event(&mut self) -> impl Future<Output = Result<(u64, Event), ClientError>>;
    /// Events buffered while a request waited for its response.
    fn take_events(&mut self) -> Vec<(u64, Event)>;
    /// `StreamOpen` for a stream op; items arrive on the receiver.
    fn open_stream(
        &mut self,
        _op: Op,
        _actor: Actor,
    ) -> impl Future<Output = Result<(RequestId, mpsc::Receiver<StreamEvent>), ClientError>> {
        std::future::ready(Err(ClientError::Rejected(ErrorCode::Unsupported)))
    }
    fn cancel_stream(&mut self, _id: RequestId) -> impl Future<Output = Result<(), ClientError>> {
        std::future::ready(Ok(()))
    }
    /// Periodic chores that write (queued stream cancels).
    fn housekeeping(&mut self) -> impl Future<Output = Result<(), ClientError>> {
        std::future::ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AgentLink for Session<'_, S> {
    async fn request(
        &mut self,
        op: Op,
        actor: Actor,
        approval: Option<RootApproval>,
    ) -> Result<Reply, ClientError> {
        let server = self.server_id().clone();
        Session::request(self, op, &server, actor, approval).await
    }

    async fn next_event(&mut self) -> Result<(u64, Event), ClientError> {
        Session::next_event(self).await
    }

    fn take_events(&mut self) -> Vec<(u64, Event)> {
        Session::take_events(self)
    }

    async fn open_stream(
        &mut self,
        op: Op,
        actor: Actor,
    ) -> Result<(RequestId, mpsc::Receiver<StreamEvent>), ClientError> {
        Session::open_stream(self, op, actor).await
    }

    async fn cancel_stream(&mut self, id: RequestId) -> Result<(), ClientError> {
        Session::cancel_stream(self, id).await
    }

    async fn housekeeping(&mut self) -> Result<(), ClientError> {
        self.flush_cancels().await
    }
}

/// Builds sessions. Runs on the manager's thread (no `Send` needed).
pub trait Connector: 'static {
    /// Connects to `server` with a `kind` session, calls
    /// [`LinkCtx::authenticating`] once the transport is up, then
    /// [`LinkCtx::serve`] with the session and returns its result.
    fn run(
        &self,
        server: &ServerSpec,
        kind: SessionKind,
        ctx: LinkCtx<'_>,
    ) -> impl Future<Output = Result<ServeEnd, LinkError>>;
}

enum Work {
    Request {
        op: Op,
        actor: Actor,
        approval: Option<RootApproval>,
        reply: oneshot::Sender<Result<Reply, RequestError>>,
    },
    OpenStream {
        op: Op,
        actor: Actor,
        reply: oneshot::Sender<Result<OpenedStream, RequestError>>,
    },
    /// `generation` of the link the stream was opened on; a cancel for an
    /// older link is dropped (its streams died with it).
    CancelStream { id: RequestId, link: u64 },
}

impl Work {
    fn fail(self, e: RequestError) {
        match self {
            Work::Request { reply, .. } => {
                let _ = reply.send(Err(e));
            }
            Work::OpenStream { reply, .. } => {
                let _ = reply.send(Err(e));
            }
            Work::CancelStream { .. } => {}
        }
    }
}

/// Stream id, link generation, receiver.
type OpenedStream = (RequestId, u64, mpsc::Receiver<StreamEvent>);

/// SSH connections of Ready servers, for terminals and SFTP (design §3.2:
/// one connection per server).
type Transports = Arc<Mutex<HashMap<ServerId, (u64, Arc<SshConnection>)>>>;

/// A live stream from [`ManagerHandle::open_stream`]. Dropping it cancels
/// the stream on the agent. The receiver closes without an
/// [`StreamEvent::End`] when the connection drops.
pub struct ManagedStream {
    pub events: mpsc::Receiver<StreamEvent>,
    id: RequestId,
    link: u64,
    work: mpsc::Sender<Work>,
}

impl Drop for ManagedStream {
    fn drop(&mut self) {
        let _ = self.work.try_send(Work::CancelStream {
            id: self.id,
            link: self.link,
        });
    }
}

#[derive(Debug, Clone)]
struct ServerCtl {
    spec: ServerSpec,
    generation: u64,
    stop: bool,
}

/// Worker-side channels of one server.
struct Worker {
    id: ServerId,
    requests: mpsc::Receiver<Work>,
    ctl: watch::Receiver<ServerCtl>,
    kind: watch::Receiver<SessionKind>,
    state: watch::Sender<ConnState>,
    events: broadcast::Sender<ManagerEvent>,
    failures: u32,
    transports: Transports,
    /// Incremented per served link.
    link: u64,
}

impl Worker {
    fn set_state(&self, state: ConnState, kind: Option<SessionKind>, failure: Option<Failure>) {
        self.state.send_replace(state);
        let _ = self.events.send(ManagerEvent::State {
            server: self.id.clone(),
            state,
            kind,
            failure,
        });
    }

    fn emit_events(&self, evs: Vec<(u64, Event)>) {
        for (seq, event) in evs {
            let _ = self.events.send(ManagerEvent::Event {
                server: self.id.clone(),
                seq,
                event,
            });
        }
    }

    /// Stop requested or the handle is gone.
    fn stopped(&self) -> bool {
        self.ctl.borrow().stop || self.ctl.has_changed().is_err()
    }
}

/// Handed to [`Connector::run`] for one connection attempt.
pub struct LinkCtx<'w> {
    worker: &'w mut Worker,
    kind: SessionKind,
    permit: Option<OwnedSemaphorePermit>,
}

impl LinkCtx<'_> {
    /// Transport is up; agent authentication (Noise, `DeviceAuth`) next.
    pub fn authenticating(&mut self) {
        self.worker
            .set_state(ConnState::Authenticating, Some(self.kind), None);
    }

    pub fn host_key_first_use(&self, observation: HostKeyObservation) {
        let _ = self.worker.events.send(ManagerEvent::HostKeyFirstUse {
            server: self.worker.id.clone(),
            observation,
        });
    }

    /// Shares this link's SSH connection (terminals, SFTP) until the link
    /// ends; [`ManagerHandle::ssh`] hands it out.
    pub fn publish_ssh(&self, conn: Arc<SshConnection>) {
        self.worker
            .transports
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(self.worker.id.clone(), (self.worker.link + 1, conn));
    }

    /// Marks the server Ready and serves requests and events until the
    /// link breaks (`Err`) or the manager wants it closed.
    pub async fn serve<L: AgentLink>(mut self, link: &mut L) -> Result<ServeEnd, LinkError> {
        self.permit = None;
        let kind = self.kind;
        let w = self.worker;
        w.link += 1;
        let generation = w.link;
        w.failures = 0;
        w.set_state(ConnState::Ready, Some(kind), None);
        let mut chores = tokio::time::interval(HOUSEKEEPING);
        chores.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                r = w.ctl.changed() => {
                    if r.is_err() || w.ctl.borrow_and_update().stop {
                        return Ok(ServeEnd::Stopped);
                    }
                    return Ok(ServeEnd::Reconnect);
                }
                r = w.kind.changed() => {
                    if r.is_err() {
                        return Ok(ServeEnd::Stopped);
                    }
                    if *w.kind.borrow_and_update() != kind {
                        return Ok(ServeEnd::KindChanged);
                    }
                }
                work = w.requests.recv() => {
                    let Some(work) = work else { return Ok(ServeEnd::Stopped) };
                    let res = match work {
                        Work::Request { op, actor, approval, reply } => {
                            // The caller gave up (timeout): don't run it late.
                            if reply.is_closed() {
                                continue;
                            }
                            if kind == SessionKind::Monitor && !op.monitor_allowed() {
                                let _ = reply.send(Err(RequestError::Locked));
                                continue;
                            }
                            let res = link.request(op, actor, approval).await;
                            w.emit_events(link.take_events());
                            match res {
                                Ok(r) => {
                                    let _ = reply.send(Ok(r));
                                    Ok(())
                                }
                                Err(e) => Err((e, Some(reply))),
                            }
                        }
                        Work::OpenStream { op, actor, reply } => {
                            if reply.is_closed() {
                                continue;
                            }
                            if kind == SessionKind::Monitor && !op.monitor_allowed() {
                                let _ = reply.send(Err(RequestError::Locked));
                                continue;
                            }
                            match link.open_stream(op, actor).await {
                                Ok((id, rx)) => {
                                    let _ = reply.send(Ok((id, generation, rx)));
                                    Ok(())
                                }
                                Err(e) => {
                                    let broken = link_broken(&e);
                                    let _ = reply.send(Err(if broken {
                                        RequestError::NotReady(ConnState::Degraded)
                                    } else {
                                        RequestError::Client(e)
                                    }));
                                    if broken {
                                        return Err(LinkError::Client(ClientError::Closed));
                                    }
                                    Ok(())
                                }
                            }
                        }
                        Work::CancelStream { id, link: g } => {
                            if g != generation {
                                continue;
                            }
                            link.cancel_stream(id).await.map_err(|e| (e, None))
                        }
                    };
                    match res {
                        Ok(()) => {}
                        Err((e, reply)) if link_broken(&e) => {
                            if let Some(reply) = reply {
                                let _ = reply.send(Err(RequestError::NotReady(ConnState::Degraded)));
                            }
                            return Err(e.into());
                        }
                        Err((e, reply)) => {
                            if let Some(reply) = reply {
                                let _ = reply.send(Err(RequestError::Client(e)));
                            }
                        }
                    }
                }
                _ = chores.tick() => {
                    if let Err(e) = link.housekeeping().await {
                        return Err(e.into());
                    }
                }
                ev = link.next_event() => {
                    let (seq, event) = ev?;
                    w.emit_events(vec![(seq, event)]);
                }
            }
        }
    }
}

/// How often the serve loop runs [`AgentLink::housekeeping`].
const HOUSEKEEPING: Duration = Duration::from_secs(2);

/// Transport or framing failure (the session can't be used any more), as
/// opposed to a per-command verdict or a signer refusal.
fn link_broken(e: &ClientError) -> bool {
    match e {
        ClientError::Io(_) | ClientError::Closed | ClientError::Malformed => true,
        ClientError::Crypto(c) => !matches!(c, fleet_crypto::Error::Signer),
        _ => false,
    }
}

async fn worker_loop<C: Connector>(
    connector: Rc<C>,
    mut w: Worker,
    sem: Arc<Semaphore>,
    cfg: Rc<ManagerConfig>,
) {
    'outer: loop {
        if w.stopped() {
            break;
        }
        let kind = *w.kind.borrow_and_update();
        let spec = w.ctl.borrow_and_update().spec.clone();
        w.set_state(ConnState::Connecting, Some(kind), None);
        let permit = tokio::select! {
            p = sem.clone().acquire_owned() => p.ok(),
            r = w.ctl.changed() => {
                if r.is_err() || w.ctl.borrow().stop { break 'outer; }
                continue 'outer;
            }
        };
        let ctx = LinkCtx {
            worker: &mut w,
            kind,
            permit,
        };
        let ran = connector.run(&spec, kind, ctx).await;
        w.transports
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&w.id);
        let err = match ran {
            Ok(ServeEnd::Stopped) => break,
            Ok(ServeEnd::KindChanged | ServeEnd::Reconnect) => continue,
            Err(e) => e,
        };
        w.failures = w.failures.saturating_add(1);
        let fatal = err.is_fatal();
        let state = if fatal || w.failures >= cfg.offline_after {
            ConnState::Offline
        } else {
            ConnState::Degraded
        };
        w.set_state(
            state,
            None,
            Some(Failure {
                message: err.to_string(),
                fatal,
            }),
        );
        drop(err);
        // Fatal: wait for the operator (reconnect, new spec, removal).
        // Otherwise back off. Requests meanwhile fail fast.
        let sleep = tokio::time::sleep(if fatal {
            Duration::MAX / 4
        } else {
            backoff_delay(&cfg, w.failures - 1, random_u32())
        });
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                () = &mut sleep => break,
                r = w.ctl.changed() => {
                    if r.is_err() || w.ctl.borrow().stop { break 'outer; }
                    w.failures = 0;
                    break;
                }
                req = w.requests.recv() => match req {
                    Some(work) => work.fail(RequestError::NotReady(state)),
                    None => break 'outer,
                },
            }
        }
    }
    w.set_state(ConnState::Disconnected, None, None);
}

struct Slot {
    requests: mpsc::Sender<Work>,
    ctl: watch::Sender<ServerCtl>,
    state: watch::Receiver<ConnState>,
}

struct Shared {
    cfg: ManagerConfig,
    slots: Mutex<HashMap<ServerId, Slot>>,
    kind: watch::Sender<SessionKind>,
    events: broadcast::Sender<ManagerEvent>,
    spawn: mpsc::UnboundedSender<Worker>,
    transports: Transports,
}

/// Thread-safe front of the manager. Cheap to clone.
#[derive(Clone)]
pub struct ManagerHandle {
    shared: Arc<Shared>,
}

/// Owns the workers; see the module docs for threading.
pub struct ConnectionManager<C> {
    connector: Rc<C>,
    cfg: Rc<ManagerConfig>,
    sem: Arc<Semaphore>,
    spawn: mpsc::UnboundedReceiver<Worker>,
}

impl<C: Connector> ConnectionManager<C> {
    pub fn new(connector: C, cfg: ManagerConfig, kind: SessionKind) -> (Self, ManagerHandle) {
        let (spawn_tx, spawn_rx) = mpsc::unbounded_channel();
        let (events, _) = broadcast::channel(cfg.event_capacity.max(1));
        let handle = ManagerHandle {
            shared: Arc::new(Shared {
                cfg: cfg.clone(),
                slots: Mutex::new(HashMap::new()),
                kind: watch::Sender::new(kind),
                events,
                spawn: spawn_tx,
                transports: Arc::default(),
            }),
        };
        let mgr = Self {
            connector: Rc::new(connector),
            sem: Arc::new(Semaphore::new(cfg.max_handshakes.max(1))),
            cfg: Rc::new(cfg),
            spawn: spawn_rx,
        };
        (mgr, handle)
    }

    /// Spawns a worker per added server (with `spawn_local`: call inside a
    /// `LocalSet`). Returns when every handle is dropped; workers then wind
    /// down on their own.
    pub async fn run(mut self) {
        while let Some(w) = self.spawn.recv().await {
            tokio::task::spawn_local(worker_loop(
                self.connector.clone(),
                w,
                self.sem.clone(),
                self.cfg.clone(),
            ));
        }
    }
}

impl ManagerHandle {
    fn slots(&self) -> std::sync::MutexGuard<'_, HashMap<ServerId, Slot>> {
        self.shared.slots.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Starts managing `spec.id`, or updates its spec (and reconnects).
    pub fn add_server(&self, spec: ServerSpec) {
        let mut slots = self.slots();
        if let Some(slot) = slots.get(&spec.id) {
            slot.ctl.send_modify(|c| {
                c.spec = spec;
                c.generation += 1;
            });
            return;
        }
        let (req_tx, req_rx) = mpsc::channel(self.shared.cfg.request_queue.max(1));
        let (ctl_tx, ctl_rx) = watch::channel(ServerCtl {
            spec: spec.clone(),
            generation: 0,
            stop: false,
        });
        let (state_tx, state_rx) = watch::channel(ConnState::Disconnected);
        let worker = Worker {
            id: spec.id.clone(),
            requests: req_rx,
            ctl: ctl_rx,
            kind: self.shared.kind.subscribe(),
            state: state_tx,
            events: self.shared.events.clone(),
            failures: 0,
            transports: self.shared.transports.clone(),
            link: 0,
        };
        if self.shared.spawn.send(worker).is_ok() {
            slots.insert(
                spec.id,
                Slot {
                    requests: req_tx,
                    ctl: ctl_tx,
                    state: state_rx,
                },
            );
        }
    }

    pub fn remove_server(&self, id: &ServerId) {
        if let Some(slot) = self.slots().remove(id) {
            slot.ctl.send_modify(|c| c.stop = true);
        }
    }

    /// Reconnects now (clears backoff and a fatal block).
    pub fn reconnect(&self, id: &ServerId) {
        if let Some(slot) = self.slots().get(id) {
            slot.ctl.send_modify(|c| c.generation += 1);
        }
    }

    /// Monitor while locked, Device once unlocked (design §7.2).
    pub fn set_session_kind(&self, kind: SessionKind) {
        self.shared.kind.send_if_modified(|k| {
            let changed = *k != kind;
            *k = kind;
            changed
        });
    }

    pub fn session_kind(&self) -> SessionKind {
        *self.shared.kind.borrow()
    }

    pub fn state(&self, id: &ServerId) -> Option<ConnState> {
        self.slots().get(id).map(|s| *s.state.borrow())
    }

    pub fn servers(&self) -> Vec<(ServerId, ConnState)> {
        self.slots()
            .iter()
            .map(|(id, s)| (id.clone(), *s.state.borrow()))
            .collect()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ManagerEvent> {
        self.shared.events.subscribe()
    }

    /// Signs and sends `op` on `id`'s session. Waits (up to the request
    /// timeout) while the server is connecting; fails fast while it backs
    /// off.
    pub async fn request(
        &self,
        id: &ServerId,
        op: Op,
        actor: Actor,
        approval: Option<RootApproval>,
    ) -> Result<Reply, RequestError> {
        let tx = self
            .slots()
            .get(id)
            .map(|s| s.requests.clone())
            .ok_or(RequestError::UnknownServer)?;
        let (reply, rx) = oneshot::channel();
        let req = Work::Request {
            op,
            actor,
            approval,
            reply,
        };
        let fut = async {
            tx.send(req).await.map_err(|_| RequestError::Stopped)?;
            rx.await.map_err(|_| RequestError::Stopped)?
        };
        tokio::time::timeout(self.shared.cfg.request_timeout, fut)
            .await
            .map_err(|_| RequestError::Timeout)?
    }

    /// Opens a stream op ([`Op::is_stream`]) on `id`'s session. Waits like
    /// [`ManagerHandle::request`] while connecting.
    pub async fn open_stream(
        &self,
        id: &ServerId,
        op: Op,
        actor: Actor,
    ) -> Result<ManagedStream, RequestError> {
        let tx = self
            .slots()
            .get(id)
            .map(|s| s.requests.clone())
            .ok_or(RequestError::UnknownServer)?;
        let (reply, rx) = oneshot::channel();
        let fut = async {
            tx.send(Work::OpenStream { op, actor, reply })
                .await
                .map_err(|_| RequestError::Stopped)?;
            rx.await.map_err(|_| RequestError::Stopped)?
        };
        let (sid, link, events) = tokio::time::timeout(self.shared.cfg.request_timeout, fut)
            .await
            .map_err(|_| RequestError::Timeout)??;
        Ok(ManagedStream {
            events,
            id: sid,
            link,
            work: tx,
        })
    }

    /// The SSH connection of `id` while its session is Ready.
    pub fn ssh(&self, id: &ServerId) -> Option<Arc<SshConnection>> {
        self.shared
            .transports
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .map(|(_, c)| c.clone())
    }

    /// Waits until `id` is Ready (or `timeout`); the final state.
    pub async fn wait_ready(&self, id: &ServerId, timeout: Duration) -> Option<ConnState> {
        let mut rx = self.slots().get(id).map(|s| s.state.clone())?;
        let wait = rx.wait_for(|s| *s == ConnState::Ready);
        let _ = tokio::time::timeout(timeout, wait).await;
        let s = *rx.borrow();
        Some(s)
    }
}

/// The app's connector: SSH with the enclave SSH key, the agent exec
/// channel, then a Noise session signed by the device or monitor key.
pub struct SshConnector {
    pub keys: Arc<dyn DeviceSigner>,
    pub noise: Arc<StaticKeypair>,
    pub fleet_id: FleetId,
    pub device_id: DeviceId,
    pub ssh: SshOptions,
    /// Noise handshake + `DeviceAuth` + signed status read.
    pub session_timeout: Duration,
}

impl Connector for SshConnector {
    async fn run(
        &self,
        server: &ServerSpec,
        kind: SessionKind,
        mut ctx: LinkCtx<'_>,
    ) -> Result<ServeEnd, LinkError> {
        let ssh_key = P256SshSigner(RoleSigner::new(&*self.keys, KeyRole::Ssh)?);
        let (conn, observation) = SshConnection::connect_with(
            &server.target,
            &ssh_key,
            server.host_key.clone(),
            &self.ssh,
        )
        .await?;
        if observation.needs_confirmation() {
            ctx.host_key_first_use(observation);
        }
        let conn = Arc::new(conn);
        ctx.authenticating();
        let role = match kind {
            SessionKind::Monitor => KeyRole::Monitor,
            SessionKind::Device => KeyRole::Device,
        };
        let signer = RoleSigner::new(&*self.keys, role)?;
        let result = async {
            let stream = conn.open_agent_channel(false).await?;
            let cfg = SessionConfig {
                mode: SessionMode::Normal,
                noise: &self.noise,
                pinned_agent_noise: server.agent_noise,
                pinned_agent_signing: server.agent_signing,
                fleet_id: self.fleet_id,
                server_id: server.id.clone(),
                device_id: self.device_id,
                key: kind.key_kind(),
                signer: CommandSigner::P256(&signer),
            };
            let mut session =
                tokio::time::timeout(self.session_timeout, Session::connect_bridged(stream, cfg))
                    .await
                    .map_err(|_| LinkError::Timeout)??;
            ctx.publish_ssh(conn.clone());
            ctx.serve(&mut session).await
        }
        .await;
        conn.disconnect().await;
        result
    }
}
