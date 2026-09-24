//! `fleet-agent gate` (design §4.1, §5.5, §6.1): terminates Noise sessions
//! from bridges and relays chunks to exec. Unprivileged and **never
//! trusted**: exec re-verifies every command, so the gate only authenticates
//! sessions (`DeviceAuth` against the roster exec sent it), applies size
//! and rate limits, drives Noise rekeying and moves bytes.
//!
//! The gate keeps one long-lived **control** connection to exec, which only
//! carries roster and limits updates. Per bridge connection: mode byte →
//! Noise XX responder → `DeviceAuth` (one chunk) checked against the
//! control roster → only then connect to exec (one IPC stream per session),
//! re-check `DeviceAuth` against the roster exec sends on it →
//! `SessionOpen` → relay. Unauthenticated peers never reach exec.
//!
//! The gate never reassembles: it decodes a frame only when it fits in one
//! chunk (to refuse wrong-mode commands early); for longer frames it checks
//! just the message kind in the first chunk. Memory per session is a few
//! chunks.

use crate::bridge::BridgeMode;
use crate::frame::{self, MAX_STREAM_FRAME};
use crate::ipc::{self, GATE_FRAME_BIT, IpcMsg};
use crate::paths::Paths;
use fleet_crypto::noise::{self, Handshake, StaticKeypair, Transport};
use fleet_crypto::roster::RecoveryClock;
use fleet_proto::chunk::{MAX_CHUNK_DATA, parse_chunk, split_frame};
use fleet_proto::{
    DeviceId, ErrorCode, KeyKind, Message, MessageKind, Op, Signature, SignedCommand, SignedRoster,
    X25519Public, decode, encode,
};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::rc::Rc;
use std::time::{Duration, Instant};
use tokio::net::UnixStream;
use tokio::sync::{Notify, mpsc};

/// Handshake, auth and exec setup must finish within this.
pub const SETUP_TIMEOUT: Duration = Duration::from_secs(15);
/// Default until exec sends `Limits` (design §5.4 default).
pub const DEFAULT_COMMANDS_PER_MINUTE: u32 = 240;
/// Sessions still in setup (handshake, `DeviceAuth`), across all peers.
/// When full, the oldest is dropped to admit the new one: unauthenticated
/// floods can slow a real client down but never lock it out.
pub const MAX_PREAUTH_SESSIONS: usize = 64;
/// Setup slots of their own for connections that sent the recovery mode
/// byte (also oldest-evicted), so normal-mode floods can't crowd out a
/// recovery login.
pub const MAX_PREAUTH_RECOVERY: usize = 8;
/// Authenticated sessions per device id (a recovery session counts under
/// its self-chosen id). Unauthenticated sessions don't count.
pub const MAX_SESSIONS_PER_DEVICE: usize = 8;
/// Frames the client may have in flight across chunks (matches exec).
const MAX_PARTIAL: usize = 4;
/// Control connection retry delay while exec is down.
const CONTROL_RETRY: Duration = Duration::from_millis(200);

#[derive(Debug, thiserror::Error)]
pub enum GateError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("noise static key: {0}")]
    Key(String),
}

pub struct GateConfig {
    pub paths: Paths,
    /// Rekey the outgoing direction at least this often, on top of the
    /// protocol's own schedule (`Transport::needs_rekey`). Tests only.
    pub rekey_interval: Option<Duration>,
}

impl GateConfig {
    pub fn new(paths: Paths) -> Self {
        Self {
            paths,
            rekey_interval: None,
        }
    }
}

/// Loads the gate's Noise static key (32 raw bytes, read into a wiped
/// buffer; symlinks refused).
pub fn load_noise_key(paths: &Paths) -> Result<StaticKeypair, GateError> {
    let key = crate::fsutil::read_key32(&paths.noise_key)
        .map_err(|e| GateError::Key(e.to_string()))?
        .ok_or_else(|| GateError::Key("missing".into()))?;
    Ok(StaticKeypair::from_bytes(&key))
}

/// Runs the gate until `shutdown` completes.
pub async fn run(cfg: GateConfig, shutdown: impl Future<Output = ()>) -> Result<(), GateError> {
    let key = load_noise_key(&cfg.paths)?;
    let shared = Rc::new(Shared {
        key,
        paths: cfg.paths.clone(),
        newest: Cell::new((0, 0)),
        next_id: Cell::new(0),
        roster: RefCell::new(None),
        cpm: Cell::new(DEFAULT_COMMANDS_PER_MINUTE),
        next_slot: Cell::new(0),
        preauth: Pool::default(),
        preauth_recovery: Pool::default(),
        per_device: RefCell::new(HashMap::new()),
        rekey_interval: cfg.rekey_interval,
        ready: tokio::sync::Notify::new(),
    });
    let local = tokio::task::LocalSet::new();
    let res = local
        .run_until(async move {
            tokio::pin!(shutdown);
            let ctl = tokio::task::spawn_local(control(shared.clone()));
            // Listen only once exec has sent a roster: before that every
            // session would be refused anyway.
            tokio::select! {
                () = shared.ready.notified() => {}
                () = &mut shutdown => {
                    ctl.abort();
                    return Ok(());
                }
            }
            // `run_dir` is the gate's own directory: binding there is safe.
            let listener = crate::fsutil::bind_socket(
                &shared.paths.agent_sock,
                &shared.paths.run_dir,
                0o660,
                None,
            )?;
            loop {
                tokio::select! {
                    r = listener.accept() => {
                        // Accept errors (EMFILE…) are transient; keep serving.
                        if let Ok((stream, _)) = r {
                            let slot = PreauthSlot::take(&shared);
                            let sh = shared.clone();
                            tokio::task::spawn_local(async move {
                                let _ = session(stream, sh, slot).await;
                            });
                        }
                    }
                    () = &mut shutdown => break,
                }
            }
            ctl.abort();
            Ok::<(), GateError>(())
        })
        .await;
    let _ = std::fs::remove_file(&cfg.paths.agent_sock);
    res
}

/// Keeps the control connection to exec up and the shared roster current.
async fn control(sh: Rc<Shared>) {
    loop {
        let _ = control_once(&sh).await;
        tokio::time::sleep(CONTROL_RETRY).await;
    }
}

async fn control_once(sh: &Shared) -> Option<()> {
    let s = UnixStream::connect(&sh.paths.exec_sock).await.ok()?;
    let (mut r, mut w) = s.into_split();
    ipc::write_msg(&mut w, &IpcMsg::ControlOpen).await.ok()?;
    loop {
        match ipc::read_msg(&mut r).await.ok()?? {
            IpcMsg::RosterUpdate {
                roster,
                grace_remaining_ms,
            } => {
                if let Some(r) = sh.accept_roster(&roster) {
                    *sh.roster.borrow_mut() = Some((r, grace_deadline(grace_remaining_ms)));
                    sh.ready.notify_one();
                }
            }
            IpcMsg::Limits {
                commands_per_minute,
            } => sh.cpm.set(commands_per_minute.max(1)),
            _ => return None,
        }
    }
}

struct Shared {
    key: StaticKeypair,
    paths: Paths,
    /// Newest `(epoch, version)` seen from exec; a roster never goes back.
    newest: Cell<(u32, u64)>,
    /// Counter for gate-originated frame ids.
    next_id: Cell<u32>,
    /// Latest roster from the control connection, for pre-exec auth, and
    /// the end of its local recovery grace (see [`grace_deadline`]).
    roster: RefCell<Option<(SignedRoster, Option<Instant>)>>,
    cpm: Cell<u32>,
    next_slot: Cell<u64>,
    preauth: Pool,
    preauth_recovery: Pool,
    per_device: RefCell<HashMap<DeviceId, usize>>,
    rekey_interval: Option<Duration>,
    /// Signalled when the control connection delivers a roster.
    ready: tokio::sync::Notify,
}

impl Shared {
    fn frame_id(&self) -> u32 {
        let n = self.next_id.get();
        self.next_id.set(n.wrapping_add(1));
        GATE_FRAME_BIT | (n & !GATE_FRAME_BIT)
    }

    /// Accepts a roster from exec if it doesn't go backwards.
    fn accept_roster(&self, bytes: &[u8]) -> Option<SignedRoster> {
        let r: SignedRoster = decode(bytes).ok()?;
        let v = (r.roster.epoch, r.roster.version);
        if v < self.newest.get() {
            return None;
        }
        self.newest.set(v);
        Some(r)
    }

    /// A single-chunk gate-originated frame.
    fn own_chunk(&self, msg: &Message) -> Vec<u8> {
        split_frame(self.frame_id(), &encode(msg)).remove(0)
    }
}

/// Exec's remaining local recovery grace, as a deadline on the gate's own
/// monotonic clock.
fn grace_deadline(remaining_ms: Option<u64>) -> Option<Instant> {
    remaining_ms.and_then(|r| Instant::now().checked_add(Duration::from_millis(r)))
}

/// Setup slots of one pool, oldest first, each with its eviction signal.
#[derive(Default)]
struct Pool(RefCell<VecDeque<(u64, Rc<Notify>)>>);

impl Pool {
    /// Adds slot `id`, evicting the oldest while the pool holds `cap`.
    fn admit(&self, id: u64, evict: Rc<Notify>, cap: usize) {
        let mut q = self.0.borrow_mut();
        while q.len() >= cap {
            match q.pop_front() {
                // Stores a permit: the session ends at its next poll.
                Some((_, old)) => old.notify_one(),
                None => break,
            }
        }
        q.push_back((id, evict));
    }

    fn remove(&self, id: u64) {
        self.0.borrow_mut().retain(|(i, _)| *i != id);
    }
}

/// A session's setup slot (in the general pool, or the recovery pool once
/// the mode byte says so); released on drop.
struct PreauthSlot {
    sh: Rc<Shared>,
    id: u64,
    recovery: bool,
    /// Signalled when a newer session evicts this one.
    evicted: Rc<Notify>,
}

impl PreauthSlot {
    /// Always succeeds; evicts the oldest setup if the pool is full.
    fn take(sh: &Rc<Shared>) -> Self {
        let id = sh.next_slot.get();
        sh.next_slot.set(id.wrapping_add(1));
        let evicted = Rc::new(Notify::new());
        sh.preauth.admit(id, evicted.clone(), MAX_PREAUTH_SESSIONS);
        Self {
            sh: sh.clone(),
            id,
            recovery: false,
            evicted,
        }
    }

    /// Moves to the recovery pool (after the recovery mode byte).
    fn move_to_recovery(&mut self) {
        self.sh.preauth.remove(self.id);
        self.sh
            .preauth_recovery
            .admit(self.id, self.evicted.clone(), MAX_PREAUTH_RECOVERY);
        self.recovery = true;
    }
}

impl Drop for PreauthSlot {
    fn drop(&mut self) {
        if self.recovery {
            self.sh.preauth_recovery.remove(self.id);
        } else {
            self.sh.preauth.remove(self.id);
        }
    }
}

/// An authenticated session's place under the per-device cap.
struct DeviceSlot {
    sh: Rc<Shared>,
    device: DeviceId,
}

impl DeviceSlot {
    fn take(sh: &Rc<Shared>, device: DeviceId) -> Option<Self> {
        let mut per = sh.per_device.borrow_mut();
        let n = per.entry(device).or_insert(0);
        if *n >= MAX_SESSIONS_PER_DEVICE {
            return None;
        }
        *n += 1;
        Some(Self {
            sh: sh.clone(),
            device,
        })
    }
}

impl Drop for DeviceSlot {
    fn drop(&mut self) {
        let mut per = self.sh.per_device.borrow_mut();
        if let Some(n) = per.get_mut(&self.device) {
            *n -= 1;
            if *n == 0 {
                per.remove(&self.device);
            }
        }
    }
}

/// What the session authenticated with; re-checked on roster changes.
struct Auth {
    device_id: DeviceId,
    key: KeyKind,
    sig: Signature,
    handshake_hash: [u8; 32],
    remote_static: X25519Public,
    recovery: bool,
}

impl Auth {
    fn verify(&self, roster: &SignedRoster, grace_deadline: Option<Instant>) -> bool {
        let remaining = grace_deadline.map(|d| {
            u64::try_from(d.saturating_duration_since(Instant::now()).as_millis())
                .unwrap_or(u64::MAX)
        });
        let clock = RecoveryClock::with_grace_remaining(crate::now_ms(), remaining);
        noise::verify_device_auth(
            &roster.roster,
            &self.device_id,
            self.key,
            &self.sig,
            &self.handshake_hash,
            &self.remote_static,
            self.recovery,
            clock,
        )
        .is_ok()
    }

    fn op_allowed(&self, op: &Op) -> bool {
        match self.key {
            KeyKind::Device => true,
            KeyKind::Monitor => op.monitor_allowed(),
            KeyKind::Recovery => op.recovery_allowed(),
        }
    }
}

/// Token bucket, refilled continuously.
struct RateLimit {
    per_minute: u32,
    tokens: f64,
    last: Instant,
}

impl RateLimit {
    fn new(per_minute: u32) -> Self {
        Self {
            per_minute,
            tokens: f64::from(per_minute),
            last: Instant::now(),
        }
    }

    fn set(&mut self, per_minute: u32) {
        self.per_minute = per_minute;
        self.tokens = self.tokens.min(f64::from(per_minute));
    }

    fn take(&mut self) -> bool {
        let now = Instant::now();
        let cap = f64::from(self.per_minute);
        let refill = now.duration_since(self.last).as_secs_f64() * cap / 60.0;
        self.tokens = (self.tokens + refill).min(cap);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Result of inspecting one chunk from the client.
enum Verdict {
    Forward,
    /// Refuse this frame with a gate-originated message; keep the session.
    Reply(Box<Message>),
    /// The client rekeyed its sending direction: rekey our receiving one.
    Rekey,
    Close,
}

struct Relay {
    auth: Auth,
    rate: RateLimit,
    /// Client frame ids whose first chunk passed and whose last hasn't.
    partial: Vec<u32>,
}

impl Relay {
    fn inspect(&mut self, chunk: &[u8]) -> Verdict {
        let Ok((hdr, data)) = parse_chunk(chunk) else {
            return Verdict::Close;
        };
        if let Some(i) = self.partial.iter().position(|id| *id == hdr.frame_id) {
            if hdr.last {
                self.partial.swap_remove(i);
            }
            return Verdict::Forward;
        }
        // First chunk of a new frame. Rekey is Noise control, not a
        // command: not rate limited, never forwarded.
        if Message::kind_tag(data) == Some(MessageKind::Rekey) {
            let ok = hdr.last && decode::<Message>(data).is_ok_and(|m| m == Message::Rekey);
            return if ok { Verdict::Rekey } else { Verdict::Close };
        }
        let limited = !self.rate.take();
        if !hdr.last {
            if limited || self.partial.len() >= MAX_PARTIAL {
                return Verdict::Close;
            }
            return match Message::kind_tag(data) {
                Some(MessageKind::Request | MessageKind::StreamOpen) => {
                    self.partial.push(hdr.frame_id);
                    Verdict::Forward
                }
                _ => Verdict::Close,
            };
        }
        let Ok(msg) = decode::<Message>(data) else {
            return Verdict::Close;
        };
        match msg {
            Message::Request { id, cmd } => {
                if limited {
                    return Verdict::Reply(response(id, ErrorCode::Busy));
                }
                if !self.command_ok(&cmd) {
                    return Verdict::Reply(response(id, ErrorCode::Unauthorized));
                }
                Verdict::Forward
            }
            Message::StreamOpen { id, cmd } => {
                let refuse = if limited {
                    Some(ErrorCode::Busy)
                } else if !self.command_ok(&cmd) {
                    Some(ErrorCode::Unauthorized)
                } else {
                    None
                };
                match refuse {
                    Some(code) => Verdict::Reply(Box::new(Message::StreamEnd {
                        id,
                        status: Err(code),
                    })),
                    None => Verdict::Forward,
                }
            }
            Message::StreamCancel { .. } if !limited => Verdict::Forward,
            _ => Verdict::Close,
        }
    }

    /// Session mode (an early filter; exec checks again). A body that
    /// doesn't decode goes to exec, which answers a signed
    /// `InvalidArgument` if the envelope signature verifies.
    fn command_ok(&self, cmd: &SignedCommand) -> bool {
        cmd.key == self.auth.key
            && cmd
                .decode_body()
                .ok()
                .is_none_or(|b| self.auth.op_allowed(&b.op))
    }
}

/// Gate-originated refusal. Unsigned: the Mac treats it as advisory
/// ("outcome unknown"), never as proof (design §5.6).
fn response(id: u32, code: ErrorCode) -> Box<Message> {
    Box::new(Message::Response {
        id,
        result: Err(code),
        receipt: None,
    })
}

async fn read_noise<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> Option<Vec<u8>> {
    frame::read_frame(r, MAX_STREAM_FRAME).await.ok().flatten()
}

/// Encrypts and sends a gate-originated single-chunk message (setup only).
async fn send_own<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    t: &mut Transport,
    sh: &Shared,
    msg: &Message,
) -> Option<()> {
    if encode(msg).len() > MAX_CHUNK_DATA {
        return None;
    }
    let ct = t.encrypt(&sh.own_chunk(msg)).ok()?;
    frame::write_frame(w, &ct, MAX_STREAM_FRAME).await.ok()
}

/// Outgoing rekey schedule: the protocol's (`needs_rekey`) or, if
/// configured, a shorter interval.
struct Rekeyer {
    interval: Option<Duration>,
    last: Instant,
}

impl Rekeyer {
    /// Encrypts `chunk`, first sending `Message::Rekey` under the old key
    /// and advancing the key when due. Returns the ciphertexts in order.
    fn seal(&mut self, t: &mut Transport, sh: &Shared, chunk: &[u8]) -> Option<Vec<Vec<u8>>> {
        let now = crate::now_ms();
        let mut out = Vec::with_capacity(2);
        let due = t.needs_rekey(now) || self.interval.is_some_and(|i| self.last.elapsed() >= i);
        if due {
            out.push(t.encrypt(&sh.own_chunk(&Message::Rekey)).ok()?);
            t.rekey_outgoing(now);
            self.last = Instant::now();
        }
        out.push(t.encrypt(chunk).ok()?);
        Some(out)
    }
}

struct Setup {
    exec_r: tokio::net::unix::OwnedReadHalf,
    exec_w: tokio::net::unix::OwnedWriteHalf,
    relay: Relay,
    transport: Transport,
    device: DeviceSlot,
}

async fn session(stream: UnixStream, sh: Rc<Shared>, mut slot: PreauthSlot) -> Option<()> {
    let (mut br, mut bw) = stream.into_split();
    let evicted = slot.evicted.clone();
    let setup = tokio::select! {
        r = tokio::time::timeout(SETUP_TIMEOUT, setup(&mut br, &mut bw, &sh, &mut slot)) => r.ok()??,
        () = evicted.notified() => return None,
    };
    // Authenticated: the setup slot is free again.
    drop(slot);
    let Setup {
        mut exec_r,
        mut exec_w,
        relay,
        transport,
        device: _device,
    } = setup;
    let relay = RefCell::new(relay);
    let transport = RefCell::new(transport);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(32);

    // Both directions; owns `tx`, so when either ends the writer still
    // drains what was queued (e.g. the response to the roster update that
    // ended this session) and then stops.
    let pump = async {
        let tx = tx;
        let up = client_to_exec(&mut br, &mut exec_w, &transport, &relay, &sh, &tx);
        let down = exec_to_client(&mut exec_r, &relay, &sh, &tx);
        tokio::select! {
            _ = up => {},
            _ = down => {},
        }
    };
    // Single writer, so Noise nonces (and rekeys) go out in order.
    let writer = async {
        let mut rekey = Rekeyer {
            interval: sh.rekey_interval,
            last: Instant::now(),
        };
        while let Some(chunk) = rx.recv().await {
            // Encrypt under one borrow; never hold it across an await.
            let cts = rekey.seal(&mut transport.borrow_mut(), &sh, &chunk)?;
            for ct in &cts {
                frame::write_frame(&mut bw, ct, MAX_STREAM_FRAME)
                    .await
                    .ok()?;
            }
        }
        None::<()>
    };
    tokio::join!(pump, writer);
    Some(())
}

type ExecWrite = tokio::net::unix::OwnedWriteHalf;
type ExecRead = tokio::net::unix::OwnedReadHalf;

async fn client_to_exec(
    br: &mut tokio::net::unix::OwnedReadHalf,
    exec_w: &mut ExecWrite,
    transport: &RefCell<Transport>,
    relay: &RefCell<Relay>,
    sh: &Shared,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Option<()> {
    loop {
        let ct = read_noise(br).await?;
        let pt = transport.borrow_mut().decrypt(&ct).ok()?;
        let verdict = relay.borrow_mut().inspect(&pt);
        match verdict {
            Verdict::Forward => ipc::write_msg(exec_w, &IpcMsg::Chunk(pt)).await.ok()?,
            Verdict::Reply(msg) => tx.send(sh.own_chunk(&msg)).await.ok()?,
            Verdict::Rekey => transport.borrow_mut().rekey_incoming(),
            Verdict::Close => return None,
        }
    }
}

async fn exec_to_client(
    exec_r: &mut ExecRead,
    relay: &RefCell<Relay>,
    sh: &Shared,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Option<()> {
    loop {
        match ipc::read_msg(exec_r).await.ok()?? {
            IpcMsg::Chunk(c) => tx.send(c).await.ok()?,
            IpcMsg::RosterUpdate {
                roster,
                grace_remaining_ms,
            } => {
                let r = sh.accept_roster(&roster)?;
                // End the session if its DeviceAuth no longer holds
                // (device removed, keys changed, recovery grace over).
                if !relay
                    .borrow()
                    .auth
                    .verify(&r, grace_deadline(grace_remaining_ms))
                {
                    return None;
                }
            }
            IpcMsg::Limits {
                commands_per_minute,
            } => relay.borrow_mut().rate.set(commands_per_minute.max(1)),
            IpcMsg::SessionOpen { .. } | IpcMsg::ControlOpen => return None,
        }
    }
}

async fn setup(
    br: &mut tokio::net::unix::OwnedReadHalf,
    bw: &mut tokio::net::unix::OwnedWriteHalf,
    sh: &Rc<Shared>,
    slot: &mut PreauthSlot,
) -> Option<Setup> {
    let (mode, client_ip) = crate::bridge::read_header(br).await?;
    let recovery = mode == BridgeMode::Recovery;
    if recovery {
        slot.move_to_recovery();
    }
    // Without a roster from exec no session can be authenticated.
    let (roster, seen) = sh.roster.borrow().clone()?;

    // Noise XX, responder.
    let mut hs = Handshake::responder(&sh.key, &noise::prologue(mode.header())).ok()?;
    hs.read_message(&read_noise(br).await?).ok()?;
    let m2 = hs.write_message(&[]).ok()?;
    frame::write_frame(bw, &m2, MAX_STREAM_FRAME).await.ok()?;
    hs.read_message(&read_noise(br).await?).ok()?;
    let mut t = hs.into_transport(crate::now_ms()).ok()?;

    // DeviceAuth: one chunk.
    let pt = t.decrypt(&read_noise(br).await?).ok()?;
    let (hdr, data) = parse_chunk(&pt).ok()?;
    if !hdr.last {
        return None;
    }
    let Message::DeviceAuth {
        device_id,
        key,
        sig,
    } = decode::<Message>(data).ok()?
    else {
        return None;
    };
    let auth = Auth {
        device_id,
        key,
        sig,
        handshake_hash: *t.handshake_hash(),
        remote_static: *t.remote_static(),
        recovery,
    };
    if !auth.verify(&roster, seen) {
        // Session-level refusal: request id 0 (design §5.3 "Removed from
        // the roster").
        send_own(bw, &mut t, sh, &response(0, ErrorCode::Unauthorized)).await;
        return None;
    }
    let Some(device) = DeviceSlot::take(sh, device_id) else {
        send_own(bw, &mut t, sh, &response(0, ErrorCode::Busy)).await;
        return None;
    };

    // Authenticated: now open this session's exec stream, and re-check
    // against the roster exec sends on it (it may be newer).
    let exec = UnixStream::connect(&sh.paths.exec_sock).await.ok()?;
    let (mut exec_r, mut exec_w) = exec.into_split();
    let (mut fresh, mut cpm) = (None, sh.cpm.get());
    while fresh.is_none() {
        match ipc::read_msg(&mut exec_r).await.ok()?? {
            IpcMsg::RosterUpdate {
                roster: r,
                grace_remaining_ms,
            } => fresh = Some((sh.accept_roster(&r)?, grace_deadline(grace_remaining_ms))),
            IpcMsg::Limits {
                commands_per_minute,
            } => cpm = commands_per_minute.max(1),
            _ => return None,
        }
    }
    let (fresh, fresh_seen) = fresh?;
    if !auth.verify(&fresh, fresh_seen) {
        send_own(bw, &mut t, sh, &response(0, ErrorCode::Unauthorized)).await;
        return None;
    }
    let open = IpcMsg::SessionOpen {
        mode: mode.header(),
        device_id,
        key,
        client_ip,
    };
    ipc::write_msg(&mut exec_w, &open).await.ok()?;
    Some(Setup {
        exec_r,
        exec_w,
        relay: Relay {
            auth,
            rate: RateLimit::new(cpm),
            partial: Vec::new(),
        },
        transport: t,
        device,
    })
}
