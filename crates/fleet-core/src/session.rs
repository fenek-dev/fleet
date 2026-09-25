//! Agent session client, transport-agnostic.
//!
//! [`Session::connect`] sends the bridge mode byte (the caller *is* the
//! bridge: tests on the gate socket), [`Session::connect_bridged`] leaves it
//! to `fleet-agent bridge` (SSH exec channel). Both then run the Noise XX
//! initiator with the Mac's static key, refuses an agent whose static key
//! isn't the pinned one, authenticates with `DeviceAuth`, reads the
//! advisory `Hello` (protocol version check only) and then confirms roster
//! and recovery state with a signed read ([`Session::status`]).
//! [`Session::request`] builds, signs and sends a `CommandBody` and requires
//! a receipt signed by the pinned agent key, bound to this server, the exact
//! command sent and the exact result received — for every response, reads
//! and errors included. A signed `Replay` for a state-changing command is
//! "outcome unknown" (the first delivery may have run). Events are accepted
//! only with a valid agent signature, the exec run id from the signed
//! `agent.health`, a time not before the session start and increasing
//! sequence numbers.
//!
//! Reads are cancel-safe ([`Session::next_event`] can sit in `select!`):
//! partial Noise messages stay buffered in the session.
//!
//! **Streams** ([`Session::open_stream`], design §6.3): each `StreamData`
//! runs through a `fleet_crypto::stream::StreamVerifier` bound to the pinned
//! agent key, this server and the exact `StreamOpen` command. Items are
//! delivered as they arrive (provisional: the next signed checkpoint, at
//! most `CHECKPOINT_EVERY` chunks or ~5 s later, covers them and is
//! reported as [`StreamEvent::Verified`]); a seal that doesn't match ends
//! the stream with [`StreamFailure::Verification`], so a tampering gate can
//! at most delay the failure by one checkpoint window. A `StreamEnd`
//! without a verified final seal is reported as
//! [`StreamFailure::Unsigned`] ("outcome unknown"), never as success.
//! Stream frames are routed from every read loop (`send`, `next_event`),
//! so streams keep flowing while requests wait for their responses.

use fleet_crypto::noise::{self, Handshake, StaticKeypair, Transport};
use fleet_crypto::receipt::{verify_event, verify_response};
use fleet_crypto::sig::{self, Ed25519Signer, Signer};
use fleet_crypto::stream::{StreamError, StreamItem, StreamVerifier};
use fleet_crypto::verify::{DEFAULT_SKEW_MS, DEFAULT_TTL_MS, command_hash};
use fleet_proto::chunk::{NOISE_MAX_MSG, Reassembler, split_frame};
use fleet_proto::{
    Actor, AgentHealth, AgentVersion, CommandBody, DeviceId, Ed25519Public, ErrorCode, Event,
    FleetId, KeyKind, Message, Op, Outcome, PROTO_VERSION, Payload, PendingRecovery, RequestId,
    RootApproval, ServerId, Signature, SignedCommand, SignedEvent, SignedReceipt, Tier,
    X25519Public, decode, encode,
};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

/// Events kept until [`Session::take_events`]; older ones are dropped.
pub const MAX_BUFFERED_EVENTS: usize = 1024;

/// Delivery queue per stream. A consumer that falls this far behind has
/// its stream cancelled (the session never blocks on a slow consumer).
pub const STREAM_QUEUE: usize = 1024;

/// What a stream consumer receives, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    /// One decoded item. Provisional until a later `Verified` covers it.
    Item(Payload),
    /// A signed checkpoint covering every item so far verified.
    Verified { count: u64 },
    /// The stream is over: `Ok` only with a verified final seal.
    End(Result<Outcome, StreamFailure>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StreamFailure {
    /// A seal did not verify or did not match the data received
    /// (injected, dropped or reordered chunks).
    #[error("stream verification failed: {0}")]
    Verification(StreamError),
    /// `StreamEnd` without a verified final seal (gate refusal, cut stream).
    #[error("stream ended without a signed seal (claimed {claimed:?})")]
    Unsigned { claimed: Option<ErrorCode> },
    /// A data chunk did not decode as a `Payload`.
    #[error("malformed stream item")]
    Malformed,
}

struct OpenStream {
    verifier: StreamVerifier,
    tx: mpsc::Sender<StreamEvent>,
    /// From the verified final seal, reported at `StreamEnd`.
    outcome: Option<Outcome>,
}

/// First byte on the agent socket (design §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMode {
    Normal = 0,
    Recovery = 1,
}

/// Signs `DeviceAuth` and commands. On a Mac the P-256 keys are Secure
/// Enclave callbacks; the recovery key exists only in memory during recovery.
#[derive(Clone, Copy)]
pub enum CommandSigner<'a> {
    P256(&'a dyn Signer),
    Recovery(&'a Ed25519Signer),
}

impl CommandSigner<'_> {
    fn sign(&self, msg: &[u8]) -> Result<Signature, ClientError> {
        match self {
            CommandSigner::P256(s) => sig::p256_sign(*s, msg).map_err(ClientError::Crypto),
            CommandSigner::Recovery(k) => Ok(k.sign(msg)),
        }
    }
}

pub struct SessionConfig<'a> {
    pub mode: SessionMode,
    /// This Mac's Noise static key (a recovering Mac: a fresh one).
    pub noise: &'a StaticKeypair,
    pub pinned_agent_noise: X25519Public,
    /// Agent Ed25519 key that must sign receipts and events.
    pub pinned_agent_signing: Ed25519Public,
    pub fleet_id: FleetId,
    /// Expected in `Hello`, receipts and events.
    pub server_id: ServerId,
    pub device_id: DeviceId,
    pub key: KeyKind,
    pub signer: CommandSigner<'a>,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto: {0}")]
    Crypto(fleet_crypto::Error),
    #[error("agent Noise key does not match the pinned key")]
    AgentKeyMismatch,
    /// Session refused (unsigned, from the gate) or the signed status read
    /// at connect failed.
    #[error("session refused: {0:?}")]
    Rejected(ErrorCode),
    #[error("connection closed")]
    Closed,
    #[error("malformed frame from agent")]
    Malformed,
    #[error("Hello is for another server")]
    WrongServer,
    #[error("agent supports protocol {min}..={max}, we speak {PROTO_VERSION}")]
    ProtoVersion { min: u16, max: u16 },
    /// A state-changing command got no valid receipt, or a signed `Replay`
    /// (its first delivery may have run and the answer been dropped): it may
    /// or may not have run. `claimed` is the error in the response, if any
    /// (e.g. `Busy` from the gate's rate limit).
    #[error("outcome unknown (no valid receipt; claimed {claimed:?})")]
    OutcomeUnknown { claimed: Option<ErrorCode> },
    /// A read without a receipt (gate-originated refusal or tampering).
    #[error("response without a receipt (claimed {claimed:?})")]
    MissingReceipt { claimed: Option<ErrorCode> },
    #[error("receipt invalid or not for this command")]
    BadReceipt,
}

impl From<fleet_crypto::Error> for ClientError {
    fn from(e: fleet_crypto::Error) -> Self {
        ClientError::Crypto(e)
    }
}

/// The agent's `Hello`. **Advisory**: unsigned, so a compromised gate can
/// forge it. Used only for version negotiation and the clock-skew warning;
/// roster and recovery state come from [`Session::status`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloInfo {
    pub proto_min: u16,
    pub proto_max: u16,
    pub agent_version: AgentVersion,
    pub server_id: ServerId,
    pub time_ms: u64,
}

/// Agent state from the receipted read done at connect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedStatus {
    /// `agent.health` (device and monitor sessions). `None` in recovery
    /// sessions, which may only read `roster.pending`.
    pub health: Option<AgentHealth>,
    pub pending_recovery: Option<PendingRecovery>,
}

/// A response whose receipt verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub result: Result<Payload, ErrorCode>,
    pub receipt: SignedReceipt,
}

/// Envelope fields a caller may override (tests, canary pacing).
#[derive(Debug, Clone, Default)]
pub struct CommandOpts {
    pub issued_at_ms: Option<u64>,
    pub ttl_ms: Option<u32>,
    pub expected_version: Option<u64>,
}

pub struct Session<'a, S> {
    stream: S,
    /// Bytes read but not yet a complete Noise message (cancel safety).
    rbuf: Vec<u8>,
    transport: Transport,
    reasm: Reassembler,
    cfg: SessionConfig<'a>,
    hello: HelloInfo,
    status: VerifiedStatus,
    next_frame: u32,
    next_request: u32,
    events: VecDeque<(u64, Event)>,
    /// Exec run whose events this session accepts: `None` until the signed
    /// status read at connect (events meanwhile wait in `early_events`),
    /// `Some(None)` when that read carries no run id (recovery sessions:
    /// events are refused).
    run_id: Option<Option<[u8; 16]>>,
    early_events: Vec<SignedEvent>,
    /// Wall time at connect; older events are refused (minus skew).
    session_start_ms: u64,
    /// Last event seq accepted in this session (exec restarts begin a new
    /// run, and its counter restarts too).
    last_event_seq: Option<u64>,
    event_gaps: u64,
    rejected_events: u64,
    rekey_interval: Option<Duration>,
    last_rekey: Instant,
    streams: HashMap<RequestId, OpenStream>,
    /// Streams to cancel on the agent (consumer gone or too slow), sent on
    /// the next write opportunity (reads never write: cancel safety).
    cancels: Vec<RequestId>,
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Anything but a read (undecodable bodies count as state-changing).
fn changes_state(cmd: &SignedCommand) -> bool {
    cmd.decode_body()
        .map(|b| b.op.tier() != Tier::Read)
        .unwrap_or(true)
}

/// Pops one complete length-prefixed Noise message off `buf`, if present.
fn take_noise(buf: &mut Vec<u8>) -> Result<Option<Vec<u8>>, ClientError> {
    let Some(len) = buf.first_chunk::<4>() else {
        return Ok(None);
    };
    let len = u32::from_be_bytes(*len) as usize;
    if len > NOISE_MAX_MSG {
        return Err(ClientError::Malformed);
    }
    if buf.len() < 4 + len {
        return Ok(None);
    }
    let msg = buf[4..4 + len].to_vec();
    buf.drain(..4 + len);
    Ok(Some(msg))
}

/// Reads one Noise message. Cancel-safe: bytes read so far stay in `buf`
/// (a single `read` either completes or consumes nothing).
async fn read_noise<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
) -> Result<Vec<u8>, ClientError> {
    loop {
        if let Some(msg) = take_noise(buf)? {
            return Ok(msg);
        }
        let mut tmp = [0u8; 16 * 1024];
        let n = r.read(&mut tmp).await?;
        if n == 0 {
            return Err(ClientError::Closed);
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

async fn write_noise<W: AsyncWrite + Unpin>(w: &mut W, msg: &[u8]) -> Result<(), ClientError> {
    let mut buf = Vec::with_capacity(4 + msg.len());
    buf.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    buf.extend_from_slice(msg);
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

impl<'a, S: AsyncRead + AsyncWrite + Unpin> Session<'a, S> {
    /// Connects straight to the gate socket: sends the bridge mode byte
    /// itself, then runs the session setup.
    pub async fn connect(stream: S, cfg: SessionConfig<'a>) -> Result<Self, ClientError> {
        Self::setup(stream, cfg, true).await
    }

    /// Connects through `fleet-agent bridge [--recovery]` (an SSH exec
    /// channel): the bridge writes the mode byte to the gate, so none is
    /// sent here. `cfg.mode` must match how the bridge was started; it is
    /// still bound into the Noise prologue.
    pub async fn connect_bridged(stream: S, cfg: SessionConfig<'a>) -> Result<Self, ClientError> {
        Self::setup(stream, cfg, false).await
    }

    async fn setup(
        mut stream: S,
        cfg: SessionConfig<'a>,
        send_mode: bool,
    ) -> Result<Self, ClientError> {
        let session_start_ms = now_ms();
        let mode = cfg.mode as u8;
        if send_mode {
            stream.write_all(&[mode]).await?;
        }
        let mut rbuf = Vec::new();
        let mut hs = Handshake::initiator(cfg.noise, &noise::prologue(mode))?;
        write_noise(&mut stream, &hs.write_message(&[])?).await?;
        hs.read_message(&read_noise(&mut stream, &mut rbuf).await?)?;
        // Check the agent's identity before sending anything of ours.
        if hs.remote_static() != Some(cfg.pinned_agent_noise) {
            return Err(ClientError::AgentKeyMismatch);
        }
        write_noise(&mut stream, &hs.write_message(&[])?).await?;
        let transport = hs.into_transport(now_ms())?;

        let auth_msg =
            Message::device_auth_message(cfg.key, &cfg.device_id, transport.handshake_hash());
        let auth = Message::DeviceAuth {
            device_id: cfg.device_id,
            key: cfg.key,
            sig: cfg.signer.sign(&auth_msg)?,
        };
        let mut s = Session {
            stream,
            rbuf,
            transport,
            reasm: Reassembler::for_exec(),
            hello: HelloInfo {
                proto_min: 0,
                proto_max: 0,
                agent_version: AgentVersion {
                    major: 0,
                    minor: 0,
                    patch: 0,
                },
                server_id: cfg.server_id.clone(),
                time_ms: 0,
            },
            status: VerifiedStatus {
                health: None,
                pending_recovery: None,
            },
            cfg,
            next_frame: 0,
            next_request: 1,
            events: VecDeque::new(),
            run_id: None,
            early_events: Vec::new(),
            session_start_ms,
            last_event_seq: None,
            event_gaps: 0,
            rejected_events: 0,
            rekey_interval: None,
            last_rekey: Instant::now(),
            streams: HashMap::new(),
            cancels: Vec::new(),
        };
        s.send_message(&auth).await?;
        loop {
            match s.read_message().await? {
                Message::Hello {
                    proto_min,
                    proto_max,
                    agent_version,
                    server_id,
                    time_ms,
                    ..
                } => {
                    if server_id != s.cfg.server_id {
                        return Err(ClientError::WrongServer);
                    }
                    if !(proto_min..=proto_max).contains(&PROTO_VERSION) {
                        return Err(ClientError::ProtoVersion {
                            min: proto_min,
                            max: proto_max,
                        });
                    }
                    s.hello = HelloInfo {
                        proto_min,
                        proto_max,
                        agent_version,
                        server_id,
                        time_ms,
                    };
                    break;
                }
                Message::Response {
                    result: Err(code), ..
                } => return Err(ClientError::Rejected(code)),
                Message::Event(e) => s.accept_event(e),
                _ => return Err(ClientError::Malformed),
            }
        }
        s.status = s.read_status().await?;
        s.run_id = Some(s.status.health.as_ref().map(|h| h.run_id));
        for e in std::mem::take(&mut s.early_events) {
            s.accept_event(e);
        }
        Ok(s)
    }

    /// Signed roster/recovery state: `agent.health`, or `roster.pending` in
    /// a recovery session.
    async fn read_status(&mut self) -> Result<VerifiedStatus, ClientError> {
        let server = self.cfg.server_id.clone();
        let (op, actor) = match self.cfg.key {
            KeyKind::Recovery => (Op::RosterPending, Actor::Recovery),
            _ => (Op::AgentHealth, Actor::Human),
        };
        match self.request(op, &server, actor, None).await?.result {
            Ok(Payload::AgentHealth(h)) => Ok(VerifiedStatus {
                pending_recovery: h.pending_recovery,
                health: Some(h),
            }),
            Ok(Payload::RosterPending(p)) => Ok(VerifiedStatus {
                health: None,
                pending_recovery: p,
            }),
            Ok(_) => Err(ClientError::Malformed),
            Err(code) => Err(ClientError::Rejected(code)),
        }
    }

    pub fn hello(&self) -> &HelloInfo {
        &self.hello
    }

    /// Agent state verified at connect (see [`VerifiedStatus`]).
    pub fn status(&self) -> &VerifiedStatus {
        &self.status
    }

    /// Rekey the sending direction at least this often, on top of the
    /// protocol schedule. For tests.
    pub fn set_rekey_interval(&mut self, interval: Option<Duration>) {
        self.rekey_interval = interval;
    }

    /// Verified events received so far (while waiting for responses), at
    /// most [`MAX_BUFFERED_EVENTS`], oldest first.
    pub fn take_events(&mut self) -> Vec<(u64, Event)> {
        self.events.drain(..).collect()
    }

    /// Events dropped for a bad signature, wrong server, another exec run,
    /// a time before this session, or a non-increasing seq (a forging or
    /// replaying gate, or tampering).
    pub fn rejected_events(&self) -> u64 {
        self.rejected_events
    }

    /// Times an accepted event's seq skipped ahead (events were lost).
    pub fn event_gaps(&self) -> u64 {
        self.event_gaps
    }

    fn accept_event(&mut self, e: SignedEvent) {
        let run_id = match self.run_id {
            Some(Some(id)) => id,
            Some(None) => {
                self.rejected_events += 1;
                return;
            }
            None => {
                // Before the signed status names the run: hold (bounded).
                if self.early_events.len() < MAX_BUFFERED_EVENTS {
                    self.early_events.push(e);
                } else {
                    self.rejected_events += 1;
                }
                return;
            }
        };
        let ok = verify_event(&e, &self.cfg.pinned_agent_signing, &self.cfg.server_id).is_ok()
            && e.run_id == run_id
            && e.time_ms >= self.session_start_ms.saturating_sub(DEFAULT_SKEW_MS)
            && self.last_event_seq.is_none_or(|last| e.seq > last);
        if !ok {
            self.rejected_events += 1;
            return;
        }
        // Signed, this run, fresh: a skip means events were lost; count it
        // and continue from here.
        if self
            .last_event_seq
            .is_some_and(|last| e.seq != last.saturating_add(1))
        {
            self.event_gaps += 1;
        }
        self.last_event_seq = Some(e.seq);
        if self.events.len() == MAX_BUFFERED_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back((e.seq, e.event));
    }

    /// Builds and signs a command envelope without sending it.
    pub fn build_command(
        &self,
        op: Op,
        server_id: &ServerId,
        actor: Actor,
        approval: Option<RootApproval>,
        opts: &CommandOpts,
    ) -> Result<SignedCommand, ClientError> {
        let mut nonce = [0u8; 16];
        fleet_crypto::random_bytes(&mut nonce)?;
        let body = encode(&CommandBody {
            v: PROTO_VERSION,
            fleet_id: self.cfg.fleet_id,
            server_id: server_id.clone(),
            issued_at_ms: opts.issued_at_ms.unwrap_or_else(now_ms),
            ttl_ms: opts.ttl_ms.unwrap_or(DEFAULT_TTL_MS),
            nonce,
            actor,
            op,
            expected_version: opts.expected_version,
        });
        let msg = SignedCommand::signed_message(self.cfg.key, &self.cfg.device_id, &body);
        Ok(SignedCommand {
            signature: self.cfg.signer.sign(&msg)?,
            body,
            device_id: self.cfg.device_id,
            key: self.cfg.key,
            approval,
        })
    }

    /// Signs and sends `op`, returning the verified reply.
    pub async fn request(
        &mut self,
        op: Op,
        server_id: &ServerId,
        actor: Actor,
        approval: Option<RootApproval>,
    ) -> Result<Reply, ClientError> {
        let cmd = self.build_command(op, server_id, actor, approval, &CommandOpts::default())?;
        self.send(&cmd).await
    }

    /// Sends a prepared envelope (possibly one built elsewhere) and checks
    /// the reply's receipt against the pinned key and this exact envelope.
    pub async fn send(&mut self, cmd: &SignedCommand) -> Result<Reply, ClientError> {
        self.flush_cancels().await?;
        let id = self.next_id();
        self.send_message(&Message::Request {
            id,
            cmd: cmd.clone(),
        })
        .await?;
        loop {
            match self.read_message().await? {
                Message::Response {
                    id: rid,
                    result,
                    receipt,
                } if rid == id => {
                    let receipt = self.check_receipt(cmd, &result, receipt)?;
                    // A signed Replay (nonce or approval leaf already used)
                    // doesn't mean the command failed: an earlier delivery
                    // may have run with its answer dropped.
                    if result == Err(ErrorCode::Replay) && changes_state(cmd) {
                        return Err(ClientError::OutcomeUnknown {
                            claimed: Some(ErrorCode::Replay),
                        });
                    }
                    return Ok(Reply { result, receipt });
                }
                m => {
                    self.dispatch(m);
                }
            }
        }
    }

    fn next_id(&mut self) -> RequestId {
        let id = self.next_request;
        self.next_request = self.next_request.wrapping_add(1).max(1);
        id
    }

    /// Signs `op` (a stream op, [`Op::is_stream`]) and sends `StreamOpen`.
    /// Items arrive on the returned receiver while any read loop of this
    /// session runs (`send`, `next_event`). Dropping the receiver cancels
    /// the stream on the next write.
    pub async fn open_stream(
        &mut self,
        op: Op,
        actor: Actor,
    ) -> Result<(RequestId, mpsc::Receiver<StreamEvent>), ClientError> {
        self.flush_cancels().await?;
        let server = self.cfg.server_id.clone();
        let cmd = self.build_command(op, &server, actor, None, &CommandOpts::default())?;
        let id = self.next_id();
        let (tx, rx) = mpsc::channel(STREAM_QUEUE);
        let verifier =
            StreamVerifier::new(self.cfg.pinned_agent_signing, server, command_hash(&cmd));
        self.streams.insert(
            id,
            OpenStream {
                verifier,
                tx,
                outcome: None,
            },
        );
        self.send_message(&Message::StreamOpen { id, cmd }).await?;
        Ok((id, rx))
    }

    /// Stops a stream; later frames for it are ignored.
    pub async fn cancel_stream(&mut self, id: RequestId) -> Result<(), ClientError> {
        if self.streams.remove(&id).is_some() {
            self.cancels.push(id);
        }
        self.flush_cancels().await
    }

    /// Open streams.
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Sends queued `StreamCancel`s (dropped or overflowing consumers).
    pub async fn flush_cancels(&mut self) -> Result<(), ClientError> {
        while let Some(id) = self.cancels.pop() {
            self.send_message(&Message::StreamCancel { id }).await?;
        }
        Ok(())
    }

    /// Routes events and stream frames; returns anything else.
    fn dispatch(&mut self, m: Message) -> Option<Message> {
        match m {
            Message::Event(e) => self.accept_event(e),
            Message::StreamData { id, seq, chunk } => self.stream_data(id, seq, &chunk),
            Message::StreamEnd { id, status } => self.stream_end(id, status),
            other => return Some(other),
        }
        None
    }

    fn stream_data(&mut self, id: RequestId, seq: u64, chunk: &[u8]) {
        let Some(s) = self.streams.get_mut(&id) else {
            return;
        };
        let ev = match s.verifier.accept(seq, chunk) {
            Ok(StreamItem::Data(d)) => match decode::<Payload>(&d) {
                Ok(p) => StreamEvent::Item(p),
                Err(_) => return self.fail_stream(id, StreamFailure::Malformed),
            },
            Ok(StreamItem::Checkpoint { count }) => StreamEvent::Verified { count },
            Ok(StreamItem::Final { outcome, .. }) => {
                s.outcome = Some(outcome);
                return;
            }
            Err(e) => return self.fail_stream(id, StreamFailure::Verification(e)),
        };
        if s.tx.try_send(ev).is_err() {
            // Consumer gone or too slow: stop the stream.
            self.streams.remove(&id);
            self.cancels.push(id);
        }
    }

    fn fail_stream(&mut self, id: RequestId, f: StreamFailure) {
        if let Some(s) = self.streams.remove(&id) {
            let _ = s.tx.try_send(StreamEvent::End(Err(f)));
            self.cancels.push(id);
        }
    }

    fn stream_end(&mut self, id: RequestId, status: Result<(), ErrorCode>) {
        let Some(s) = self.streams.remove(&id) else {
            return;
        };
        let end = match s.outcome {
            Some(o) => Ok(o),
            None => Err(StreamFailure::Unsigned {
                claimed: status.err(),
            }),
        };
        let _ = s.tx.try_send(StreamEvent::End(end));
    }

    /// A response counts only with a receipt from the pinned agent key for
    /// this server, this command and exactly this result (design §5.6).
    fn check_receipt(
        &self,
        cmd: &SignedCommand,
        result: &Result<Payload, ErrorCode>,
        receipt: Option<SignedReceipt>,
    ) -> Result<SignedReceipt, ClientError> {
        let present = receipt.is_some();
        let valid = receipt.filter(|r| {
            verify_response(
                r,
                &self.cfg.pinned_agent_signing,
                &self.cfg.server_id,
                &command_hash(cmd),
                result,
            )
            .is_ok()
        });
        if let Some(r) = valid {
            return Ok(r);
        }
        let claimed = result.as_ref().err().copied();
        Err(if changes_state(cmd) {
            ClientError::OutcomeUnknown { claimed }
        } else if !present {
            ClientError::MissingReceipt { claimed }
        } else {
            ClientError::BadReceipt
        })
    }

    async fn send_message(&mut self, msg: &Message) -> Result<(), ClientError> {
        for chunk in split_frame(self.frame_id(), &encode(msg)) {
            self.maybe_rekey().await?;
            let ct = self.transport.encrypt(&chunk)?;
            write_noise(&mut self.stream, &ct).await?;
        }
        Ok(())
    }

    fn frame_id(&mut self) -> u32 {
        let id = self.next_frame;
        self.next_frame = self.next_frame.wrapping_add(1);
        id
    }

    /// Sends `Message::Rekey` under the old key and advances the sending
    /// key when due (design §5.5).
    async fn maybe_rekey(&mut self) -> Result<(), ClientError> {
        let now = now_ms();
        let due = self.transport.needs_rekey(now)
            || self
                .rekey_interval
                .is_some_and(|i| self.last_rekey.elapsed() >= i);
        if !due {
            return Ok(());
        }
        let chunk = split_frame(self.frame_id(), &encode(&Message::Rekey)).remove(0);
        let ct = self.transport.encrypt(&chunk)?;
        self.transport.rekey_outgoing(now);
        self.last_rekey = Instant::now();
        write_noise(&mut self.stream, &ct).await
    }

    /// Waits for the next verified event (see [`Session::take_events`] for
    /// what is accepted). Cancel-safe, so it can wait in `select!` next to a
    /// request queue; responses arriving here (no request outstanding) are
    /// dropped.
    pub async fn next_event(&mut self) -> Result<(u64, Event), ClientError> {
        loop {
            if let Some(e) = self.events.pop_front() {
                return Ok(e);
            }
            let m = self.read_message().await?;
            self.dispatch(m);
        }
    }

    /// The server this session is bound to.
    pub fn server_id(&self) -> &ServerId {
        &self.cfg.server_id
    }

    /// Key kind this session authenticated with.
    pub fn key_kind(&self) -> KeyKind {
        self.cfg.key
    }

    /// Cancel-safe: the only await is [`read_noise`]; decryption,
    /// reassembly and rekeying run without yielding.
    async fn read_message(&mut self) -> Result<Message, ClientError> {
        loop {
            let ct = read_noise(&mut self.stream, &mut self.rbuf).await?;
            let pt = self.transport.decrypt(&ct)?;
            if let Some((_, frame)) = self.reasm.push(&pt).map_err(|_| ClientError::Malformed)? {
                match decode(&frame).map_err(|_| ClientError::Malformed)? {
                    // The agent rekeyed its sending side: follow before
                    // decrypting anything else.
                    Message::Rekey => self.transport.rekey_incoming(),
                    m => return Ok(m),
                }
            }
        }
    }
}
