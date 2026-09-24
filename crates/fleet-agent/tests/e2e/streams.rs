//! Stream sessions: `StreamOpen` → verified `StreamData`… `StreamEnd`, both
//! straight to exec (as the gate) and through the gate over Noise.
//! fleet-core has no stream client yet, so these tests speak the protocol
//! directly and check every chunk with `fleet_crypto::stream::StreamVerifier`.

use super::*;
use fleet_crypto::stream::{StreamItem, StreamVerifier};
use fleet_ops::{
    Invocation, LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, SysCtx, VecStream,
};
use fleet_proto::{SystemInfo, op::tag};
use std::rc::Rc;
use tokio::io::AsyncWriteExt;

/// Test-only `system.info`: a request answers one item, `StreamOpen`
/// streams `n` of them.
struct TestStream {
    n: u32,
    interval: Option<Duration>,
    big: bool,
    latest_only: bool,
}

impl TestStream {
    fn finite(n: u32) -> Self {
        Self {
            n,
            interval: None,
            big: false,
            latest_only: false,
        }
    }
}

fn item(i: u32, big: bool) -> Payload {
    Payload::SystemInfo(SystemInfo {
        hostname: if big {
            "h".repeat(4000)
        } else {
            format!("item{i}")
        },
        os_id: String::new(),
        os_version: String::new(),
        kernel: String::new(),
        arch: String::new(),
        cpu_count: i,
        mem_total_bytes: 0,
        uptime_s: 0,
    })
}

impl OpHandler for TestStream {
    fn supports(&self, _: &Op, _: Invocation) -> bool {
        true
    }

    fn handle<'a>(
        &'a self,
        _: &'a SysCtx,
        _: &'a Op,
        meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            if meta.invocation == Invocation::Request {
                return Ok(OpOutput::Payload(item(0, false)));
            }
            let mut s = VecStream::new((0..self.n).map(|i| Ok(item(i, self.big))));
            if let Some(d) = self.interval {
                s = s.interval(d);
            }
            if self.latest_only {
                s = s.latest_only();
            }
            Ok(OpOutput::Stream(Box::new(s)))
        })
    }
}

/// Fixture whose exec streams `system.info` via `make()`.
fn fixture(pol: Pol, make: fn() -> TestStream) -> Fixture {
    let mut fx = Fixture::with(
        1,
        0,
        Opts {
            pol,
            ..Opts::default()
        },
    );
    fx.exec = None;
    fx.start_exec_with(move |cfg| {
        cfg.handlers.push((tag::SYSTEM_INFO, Rc::new(make())));
        cfg.stream_checkpoint_interval = Duration::from_millis(50);
    });
    fx
}

fn signed(fx: &Fixture, mac: &Mac, op: Op) -> SignedCommand {
    let mut nonce = [0u8; 16];
    fleet_crypto::random_bytes(&mut nonce).unwrap();
    let body = encode(&CommandBody {
        v: PROTO_VERSION,
        fleet_id: fx.fleet,
        server_id: fx.server.clone(),
        issued_at_ms: now_ms(),
        ttl_ms: 60_000,
        nonce,
        actor: Actor::Human,
        op,
        expected_version: None,
    });
    let msg = SignedCommand::signed_message(KeyKind::Device, &mac.id, &body);
    SignedCommand {
        signature: mac.device.sign(&msg).unwrap(),
        body,
        device_id: mac.id,
        key: KeyKind::Device,
        approval: None,
    }
}

/// Everything received for one stream, every chunk verified.
struct StreamLog {
    id: u32,
    v: StreamVerifier,
    data: Vec<Payload>,
    checkpoints: u32,
    fin: Option<(Outcome, Option<u64>)>,
    end: Option<Result<(), ErrorCode>>,
}

impl StreamLog {
    fn new(fx: &Fixture, cmd: &SignedCommand, id: u32) -> Self {
        Self {
            id,
            v: StreamVerifier::new(fx.keys.signing_key, fx.server.clone(), command_hash(cmd)),
            data: Vec::new(),
            checkpoints: 0,
            fin: None,
            end: None,
        }
    }

    /// Takes one message (others' are ignored); `true` at this `StreamEnd`.
    fn on(&mut self, m: &Message) -> bool {
        match m {
            Message::StreamData { id, seq, chunk } if *id == self.id => {
                match self.v.accept(*seq, chunk).expect("chunk verifies") {
                    StreamItem::Data(d) => self.data.push(decode(&d).unwrap()),
                    StreamItem::Checkpoint { .. } => self.checkpoints += 1,
                    StreamItem::Final {
                        outcome, audit_seq, ..
                    } => self.fin = Some((outcome, audit_seq)),
                }
                false
            }
            Message::StreamEnd { id, status } if *id == self.id => {
                self.end = Some(*status);
                true
            }
            _ => false,
        }
    }
}

/// Straight to exec as the gate's uid (exec never trusts the gate, so the
/// stream must verify all the same).
struct ExecConn {
    s: UnixStream,
    reasm: Reassembler,
    next: u32,
}

impl ExecConn {
    async fn open(fx: &Fixture, mac: &Mac) -> Self {
        let mut s = UnixStream::connect(&fx.paths.exec_sock).await.unwrap();
        for _ in 0..2 {
            ipc::read_msg(&mut s).await.unwrap().unwrap();
        }
        let open = IpcMsg::SessionOpen {
            mode: 0,
            device_id: mac.id,
            key: KeyKind::Device,
        };
        ipc::write_msg(&mut s, &open).await.unwrap();
        let mut c = Self {
            s,
            reasm: Reassembler::for_exec(),
            next: 0,
        };
        assert!(matches!(c.recv().await, Message::Hello { .. }));
        c
    }

    async fn send(&mut self, msg: &Message) {
        self.next += 1;
        for c in split_frame(self.next, &encode(msg)) {
            ipc::write_msg(&mut self.s, &IpcMsg::Chunk(c))
                .await
                .unwrap();
        }
    }

    async fn recv(&mut self) -> Message {
        next_message(&mut self.s, &mut self.reasm).await
    }

    async fn drain(&mut self, log: &mut StreamLog) {
        while !log.on(&self.recv().await) {}
    }
}

/// Mac-side Noise session through the gate, speaking raw frames.
struct GateConn {
    s: UnixStream,
    t: Transport,
    reasm: Reassembler,
    next: u32,
}

impl GateConn {
    async fn open(fx: &Fixture, mac: &Mac) -> Self {
        let mut s = UnixStream::connect(&fx.paths.agent_sock).await.unwrap();
        s.write_all(&[0]).await.unwrap();
        let mut hs = Handshake::initiator(&mac.noise, &noise::prologue(0)).unwrap();
        let m1 = hs.write_message(&[]).unwrap();
        frame::write_frame(&mut s, &m1, MAX_STREAM_FRAME)
            .await
            .unwrap();
        let m2 = frame::read_frame(&mut s, MAX_STREAM_FRAME)
            .await
            .unwrap()
            .unwrap();
        hs.read_message(&m2).unwrap();
        let m3 = hs.write_message(&[]).unwrap();
        frame::write_frame(&mut s, &m3, MAX_STREAM_FRAME)
            .await
            .unwrap();
        let t = hs.into_transport(now_ms()).unwrap();
        let auth_msg = Message::device_auth_message(KeyKind::Device, &mac.id, t.handshake_hash());
        let auth = Message::DeviceAuth {
            device_id: mac.id,
            key: KeyKind::Device,
            sig: mac.device.sign(&auth_msg).unwrap(),
        };
        let mut c = Self {
            s,
            t,
            reasm: Reassembler::for_exec(),
            next: 0,
        };
        c.send(&auth).await;
        loop {
            if let Message::Hello { .. } = c.recv().await {
                return c;
            }
        }
    }

    async fn send(&mut self, msg: &Message) {
        self.next += 1;
        for c in split_frame(self.next, &encode(msg)) {
            let ct = self.t.encrypt(&c).unwrap();
            frame::write_frame(&mut self.s, &ct, MAX_STREAM_FRAME)
                .await
                .unwrap();
        }
    }

    async fn recv(&mut self) -> Message {
        loop {
            let ct = frame::read_frame(&mut self.s, MAX_STREAM_FRAME)
                .await
                .unwrap()
                .unwrap();
            let pt = self.t.decrypt(&ct).unwrap();
            if let Some((_, f)) = self.reasm.push(&pt).unwrap() {
                return decode(&f).unwrap();
            }
        }
    }
}

#[test]
fn stream_to_exec_verified_then_replay_refused() {
    let fx = fixture(Pol::default(), || TestStream::finite(40));
    run(async {
        let m = &fx.macs[0];
        let mut c = ExecConn::open(&fx, m).await;
        let cmd = signed(&fx, m, Op::SystemInfo);
        c.send(&Message::StreamOpen {
            id: 7,
            cmd: cmd.clone(),
        })
        .await;
        let mut log = StreamLog::new(&fx, &cmd, 7);
        c.drain(&mut log).await;
        assert_eq!(log.data.len(), 40);
        assert_eq!(log.data[39], item(39, false));
        assert!(log.checkpoints >= 1, "checkpoint after 32 chunks");
        let (outcome, audit_seq) = log.fin.expect("signed final seal");
        assert_eq!(outcome, Outcome::Ok);
        assert!(audit_seq.is_some());
        assert_eq!(log.end, Some(Ok(())));

        // The same envelope again: its nonce is spent. Signed refusal.
        c.send(&Message::StreamOpen {
            id: 8,
            cmd: cmd.clone(),
        })
        .await;
        let mut log = StreamLog::new(&fx, &cmd, 8);
        c.drain(&mut log).await;
        assert_eq!(log.fin, Some((Outcome::Failed(ErrorCode::Replay), None)));
        assert_eq!(log.end, Some(Err(ErrorCode::Replay)));
        assert!(log.data.is_empty());

        // Requests still work next to streams.
        let req = signed(&fx, m, Op::SystemInfo);
        c.send(&Message::Request { id: 9, cmd: req }).await;
        match c.recv().await {
            Message::Response { id: 9, result, .. } => assert_eq!(result, Ok(item(0, false))),
            other => panic!("{other:?}"),
        }
    });
}

#[test]
fn stream_rejections_session_limit_and_cancel() {
    let pol = Pol {
        max_streams: 1,
        ..Pol::default()
    };
    let fx = fixture(pol, || TestStream {
        interval: Some(Duration::from_millis(20)),
        ..TestStream::finite(10_000)
    });
    run(async {
        let m = &fx.macs[0];
        let mut c = ExecConn::open(&fx, m).await;

        // Forged signature: refused with a signed final seal, no audit.
        let mut bad = signed(&fx, m, Op::SystemInfo);
        bad.signature = Signature([0; 64]);
        c.send(&Message::StreamOpen {
            id: 1,
            cmd: bad.clone(),
        })
        .await;
        let mut log = StreamLog::new(&fx, &bad, 1);
        c.drain(&mut log).await;
        assert_eq!(
            log.fin,
            Some((Outcome::Failed(ErrorCode::SignatureInvalid), None))
        );

        // One long stream takes the only slot.
        let long = signed(&fx, m, Op::SystemInfo);
        c.send(&Message::StreamOpen {
            id: 2,
            cmd: long.clone(),
        })
        .await;
        let mut long_log = StreamLog::new(&fx, &long, 2);
        while long_log.data.len() < 3 {
            assert!(!long_log.on(&c.recv().await));
        }
        let second = signed(&fx, m, Op::SystemInfo);
        c.send(&Message::StreamOpen {
            id: 3,
            cmd: second.clone(),
        })
        .await;
        let mut log = StreamLog::new(&fx, &second, 3);
        loop {
            let msg = c.recv().await;
            assert!(!long_log.on(&msg));
            if log.on(&msg) {
                break;
            }
        }
        assert_eq!(log.fin, Some((Outcome::Failed(ErrorCode::Busy), None)));

        // Cancel: signed Ok final, and the slot is free again.
        c.send(&Message::StreamCancel { id: 2 }).await;
        c.drain(&mut long_log).await;
        let (outcome, audit_seq) = long_log.fin.expect("final seal");
        assert_eq!((outcome, long_log.end), (Outcome::Ok, Some(Ok(()))));
        assert!(audit_seq.is_some());
        assert!(long_log.checkpoints >= 1, "time-based checkpoints");

        let third = signed(&fx, m, Op::SystemInfo);
        c.send(&Message::StreamOpen {
            id: 4,
            cmd: third.clone(),
        })
        .await;
        let mut log = StreamLog::new(&fx, &third, 4);
        while log.data.is_empty() {
            assert!(!log.on(&c.recv().await));
        }
        c.send(&Message::StreamCancel { id: 4 }).await;
        c.drain(&mut log).await;
        assert_eq!(log.fin.map(|f| f.0), Some(Outcome::Ok));
    });
}

#[test]
fn latest_only_stream_drops_instead_of_blocking() {
    let fx = fixture(Pol::default(), || TestStream {
        big: true,
        latest_only: true,
        ..TestStream::finite(2_000)
    });
    run(async {
        let m = &fx.macs[0];
        let mut c = ExecConn::open(&fx, m).await;
        let cmd = signed(&fx, m, Op::SystemInfo);
        c.send(&Message::StreamOpen {
            id: 1,
            cmd: cmd.clone(),
        })
        .await;
        // A slow client: ~8 MB of items can't all queue.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut log = StreamLog::new(&fx, &cmd, 1);
        c.drain(&mut log).await;
        assert!(
            !log.data.is_empty() && log.data.len() < 2_000,
            "{}",
            log.data.len()
        );
        assert_eq!(log.fin.map(|f| f.0), Some(Outcome::Ok));
    });
}

#[test]
fn stream_through_gate_verified() {
    let fx = fixture(Pol::default(), || TestStream::finite(70));
    run(async {
        let m = &fx.macs[0];
        let mut c = GateConn::open(&fx, m).await;
        let cmd = signed(&fx, m, Op::SystemInfo);
        c.send(&Message::StreamOpen {
            id: 5,
            cmd: cmd.clone(),
        })
        .await;
        let mut log = StreamLog::new(&fx, &cmd, 5);
        while !log.on(&c.recv().await) {}
        assert_eq!(log.data.len(), 70);
        assert!(log.checkpoints >= 2);
        assert_eq!(log.fin.map(|f| f.0), Some(Outcome::Ok));
        assert_eq!(log.end, Some(Ok(())));

        // Cancel through the gate.
        let fx_cmd = signed(&fx, m, Op::SystemInfo);
        c.send(&Message::StreamOpen {
            id: 6,
            cmd: fx_cmd.clone(),
        })
        .await;
        c.send(&Message::StreamCancel { id: 6 }).await;
        let mut log = StreamLog::new(&fx, &fx_cmd, 6);
        while !log.on(&c.recv().await) {}
        assert_eq!(log.fin.map(|f| f.0), Some(Outcome::Ok));
    });
}
