//! `Session::connect_bridged` and cancel-safe `next_event` against a
//! minimal fake agent over a tiny in-memory pipe (forces partial reads).

use fleet_core::{CommandSigner, Session, SessionConfig, SessionMode, now_ms};
use fleet_crypto::noise::{self, Handshake, StaticKeypair};
use fleet_crypto::receipt::{receipt_for, sign_event, sign_receipt};
use fleet_crypto::sig::{Ed25519Signer, SoftwareP256Signer};
use fleet_crypto::verify::command_hash;
use fleet_proto::chunk::{Reassembler, split_frame};
use fleet_proto::{
    Actor, AgentHealth, AgentVersion, DeviceId, Event, FleetId, KeyKind, Message, Op,
    PROTO_VERSION, Payload, ServerId, decode, encode,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

const T: Duration = Duration::from_secs(10);
const RUN: [u8; 16] = [5; 16];

struct Agent {
    io: DuplexStream,
    t: fleet_crypto::noise::Transport,
    reasm: Reassembler,
    frame: u32,
}

async fn read_raw(io: &mut DuplexStream) -> Vec<u8> {
    let mut len = [0u8; 4];
    io.read_exact(&mut len).await.unwrap();
    let mut b = vec![0u8; u32::from_be_bytes(len) as usize];
    io.read_exact(&mut b).await.unwrap();
    b
}

async fn write_raw(io: &mut DuplexStream, m: &[u8]) {
    io.write_all(&(m.len() as u32).to_be_bytes()).await.unwrap();
    io.write_all(m).await.unwrap();
}

impl Agent {
    async fn send(&mut self, m: &Message) {
        self.frame += 1;
        for c in split_frame(self.frame, &encode(m)) {
            let ct = self.t.encrypt(&c).unwrap();
            write_raw(&mut self.io, &ct).await;
        }
    }

    async fn recv(&mut self) -> Message {
        loop {
            let ct = read_raw(&mut self.io).await;
            let pt = self.t.decrypt(&ct).unwrap();
            if let Some((_, f)) = self.reasm.push(&pt).unwrap() {
                return decode(&f).unwrap();
            }
        }
    }
}

async fn fake_agent(
    mut io: DuplexStream,
    key: StaticKeypair,
    signing: Ed25519Signer,
    server: ServerId,
    mut events: mpsc::UnboundedReceiver<Event>,
) {
    // Bridged: no mode byte on the wire; normal-mode prologue.
    let mut hs = Handshake::responder(&key, &noise::prologue(SessionMode::Normal as u8)).unwrap();
    hs.read_message(&read_raw(&mut io).await).unwrap();
    let m = hs.write_message(&[]).unwrap();
    write_raw(&mut io, &m).await;
    hs.read_message(&read_raw(&mut io).await).unwrap();
    let mut a = Agent {
        io,
        t: hs.into_transport(now_ms()).unwrap(),
        reasm: Reassembler::for_exec(),
        frame: 0,
    };
    assert!(matches!(a.recv().await, Message::DeviceAuth { .. }));
    a.send(&Message::Hello {
        proto_min: PROTO_VERSION,
        proto_max: PROTO_VERSION,
        agent_version: AgentVersion {
            major: 0,
            minor: 1,
            patch: 0,
        },
        server_id: server.clone(),
        time_ms: now_ms(),
        roster_epoch: 1,
        roster_version: 1,
        pending_recovery: None,
    })
    .await;
    let mut seq = 0;
    loop {
        tokio::select! {
            m = a.recv() => {
                let Message::Request { id, cmd } = m else { panic!("unexpected message") };
                let result = Ok(match cmd.decode_body().unwrap().op {
                    Op::AgentHealth => Payload::AgentHealth(AgentHealth {
                        agent_version: AgentVersion { major: 0, minor: 1, patch: 0 },
                        proto_version: PROTO_VERSION,
                        uptime_s: 1,
                        gate_rss_bytes: 0,
                        exec_rss_bytes: 0,
                        audit_seq: 0,
                        roster_epoch: 1,
                        roster_version: 1,
                        policy_version: 1,
                        pending_recovery: None,
                        run_id: RUN,
                    }),
                    _ => Payload::Empty,
                });
                let receipt = sign_receipt(
                    receipt_for(server.clone(), command_hash(&cmd), None, &result, now_ms()),
                    &signing,
                );
                a.send(&Message::Response { id, result, receipt: Some(receipt) }).await;
            }
            e = events.recv() => {
                let Some(e) = e else { return };
                seq += 1;
                let se = sign_event(server.clone(), RUN, seq, now_ms(), e, &signing);
                a.send(&Message::Event(se)).await;
            }
        }
    }
}

#[tokio::test]
async fn bridged_session_next_event_is_cancel_safe() {
    let server = ServerId::new("srv_000001").unwrap();
    let agent_noise = StaticKeypair::generate().unwrap();
    let agent_signing = Ed25519Signer::from_seed(&[8; 32]);
    let pinned_noise = agent_noise.public();
    let pinned_signing = agent_signing.public();
    // 16-byte pipe: every Noise message arrives in many pieces.
    let (client_io, agent_io) = tokio::io::duplex(16);
    let (ev_tx, ev_rx) = mpsc::unbounded_channel();
    tokio::spawn(fake_agent(
        agent_io,
        agent_noise,
        agent_signing,
        server.clone(),
        ev_rx,
    ));

    let mac_noise = StaticKeypair::generate().unwrap();
    let device = SoftwareP256Signer::generate().unwrap();
    let cfg = SessionConfig {
        mode: SessionMode::Normal,
        noise: &mac_noise,
        pinned_agent_noise: pinned_noise,
        pinned_agent_signing: pinned_signing,
        fleet_id: FleetId([1; 16]),
        server_id: server.clone(),
        device_id: DeviceId([2; 16]),
        key: KeyKind::Device,
        signer: CommandSigner::P256(&device),
    };
    let mut s = timeout(T, Session::connect_bridged(client_io, cfg))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(s.status().health.as_ref().unwrap().run_id, RUN);

    // Idle waits that get cancelled must not lose bytes.
    for _ in 0..5 {
        assert!(
            timeout(Duration::from_millis(2), s.next_event())
                .await
                .is_err()
        );
    }
    let evs: Vec<Event> = (1..=3)
        .map(|v| Event::PolicyChanged { version: v })
        .collect();
    for e in &evs {
        ev_tx.send(e.clone()).unwrap();
    }
    let mut got = Vec::new();
    timeout(T, async {
        while got.len() < 3 {
            // Cancel constantly, mid-message.
            if let Ok(r) = timeout(Duration::from_micros(50), s.next_event()).await {
                got.push(r.unwrap());
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        got,
        evs.iter()
            .cloned()
            .enumerate()
            .map(|(i, e)| (i as u64 + 1, e))
            .collect::<Vec<_>>()
    );
    // The session is still in sync.
    let r = s
        .request(Op::SystemInfo, &server, Actor::Human, None)
        .await
        .unwrap();
    assert_eq!(r.result, Ok(Payload::Empty));
    assert_eq!(s.rejected_events(), 0);
}
