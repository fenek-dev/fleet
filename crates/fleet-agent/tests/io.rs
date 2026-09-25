//! Framing, reassembly, bridge relay, revert and argv tests.

use fleet_agent::bridge::{self, BridgeMode};
use fleet_agent::cli::{self, Mode};
use fleet_agent::frame::{
    self, FrameError, MAX_CHUNK_DATA, MAX_STREAM_FRAME, Reassembler, ReassemblyError,
};
use fleet_agent::ipc::{self, IpcError, IpcMsg};
use fleet_agent::pending::{ChangeId, ChangeKind, PendingChange, PendingDir, RevertedMarker};
use fleet_agent::revert::{self, Revert, RevertError, RevertOutcome, UnavailableRevert};
use fleet_agent::store::{Intent, Store};
use fleet_ops::{CommandOutput, CommandRunner, CommandSpec, LocalBoxFuture, RunError};
use fleet_proto::{Actor, DeviceId, OpSummary, Outcome, Phase, ResultSummary, Signature};
use std::cell::RefCell;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct NoopRevert;
impl Revert for NoopRevert {
    fn revert(&self, _: ChangeKind, _: &[u8], _: Option<u64>) -> Result<(), RevertError> {
        Ok(())
    }
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn frame_roundtrip_and_oversize() {
    rt().block_on(async {
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        frame::write_frame(&mut a, b"hello", MAX_STREAM_FRAME)
            .await
            .unwrap();
        frame::write_frame(&mut a, b"", MAX_STREAM_FRAME)
            .await
            .unwrap();
        assert!(matches!(
            frame::write_frame(&mut a, &vec![0; MAX_STREAM_FRAME + 1], MAX_STREAM_FRAME).await,
            Err(FrameError::TooLarge(_))
        ));
        // Oversize length prefix from a peer is rejected before allocating.
        a.write_all(&(u32::MAX).to_be_bytes()).await.unwrap();
        drop(a);
        assert_eq!(
            frame::read_frame(&mut b, MAX_STREAM_FRAME)
                .await
                .unwrap()
                .unwrap(),
            b"hello"
        );
        assert_eq!(
            frame::read_frame(&mut b, MAX_STREAM_FRAME)
                .await
                .unwrap()
                .unwrap(),
            b""
        );
        assert!(matches!(
            frame::read_frame(&mut b, MAX_STREAM_FRAME).await,
            Err(FrameError::TooLarge(_))
        ));
    });
}

#[test]
fn frame_truncation_and_clean_eof() {
    rt().block_on(async {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&10u32.to_be_bytes()).await.unwrap();
        a.write_all(b"abc").await.unwrap();
        drop(a);
        assert!(matches!(
            frame::read_frame(&mut b, 100).await,
            Err(FrameError::Truncated)
        ));
        let (a, mut b) = tokio::io::duplex(64);
        drop(a);
        assert!(frame::read_frame(&mut b, 100).await.unwrap().is_none());
    });
}

#[test]
fn reassembler_roundtrip_and_limits() {
    let data: Vec<u8> = (0..(MAX_CHUNK_DATA * 2 + 10)).map(|i| i as u8).collect();
    let chunks = frame::split_frame(7, &data);
    assert_eq!(chunks.len(), 3);
    let mut r = Reassembler::new(data.len(), 2);
    assert_eq!(r.push(&chunks[0]).unwrap(), None);
    // Interleaved single-chunk frame passes through unbuffered.
    let small = frame::split_frame(8, b"x");
    assert_eq!(r.push(&small[0]).unwrap(), Some((8, b"x".to_vec())));
    assert_eq!(r.push(&chunks[1]).unwrap(), None);
    assert_eq!(r.push(&chunks[2]).unwrap(), Some((7, data.clone())));
    assert_eq!(r.buffered(), 0);

    // Frame limit.
    let mut r = Reassembler::new(data.len() - 1, 2);
    r.push(&chunks[0]).unwrap();
    r.push(&chunks[1]).unwrap();
    assert_eq!(r.push(&chunks[2]), Err(ReassemblyError::FrameTooLarge(7)));
    assert_eq!(r.buffered(), 0);

    // Partial-frame limit.
    let mut r = Reassembler::new(1 << 20, 2);
    for id in 0..2 {
        r.push(&frame::split_frame(id, &data)[0]).unwrap();
    }
    assert_eq!(
        r.push(&frame::split_frame(9, &data)[0]),
        Err(ReassemblyError::TooManyPartial)
    );

    // Malformed chunks.
    let mut r = Reassembler::for_exec();
    assert_eq!(r.push(&[0, 0, 0]), Err(ReassemblyError::ShortChunk));
    assert_eq!(
        r.push(&[0, 0, 0, 1, 0x80]),
        Err(ReassemblyError::BadFlags(0x80))
    );
    let mut big = vec![0, 0, 0, 1, 1];
    big.extend(vec![0; MAX_CHUNK_DATA + 1]);
    assert!(matches!(
        r.push(&big),
        Err(ReassemblyError::ChunkTooLarge(_))
    ));
    assert_eq!(frame::split_frame(3, b"").len(), 1);
    assert_eq!(
        r.push(&frame::split_frame(3, b"")[0]).unwrap(),
        Some((3, vec![]))
    );
}

#[test]
fn bridge_relays_both_ways() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let (mut ssh_side, bridge_in) = tokio::io::duplex(1024);
        let (bridge_out, mut ssh_out) = tokio::io::duplex(1024);

        let gate = async {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut hdr = [0u8; 1];
            s.read_exact(&mut hdr).await.unwrap();
            assert_eq!(BridgeMode::from_header(hdr[0]), Some(BridgeMode::Recovery));
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            s.write_all(b"pong").await.unwrap();
            // Gate closes: bridge must exit even though stdin stays open.
        };
        let client = async {
            ssh_side.write_all(b"ping").await.unwrap();
            let mut buf = [0u8; 4];
            ssh_out.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong");
        };
        let run = bridge::run(&sock, BridgeMode::Recovery, None, bridge_in, bridge_out);
        let (r, (), ()) = tokio::join!(run, gate, client);
        r.unwrap();
        drop(ssh_side);
    });
}

#[test]
fn bridge_stdin_eof_first_still_relays_output() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let (bridge_out, mut ssh_out) = tokio::io::duplex(1024);
        let hint = bridge::ssh_client_ip("203.0.113.5 50000 192.0.2.1 22").unwrap();
        let gate = async {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut rest = Vec::new();
            // Header (with the client-address hint), then EOF (stdin was
            // empty): the write half is shut.
            s.read_to_end(&mut rest).await.unwrap();
            assert_eq!(rest[..2], [bridge::HINT_FLAG, 11]);
            assert_eq!(
                bridge::read_header(&mut &rest[..]).await,
                Some((BridgeMode::Normal, Some(hint)))
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            s.write_all(b"late reply").await.unwrap();
        };
        let run = bridge::run(
            &sock,
            BridgeMode::Normal,
            Some(hint),
            tokio::io::empty(),
            bridge_out,
        );
        let (r, ()) = tokio::join!(run, gate);
        r.unwrap();
        let mut got = Vec::new();
        ssh_out.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"late reply");
    });
}

#[test]
fn ipc_rejects_trailing_bytes() {
    rt().block_on(async {
        let mut bytes = fleet_proto::encode(&IpcMsg::ControlOpen);
        bytes.push(0);
        let mut buf = Vec::new();
        frame::write_frame(&mut buf, &bytes, ipc::MAX_IPC_FRAME)
            .await
            .unwrap();
        let r = ipc::read_msg(&mut &buf[..]).await;
        assert!(matches!(r, Err(IpcError::Malformed)), "{r:?}");
    });
}

#[test]
fn unavailable_reverter_reports_failure() {
    let dir = tempfile::tempdir().unwrap();
    let dir = PendingDir::new(dir.path().join("pending"), dir.path().join("reverted"));
    dir.create().unwrap();
    let id = ChangeId([6; 16]);
    let change = PendingChange {
        kind: ChangeKind::Ssh,
        origin: Default::default(),
        snapshot: vec![],
        deadline_ms: 1,
        audit_seq: 1,
        applying: false,
    };
    dir.insert(id, &change).unwrap();
    assert_eq!(
        revert::run_revert(&dir, id, &UnavailableRevert, 2).unwrap(),
        RevertOutcome::Failed
    );
    assert!(!dir.markers().unwrap()[0].1.restored);
    // Double revert: once claimed, a second runner finds nothing.
    dir.insert(ChangeId([7; 16]), &change).unwrap();
    assert!(dir.claim(ChangeId([7; 16])).unwrap());
    assert_eq!(
        revert::run_revert(&dir, ChangeId([7; 16]), &NoopRevert, 3).unwrap(),
        RevertOutcome::NotPending
    );
}

#[test]
fn bridge_fails_without_socket() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let r = bridge::run(
            &dir.path().join("missing.sock"),
            BridgeMode::Normal,
            None,
            tokio::io::empty(),
            tokio::io::sink(),
        )
        .await;
        assert!(r.is_err());
    });
}

/// Records commands; exits with `code`.
struct Recorder(RefCell<Vec<CommandSpec>>, i32);
impl CommandRunner for Recorder {
    fn run(&self, spec: CommandSpec) -> LocalBoxFuture<'_, Result<CommandOutput, RunError>> {
        Box::pin(std::future::ready(self.run_blocking(spec)))
    }
    fn run_blocking(&self, spec: CommandSpec) -> Result<CommandOutput, RunError> {
        self.0.borrow_mut().push(spec);
        Ok(CommandOutput::exit(self.1))
    }
}

fn argv(s: &CommandSpec) -> Vec<String> {
    s.args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
}

#[test]
fn revert_timer_argv() {
    let id = ChangeId([0xab; 16]);
    let hex = "ab".repeat(16);
    let rec = Recorder(RefCell::default(), 0);
    revert::arm_timer(&rec, id, 60).unwrap();
    revert::arm_guard(&rec, id, 120).unwrap();
    revert::disarm_timer(&rec, id).unwrap();
    let cmds = rec.0.into_inner();
    assert_eq!(cmds[0].program, "/usr/bin/systemd-run");
    assert_eq!(
        argv(&cmds[0]),
        vec![
            "--on-active=60".to_owned(),
            "--timer-property=AccuracySec=1s".to_owned(),
            format!("--unit=fleet-revert-{hex}"),
            "/usr/lib/fleet/fleet-agent".to_owned(),
            "revert".to_owned(),
            hex.clone(),
        ]
    );
    assert!(cmds[0].timeout <= std::time::Duration::from_secs(10));
    assert!(argv(&cmds[1]).contains(&format!("--unit=fleet-revert-{hex}-guard")));
    assert_eq!(cmds[2].program, "/usr/bin/systemctl");
    assert_eq!(
        argv(&cmds[2]),
        vec![
            "stop".to_owned(),
            format!("fleet-revert-{hex}.timer"),
            format!("fleet-revert-{hex}-guard.timer"),
        ]
    );
    // A failing systemd-run is an error (no timer, no apply).
    let bad = Recorder(RefCell::default(), 1);
    assert!(revert::arm_timer(&bad, id, 60).is_err());
}

/// Restores only while the state still has the change's version.
struct Versioned(u64, RefCell<u32>);
impl Revert for Versioned {
    fn revert(&self, _: ChangeKind, _: &[u8], _: Option<u64>) -> Result<(), RevertError> {
        *self.1.borrow_mut() += 1;
        Ok(())
    }
    fn current_version(&self, _: ChangeKind, _: &[u8]) -> Option<u64> {
        Some(self.0)
    }
}

#[test]
fn revert_keeps_state_changed_since() {
    let dir = tempfile::tempdir().unwrap();
    let dir = PendingDir::new(dir.path().join("pending"), dir.path().join("reverted"));
    dir.create().unwrap();
    let mut change = PendingChange {
        kind: ChangeKind::Firewall,
        origin: Default::default(),
        snapshot: vec![],
        deadline_ms: 1,
        audit_seq: 1,
        applying: false,
    };
    change.origin.new_version = Some(8);
    let (a, b) = (ChangeId([1; 16]), ChangeId([2; 16]));
    dir.insert(a, &change).unwrap();
    dir.insert(b, &change).unwrap();
    // Still at the change's version: restored.
    let same = Versioned(8, RefCell::default());
    assert_eq!(
        revert::run_revert(&dir, a, &same, 5).unwrap(),
        RevertOutcome::Reverted
    );
    assert_eq!(*same.1.borrow(), 1);
    // Changed again since: kept, marker records the conflict.
    let moved = Versioned(9, RefCell::default());
    assert_eq!(
        revert::run_revert(&dir, b, &moved, 6).unwrap(),
        RevertOutcome::Kept
    );
    assert_eq!(*moved.1.borrow(), 0);
    let m = dir.markers().unwrap();
    let m = &m.iter().find(|(id, _)| *id == b).unwrap().1;
    assert_eq!((m.restored, m.conflict), (false, Some(9)));
}

#[test]
fn pending_update_never_resurrects_a_claimed_change() {
    let dir = tempfile::tempdir().unwrap();
    let p = PendingDir::new(dir.path().join("pending"), dir.path().join("reverted"));
    p.create().unwrap();
    let id = ChangeId([3; 16]);
    let mut c = PendingChange {
        kind: ChangeKind::Firewall,
        origin: Default::default(),
        snapshot: vec![],
        deadline_ms: 1,
        audit_seq: 1,
        applying: true,
    };
    p.insert(id, &c).unwrap();
    c.applying = false;
    assert!(p.update(id, &c).unwrap());
    assert_eq!(p.get(id).unwrap(), Some(c.clone()));
    assert!(p.claim(id).unwrap());
    assert!(!p.update(id, &c).unwrap());
    assert_eq!(p.get(id).unwrap(), None);
    // An update cut short by a crash is repaired at startup.
    let id2 = ChangeId([4; 16]);
    p.insert(id2, &c).unwrap();
    std::fs::rename(
        dir.path().join(format!("pending/{id2}.bin")),
        dir.path().join(format!("pending/{id2}.updating")),
    )
    .unwrap();
    p.repair_updates().unwrap();
    assert_eq!(p.get(id2).unwrap(), Some(c));
}

#[test]
fn revert_runs_once_and_audits() {
    let dir = tempfile::tempdir().unwrap();
    let s = Store::open(dir.path().join("state.redb")).unwrap();
    let origin = s
        .audit()
        .append_intent(Intent {
            time_ms: 1,
            actor: Actor::Human,
            device_id: DeviceId([1; 16]),
            command_hash: [5; 32],
            signature: Signature([0; 64]),
            op: OpSummary {
                tag: 400,
                args: vec![],
            },
        })
        .unwrap();
    s.audit().append_result(origin, 2, Outcome::Ok).unwrap();
    // The revert process works on files only (exec holds the redb lock).
    let dir = PendingDir::new(dir.path().join("pending"), dir.path().join("reverted"));
    dir.create().unwrap();
    let id = ChangeId([4; 16]);
    dir.insert(
        id,
        &PendingChange {
            kind: ChangeKind::Firewall,
            origin: Default::default(),
            snapshot: vec![],
            deadline_ms: 10,
            audit_seq: origin,
            applying: false,
        },
    )
    .unwrap();
    let out = revert::run_revert(&dir, id, &NoopRevert, 70).unwrap();
    assert_eq!(out, RevertOutcome::Reverted);
    assert_eq!(dir.get(id).unwrap(), None);
    let markers = dir.markers().unwrap();
    assert_eq!(
        markers,
        vec![(
            id,
            RevertedMarker {
                kind: ChangeKind::Firewall,
                origin_audit_seq: origin,
                restored: true,
                time_ms: 70,
                conflict: None,
            }
        )]
    );
    assert_eq!(
        revert::run_revert(&dir, id, &NoopRevert, 71).unwrap(),
        RevertOutcome::NotPending
    );

    // What exec does with the marker.
    let seq = s.audit().append_revert(origin, 72, true).unwrap();
    let e = s.audit().get(seq).unwrap().unwrap();
    assert_eq!(e.actor, Actor::System);
    assert_eq!(e.phase, Phase::Result);
    assert_eq!(e.command_hash, [5; 32]);
    assert_eq!(e.result, ResultSummary::Done(Outcome::Reverted));
    s.audit().verify_chain(1).unwrap();
}

#[test]
fn cli_parse() {
    assert_eq!(cli::parse(&["gate"]), Some(Mode::Gate));
    assert_eq!(
        cli::parse(&["bridge", "--recovery"]),
        Some(Mode::Bridge(BridgeMode::Recovery))
    );
    let hex = "0f".repeat(16);
    assert_eq!(
        cli::parse(&["revert", hex.as_str()]),
        Some(Mode::Revert(ChangeId([0x0f; 16])))
    );
    assert_eq!(cli::parse(&["revert", "0F".repeat(16).as_str()]), None);
    assert_eq!(cli::parse(&["revert"]), None);
    // Extra argv (a forced command's user input) never widens a bridge.
    assert_eq!(
        cli::parse(&["bridge", "--x"]),
        Some(Mode::Bridge(BridgeMode::Normal))
    );
    for args in [
        &["bridge", "--monitor"][..],
        &["bridge", "--monitor", "--x"],
        &["bridge", "--x", "--monitor"],
        &["bridge", "--recovery", "--monitor"],
    ] {
        assert_eq!(
            cli::parse(args),
            Some(Mode::Bridge(BridgeMode::Monitor)),
            "{args:?}"
        );
    }
    assert_eq!(
        cli::parse(&["bridge", "--recovery", "sh"]),
        Some(Mode::Bridge(BridgeMode::Recovery))
    );
    assert_eq!(BridgeMode::from_header(2), Some(BridgeMode::Monitor));
    assert_eq!(BridgeMode::from_header(3), None);
    assert_eq!(cli::parse::<&str>(&[]), None);
    assert_eq!(cli::parse(&["gate", "extra"]), None);
}
