//! Shared helpers for this crate's unit tests.

use crate::handler::{Invocation, OpMeta};
use crate::{FakeRunner, ManualClock, SysCtx};
use fleet_crypto::verify::VerifiedCommand;
use fleet_proto::{Actor, CommandBody, DeviceId, FleetId, KeyKind, Op, ServerId};
use std::path::Path;
use std::rc::Rc;

/// A realistic wall-clock instant (2023-11-14) for time-sensitive tests.
pub const T0: u64 = 1_700_000_000_000;

/// Meta for `op` at time 0; `seq` is the audit intent seq (`None` = validate stage).
pub fn meta(op: Op, seq: Option<u64>) -> OpMeta {
    meta_at(op, seq, 0)
}

/// Meta for `op` issued and verified at `now_ms`.
pub fn meta_at(op: Op, seq: Option<u64>, now_ms: u64) -> OpMeta {
    OpMeta {
        command: VerifiedCommand {
            body: CommandBody {
                v: 1,
                fleet_id: FleetId([1; 16]),
                server_id: ServerId::new("srv_test01").unwrap(),
                issued_at_ms: now_ms,
                ttl_ms: 60_000,
                nonce: [0; 16],
                actor: Actor::Human,
                op,
                expected_version: None,
            },
            device_id: DeviceId([2; 16]),
            key: KeyKind::Device,
            approval: None,
            command_hash: [0; 32],
            nonce_expires_at_ms: 0,
        },
        approval: None,
        audit_seq: seq,
        now_ms,
        invocation: Invocation::Request,
    }
}

/// Context rooted at `root` with the clock at 0.
pub fn ctx(root: &Path, runner: Rc<FakeRunner>) -> SysCtx {
    ctx_at(root, runner, 0)
}

/// Context rooted at `root` with the clock at `now_ms`.
pub fn ctx_at(root: &Path, runner: Rc<FakeRunner>, now_ms: u64) -> SysCtx {
    SysCtx::new(root, runner, Rc::new(ManualClock::new(now_ms)))
}

/// Context rooted at a directory that does not exist, clock at [`T0`].
pub fn ctx_empty() -> SysCtx {
    ctx_at(
        Path::new("/nonexistent-fleet-test-root"),
        Rc::new(FakeRunner::new()),
        T0,
    )
}

/// Runs `f` to completion on a fresh current-thread runtime.
pub fn block<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}
