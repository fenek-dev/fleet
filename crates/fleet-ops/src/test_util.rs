//! Shared helpers for this crate's unit tests.

use crate::ctx::{ManualClock, SysCtx};
use crate::handler::{Invocation, OpMeta};
use crate::runner::FakeRunner;
use fleet_crypto::verify::VerifiedCommand;
use fleet_proto::{Actor, CommandBody, DeviceId, FleetId, KeyKind, Op, ServerId};
use std::path::Path;
use std::rc::Rc;

pub fn block<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

/// Context rooted at a directory that does not exist.
pub fn ctx() -> SysCtx {
    ctx_at(
        Path::new("/nonexistent-fleet-test-root"),
        Rc::new(FakeRunner::new()),
    )
}

pub fn ctx_at(root: &Path, runner: Rc<FakeRunner>) -> SysCtx {
    SysCtx::new(root, runner, Rc::new(ManualClock::new(1_700_000_000_000)))
}

pub fn meta() -> OpMeta {
    OpMeta {
        command: VerifiedCommand {
            body: CommandBody {
                v: 1,
                fleet_id: FleetId([1; 16]),
                server_id: ServerId::new("srv_test01").unwrap(),
                issued_at_ms: 1_700_000_000_000,
                ttl_ms: 30_000,
                nonce: [0; 16],
                actor: Actor::Human,
                op: Op::SystemInfo,
                expected_version: None,
            },
            device_id: DeviceId([2; 16]),
            key: KeyKind::Device,
            approval: None,
            command_hash: [0; 32],
            nonce_expires_at_ms: 0,
        },
        approval: None,
        audit_seq: Some(1),
        now_ms: 1_700_000_000_000,
        invocation: Invocation::Request,
    }
}
