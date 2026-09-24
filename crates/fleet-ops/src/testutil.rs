//! Shared test helpers.

use crate::handler::{Invocation, OpMeta};
use crate::{FakeRunner, ManualClock, SysCtx};
use fleet_crypto::verify::VerifiedCommand;
use fleet_proto::{Actor, CommandBody, DeviceId, FleetId, KeyKind, Op, ServerId};
use std::path::Path;
use std::rc::Rc;

/// Meta for `op`; `seq` is the audit intent seq (`None` = validate stage).
pub fn meta(op: Op, seq: Option<u64>) -> OpMeta {
    OpMeta {
        command: VerifiedCommand {
            body: CommandBody {
                v: 1,
                fleet_id: FleetId([1; 16]),
                server_id: ServerId::new("srv_test01").unwrap(),
                issued_at_ms: 0,
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
        now_ms: 0,
        invocation: Invocation::Request,
    }
}

pub fn ctx(root: &Path, runner: Rc<FakeRunner>) -> SysCtx {
    SysCtx::new(root, runner, Rc::new(ManualClock::new(0)))
}

pub fn block<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}
