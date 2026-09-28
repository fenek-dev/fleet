//! `SignedCommand` decode + `verify_command` against the golden roster.
//! Must never panic; the context mirrors the golden command so the seed
//! reaches the signature check.
#![no_main]

#[path = "common.rs"]
mod common;

use std::sync::LazyLock;

use fleet_crypto::verify::{MemoryReplayStore, VerifyCtx, verify_command};
use fleet_proto::{CommandBody, SignedCommand, SignedRoster, decode};
use libfuzzer_sys::fuzz_target;

static ROSTER: LazyLock<SignedRoster> = LazyLock::new(common::roster);
static BODY: LazyLock<CommandBody> =
    LazyLock::new(|| decode(&common::command().body).expect("golden body"));

fuzz_target!(|data: &[u8]| {
    let Ok(cmd) = decode::<SignedCommand>(data) else {
        return;
    };
    let _ = decode::<CommandBody>(&cmd.body);
    let replay = MemoryReplayStore::default();
    for session in [cmd.key, fleet_proto::KeyKind::Device] {
        let ctx = VerifyCtx::new(&ROSTER.roster, &BODY.server_id, BODY.issued_at_ms, session);
        if let Ok(v) = verify_command(&cmd, &ctx, &replay) {
            let mut r = MemoryReplayStore::default();
            let _ = v.commit(&mut r);
        }
    }
});
