//! Arbitrary candidate `SignedRoster` bytes into `roster::evaluate` (and
//! the genesis check) against the golden roster, in both directions and at
//! extreme clocks. Must never panic.
#![no_main]

#[path = "common.rs"]
mod common;

use std::sync::LazyLock;

use fleet_crypto::roster::{RecoveryClock, evaluate, roster_hash, verify_genesis};
use fleet_proto::{SignedRoster, decode};
use libfuzzer_sys::fuzz_target;

static CURRENT: LazyLock<SignedRoster> = LazyLock::new(common::roster);

fuzz_target!(|data: &[u8]| {
    let Ok(cand) = decode::<SignedRoster>(data) else {
        return;
    };
    let now = CURRENT.roster.issued_at_ms;
    let _ = verify_genesis(&cand, now);
    let hashes = [roster_hash(&cand)];
    for clock in [
        RecoveryClock::at(now),
        RecoveryClock::at(now.saturating_add(365 * 86_400_000)),
        RecoveryClock::at(u64::MAX),
    ] {
        let _ = evaluate(&CURRENT, &[], &cand, clock);
        let _ = evaluate(&CURRENT, &hashes, &cand, clock);
        let _ = evaluate(&cand, &[], &CURRENT, clock);
    }
});
