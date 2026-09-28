//! `compose.deploy` validator (fleet-compose), shared by agent and Mac.
#![no_main]

#[path = "common.rs"]
mod common;

use std::sync::LazyLock;

use fleet_proto::args::ComposeProject;
use libfuzzer_sys::fuzz_target;

static PROJECT: LazyLock<ComposeProject> =
    LazyLock::new(|| ComposeProject::new("app").expect("valid name"));

fuzz_target!(|data: &[u8]| {
    let _ = fleet_compose::validate(&PROJECT, &common::text(data));
});
