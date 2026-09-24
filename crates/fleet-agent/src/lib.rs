//! Fleet server agent library: the `fleet-agent` binary is a thin wrapper.
#![forbid(unsafe_code)]

pub mod authorized_keys;
pub mod bridge;
pub mod cli;
pub mod exec;
pub mod frame;
pub mod fsutil;
pub mod gate;
pub mod install;
pub mod ipc;
pub mod notify;
pub mod paths;
pub mod pending;
pub mod revert;
pub mod store;

/// Wall clock in Unix milliseconds (0 if the clock is before 1970).
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// This build's version, from Cargo.
pub fn agent_version() -> fleet_proto::AgentVersion {
    let mut it = env!("CARGO_PKG_VERSION")
        .split(['.', '-'])
        .map(|p| p.parse::<u16>().unwrap_or(0));
    fleet_proto::AgentVersion {
        major: it.next().unwrap_or(0),
        minor: it.next().unwrap_or(0),
        patch: it.next().unwrap_or(0),
    }
}
