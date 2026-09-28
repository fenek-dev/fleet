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
pub mod uninstall;
pub mod update;
pub mod userkeys;

/// Wall clock in Unix milliseconds (0 if the clock is before 1970).
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// This build's version string: `FLEET_AGENT_VERSION` at build time
/// (release builds and the update harness, which builds two versions of
/// the same source), else Cargo's.
pub const AGENT_VERSION_STR: &str = match option_env!("FLEET_AGENT_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

/// This build's version ([`AGENT_VERSION_STR`]).
pub fn agent_version() -> fleet_proto::AgentVersion {
    parse_version(AGENT_VERSION_STR)
}

/// `major.minor.patch[-suffix]`; missing or bad parts are 0.
pub fn parse_version(s: &str) -> fleet_proto::AgentVersion {
    let mut it = s.split(['.', '-']).map(|p| p.parse::<u16>().unwrap_or(0));
    fleet_proto::AgentVersion {
        major: it.next().unwrap_or(0),
        minor: it.next().unwrap_or(0),
        patch: it.next().unwrap_or(0),
    }
}
