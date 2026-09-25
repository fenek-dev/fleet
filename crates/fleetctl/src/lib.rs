//! `fleetctl`: the Fleet command-line tool (design §7.1, §8).
//!
//! `fleetctl mcp` is a stdio MCP server (`rmcp`). It holds no keys and no
//! state: every tool call is forwarded to the running app over its Unix
//! socket ([`client`]), where pairing, the pause switch, the lock, rate
//! limits and approvals are enforced. Results come back with server text
//! already redacted and truncated; [`render`] wraps it in untrusted-content
//! markers before the AI sees it.
//!
//! Tools for keys, roster, policy, agent updates, recovery and sync don't
//! exist ([`tools`] lists every tool there is).
#![forbid(unsafe_code)]

pub mod client;
pub mod render;
pub mod server;
pub mod tools;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
