//! UniFFI bindings of `fleet-core` for the Swift app (design §7.1).
//!
//! The surface is small and typed:
//!
//! - [`FleetCore`]: one object per app. Opens the cache, lists and edits
//!   servers and groups, runs the connection manager on its own core
//!   thread, switches the session kind on lock/unlock and sends
//!   `system.info` / `agent.health`, and the typed operations the server
//!   tabs use (`ops`).
//! - [`Enrollment`]: first-Mac fleet bootstrap (genesis roster, recovery
//!   code shown once); `install_agent` puts the agent on a server over SSH.
//! - Streams ([`StreamHandle`] with [`MetricsSink`] / [`JournalSink`]),
//!   terminals ([`TerminalSession`] with [`TerminalSink`]) and SFTP files.
//! - Callback interfaces Swift implements: [`DeviceSigner`] (Secure Enclave
//!   signing, one role at a time), [`KeyStore`] (the Keychain-held X25519
//!   Noise key) and [`CoreListener`] (state changes, events, host key
//!   prompts).
//!
//! Only public keys and signatures cross for enclave keys (rule 7). The one
//! secret that crosses is the Noise static key, which lives in the Keychain
//! rather than the enclave (design §5.2: the enclave can't do X25519); the
//! core holds it zeroized.
//!
//! `forbid(unsafe_code)` holds here too: the `unsafe` FFI glue lives in the
//! `uniffi` crates (third-party) and the lint does not fire on the
//! scaffolding the proc macros expand.
#![forbid(unsafe_code)]

mod admin_ops;
mod admin_rows;
mod api;
mod approvals;
mod bulk;
mod docker_ops;
mod enrollment;
mod files;
mod fleet_mgmt;
mod install;
mod mcp;
mod mesh_game;
mod ops;
mod provision;
mod recovery;
mod release;
mod rows;
mod search;
mod signer;
mod streams;
mod terminal;
mod text;
mod timeline;
mod types;
mod ui_fleet;
mod ui_security;
mod ui_server;
mod validate;
mod vuln;

pub use admin_ops::{
    config_rollback_needs_approval, firewall_check, firewall_diff, firewall_rules_to_args,
    privileged_groups,
};
pub use admin_rows::*;
pub use api::FleetCore;
pub use bulk::{BulkListener, BulkRunHandle};
pub use docker_ops::{DockerLogSink, DockerStatsSink, compose_validate};
pub use enrollment::Enrollment;
pub use files::TransferListener;
pub use fleet_mgmt::{CloudRecordRow, FleetListener, SyncSecrets};
pub use install::InstallListener;
pub use mcp::{McpConnection, McpDelegate};
pub use provision::*;
pub use recovery::RecoverySession;
pub use rows::*;
pub use search::*;
pub use signer::{CoreListener, DeviceSigner, KeyStore, SignerAdapter};
pub use streams::{JournalSink, MetricsSink, StreamHandle};
pub use terminal::{TerminalSession, TerminalSink};
pub use timeline::*;
pub use types::*;
pub use vuln::*;

uniffi::setup_scaffolding!("fleet_core");

/// Version of the Rust core, for the About panel and bug reports.
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
