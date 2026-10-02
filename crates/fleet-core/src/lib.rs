//! Fleet Mac core (design §7).
//!
//! - [`session`]: the Noise agent session over any byte stream (§5.5, §5.6).
//! - [`ssh`]: `russh` transport — host key pinning, external signing,
//!   agent exec channel, PTY, ProxyJump (§3.2).
//! - [`manager`]: per-server connection state machine, backoff, handshake
//!   limit, monitor/device sessions, request routing, event fan-out (§7.2).
//! - [`cache`]: the local SQLite cache (§7.4).
//! - [`enroll`]: first-Mac fleet bootstrap: genesis roster, recovery code
//!   (§5.3, §5.11).
//! - [`install`]: agent install over SSH (§10.1); [`policy`]: default
//!   per-server policy (§5.4).
//! - [`sftp`]: file browser over the server's SSH connection (§2.3).
//! - [`signer`]: the Secure Enclave signing interface Swift implements (§7.1).
//! - [`bulk`]: bulk action engine — concurrency, canary, one root approval
//!   per run, dry runs (§7.3); [`opspec`]: typed op descriptions to `Op`.
//! - [`runbook`]: snippets and runbooks (§2.3); [`mcp_host`]: the app side
//!   of the `fleetctl` socket — pairing, pause, lock, rate limit, approvals,
//!   untrusted results (§5.10, §8).
//! - [`vuln`]: vulnerability feeds and matching (§2.4, §7.7);
//!   [`fleetsearch`]: fleet-wide `search.*` fan-out (§2.7); [`timeline`]:
//!   the unified per-server and fleet timeline (§2.7).
//! - [`roster_mgmt`]: adding/revoking Macs, chain pushes, veto (§5.12);
//!   [`catchup`]: `events.query` catch-up on connect; [`sync`]: end-to-end
//!   encrypted iCloud sync (§7.6); [`recovery_flow`]: recovery and the
//!   drill (§5.11); [`sudo`]: per-server sudo passwords (§5.9);
//!   [`runner`]: the op-sending trait those flows share.
//! - [`autorevert`]: confirming auto-revert changes from a fresh connection
//!   (§4.10), wrapped by [`confirm`] for bulk/provisioning/MCP;
//!   [`mesh_orch`]: fleet-level WireGuard mesh (§2.5);
//!   [`compose_check`]: the agent's pure Compose validator (`fleet-compose`),
//!   linked here too so the Mac knows before signing whether a deploy needs Touch ID.
//! - [`versions`]: `expected_version` reads for version-checked ops;
//!   [`escalate`]: root approval on `ApprovalRequired` for may-escalate
//!   ops; [`provision`]: the provisioning wizard's orchestration (§9.1).
#![forbid(unsafe_code)]

/// Audit mirror: `audit.query` pages verified and stored (§5.8).
pub mod audit_mirror;
pub mod autorevert;
pub mod bootstrap;
pub mod bulk;
pub mod cache;
pub mod catchup;
pub mod cloudinit_export;
/// The `fleet-compose` crate (also `fleet_ops::compose`; pure:
/// `fleet-proto` + `yaml-rust2`), so the Mac core doesn't pull in the
/// agent's system dependencies.
pub use fleet_compose as compose_check;
pub mod confirm;
pub mod enroll;
pub mod escalate;
pub mod fleetsearch;
pub mod fw_history;
pub mod install;
pub mod manager;
pub mod mcp_host;
pub mod mesh_orch;
pub mod opspec;
pub mod policy;
pub mod provision;
pub mod recovery_flow;
pub mod release;
pub mod roster_mgmt;
pub mod runbook;
pub mod runner;
pub mod secret;
pub mod session;
pub mod sftp;
pub mod signer;
pub mod ssh;
pub mod sudo;
pub mod sync;
#[cfg(test)]
pub(crate) mod testutil;
pub mod timeline;
pub mod versions;
pub mod vuln;

pub use session::{
    ClientError, CommandOpts, CommandSigner, HelloInfo, MAX_BUFFERED_EVENTS, PendingReply, Reply,
    STREAM_QUEUE, Session, SessionConfig, SessionMode, StreamEvent, StreamFailure, VerifiedStatus,
    now_ms,
};
