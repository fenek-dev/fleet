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
//! - [`vuln`]: vulnerability feeds and matching (§2.4, §7.7);
//!   [`fleetsearch`]: fleet-wide `search.*` fan-out (§2.7); [`timeline`]:
//!   the unified per-server and fleet timeline (§2.7).
#![forbid(unsafe_code)]

pub mod cache;
pub mod enroll;
pub mod fleetsearch;
pub mod install;
pub mod manager;
pub mod policy;
pub mod session;
pub mod sftp;
pub mod signer;
pub mod ssh;
pub mod timeline;
pub mod vuln;

pub use session::{
    ClientError, CommandOpts, CommandSigner, HelloInfo, MAX_BUFFERED_EVENTS, PendingReply, Reply,
    STREAM_QUEUE, Session, SessionConfig, SessionMode, StreamEvent, StreamFailure, VerifiedStatus,
    now_ms,
};
