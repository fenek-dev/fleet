//! Protocol between `fleetctl` and the running Fleet app (design §5.10, §8).
//!
//! - [`frame`]: length-prefixed JSON frames over the app's Unix socket.
//! - [`msg`]: versioned requests/responses; one typed [`msg::Call`] per MCP
//!   tool, with its argument struct.
//! - [`opspec`]: typed operation descriptions shared by `bulk_run`, the
//!   bulk sheet and runbooks (validated into `fleet_proto::Op` by the app).
//! - [`untrusted`]: redaction, truncation and markers for server-derived
//!   text in tool results.
//!
//! This crate has no dependency on the wire protocol (`fleet-proto`): the
//! app validates everything it receives here before anything is signed.
#![forbid(unsafe_code)]

pub mod frame;
pub mod msg;
pub mod opspec;
pub mod untrusted;

pub use frame::{FrameError, MAX_FRAME, decode_body, encode_frame, frame_len};
pub use msg::*;
pub use opspec::OpSpec;

/// Version of this protocol. The app answers `Version` to any other.
pub const PROTO_VERSION: u16 = 1;

/// Socket path under the user's home (design §5.10).
pub const SOCKET_RELATIVE_PATH: &str = "Library/Application Support/Fleet/mcp.sock";
