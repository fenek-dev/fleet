//! Fixed protocol error codes (design §6.6). No free-form text on the wire.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorCode {
    Unauthorized,
    SignatureInvalid,
    Stale,
    Replay,
    PolicyDenied,
    ApprovalRequired,
    ApprovalInvalid,
    InvalidArgument,
    VersionConflict { current: u64 },
    NotFound,
    Busy,
    Timeout,
    Unsupported,
    Internal,
}
