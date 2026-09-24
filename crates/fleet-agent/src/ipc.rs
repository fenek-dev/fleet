//! Gate ↔ exec IPC over `exec.sock` (design §4.1).
//!
//! One Unix stream per authenticated gate session (no multiplexing): the
//! gate connects to exec only after a bridge session passed `DeviceAuth`,
//! so session lifetime, backpressure and teardown are just the stream's.
//! Plus one long-lived **control** connection per gate (first message from
//! the gate: `ControlOpen`) that only carries `RosterUpdate`/`Limits`, which
//! the gate uses to authenticate new sessions before touching exec. Every
//! message is a stream frame (`len: u32 BE ‖ postcard(IpcMsg)`, see `frame`).
//!
//! Order on a new connection:
//! 1. exec → gate: `RosterUpdate`, then `Limits`.
//! 2. gate → exec: `SessionOpen` once the Noise handshake and `DeviceAuth`
//!    succeeded. Informational: exec authorizes every command from its own
//!    signature check and never from this message.
//! 3. exec → gate: the `Hello` frame as `Chunk`s; afterwards `Chunk`s both
//!    ways, plus `RosterUpdate`/`Limits` from exec whenever they change.
//!
//! Chunks from the gate are the decrypted Noise plaintexts, forwarded one by
//! one; exec reassembles. Chunks from exec are encrypted by the gate one by
//! one. Exec's frame ids have the top bit clear; frames the gate originates
//! itself (session-level refusals) set it, so the two never collide.

use crate::frame::{self, FrameError};
use fleet_proto::chunk::MAX_CHUNK;
use fleet_proto::{DeviceId, KeyKind, MAX_FRAME};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

/// Largest IPC frame: a roster (≤ `MAX_FRAME`) plus envelope.
pub const MAX_IPC_FRAME: usize = MAX_FRAME + 64;
/// Frame ids chosen by the gate have this bit set.
pub const GATE_FRAME_BIT: u32 = 0x8000_0000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpcMsg {
    /// Either direction: one chunk (`fleet_proto::chunk` format).
    Chunk(Vec<u8>),
    /// exec → gate: `postcard(SignedRoster)` now in force, and the local
    /// recovery grace left for its `prev_recovery` as of sending (the gate
    /// keeps counting it down on its own monotonic clock).
    RosterUpdate {
        roster: Vec<u8>,
        grace_remaining_ms: Option<u64>,
    },
    /// exec → gate: per-session limits from the policy.
    Limits { commands_per_minute: u32 },
    /// gate → exec: the session's authenticated identity. Informational.
    SessionOpen {
        /// Bridge mode header (0 normal, 1 recovery).
        mode: u8,
        device_id: DeviceId,
        key: KeyKind,
    },
    /// gate → exec, instead of `SessionOpen`: this is the gate's control
    /// connection; exec sends only `RosterUpdate`/`Limits` on it.
    ControlOpen,
}

#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("malformed IPC message")]
    Malformed,
    #[error("chunk exceeds the Noise message size")]
    ChunkTooLarge,
}

/// Reads one message. `Ok(None)` on clean EOF.
pub async fn read_msg<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<IpcMsg>, IpcError> {
    let Some(bytes) = frame::read_frame(r, MAX_IPC_FRAME).await? else {
        return Ok(None);
    };
    // Exactly one message per frame: trailing bytes are malformed.
    let (msg, rest): (IpcMsg, _) =
        postcard::take_from_bytes(&bytes).map_err(|_| IpcError::Malformed)?;
    if !rest.is_empty() {
        return Err(IpcError::Malformed);
    }
    if let IpcMsg::Chunk(c) = &msg
        && c.len() > MAX_CHUNK
    {
        return Err(IpcError::ChunkTooLarge);
    }
    Ok(Some(msg))
}

pub async fn write_msg<W: AsyncWrite + Unpin>(w: &mut W, msg: &IpcMsg) -> Result<(), IpcError> {
    let bytes = fleet_proto::encode(msg);
    Ok(frame::write_frame(w, &bytes, MAX_IPC_FRAME).await?)
}
