//! Stream framing (design §6.1); chunk format lives in `fleet_proto::chunk`.
//!
//! **Stream frames** (bridge ↔ gate after the mode byte, gate ↔ exec):
//! `len: u32 BE ‖ payload`, with `len ≤ max`. Between bridge and gate a
//! payload is one Noise transport message; between gate and exec it is one
//! postcard `ipc::IpcMsg` (a chunk or a control message).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub use fleet_proto::chunk::{
    CHUNK_HEADER_LEN, FLAG_LAST, MAX_CHUNK, MAX_CHUNK_DATA, NOISE_MAX_MSG, NOISE_TAG_LEN,
    Reassembler, ReassemblyError, parse_chunk, split_frame,
};

/// Largest stream frame payload on the bridge ↔ gate stream.
pub const MAX_STREAM_FRAME: usize = NOISE_MAX_MSG;
/// Frame bodies are read (and allocated) at most this much at a time.
const READ_STEP: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame length {0} exceeds limit")]
    TooLarge(usize),
    #[error("stream ended inside a frame")]
    Truncated,
}

/// Reads one frame. `Ok(None)` on clean EOF before a length prefix.
/// Not cancellation-safe: callers keep one read loop per stream.
pub async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> Result<Option<Vec<u8>>, FrameError> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        let n = r.read(&mut len[got..]).await?;
        if n == 0 {
            return if got == 0 {
                Ok(None)
            } else {
                Err(FrameError::Truncated)
            };
        }
        got += n;
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > max {
        return Err(FrameError::TooLarge(len));
    }
    // Grow with the bytes actually received: a peer announcing a large
    // length and then stalling holds at most one read's worth of memory.
    let mut buf = Vec::with_capacity(len.min(READ_STEP));
    while buf.len() < len {
        let want = (len - buf.len()).min(READ_STEP);
        let start = buf.len();
        buf.resize(start + want, 0);
        let n = r.read(&mut buf[start..]).await?;
        buf.truncate(start + n);
        if n == 0 {
            return Err(FrameError::Truncated);
        }
    }
    Ok(Some(buf))
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    payload: &[u8],
    max: usize,
) -> Result<(), FrameError> {
    if payload.len() > max {
        return Err(FrameError::TooLarge(payload.len()));
    }
    let len = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge(payload.len()))?;
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(payload);
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}
