//! Chunk format inside Noise plaintexts (design §6.1). Shared by the agent
//! (gate forwards chunks, exec reassembles) and the Mac core.
//!
//! A chunk is `frame_id: u32 BE ‖ flags: u8 ‖ data`. `flags` bit 0 = last
//! chunk of the frame; other bits must be zero. Only exec and the Mac
//! reassemble, up to [`crate::MAX_FRAME`] per application frame.

/// Largest Noise transport message.
pub const NOISE_MAX_MSG: usize = 65_535;
/// ChaChaPoly tag appended to every Noise transport message.
pub const NOISE_TAG_LEN: usize = 16;
pub const CHUNK_HEADER_LEN: usize = 5;
/// Largest chunk data so that header + data + tag fit one Noise message.
pub const MAX_CHUNK_DATA: usize = NOISE_MAX_MSG - NOISE_TAG_LEN - CHUNK_HEADER_LEN;
/// Largest chunk (header + data).
pub const MAX_CHUNK: usize = CHUNK_HEADER_LEN + MAX_CHUNK_DATA;
pub const FLAG_LAST: u8 = 0x01;

/// Splits an application frame into encoded chunks (header included).
/// An empty frame is one empty last chunk.
pub fn split_frame(frame_id: u32, data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut parts = data.chunks(MAX_CHUNK_DATA).peekable();
    if parts.peek().is_none() {
        return vec![chunk(frame_id, true, &[])];
    }
    while let Some(p) = parts.next() {
        out.push(chunk(frame_id, parts.peek().is_none(), p));
    }
    out
}

fn chunk(frame_id: u32, last: bool, data: &[u8]) -> Vec<u8> {
    let mut c = Vec::with_capacity(CHUNK_HEADER_LEN + data.len());
    c.extend_from_slice(&frame_id.to_be_bytes());
    c.push(if last { FLAG_LAST } else { 0 });
    c.extend_from_slice(data);
    c
}

/// Parsed chunk header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkHeader {
    pub frame_id: u32,
    pub last: bool,
}

/// Validates a chunk's header and size; returns the header and data.
pub fn parse_chunk(chunk: &[u8]) -> Result<(ChunkHeader, &[u8]), ReassemblyError> {
    if chunk.len() < CHUNK_HEADER_LEN {
        return Err(ReassemblyError::ShortChunk);
    }
    let (hdr, data) = chunk.split_at(CHUNK_HEADER_LEN);
    let frame_id = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    let flags = hdr[4];
    if flags & !FLAG_LAST != 0 {
        return Err(ReassemblyError::BadFlags(flags));
    }
    if data.len() > MAX_CHUNK_DATA {
        return Err(ReassemblyError::ChunkTooLarge(data.len()));
    }
    Ok((
        ChunkHeader {
            frame_id,
            last: flags & FLAG_LAST != 0,
        },
        data,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReassemblyError {
    #[error("chunk shorter than its header")]
    ShortChunk,
    #[error("unknown chunk flags {0:#04x}")]
    BadFlags(u8),
    #[error("chunk data of {0} bytes exceeds MAX_CHUNK_DATA")]
    ChunkTooLarge(usize),
    #[error("frame {0} exceeds the frame size limit")]
    FrameTooLarge(u32),
    #[error("more than the allowed number of partial frames")]
    TooManyPartial,
}

/// Reassembles chunks into application frames with bounded memory: at most
/// `max_partial` frames in progress, each at most `max_frame` bytes.
/// Any error is fatal for the session; the caller drops the connection.
#[derive(Debug)]
pub struct Reassembler {
    max_frame: usize,
    max_partial: usize,
    partial: Vec<(u32, Vec<u8>)>,
}

impl Reassembler {
    pub fn new(max_frame: usize, max_partial: usize) -> Self {
        Self {
            max_frame,
            max_partial,
            partial: Vec::new(),
        }
    }

    /// Exec (and Mac) defaults: `MAX_FRAME`, 4 frames in flight.
    pub fn for_exec() -> Self {
        Self::new(crate::MAX_FRAME, 4)
    }

    /// Feeds one chunk. Returns a completed `(frame_id, frame)` if this was
    /// the last chunk of its frame.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Option<(u32, Vec<u8>)>, ReassemblyError> {
        let (hdr, data) = parse_chunk(chunk)?;
        let id = hdr.frame_id;
        let pos = self.partial.iter().position(|(pid, _)| *pid == id);
        let idx = match pos {
            Some(i) => i,
            None => {
                if hdr.last {
                    // Single-chunk frame: no buffering.
                    if data.len() > self.max_frame {
                        return Err(ReassemblyError::FrameTooLarge(id));
                    }
                    return Ok(Some((id, data.to_vec())));
                }
                if self.partial.len() >= self.max_partial {
                    return Err(ReassemblyError::TooManyPartial);
                }
                self.partial.push((id, Vec::new()));
                self.partial.len() - 1
            }
        };
        let buf = &mut self.partial[idx].1;
        if buf.len() + data.len() > self.max_frame {
            self.partial.swap_remove(idx);
            return Err(ReassemblyError::FrameTooLarge(id));
        }
        buf.extend_from_slice(data);
        if hdr.last {
            let (id, frame) = self.partial.swap_remove(idx);
            return Ok(Some((id, frame)));
        }
        Ok(None)
    }

    /// Bytes currently buffered across partial frames.
    pub fn buffered(&self) -> usize {
        self.partial.iter().map(|(_, b)| b.len()).sum()
    }
}
