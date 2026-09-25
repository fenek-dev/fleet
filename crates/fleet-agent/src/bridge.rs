//! `fleet-agent bridge [--recovery | --monitor]` (design §6.1): runs as the SSH login
//! user, one per SSH exec channel. Connects to the gate socket, sends a
//! mode header, then copies bytes in both directions until either side
//! closes. Holds no keys and parses nothing after the header.
//!
//! Header: one mode byte; with [`HINT_FLAG`] set it is followed by
//! `len: u8` (at most [`MAX_HINT`]) and the SSH client address as text,
//! from `SSH_CONNECTION`. The address is an **untrusted hint**: anyone who
//! can reach the gate socket can send any value. Exec uses it only for
//! learning ban exemptions, and only when sshd's own journal entry
//! corroborates it (design §4.7). The Noise prologue binds the mode
//! without the flag, so the Mac never sees the hint.

use std::net::IpAddr;
use std::path::Path;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;

/// Set on the mode byte when a client-address hint follows.
pub const HINT_FLAG: u8 = 0x80;
/// Longest address text (a full IPv6 address with embedded IPv4).
pub const MAX_HINT: usize = 45;

/// The whole header for `mode` and an optional client address.
pub fn header_bytes(mode: BridgeMode, hint: Option<IpAddr>) -> Vec<u8> {
    match hint {
        None => vec![mode.header()],
        Some(ip) => {
            let text = ip.to_string();
            let mut v = vec![mode.header() | HINT_FLAG, text.len() as u8];
            v.extend_from_slice(text.as_bytes());
            v
        }
    }
}

/// Gate side: reads the header. `None` for an unknown mode or a malformed
/// hint length; an unparsable address is just no hint.
pub async fn read_header<R: AsyncRead + Unpin>(r: &mut R) -> Option<(BridgeMode, Option<IpAddr>)> {
    let b = r.read_u8().await.ok()?;
    let mode = BridgeMode::from_header(b & !HINT_FLAG)?;
    if b & HINT_FLAG == 0 {
        return Some((mode, None));
    }
    let len = usize::from(r.read_u8().await.ok()?);
    if len > MAX_HINT {
        return None;
    }
    let mut buf = [0u8; MAX_HINT];
    r.read_exact(&mut buf[..len]).await.ok()?;
    let hint = std::str::from_utf8(&buf[..len])
        .ok()
        .and_then(|s| s.parse().ok());
    Some((mode, hint))
}

/// The client address from `SSH_CONNECTION` (`client port server port`).
pub fn ssh_client_ip(ssh_connection: &str) -> Option<IpAddr> {
    ssh_connection.split(' ').next()?.parse().ok()
}

/// First byte sent to the gate on every bridge connection (also bound into
/// the Noise prologue).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BridgeMode {
    /// Device or monitor sessions.
    Normal = 0,
    /// Started by the restricted recovery SSH key (design §5.9).
    Recovery = 1,
    /// Started by a Mac's restricted monitor SSH key (design §5.9): the
    /// gate accepts only a monitor-key `DeviceAuth` on it.
    Monitor = 2,
}

impl BridgeMode {
    pub fn header(self) -> u8 {
        self as u8
    }

    pub fn from_header(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Normal),
            1 => Some(Self::Recovery),
            2 => Some(Self::Monitor),
            _ => None,
        }
    }
}

/// Connects to `sock` and relays `input` → socket and socket → `output`.
/// Stdin EOF half-closes the socket and keeps relaying the gate's output
/// until the gate closes; the gate closing ends the bridge at once.
pub async fn run<I, O>(
    sock: &Path,
    mode: BridgeMode,
    hint: Option<IpAddr>,
    input: I,
    output: O,
) -> std::io::Result<()>
where
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
{
    let stream = UnixStream::connect(sock).await?;
    relay(stream, mode, hint, input, output).await
}

pub async fn relay<I, O>(
    stream: UnixStream,
    mode: BridgeMode,
    hint: Option<IpAddr>,
    mut input: I,
    mut output: O,
) -> std::io::Result<()>
where
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
{
    let (mut rd, mut wr) = stream.into_split();
    wr.write_all(&header_bytes(mode, hint)).await?;
    let up = async {
        tokio::io::copy(&mut input, &mut wr).await?;
        wr.shutdown().await
    };
    let down = async {
        tokio::io::copy(&mut rd, &mut output).await?;
        output.flush().await
    };
    tokio::pin!(up, down);
    tokio::select! {
        // Input done: the write half is shut down; what the gate still
        // sends (e.g. responses to the last requests) must get through.
        r = &mut up => {
            r?;
            down.await
        }
        r = &mut down => r,
    }
}
