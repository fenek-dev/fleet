//! `fleet-agent bridge [--recovery]` (design §6.1): runs as the SSH login
//! user, one per SSH exec channel. Connects to the gate socket, sends a
//! one-byte mode header, then copies bytes in both directions until either
//! side closes. Holds no keys and parses nothing after the header.

use std::path::Path;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;

/// First byte sent to the gate on every bridge connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BridgeMode {
    Normal = 0,
    /// Started by the restricted recovery SSH key (design §5.9).
    Recovery = 1,
}

impl BridgeMode {
    pub fn header(self) -> u8 {
        self as u8
    }

    pub fn from_header(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Normal),
            1 => Some(Self::Recovery),
            _ => None,
        }
    }
}

/// Connects to `sock` and relays `input` → socket and socket → `output`.
/// Stdin EOF half-closes the socket and keeps relaying the gate's output
/// until the gate closes; the gate closing ends the bridge at once.
pub async fn run<I, O>(sock: &Path, mode: BridgeMode, input: I, output: O) -> std::io::Result<()>
where
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
{
    let stream = UnixStream::connect(sock).await?;
    relay(stream, mode, input, output).await
}

pub async fn relay<I, O>(
    stream: UnixStream,
    mode: BridgeMode,
    mut input: I,
    mut output: O,
) -> std::io::Result<()>
where
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
{
    let (mut rd, mut wr) = stream.into_split();
    wr.write_all(&[mode.header()]).await?;
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
