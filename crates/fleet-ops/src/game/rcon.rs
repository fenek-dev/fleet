//! Source RCON client (used by Minecraft and Source games): loopback TCP,
//! bounded packets, bounded total output, one deadline for the exchange.
//!
//! Packet: `size: i32 LE` (bytes after this field), `id: i32`, `type: i32`,
//! body, `\0`, `\0`. Types: 3 auth, 2 auth response / exec command, 0
//! response value. Multi-packet responses end at the echo of an empty
//! type-0 packet sent right after the command.

use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const AUTH: i32 = 3;
pub const AUTH_RESPONSE: i32 = 2;
pub const EXEC: i32 = 2;
pub const RESPONSE: i32 = 0;
/// Largest packet accepted (Minecraft sends ≤ 4096 body bytes).
pub const MAX_PACKET: usize = 16 * 1024;
/// Output kept per command.
pub const MAX_OUTPUT: usize = 64 * 1024;
pub const TIMEOUT: Duration = Duration::from_secs(5);

const AUTH_ID: i32 = 1;
const CMD_ID: i32 = 2;
const END_ID: i32 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub id: i32,
    pub ty: i32,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RconError {
    #[error("authentication failed")]
    Auth,
    #[error("protocol error: {0}")]
    Protocol(&'static str),
    #[error("i/o error")]
    Io,
    #[error("timed out")]
    Timeout,
    #[error("not loopback")]
    NotLoopback,
}

pub fn encode(p: &Packet) -> Result<Vec<u8>, RconError> {
    if p.body.contains(&0) {
        return Err(RconError::Protocol("NUL in body"));
    }
    let size = 10 + p.body.len();
    if size > MAX_PACKET {
        return Err(RconError::Protocol("packet too large"));
    }
    let mut v = Vec::with_capacity(size + 4);
    v.extend_from_slice(&(size as i32).to_le_bytes());
    v.extend_from_slice(&p.id.to_le_bytes());
    v.extend_from_slice(&p.ty.to_le_bytes());
    v.extend_from_slice(&p.body);
    v.extend_from_slice(&[0, 0]);
    Ok(v)
}

/// One packet from the front of `buf`: `Ok(None)` if incomplete, else the
/// packet and the bytes it used.
pub fn decode(buf: &[u8]) -> Result<Option<(Packet, usize)>, RconError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let size = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let size = usize::try_from(size).map_err(|_| RconError::Protocol("negative size"))?;
    if !(10..=MAX_PACKET).contains(&size) {
        return Err(RconError::Protocol("bad size"));
    }
    if buf.len() < 4 + size {
        return Ok(None);
    }
    let f = &buf[4..4 + size];
    let id = i32::from_le_bytes([f[0], f[1], f[2], f[3]]);
    let ty = i32::from_le_bytes([f[4], f[5], f[6], f[7]]);
    let rest = &f[8..];
    // Body, then its terminator, then the empty-string terminator.
    if rest[rest.len() - 1] != 0 || rest[rest.len() - 2] != 0 {
        return Err(RconError::Protocol("missing terminator"));
    }
    let body = rest[..rest.len() - 2].to_vec();
    Ok(Some((Packet { id, ty, body }, 4 + size)))
}

/// Reads packets from `s`, buffering partial ones.
struct Reader {
    buf: Vec<u8>,
}

impl Reader {
    async fn next<S: AsyncRead + Unpin>(&mut self, s: &mut S) -> Result<Packet, RconError> {
        loop {
            if let Some((p, used)) = decode(&self.buf)? {
                self.buf.drain(..used);
                return Ok(p);
            }
            let mut chunk = [0u8; 4096];
            let n = s.read(&mut chunk).await.map_err(|_| RconError::Io)?;
            if n == 0 {
                return Err(RconError::Protocol("connection closed"));
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

async fn send<S: AsyncWrite + Unpin>(
    s: &mut S,
    id: i32,
    ty: i32,
    body: &[u8],
) -> Result<(), RconError> {
    let b = encode(&Packet {
        id,
        ty,
        body: body.to_vec(),
    })?;
    s.write_all(&b).await.map_err(|_| RconError::Io)
}

/// Authenticates and runs `command` on an open stream; the output is the
/// command's response bodies joined (untrusted server text, capped).
pub async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    password: &str,
    command: &str,
) -> Result<String, RconError> {
    let mut r = Reader { buf: Vec::new() };
    send(s, AUTH_ID, AUTH, password.as_bytes()).await?;
    // Source servers send an empty RESPONSE first; Minecraft doesn't.
    loop {
        let p = r.next(s).await?;
        if p.ty == AUTH_RESPONSE {
            if p.id == -1 {
                return Err(RconError::Auth);
            }
            if p.id != AUTH_ID {
                return Err(RconError::Protocol("auth id"));
            }
            break;
        }
    }
    send(s, CMD_ID, EXEC, command.as_bytes()).await?;
    send(s, END_ID, RESPONSE, b"").await?;
    let mut out = Vec::new();
    loop {
        let p = r.next(s).await?;
        match p.id {
            CMD_ID => {
                let room = MAX_OUTPUT.saturating_sub(out.len());
                out.extend_from_slice(&p.body[..p.body.len().min(room)]);
            }
            END_ID => break,
            _ => return Err(RconError::Protocol("unexpected id")),
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// Connects to `127.0.0.1:<port>` and runs `command`, all within
/// `timeout`.
pub async fn run(
    port: u16,
    password: &str,
    command: &str,
    timeout: Duration,
) -> Result<String, RconError> {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    tokio::time::timeout(timeout, async {
        let mut s = crate::health::connect(addr, timeout).await.map_err(|e| {
            if e == "not loopback" {
                RconError::NotLoopback
            } else {
                RconError::Io
            }
        })?;
        exchange(&mut s, password, command).await
    })
    .await
    .map_err(|_| RconError::Timeout)?
}

/// The first number after `prefix` in `text` (`There are 3 of …` → 3).
pub fn player_count(text: &str, prefix: &str) -> Option<u32> {
    let i = text.find(prefix)?;
    let digits: String = text[i + prefix.len()..]
        .chars()
        .take_while(char::is_ascii_digit)
        .take(6)
        .collect();
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::block;

    fn pkt(id: i32, ty: i32, body: &str) -> Packet {
        Packet {
            id,
            ty,
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn encode_decode_vectors() {
        let b = encode(&pkt(1, AUTH, "pw")).unwrap();
        assert_eq!(b, [12, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, b'p', b'w', 0, 0]);
        let (p, used) = decode(&b).unwrap().unwrap();
        assert_eq!((p, used), (pkt(1, AUTH, "pw"), 16));
        assert_eq!(decode(&b[..15]).unwrap(), None);
        assert_eq!(decode(&b[..3]).unwrap(), None);
        // Size field lies.
        let mut bad = b.clone();
        bad[0] = 5;
        assert!(decode(&bad).is_err());
        let mut huge = b.clone();
        huge[..4].copy_from_slice(&(MAX_PACKET as i32 + 1).to_le_bytes());
        assert!(decode(&huge).is_err());
        huge[..4].copy_from_slice(&(-1i32).to_le_bytes());
        assert!(decode(&huge).is_err());
        let mut noterm = b.clone();
        noterm[15] = b'x';
        assert!(decode(&noterm).is_err());
        assert!(encode(&pkt(1, EXEC, "a\0b")).is_err());
        assert!(encode(&pkt(1, EXEC, &"x".repeat(MAX_PACKET))).is_err());
    }

    /// Fake Minecraft-style server on one end of a duplex pipe.
    async fn server(
        mut s: tokio::io::DuplexStream,
        password: &'static str,
        reply: Vec<&'static str>,
    ) {
        let mut r = Reader { buf: Vec::new() };
        let auth = r.next(&mut s).await.unwrap();
        assert_eq!(auth.ty, AUTH);
        let ok = auth.body == password.as_bytes();
        let id = if ok { auth.id } else { -1 };
        s.write_all(&encode(&pkt(id, AUTH_RESPONSE, "")).unwrap())
            .await
            .unwrap();
        if !ok {
            return;
        }
        let cmd = r.next(&mut s).await.unwrap();
        assert_eq!((cmd.ty, cmd.body.as_slice()), (EXEC, b"list".as_slice()));
        for part in reply {
            s.write_all(&encode(&pkt(cmd.id, RESPONSE, part)).unwrap())
                .await
                .unwrap();
        }
        let end = r.next(&mut s).await.unwrap();
        s.write_all(&encode(&pkt(end.id, RESPONSE, "Unknown request 0")).unwrap())
            .await
            .unwrap();
    }

    #[test]
    fn exchange_multi_packet_and_auth_failure() {
        block(async {
            let (mut a, b) = tokio::io::duplex(64);
            let srv = server(
                b,
                "secret",
                vec!["There are 3 of a max ", "of 20 players online"],
            );
            let (out, ()) = tokio::join!(exchange(&mut a, "secret", "list"), srv);
            let out = out.unwrap();
            assert_eq!(out, "There are 3 of a max of 20 players online");
            assert_eq!(player_count(&out, "There are "), Some(3));

            let (mut a, b) = tokio::io::duplex(64);
            let (out, ()) = tokio::join!(
                exchange(&mut a, "wrong", "list"),
                server(b, "secret", vec![])
            );
            assert_eq!(out, Err(RconError::Auth));
        });
    }

    #[test]
    fn real_socket_and_timeout() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        tokio::task::LocalSet::new().block_on(&rt, async {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = l.local_addr().unwrap().port();
            // Accepts, never answers.
            let _h = tokio::task::spawn_local(async move {
                let (_s, _) = l.accept().await.unwrap();
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
            let r = run(port, "pw", "list", Duration::from_millis(200)).await;
            assert_eq!(r, Err(RconError::Timeout));
        });
    }

    #[test]
    fn player_count_parsing() {
        assert_eq!(
            player_count("There are 0 of a max of 20", "There are "),
            Some(0)
        );
        assert_eq!(player_count("xx There are 12/20", "There are "), Some(12));
        assert_eq!(player_count("no players", "There are "), None);
        assert_eq!(player_count("There are many", "There are "), None);
    }
}
