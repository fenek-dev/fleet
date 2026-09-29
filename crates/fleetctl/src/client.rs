//! Connection to the running app's socket (design §5.10).
//!
//! One connection, one request at a time (a call that waits for the
//! operator's approval holds it). The connection opens lazily with a
//! `Hello` naming the MCP client, and reopens after the app restarts or
//! the MCP client name changes. No socket means [`ProtoError::NotRunning`].

use fleetctl_proto::{
    Call, FrameError, Hello, PROTO_VERSION, ProtoError, Request, RequestBody, Response,
    ResponseBody, SOCKET_RELATIVE_PATH, ToolOutput, decode_body, encode_frame, frame_len,
};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

/// `$FLEET_MCP_SOCKET`, else `~/Library/Application Support/Fleet/mcp.sock`.
pub fn default_socket_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("FLEET_MCP_SOCKET") {
        return Some(PathBuf::from(p));
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(SOCKET_RELATIVE_PATH))
}

struct Conn {
    stream: UnixStream,
    client_name: String,
}

pub struct AppClient {
    path: PathBuf,
    session: String,
    conn: Mutex<Option<Conn>>,
    next_id: std::sync::atomic::AtomicU64,
}

#[derive(Debug, thiserror::Error)]
enum IoError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Frame(#[from] FrameError),
}

impl AppClient {
    pub fn new(path: PathBuf) -> Self {
        let mut s = [0u8; 16];
        // A failed RNG only weakens session attribution, never access.
        let _ = getrandom::fill(&mut s);
        Self {
            path,
            session: hex::encode(s),
            conn: Mutex::new(None),
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    fn id(&self) -> u64 {
        self.next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Forwards `call` on behalf of MCP client `client_name`.
    pub async fn call(&self, client_name: &str, call: Call) -> Result<ToolOutput, ProtoError> {
        let mut guard = self.conn.lock().await;
        if guard.as_ref().is_some_and(|c| c.client_name != client_name) {
            *guard = None;
        }
        if guard.is_none() {
            *guard = Some(self.connect(client_name).await?);
        }
        let conn = guard.as_mut().ok_or(ProtoError::NotRunning)?;
        let req = Request {
            v: PROTO_VERSION,
            id: self.id(),
            body: RequestBody::Call(call),
        };
        match roundtrip(&mut conn.stream, &req).await {
            Ok(resp) => match resp.body {
                Ok(ResponseBody::Tool(out)) => Ok(out),
                Ok(ResponseBody::Welcome(_)) => Err(ProtoError::Internal),
                Err(e) => {
                    if matches!(e, ProtoError::PairingRequired | ProtoError::Version { .. }) {
                        *guard = None;
                    }
                    Err(e)
                }
            },
            Err(_) => {
                // App quit or restarted mid-call: the outcome is unknown,
                // so don't retry a possibly-executed change.
                *guard = None;
                Err(ProtoError::NotRunning)
            }
        }
    }

    async fn connect(&self, client_name: &str) -> Result<Conn, ProtoError> {
        let mut stream = UnixStream::connect(&self.path)
            .await
            .map_err(|_| ProtoError::NotRunning)?;
        let hello = Request {
            v: PROTO_VERSION,
            id: self.id(),
            body: RequestBody::Hello(Hello {
                client_name: client_name.chars().take(64).collect(),
                client_version: crate::VERSION.to_string(),
                session: self.session.clone(),
            }),
        };
        let resp = roundtrip(&mut stream, &hello)
            .await
            .map_err(|_| ProtoError::NotRunning)?;
        match resp.body {
            Ok(ResponseBody::Welcome(_)) => Ok(Conn {
                stream,
                client_name: client_name.to_string(),
            }),
            Ok(_) => Err(ProtoError::Internal),
            Err(e) => Err(e),
        }
    }
}

async fn roundtrip(stream: &mut UnixStream, req: &Request) -> Result<Response, IoError> {
    stream.write_all(&encode_frame(req)?).await?;
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let n = frame_len(header)?;
    let mut body = vec![0u8; n];
    stream.read_exact(&mut body).await?;
    let resp: Response = decode_body(&body)?;
    if resp.id != req.id {
        return Err(IoError::Frame(FrameError::Malformed("response id".into())));
    }
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleetctl_proto::{ListServersArgs, Welcome};
    use tokio::net::UnixListener;

    async fn read_req(s: &mut UnixStream) -> Option<Request> {
        let mut h = [0u8; 4];
        s.read_exact(&mut h).await.ok()?;
        let mut b = vec![0u8; frame_len(h).ok()?];
        s.read_exact(&mut b).await.ok()?;
        decode_body(&b).ok()
    }

    async fn reply(s: &mut UnixStream, id: u64, body: Result<ResponseBody, ProtoError>) {
        let f = encode_frame(&Response {
            v: PROTO_VERSION,
            id,
            body,
        })
        .unwrap();
        s.write_all(&f).await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn not_running_without_socket() {
        let dir = tempfile::tempdir().unwrap();
        let c = AppClient::new(dir.path().join("none.sock"));
        let r = c
            .call("x", Call::FleetListServers(ListServersArgs { tag: None }))
            .await;
        assert_eq!(r, Err(ProtoError::NotRunning));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hello_then_calls_and_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let app = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let hello = read_req(&mut s).await.unwrap();
            let RequestBody::Hello(h) = &hello.body else {
                panic!("first frame must be hello")
            };
            assert_eq!(h.client_name, "claude-code");
            assert_eq!(h.session.len(), 32);
            reply(
                &mut s,
                hello.id,
                Ok(ResponseBody::Welcome(Welcome {
                    app_version: "t".into(),
                    client_label: "claude-code".into(),
                })),
            )
            .await;
            let call = read_req(&mut s).await.unwrap();
            reply(
                &mut s,
                call.id,
                Ok(ResponseBody::Tool(ToolOutput {
                    summary: serde_json::json!({"servers": []}),
                    untrusted: vec![],
                    is_error: false,
                })),
            )
            .await;
            let call = read_req(&mut s).await.unwrap();
            reply(&mut s, call.id, Err(ProtoError::Paused)).await;
        });
        let c = AppClient::new(path);
        let call = Call::FleetListServers(ListServersArgs { tag: None });
        let out = c.call("claude-code", call.clone()).await.unwrap();
        assert_eq!(out.summary["servers"], serde_json::json!([]));
        assert_eq!(
            c.call("claude-code", call.clone()).await,
            Err(ProtoError::Paused)
        );
        app.await.unwrap();
        // App gone: next call reports NotRunning.
        assert_eq!(
            c.call("claude-code", call).await,
            Err(ProtoError::NotRunning)
        );
    }
}
