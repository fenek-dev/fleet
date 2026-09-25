//! Gate connections (design §4.1): the exec socket, the connection and
//! buffer budget, one task set per session (reader, event/view pusher,
//! single writer) and the gate's control connection.

use super::state::GateView;
use super::{
    Exec, ExecError, MAX_BUFFERED_BYTES, MAX_INFLIGHT_REQUESTS, SESSION_OPEN_TIMEOUT, Session,
    stream,
};
use crate::bridge::BridgeMode;
use crate::frame::Reassembler;
use crate::fsutil;
use crate::install::GATE_USER;
use crate::ipc::{self, IpcMsg};
use crate::paths::Paths;
use fleet_proto::chunk::split_frame;
use fleet_proto::{Message, RequestId, decode, encode};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use tokio::net::UnixStream;
use tokio::sync::{Semaphore, broadcast, mpsc, oneshot, watch};

/// Events a lagging connection re-reads from the log at once.
const CATCH_UP_EVENTS: usize = 256;

/// Creates the socket directories and binds `exec.sock` (design §4.1):
/// `/run/fleet-exec` `0710 root:fleet-gate`, a fresh root-only `.tmp` inside
/// it for binding, and the socket `0660 root:fleet-gate` renamed into place.
/// Nothing here resolves a path the gate can write.
pub(super) fn bind_exec_socket(paths: &Paths) -> Result<tokio::net::UnixListener, ExecError> {
    let gate_gid = if fsutil::current_uid()? == 0 {
        Some(
            fsutil::lookup_gid(&paths.group, GATE_USER)
                .ok_or(ExecError::NotInstalled("group fleet-gate"))?,
        )
    } else {
        None
    };
    fsutil::ensure_dir(&paths.exec_run_dir, 0o710)?;
    if let Some(gid) = gate_gid {
        fsutil::lchown(&paths.exec_run_dir, Some(0), Some(gid))?;
    }
    // Recreated every start: an older layout let the gate write here.
    let tmp = &paths.exec_tmp_dir;
    match std::fs::symlink_metadata(tmp) {
        Ok(m) if m.file_type().is_dir() => std::fs::remove_dir_all(tmp)?,
        Ok(_) => std::fs::remove_file(tmp)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(tmp)?;
    }
    Ok(fsutil::bind_socket(&paths.exec_sock, tmp, 0o660, gate_gid)?)
}

/// Connection count and reassembly bytes across all gate connections.
#[derive(Default)]
pub(super) struct Budget {
    pub(super) conns: Cell<usize>,
    bytes: Cell<usize>,
}

/// Releases one connection slot and its buffered bytes on drop.
pub(super) struct ConnGuard {
    budget: Rc<Budget>,
    bytes: Cell<usize>,
}

impl ConnGuard {
    pub(super) fn new(budget: Rc<Budget>) -> Self {
        Self {
            budget,
            bytes: Cell::new(0),
        }
    }

    /// Records this connection's new buffered total; `false` if the global
    /// budget is exceeded.
    fn set_bytes(&self, n: usize) -> bool {
        let total = self.budget.bytes.get() - self.bytes.get() + n;
        self.budget.bytes.set(total);
        self.bytes.set(n);
        total <= MAX_BUFFERED_BYTES
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.budget.conns.set(self.budget.conns.get() - 1);
        self.budget
            .bytes
            .set(self.budget.bytes.get() - self.bytes.get());
    }
}

/// Outgoing side of one gate connection, shared by its request and stream
/// tasks: frames messages (exec frame ids, top bit clear) into a bounded
/// queue drained by the connection's single writer.
#[derive(Clone)]
pub(super) struct Out {
    pub(super) tx: mpsc::Sender<Vec<IpcMsg>>,
    ids: Rc<Cell<u32>>,
}

impl Out {
    pub(super) fn frame(&self, msg: &Message) -> Vec<IpcMsg> {
        let id = self.ids.get();
        self.ids.set(id.wrapping_add(1) & !ipc::GATE_FRAME_BIT);
        split_frame(id, &encode(msg))
            .into_iter()
            .map(IpcMsg::Chunk)
            .collect()
    }

    pub(super) async fn send(&self, msg: &Message) -> Option<()> {
        self.tx.send(self.frame(msg)).await.ok()
    }
}

/// Running streams of one connection: id → (generation, cancel).
pub(super) type ActiveStreams = Rc<RefCell<HashMap<RequestId, (u64, oneshot::Sender<()>)>>>;

pub(super) async fn connection(
    stream: UnixStream,
    exec: Rc<Exec>,
    gate_uid: u32,
    guard: &ConnGuard,
) -> Option<()> {
    if stream.peer_cred().ok()?.uid() != gate_uid {
        return None;
    }
    let (mut r, mut w) = stream.into_split();
    // `last_event`: the newest event before this subscription (a lagging
    // connection re-reads from the log only what it should have seen).
    let (mut view_rx, mut ev_rx, last_event) = {
        let s = exec.st.borrow();
        (s.view.subscribe(), s.events.subscribe(), s.event_seq())
    };
    let (tx, mut rx) = mpsc::channel::<Vec<IpcMsg>>(16);
    let out = Out {
        tx,
        ids: Rc::new(Cell::new(0)),
    };
    let frame = |msg: &Message| out.frame(msg);

    let init = view_rx.borrow_and_update().msgs();
    for m in &init {
        ipc::write_msg(&mut w, m).await.ok()?;
    }
    let first = tokio::time::timeout(SESSION_OPEN_TIMEOUT, ipc::read_msg(&mut r))
        .await
        .ok()?
        .ok()??;
    let (key, device, mode, client_ip) = match first {
        IpcMsg::SessionOpen {
            key,
            device_id,
            mode,
            client_ip,
        } => (key, device_id, mode, client_ip),
        IpcMsg::ControlOpen => return control(r, w, view_rx).await,
        _ => return None,
    };
    // Exec's own ids for this session; the gate can't choose them.
    let mut id = [0u8; 16];
    fleet_crypto::random_bytes(&mut id).ok()?;
    let conn = exec.conns.get() + 1;
    exec.conns.set(conn);
    let key = Session {
        key,
        id,
        conn,
        device,
        recovery: mode == BridgeMode::Recovery.header(),
        client_ip,
    };
    let hello = exec.st.borrow().hello();
    for m in &frame(&hello) {
        ipc::write_msg(&mut w, m).await.ok()?;
    }

    let active: ActiveStreams = Rc::default();
    let conn_streams = Rc::new(Cell::new(0u32));
    let inflight = Rc::new(Semaphore::new(MAX_INFLIGHT_REQUESTS));
    let up = async {
        let mut reasm = Reassembler::for_exec();
        let mut generation = 0u64;
        loop {
            let IpcMsg::Chunk(c) = ipc::read_msg(&mut r).await.ok()?? else {
                return None::<()>;
            };
            let done = reasm.push(&c).ok()?;
            if !guard.set_bytes(reasm.buffered()) {
                return None;
            }
            let Some((_, bytes)) = done else {
                continue;
            };
            match decode::<Message>(&bytes).ok()? {
                // Each request runs as its own task, so a long operation
                // doesn't hold up `StreamCancel` or other requests. It runs
                // to completion (and is audited) even if the gate goes away.
                Message::Request { id, cmd } => {
                    // Released by the task (`Rc`: no owned permits).
                    inflight.acquire().await.ok()?.forget();
                    let (exec, out, inflight) = (exec.clone(), out.clone(), inflight.clone());
                    tokio::task::spawn_local(async move {
                        let (result, receipt) = exec.request(key, &cmd).await;
                        let reply = Message::Response {
                            id,
                            result,
                            receipt: Some(receipt),
                        };
                        let _ = out.send(&reply).await;
                        inflight.add_permits(1);
                    });
                }
                Message::StreamOpen { id, cmd } => {
                    if active.borrow().contains_key(&id) {
                        // Client bug; unsigned, nothing was verified.
                        let end = Message::StreamEnd {
                            id,
                            status: Err(fleet_proto::ErrorCode::InvalidArgument),
                        };
                        out.send(&end).await?;
                        continue;
                    }
                    generation += 1;
                    let (cancel_tx, cancel_rx) = oneshot::channel();
                    active.borrow_mut().insert(id, (generation, cancel_tx));
                    tokio::task::spawn_local(stream::run(
                        exec.clone(),
                        out.clone(),
                        stream::Handle {
                            active: active.clone(),
                            generation,
                            id,
                            cancel: cancel_rx,
                            conn_streams: conn_streams.clone(),
                        },
                        key,
                        cmd,
                    ));
                }
                Message::StreamCancel { id } => {
                    if let Some((_, c)) = active.borrow_mut().remove(&id) {
                        let _ = c.send(());
                    }
                }
                _ => return None,
            }
        }
    };
    let tx = out.tx.clone();
    let down = async {
        // Highest event seq sent on (or predating) this connection.
        let mut last = last_event;
        loop {
            tokio::select! {
                r = view_rx.changed() => {
                    r.ok()?;
                    let msgs = view_rx.borrow_and_update().msgs();
                    tx.send(msgs).await.ok()?;
                }
                e = ev_rx.recv() => match e {
                    Ok(e) => {
                        if e.seq > last {
                            last = e.seq;
                            tx.send(frame(&Message::Event(e))).await.ok()?;
                        }
                    }
                    // Fell behind the broadcast: re-read the missed events
                    // from the log (the Mac fetches anything beyond this with
                    // `events.query`).
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let missed = exec.st.borrow().events_since(last, CATCH_UP_EVENTS);
                        for e in missed {
                            last = e.seq;
                            tx.send(frame(&Message::Event(e))).await.ok()?;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => return None::<()>,
                },
            }
        }
    };
    let writer = async {
        while let Some(batch) = rx.recv().await {
            for m in &batch {
                ipc::write_msg(&mut w, m).await.ok()?;
            }
        }
        None::<()>
    };
    tokio::select! {
        _ = up => {},
        _ = down => {},
        _ = writer => {},
    }
    // Dropping the cancel senders ends this connection's streams (each
    // still audits its result).
    active.borrow_mut().clear();
    Some(())
}

/// The gate's control connection: roster/limits updates only, until the
/// gate closes it (anything it sends ends the connection).
async fn control(
    mut r: tokio::net::unix::OwnedReadHalf,
    mut w: tokio::net::unix::OwnedWriteHalf,
    mut view_rx: watch::Receiver<GateView>,
) -> Option<()> {
    // One read for the whole connection (read_msg isn't cancellation-safe).
    let closed = ipc::read_msg(&mut r);
    tokio::pin!(closed);
    loop {
        tokio::select! {
            ch = view_rx.changed() => {
                ch.ok()?;
                let msgs = view_rx.borrow_and_update().msgs();
                for m in &msgs {
                    ipc::write_msg(&mut w, m).await.ok()?;
                }
            }
            _ = &mut closed => return Some(()),
        }
    }
}
