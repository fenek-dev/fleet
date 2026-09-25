//! Stream sessions (design §6.3): `StreamOpen` runs the full command
//! pipeline (verify, policy, validate, `max_stream_sessions`, nonce, audit
//! intent), then pumps the handler's `OpStream` as `StreamData` frames.
//!
//! Each `StreamData.chunk` is a `fleet_proto::StreamChunk`: data (an
//! encoded `Payload`), a signed checkpoint over the running chain at least
//! every `CHECKPOINT_EVERY` data chunks or `checkpoint_every` of time, and a
//! signed final seal right before `StreamEnd` — also for a rejected open, so
//! refusals are as authentic as `Response` receipts. Only ops with
//! `Op::is_stream` are accepted here (others: `Unsupported`).
//!
//! Backpressure: the connection's outgoing queue is bounded. A
//! `latest_only` stream drops items the queue can't take (the next one is
//! newer anyway; dropped items never enter the chain). Any other stream
//! waits up to `send_timeout`, then ends with `Busy`. `StreamCancel` or the
//! connection closing ends it with `Ok`. Every admitted stream gets its
//! audit result.

use super::conn::{ActiveStreams, Out};
use super::{Exec, Session, log, log_op_error};
use crate::now_ms;
use fleet_crypto::stream::StreamSealer;
use fleet_crypto::verify;
use fleet_ops::{Invocation, OpOutput, OpStream};
use fleet_proto::stream::{CHECKPOINT_EVERY, StreamChunk};
use fleet_proto::{
    DeviceId, ErrorCode, MAX_FRAME, Message, Outcome, RequestId, SignedCommand, encode,
};
use std::cell::Cell;
use std::rc::Rc;
use std::time::Instant;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::oneshot;

/// Largest encoded `Payload` per data chunk (the frame adds a few bytes).
const MAX_ITEM: usize = MAX_FRAME - 1024;

/// A stream's entry in its connection's table.
pub(super) struct Handle {
    pub(super) active: ActiveStreams,
    pub(super) generation: u64,
    pub(super) id: RequestId,
    /// Fires (or is dropped) on `StreamCancel` / connection end.
    pub(super) cancel: oneshot::Receiver<()>,
    /// Streams running on this connection.
    pub(super) conn_streams: Rc<Cell<u32>>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        let mut a = self.active.borrow_mut();
        if a.get(&self.id).is_some_and(|(g, _)| *g == self.generation) {
            a.remove(&self.id);
        }
    }
}

/// Holds one stream slot: global, the device's and the connection's.
struct Slot<'a> {
    ex: &'a Exec,
    device: DeviceId,
    conn: Rc<Cell<u32>>,
}

impl<'a> Slot<'a> {
    fn take(ex: &'a Exec, device: DeviceId, conn: Rc<Cell<u32>>) -> Self {
        ex.streams.set(ex.streams.get() + 1);
        *ex.device_streams.borrow_mut().entry(device).or_insert(0) += 1;
        conn.set(conn.get() + 1);
        Self { ex, device, conn }
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.ex.streams.set(self.ex.streams.get() - 1);
        let mut per = self.ex.device_streams.borrow_mut();
        if let Some(n) = per.get_mut(&self.device) {
            *n -= 1;
            if *n == 0 {
                per.remove(&self.device);
            }
        }
        self.conn.set(self.conn.get().saturating_sub(1));
    }
}

/// Why the pump stopped sending.
enum Stop {
    /// Ended (successfully, by cancel, or with an error); send the final seal.
    Status(Result<(), ErrorCode>),
    /// The connection is gone; nothing more can be sent.
    Gone,
}

struct Pump<'a> {
    ex: &'a Exec,
    out: &'a Out,
    id: RequestId,
    op_name: &'static str,
    seq: u64,
    sealer: StreamSealer,
}

impl Pump<'_> {
    /// Sends one `StreamData`, waiting at most `send_timeout`.
    async fn send(&mut self, chunk: &StreamChunk) -> Result<(), Stop> {
        self.send_raw(encode(chunk)).await
    }

    async fn send_raw(&mut self, chunk: Vec<u8>) -> Result<(), Stop> {
        let msg = Message::StreamData {
            id: self.id,
            seq: self.seq,
            chunk,
        };
        match tokio::time::timeout(self.ex.send_timeout, self.out.send(&msg)).await {
            Ok(Some(())) => {
                self.seq += 1;
                Ok(())
            }
            Ok(None) => Err(Stop::Gone),
            Err(_) => Err(Stop::Status(Err(ErrorCode::Busy))),
        }
    }

    async fn checkpoint(&mut self, intent_seq: u64) -> Result<(), Stop> {
        let seal = {
            let st = self.ex.st.borrow();
            self.sealer
                .checkpoint(Some(intent_seq), now_ms(), &st.signer)
        };
        self.send(&StreamChunk::Checkpoint(seal)).await
    }

    async fn data(&mut self, data: Vec<u8>, latest_only: bool) -> Result<(), Stop> {
        let chunk = encode(&StreamChunk::Data(data.clone()));
        if latest_only {
            let msg = Message::StreamData {
                id: self.id,
                seq: self.seq,
                chunk,
            };
            match self.out.tx.try_send(self.out.frame(&msg)) {
                Ok(()) => self.seq += 1,
                // Stale by the time the client could take it: skip (it
                // never enters the chain).
                Err(TrySendError::Full(_)) => return Ok(()),
                Err(TrySendError::Closed(_)) => return Err(Stop::Gone),
            }
        } else {
            self.send_raw(chunk).await?;
        }
        self.sealer.push(&data);
        Ok(())
    }

    /// Runs `s` until it ends, is cancelled or the client stalls.
    async fn run(
        &mut self,
        s: &mut dyn OpStream,
        intent_seq: u64,
        cancel: &mut oneshot::Receiver<()>,
    ) -> Stop {
        enum Step {
            Cancel,
            Checkpoint,
            Item(Option<Result<fleet_proto::Payload, fleet_ops::OpError>>),
        }
        let latest_only = s.latest_only();
        let mut last_cp = Instant::now();
        loop {
            let due = self.sealer.since_checkpoint() > 0;
            let cp_at = tokio::time::Instant::from_std(last_cp + self.ex.checkpoint_every);
            let step = tokio::select! {
                biased;
                _ = &mut *cancel => Step::Cancel,
                () = tokio::time::sleep_until(cp_at), if due => Step::Checkpoint,
                item = s.next() => Step::Item(item),
            };
            let res = match step {
                Step::Cancel => return Stop::Status(Ok(())),
                Step::Item(None) => return Stop::Status(Ok(())),
                Step::Item(Some(Err(e))) => {
                    log_op_error(self.op_name, &e);
                    return Stop::Status(Err(e.code()));
                }
                Step::Checkpoint => self.checkpoint(intent_seq).await,
                Step::Item(Some(Ok(p))) => {
                    let data = encode(&p);
                    if data.len() > MAX_ITEM {
                        log("stream item", "payload too large");
                        return Stop::Status(Err(ErrorCode::Internal));
                    }
                    match self.data(data, latest_only).await {
                        Ok(()) if self.sealer.since_checkpoint() >= CHECKPOINT_EVERY => {
                            self.checkpoint(intent_seq).await
                        }
                        r => r,
                    }
                }
            };
            match res {
                Ok(()) => {
                    if self.sealer.since_checkpoint() == 0 {
                        last_cp = Instant::now();
                    }
                }
                Err(stop) => return stop,
            }
        }
    }

    /// Final seal, then `StreamEnd` (best effort).
    async fn finish(&mut self, audit_seq: Option<u64>, status: Result<(), ErrorCode>) {
        let outcome = match status {
            Ok(()) => Outcome::Ok,
            Err(c) => Outcome::Failed(c),
        };
        let seal = {
            let st = self.ex.st.borrow();
            self.sealer.finish(audit_seq, outcome, now_ms(), &st.signer)
        };
        let data = Message::StreamData {
            id: self.id,
            seq: self.seq,
            chunk: encode(&StreamChunk::Final(seal)),
        };
        let end = Message::StreamEnd {
            id: self.id,
            status,
        };
        let mut frames = self.out.frame(&data);
        frames.extend(self.out.frame(&end));
        let _ = tokio::time::timeout(self.ex.send_timeout, self.out.tx.send(frames)).await;
    }
}

pub(super) async fn run(
    ex: Rc<Exec>,
    out: Out,
    mut handle: Handle,
    session: Session,
    cmd: SignedCommand,
) {
    let hash = verify::command_hash(&cmd);
    let server_id = ex.st.borrow().server_id.clone();
    let mut pump = Pump {
        ex: &ex,
        out: &out,
        id: handle.id,
        op_name: "stream",
        seq: 0,
        sealer: StreamSealer::new(server_id, hash),
    };
    let conn = handle.conn_streams.clone();
    let a = match ex.admit(session, &cmd, Invocation::Stream, now_ms(), conn.get()) {
        Ok(a) => a,
        Err(r) => return pump.finish(None, Err(r.code)).await,
    };
    // No await since `admit` checked the caps.
    let _slot = Slot::take(&ex, a.meta.command.device_id, conn);
    let op = &a.meta.command.body.op;
    pump.op_name = op.name();
    let stop = match a.handler.handle(&ex.ctx, op, &a.meta).await {
        Ok(OpOutput::Stream(mut s)) => pump.run(s.as_mut(), a.intent_seq, &mut handle.cancel).await,
        Ok(OpOutput::Payload(_)) => Stop::Status(Err(ErrorCode::Internal)),
        Err(e) => {
            log_op_error(op.name(), &e);
            Stop::Status(Err(e.code()))
        }
    };
    let status = match &stop {
        Stop::Status(s) => *s,
        Stop::Gone => Ok(()),
    };
    let (status, audit_seq) = match ex.st.borrow_mut().audit_result(a.intent_seq, status) {
        Some(seq) => (status, Some(seq)),
        None => (Err(ErrorCode::Internal), Some(a.intent_seq)),
    };
    if let Stop::Status(_) = stop {
        pump.finish(audit_seq, status).await;
    }
}
