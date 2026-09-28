//! `audit.query` (design §5.8): pages of the hash-chained audit log for the
//! Mac's audit mirror, plus a checkpoint of the chain head signed with the
//! agent key at answer time and the archive anchor (entries at or below it
//! are archived and no longer served). Pull-based: the Mac asks after it
//! connects and periodically.
//!
//! Entries are exactly as stored (the Mac recomputes every hash); a page
//! stops at `limit` entries, at [`PAGE_BYTES`] of encoded entries, and at
//! the head read before the entries (so the checkpoint never names an
//! entry the page skipped).

use super::log;
use super::state::State;
use fleet_crypto::receipt::sign_checkpoint;
use fleet_ops::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, SysCtx};
use fleet_proto::op::tag;
use fleet_proto::payload::{AuditAnchor, AuditPage};
use fleet_proto::{Checkpoint, ErrorCode, MAX_FRAME, Op, Payload, encode};
use std::cell::RefCell;
use std::rc::Rc;

pub(super) const TAGS: [u16; 1] = [tag::AUDIT_QUERY];

/// Encoded entries per page, well inside one frame.
pub(super) const PAGE_BYTES: usize = MAX_FRAME / 2;

pub(super) struct AuditOps(pub(super) Rc<RefCell<State>>);

fn internal(e: impl std::fmt::Display) -> OpError {
    log("audit query", &e);
    OpError::internal(e)
}

impl State {
    /// `audit.query` page after `after_seq`.
    pub(super) fn audit_page(
        &self,
        after_seq: u64,
        limit: u32,
        now: u64,
    ) -> Result<AuditPage, OpError> {
        let audit = self.store.audit();
        let head = audit.head().map_err(internal)?;
        let anchor = audit.anchor().map_err(internal)?;
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        let mut entries = Vec::new();
        let mut bytes = 0usize;
        for e in audit.entries_since(after_seq, limit).map_err(internal)? {
            if e.seq > head.seq {
                break;
            }
            let n = encode(&e).len();
            if !entries.is_empty() && bytes + n > PAGE_BYTES {
                break;
            }
            bytes += n;
            entries.push(e);
        }
        let last = entries.last().map_or(after_seq, |e| e.seq);
        let checkpoint = sign_checkpoint(
            Checkpoint {
                server_id: self.server_id.clone(),
                seq: head.seq,
                entry_hash: head.entry_hash,
                time_ms: now,
            },
            &self.signer,
        );
        Ok(AuditPage {
            more: last.max(anchor.as_ref().map_or(0, |a| a.seq)) < head.seq,
            entries,
            anchor: anchor.filter(|a| a.seq > 0).map(|a| AuditAnchor {
                seq: a.seq,
                entry_hash: a.entry_hash,
            }),
            checkpoint,
        })
    }
}

impl OpHandler for AuditOps {
    fn validate(&self, _ctx: &SysCtx, op: &Op, _meta: &OpMeta) -> Result<(), OpError> {
        match op {
            Op::AuditQuery { .. } => Ok(()),
            _ => Err(ErrorCode::Unsupported.into()),
        }
    }

    fn handle<'a>(
        &'a self,
        _ctx: &'a SysCtx,
        op: &'a Op,
        meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            let Op::AuditQuery { after_seq, limit } = op else {
                return Err(ErrorCode::Unsupported.into());
            };
            let page = self.0.borrow().audit_page(*after_seq, *limit, meta.now_ms)?;
            Ok(OpOutput::Payload(Payload::AuditPage(Box::new(page))))
        })
    }
}
