//! The Mac's audit mirror (design §5.8, §7.4).
//!
//! On connect (device session) and whenever the timeline refreshes, the
//! Mac pages through `audit.query` from the last entry it verified. Each
//! page is checked before anything is stored:
//!
//! - the page's checkpoint is signed by the server's pinned agent key and
//!   names this server;
//! - entries continue the verified chain: the first one's `prev_hash` is
//!   the hash of the last mirrored entry (or of the agent's archive anchor
//!   when entries this Mac never saw were archived meanwhile, which is
//!   reported as an unverifiable gap), seqs are contiguous, and every
//!   entry's hash is recomputed;
//! - the checkpoint agrees with the chain (same hash at its seq when this
//!   Mac has that entry) and never goes back below what was verified.
//!
//! A server whose chain is shorter than what this Mac verified
//! ([`Tamper::Truncated`]) or whose entries no longer link
//! ([`Tamper::Rewritten`], [`Tamper::CheckpointMismatch`]) is tampering or
//! lost its database: nothing is stored and the caller raises a critical
//! alert. Entries are server data (rule 6); the timeline shows them
//! escaped.

use crate::cache::{Cache, CacheError};
use crate::runner::{OpRunner, RunError};
use fleet_crypto::receipt::verify_checkpoint;
use fleet_proto::payload::AuditPage;
use fleet_proto::{
    Actor, AuditEntry, Ed25519Public, Hash32, Op, Payload, ServerId, SignedCheckpoint, decode,
    encode,
};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

/// Entries per `audit.query` page.
pub const PAGE: u32 = 500;
/// Pages per mirror run (a longer backlog continues on the next run).
pub const MAX_PAGES: usize = 20;

/// The last verified position of one server's chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MirrorHead {
    pub seq: u64,
    pub entry_hash: Hash32,
}

/// `audit_checkpoints` blob: the verified head and the last checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorState {
    pub head: MirrorHead,
    pub checkpoint: SignedCheckpoint,
    /// Seqs archived on the agent before this Mac saw them (never verified).
    pub gaps: Vec<(u64, u64)>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Tamper {
    #[error("audit chain ends at {agent}, but this Mac verified it up to {known}")]
    Truncated { known: u64, agent: u64 },
    #[error("audit entry {seq} doesn't continue the verified chain")]
    Rewritten { seq: u64 },
    #[error("audit checkpoint signature or server is wrong")]
    BadCheckpoint,
    #[error("audit checkpoint at {seq} disagrees with the chain")]
    CheckpointMismatch { seq: u64 },
}

#[derive(Debug, thiserror::Error)]
pub enum MirrorError {
    #[error(transparent)]
    Run(#[from] RunError),
    #[error(transparent)]
    Cache(#[from] CacheError),
    /// Critical: the server's audit history changed (design §5.8).
    #[error(transparent)]
    Tamper(#[from] Tamper),
}

/// One verified page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// New entries with their hashes, oldest first.
    pub entries: Vec<(AuditEntry, Hash32)>,
    pub head: MirrorHead,
    pub checkpoint: SignedCheckpoint,
    /// Archived on the agent before this Mac saw them: `(from, to)`.
    pub gap: Option<(u64, u64)>,
    pub more: bool,
}

/// Checks `page` (the answer to `audit.query { after_seq: known.seq }`)
/// against the verified head `known` (see the module docs).
pub fn verify_page(
    server: &ServerId,
    agent_key: &Ed25519Public,
    known: MirrorHead,
    page: &AuditPage,
) -> Result<Verified, Tamper> {
    let cp = &page.checkpoint.checkpoint;
    if verify_checkpoint(&page.checkpoint, agent_key).is_err() || cp.server_id != *server {
        return Err(Tamper::BadCheckpoint);
    }
    if cp.seq < known.seq {
        return Err(Tamper::Truncated {
            known: known.seq,
            agent: cp.seq,
        });
    }
    let mut head = known;
    let mut gap = None;
    if let Some(a) = page.anchor
        && a.seq > known.seq
    {
        gap = Some((known.seq + 1, a.seq));
        head = MirrorHead {
            seq: a.seq,
            entry_hash: a.entry_hash,
        };
    } else if let Some(a) = page.anchor
        && a.seq == known.seq
        && a.entry_hash != known.entry_hash
    {
        return Err(Tamper::Rewritten { seq: a.seq });
    }
    let mut entries = Vec::with_capacity(page.entries.len());
    let mut cp_seen = cp.seq == known.seq && gap.is_none();
    if cp_seen && cp.entry_hash != known.entry_hash {
        return Err(Tamper::Rewritten { seq: known.seq });
    }
    for e in &page.entries {
        if e.seq != head.seq + 1 || e.prev_hash != head.entry_hash {
            return Err(Tamper::Rewritten { seq: e.seq });
        }
        let h = e.entry_hash();
        head = MirrorHead {
            seq: e.seq,
            entry_hash: h,
        };
        if e.seq == cp.seq {
            if cp.entry_hash != h {
                return Err(Tamper::CheckpointMismatch { seq: cp.seq });
            }
            cp_seen = true;
        }
        entries.push((e.clone(), h));
    }
    if gap.is_some() && head.seq == cp.seq {
        // The anchor itself is the head (everything archived).
        if cp.entry_hash != head.entry_hash {
            return Err(Tamper::CheckpointMismatch { seq: cp.seq });
        }
        cp_seen = true;
    }
    if head.seq > cp.seq || (!page.more && !cp_seen) {
        return Err(Tamper::CheckpointMismatch { seq: cp.seq });
    }
    Ok(Verified {
        entries,
        head,
        checkpoint: page.checkpoint.clone(),
        gap,
        more: page.more,
    })
}

pub fn load_state(cache: &Cache, server: &ServerId) -> Result<Option<MirrorState>, CacheError> {
    cache
        .audit_checkpoint(server)?
        .map(|(_, blob)| decode(&blob).map_err(|_| CacheError::Corrupt("audit mirror".into())))
        .transpose()
}

/// Stores a verified page: entries, then the new state.
pub fn store_page(
    cache: &Cache,
    server: &ServerId,
    prev: Option<&MirrorState>,
    v: &Verified,
    now_ms: u64,
) -> Result<MirrorState, CacheError> {
    for (e, h) in &v.entries {
        cache.put_audit_entry(server, e.seq, &encode(e), h)?;
    }
    let mut gaps = prev.map(|p| p.gaps.clone()).unwrap_or_default();
    gaps.extend(v.gap);
    let state = MirrorState {
        head: v.head,
        checkpoint: v.checkpoint.clone(),
        gaps,
    };
    cache.put_audit_checkpoint(server, v.head.seq, &encode(&state), now_ms)?;
    Ok(state)
}

/// What one mirror run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MirrorReport {
    pub stored: u64,
    pub head: MirrorHead,
    /// Archived ranges skipped in this run.
    pub gaps: Vec<(u64, u64)>,
}

fn lock(m: &Mutex<Cache>) -> std::sync::MutexGuard<'_, Cache> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Where the page after `page` (asked with `after`) starts.
pub fn next_after(after: u64, page: &AuditPage) -> u64 {
    let anchor = page.anchor.map_or(0, |a| a.seq);
    page.entries.last().map_or(after.max(anchor), |e| e.seq)
}

/// Fetches up to [`MAX_PAGES`] pages after `after_seq` (unverified; see
/// [`apply`]). `request` runs one op and returns its verified payload.
pub async fn fetch<F, Fut>(after_seq: u64, request: F) -> Result<Vec<AuditPage>, RunError>
where
    F: Fn(Op) -> Fut,
    Fut: std::future::Future<Output = Result<Payload, RunError>>,
{
    let mut after = after_seq;
    let mut pages = Vec::new();
    for _ in 0..MAX_PAGES {
        let op = Op::AuditQuery {
            after_seq: after,
            limit: PAGE,
        };
        let page = match request(op).await? {
            Payload::AuditPage(p) => *p,
            _ => return Err(RunError::Other("unexpected audit.query reply".into())),
        };
        let next = next_after(after, &page);
        let done = !page.more || next == after;
        pages.push(page);
        if done {
            break;
        }
        after = next;
    }
    Ok(pages)
}

/// Verifies and stores `pages` in order from the stored head. Stops at the
/// first tampered page (earlier good pages stay stored).
pub fn apply(
    cache: &Cache,
    server: &ServerId,
    agent_key: &Ed25519Public,
    pages: &[AuditPage],
    now_ms: u64,
) -> Result<MirrorReport, MirrorError> {
    let mut state = load_state(cache, server)?;
    let mut report = MirrorReport {
        head: state.as_ref().map(|s| s.head).unwrap_or_default(),
        ..MirrorReport::default()
    };
    for page in pages {
        let known = state.as_ref().map(|s| s.head).unwrap_or_default();
        let v = verify_page(server, agent_key, known, page)?;
        let next = store_page(cache, server, state.as_ref(), &v, now_ms)?;
        report.stored += v.entries.len() as u64;
        report.head = v.head;
        report.gaps.extend(v.gap);
        state = Some(next);
    }
    Ok(report)
}

/// The stored head's seq (where the next fetch starts).
pub fn known_seq(cache: &Cache, server: &ServerId) -> Result<u64, CacheError> {
    Ok(load_state(cache, server)?.map_or(0, |s| s.head.seq))
}

/// Fetches, verifies and stores everything after the verified head, up to
/// [`MAX_PAGES`] pages. A [`MirrorError::Tamper`] leaves the cache as it was
/// after the last good page.
pub async fn mirror<R: OpRunner>(
    runner: &R,
    cache: &Mutex<Cache>,
    server: &ServerId,
    agent_key: &Ed25519Public,
    now_ms: u64,
) -> Result<MirrorReport, MirrorError> {
    let after = known_seq(&lock(cache), server)?;
    let pages = fetch(after, |op| runner.run(server, op, Actor::Human, None)).await?;
    apply(&lock(cache), server, agent_key, &pages, now_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_crypto::receipt::sign_checkpoint;
    use fleet_crypto::sig::Ed25519Signer;
    use fleet_proto::payload::AuditAnchor;
    use fleet_proto::{Checkpoint, DeviceId, OpSummary, Outcome, Phase, ResultSummary, Signature};

    fn server() -> ServerId {
        ServerId::new("srv_test01").unwrap()
    }

    /// A valid chain of `n` entries.
    fn chain(n: u64) -> Vec<AuditEntry> {
        let mut prev = [0; 32];
        (1..=n)
            .map(|seq| {
                let e = AuditEntry {
                    seq,
                    time: seq,
                    prev_hash: prev,
                    actor: Actor::Human,
                    device_id: DeviceId([1; 16]),
                    command_hash: [seq as u8; 32],
                    signature: Signature([0; 64]),
                    op: OpSummary {
                        tag: 0,
                        args: vec![],
                    },
                    phase: Phase::Result,
                    result: ResultSummary::Done(Outcome::Ok),
                };
                prev = e.entry_hash();
                e
            })
            .collect()
    }

    fn page(
        key: &Ed25519Signer,
        all: &[AuditEntry],
        after: u64,
        limit: usize,
        anchor: Option<u64>,
    ) -> AuditPage {
        let head = all.last().map_or((0, [0; 32]), |e| (e.seq, e.entry_hash()));
        let from = anchor.unwrap_or(0).max(after);
        let entries: Vec<AuditEntry> = all
            .iter()
            .filter(|e| e.seq > from)
            .take(limit)
            .cloned()
            .collect();
        let last = entries.last().map_or(from, |e| e.seq);
        AuditPage {
            more: last < head.0,
            entries,
            anchor: anchor.map(|s| AuditAnchor {
                seq: s,
                entry_hash: all[s as usize - 1].entry_hash(),
            }),
            checkpoint: sign_checkpoint(
                Checkpoint {
                    server_id: server(),
                    seq: head.0,
                    entry_hash: head.1,
                    time_ms: 1,
                },
                key,
            ),
        }
    }

    fn head_of(e: &AuditEntry) -> MirrorHead {
        MirrorHead {
            seq: e.seq,
            entry_hash: e.entry_hash(),
        }
    }

    #[test]
    fn verifies_pages_and_continuity() {
        let k = Ed25519Signer::from_seed(&[3; 32]);
        let pk = k.public();
        let all = chain(5);
        let v = verify_page(&server(), &pk, MirrorHead::default(), &page(&k, &all, 0, 3, None))
            .unwrap();
        assert_eq!((v.entries.len(), v.more, v.head), (3, true, head_of(&all[2])));
        let v = verify_page(&server(), &pk, v.head, &page(&k, &all, 3, 3, None)).unwrap();
        assert_eq!((v.entries.len(), v.more, v.head), (2, false, head_of(&all[4])));
        // Nothing new: the checkpoint must still name the known head.
        let v = verify_page(&server(), &pk, v.head, &page(&k, &all, 5, 3, None)).unwrap();
        assert!(v.entries.is_empty());
    }

    #[test]
    fn detects_truncation_rewrite_and_forgery() {
        let k = Ed25519Signer::from_seed(&[3; 32]);
        let pk = k.public();
        let all = chain(5);
        let known = head_of(&all[3]);
        // Chain cut back to 3 entries.
        assert_eq!(
            verify_page(&server(), &pk, known, &page(&k, &all[..3], 4, 10, None)),
            Err(Tamper::Truncated { known: 4, agent: 3 })
        );
        // Entry 4 rewritten (and everything after re-chained): entry 5
        // no longer links to what this Mac verified.
        let mut forged = all.clone();
        forged[3].actor = Actor::Recovery;
        let h4 = forged[3].entry_hash();
        forged[4].prev_hash = h4;
        assert_eq!(
            verify_page(&server(), &pk, known, &page(&k, &forged, 4, 10, None)),
            Err(Tamper::Rewritten { seq: 5 })
        );
        // Same length, last known entry rewritten: the checkpoint differs.
        let known5 = head_of(&all[4]);
        assert_eq!(
            verify_page(&server(), &pk, known5, &page(&k, &forged, 5, 10, None)),
            Err(Tamper::Rewritten { seq: 5 })
        );
        // Checkpoint signed by another key.
        let other = Ed25519Signer::from_seed(&[4; 32]);
        assert_eq!(
            verify_page(&server(), &pk, MirrorHead::default(), &page(&other, &all, 0, 10, None)),
            Err(Tamper::BadCheckpoint)
        );
        // A checkpoint that doesn't match the returned chain.
        let mut p = page(&k, &all, 0, 10, None);
        p.entries[4].time += 1;
        assert!(matches!(
            verify_page(&server(), &pk, MirrorHead::default(), &p),
            Err(Tamper::CheckpointMismatch { seq: 5 })
        ));
    }

    #[test]
    fn fetch_apply_and_resume() {
        use crate::cache::ServerRecord;
        use crate::ssh::SshTarget;
        let k = Ed25519Signer::from_seed(&[3; 32]);
        let pk = k.public();
        let mut cache = Cache::open_in_memory().unwrap();
        cache
            .upsert_server(&ServerRecord {
                id: server(),
                name: "a".into(),
                target: SshTarget::new("192.0.2.1", 22, "root"),
                group: None,
                tags: vec![],
            })
            .unwrap();
        let all = std::cell::RefCell::new(chain(7));
        let run = |op: Op| {
            let Op::AuditQuery { after_seq, .. } = op else {
                panic!()
            };
            let p = page(&k, &all.borrow(), after_seq, 3, None);
            std::future::ready(Ok::<_, RunError>(Payload::AuditPage(Box::new(p))))
        };
        let block = |f| {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(f)
        };
        let pages = block(fetch(0, run)).unwrap();
        assert_eq!(pages.len(), 3);
        let r = apply(&cache, &server(), &pk, &pages, 1).unwrap();
        assert_eq!((r.stored, r.head.seq), (7, 7));
        assert_eq!(cache.audit_mirror(&server(), 100).unwrap().len(), 7);
        assert_eq!(known_seq(&cache, &server()).unwrap(), 7);
        // The server rewrites entry 7: the next run is refused, nothing
        // stored, the verified head stays.
        all.borrow_mut()[6].actor = Actor::Recovery;
        let pages = block(fetch(7, run)).unwrap();
        assert!(matches!(
            apply(&cache, &server(), &pk, &pages, 2),
            Err(MirrorError::Tamper(Tamper::Rewritten { seq: 7 }))
        ));
        assert_eq!(known_seq(&cache, &server()).unwrap(), 7);
    }

    #[test]
    fn archived_gap_is_reported_not_alerted() {
        let k = Ed25519Signer::from_seed(&[3; 32]);
        let pk = k.public();
        let all = chain(6);
        let known = head_of(&all[1]);
        // Entries 3..=4 were archived before this Mac saw them.
        let v = verify_page(&server(), &pk, known, &page(&k, &all, 2, 10, Some(4))).unwrap();
        assert_eq!(v.gap, Some((3, 4)));
        assert_eq!(v.entries.len(), 2);
        // An anchor at the known seq with a different hash is a rewrite.
        let mut p = page(&k, &all, 2, 10, Some(2));
        p.anchor = Some(AuditAnchor {
            seq: 2,
            entry_hash: [9; 32],
        });
        assert_eq!(
            verify_page(&server(), &pk, known, &p),
            Err(Tamper::Rewritten { seq: 2 })
        );
    }
}
