//! Event catch-up on connect (design §4.5, §5.10).
//!
//! Agents record events while no Mac is connected. Each time a server
//! becomes Ready (monitor or device session), the Mac reads `agent.health`
//! (receipted: names the current exec run) and pages through
//! `events.query` from its persisted cursor — the `(run_id, seq)` of the last
//! event it delivered. Every returned event is verified like a live one
//! (agent key, server id); the cursor only moves forward.
//!
//! [`EventTracker`] dedups the live feed against the catch-up pages: live
//! events carry only `seq`, so the tracker keeps the current run per server
//! (from the health read) and drops any live event at or below the last
//! delivered seq of that run.

use crate::cache::{Cache, CacheError};
use crate::runner::{OpRunner, RunError};
use fleet_crypto::receipt::verify_event;
use fleet_proto::{
    Actor, Ed25519Public, Event, Op, Payload, ServerId, SignedEvent, decode, encode,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// `settings` key prefix; the full key is `events_cursor/<server id>`.
pub const CURSOR_PREFIX: &str = "events_cursor/";
/// Events per `events.query` page.
pub const PAGE: u32 = 500;
/// Pages per catch-up (the agent keeps 7 days; a longer backlog resumes on
/// the next connect).
pub const MAX_PAGES: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventCursor {
    pub run_id: [u8; 16],
    pub seq: u64,
}

pub fn load_cursor(cache: &Cache, server: &ServerId) -> Result<Option<EventCursor>, CacheError> {
    let Some(raw) = cache.setting(&format!("{CURSOR_PREFIX}{server}"))? else {
        return Ok(None);
    };
    decode(&raw)
        .map(Some)
        .map_err(|_| CacheError::Corrupt("event cursor".into()))
}

pub fn store_cursor(cache: &Cache, server: &ServerId, c: &EventCursor) -> Result<(), CacheError> {
    cache.set_setting(&format!("{CURSOR_PREFIX}{server}"), &encode(c))
}

/// One catch-up run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatchUp {
    /// Exec run the server is on now.
    pub run_id: [u8; 16],
    /// Verified events after the cursor, oldest first.
    pub events: Vec<SignedEvent>,
    /// Where the next catch-up starts (unchanged if nothing arrived).
    pub cursor: Option<EventCursor>,
    /// Events dropped for a bad signature or the wrong server.
    pub rejected: u64,
}

/// Reads the current run and every stored event after `from`.
pub async fn catch_up<R: OpRunner>(
    runner: &R,
    server: &ServerId,
    agent_signing: &Ed25519Public,
    from: Option<EventCursor>,
) -> Result<CatchUp, RunError> {
    let run_id = match runner
        .run(server, Op::AgentHealth, Actor::Human, None)
        .await?
    {
        Payload::AgentHealth(h) => h.run_id,
        _ => return Err(RunError::Other("unexpected agent.health reply".into())),
    };
    let mut out = CatchUp {
        run_id,
        events: Vec::new(),
        cursor: from,
        rejected: 0,
    };
    for _ in 0..MAX_PAGES {
        let op = Op::EventsQuery {
            since_run_id: out.cursor.map(|c| c.run_id),
            since_seq: out.cursor.map_or(0, |c| c.seq),
            limit: PAGE,
        };
        let page = match runner.run(server, op, Actor::Human, None).await? {
            Payload::SignedEvents(p) => p,
            _ => return Err(RunError::Other("unexpected events.query reply".into())),
        };
        let before = out.cursor;
        for e in page.events {
            if verify_event(&e, agent_signing, server).is_err() {
                out.rejected += 1;
                continue;
            }
            // Within a run, only forward (a replayed page can't rewind).
            if out
                .cursor
                .is_some_and(|c| c.run_id == e.run_id && e.seq <= c.seq)
            {
                continue;
            }
            out.cursor = Some(EventCursor {
                run_id: e.run_id,
                seq: e.seq,
            });
            out.events.push(e);
        }
        if !page.more || out.cursor == before {
            break;
        }
    }
    Ok(out)
}

/// Live/catch-up dedup per server (see the module docs).
#[derive(Debug, Default)]
pub struct EventTracker {
    servers: HashMap<ServerId, Tracked>,
}

#[derive(Debug, Clone, Copy)]
struct Tracked {
    run_id: [u8; 16],
    last_seq: Option<u64>,
}

impl EventTracker {
    /// After a catch-up: the server's current run and the last seq of it
    /// already delivered.
    pub fn caught_up(&mut self, server: &ServerId, c: &CatchUp) {
        let last_seq = c
            .cursor
            .filter(|cur| cur.run_id == c.run_id)
            .map(|cur| cur.seq);
        self.servers.insert(
            server.clone(),
            Tracked {
                run_id: c.run_id,
                last_seq,
            },
        );
    }

    /// A live event: `Some(cursor to persist)` to deliver it (the cursor is
    /// `None` while the run is unknown), `None` if it is a duplicate.
    pub fn live(&mut self, server: &ServerId, seq: u64) -> Option<Option<EventCursor>> {
        let Some(t) = self.servers.get_mut(server) else {
            return Some(None);
        };
        if t.last_seq.is_some_and(|l| seq <= l) {
            return None;
        }
        t.last_seq = Some(seq);
        Some(Some(EventCursor {
            run_id: t.run_id,
            seq,
        }))
    }

    /// The link dropped: its run may change on reconnect.
    pub fn forget(&mut self, server: &ServerId) {
        self.servers.remove(server);
    }
}

/// Events worth an alert on their own, whatever their age: roster and
/// recovery changes (design §5.10 "Roster change alerts").
pub fn is_security_event(e: &Event) -> bool {
    matches!(
        e,
        Event::RosterChanged { .. } | Event::RecoveryPending(_) | Event::RecoveryVetoed { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_crypto::sig::Ed25519Signer;
    use fleet_proto::payload::SignedEventPage;
    use fleet_proto::{AgentHealth, AgentVersion, ErrorCode, RootApproval};
    use std::cell::RefCell;

    struct FakeAgent {
        key: Ed25519Signer,
        server: ServerId,
        run: [u8; 16],
        log: Vec<SignedEvent>,
        queries: RefCell<u32>,
    }

    impl FakeAgent {
        fn event(&self, run: [u8; 16], seq: u64) -> SignedEvent {
            let event = Event::RosterChanged {
                epoch: 0,
                version: seq,
            };
            let sig = self.key.sign(&SignedEvent::signed_message(
                &self.server,
                &run,
                seq,
                1,
                &event,
            ));
            SignedEvent {
                server_id: self.server.clone(),
                run_id: run,
                seq,
                time_ms: 1,
                event,
                sig,
            }
        }
    }

    impl OpRunner for FakeAgent {
        async fn run(
            &self,
            _: &ServerId,
            op: Op,
            _: Actor,
            _: Option<RootApproval>,
        ) -> Result<Payload, RunError> {
            match op {
                Op::AgentHealth => Ok(Payload::AgentHealth(AgentHealth {
                    agent_version: AgentVersion {
                        major: 0,
                        minor: 1,
                        patch: 0,
                    },
                    proto_version: 1,
                    uptime_s: 1,
                    gate_rss_bytes: 0,
                    exec_rss_bytes: 0,
                    audit_seq: 0,
                    roster_epoch: 0,
                    roster_version: 1,
                    policy_version: 1,
                    pending_recovery: None,
                    run_id: self.run,
                })),
                Op::EventsQuery {
                    since_run_id,
                    since_seq,
                    limit,
                } => {
                    *self.queries.borrow_mut() += 1;
                    let start = match since_run_id {
                        None => 0,
                        Some(r) => self
                            .log
                            .iter()
                            .position(|e| e.run_id == r && e.seq == since_seq)
                            .map_or(0, |i| i + 1),
                    };
                    let rest = &self.log[start..];
                    let n = rest.len().min(limit as usize).min(3);
                    Ok(Payload::SignedEvents(SignedEventPage {
                        events: rest[..n].to_vec(),
                        more: n < rest.len(),
                    }))
                }
                _ => Err(RunError::Agent(ErrorCode::Unsupported)),
            }
        }
    }

    fn agent() -> FakeAgent {
        let mut a = FakeAgent {
            key: Ed25519Signer::from_seed(&[4; 32]),
            server: ServerId::new("srv_catchup").unwrap(),
            run: [2; 16],
            log: Vec::new(),
            queries: RefCell::new(0),
        };
        let mut log: Vec<SignedEvent> = (1..=4).map(|s| a.event([1; 16], s)).collect();
        log.extend((1..=5).map(|s| a.event([2; 16], s)));
        a.log = log;
        a
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pages_from_cursor_across_runs_and_dedups_live() {
        let a = agent();
        let pk = a.key.public();
        let from = Some(EventCursor {
            run_id: [1; 16],
            seq: 2,
        });
        let c = catch_up(&a, &a.server, &pk, from).await.unwrap();
        let got: Vec<_> = c.events.iter().map(|e| (e.run_id[0], e.seq)).collect();
        assert_eq!(
            got,
            [(1, 3), (1, 4), (2, 1), (2, 2), (2, 3), (2, 4), (2, 5)]
        );
        assert_eq!(
            c.cursor,
            Some(EventCursor {
                run_id: [2; 16],
                seq: 5
            })
        );
        assert_eq!(*a.queries.borrow(), 3);

        let mut t = EventTracker::default();
        t.caught_up(&a.server, &c);
        assert_eq!(t.live(&a.server, 5), None, "already delivered by catch-up");
        assert_eq!(
            t.live(&a.server, 6),
            Some(Some(EventCursor {
                run_id: [2; 16],
                seq: 6
            }))
        );
        assert_eq!(t.live(&a.server, 6), None);
        let other = ServerId::new("srv_unknown").unwrap();
        assert_eq!(t.live(&other, 1), Some(None), "unknown run: deliver");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejects_forged_events_and_persists_cursor() {
        let mut a = agent();
        let forger = Ed25519Signer::from_seed(&[5; 32]);
        let mut bad = a.log[6].clone();
        bad.sig = forger.sign(b"x");
        a.log[6] = bad;
        let pk = a.key.public();
        let c = catch_up(&a, &a.server, &pk, None).await.unwrap();
        assert_eq!(c.rejected, 1);
        assert_eq!(c.events.len(), 8);

        let cache = Cache::open_in_memory().unwrap();
        assert_eq!(load_cursor(&cache, &a.server).unwrap(), None);
        store_cursor(&cache, &a.server, &c.cursor.unwrap()).unwrap();
        assert_eq!(load_cursor(&cache, &a.server).unwrap(), c.cursor);
        // Nothing new: the cursor stays and no events come back.
        let again = catch_up(&a, &a.server, &pk, c.cursor).await.unwrap();
        assert!(again.events.is_empty());
        assert_eq!(again.cursor, c.cursor);
    }
}
