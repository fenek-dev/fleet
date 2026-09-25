use super::*;
use fleet_crypto::receipt::sign_event;
use fleet_crypto::sig::Ed25519Signer;
use fleet_proto::payload::{PackageChange, PkgAction};
use fleet_proto::{
    BoundedString, DeviceId, OpSummary, Outcome, Phase, ResultSummary, Signature, SignedEvent,
};
use std::cell::RefCell;

const RUN: [u8; 16] = [7; 16];

fn sid(s: &str) -> ServerId {
    ServerId::new(s).unwrap()
}

fn login(user: &str) -> Event {
    Event::Login {
        user: user.into(),
        source: Some("192.0.2.1".parse().unwrap()),
        success: true,
        new_source: true,
        device_id: None,
    }
}

fn signed(server: &ServerId, key: &Ed25519Signer, seq: u64, time: u64, e: Event) -> SignedEvent {
    sign_event(server.clone(), RUN, seq, time, e, key)
}

use crate::testutil::block_on;

#[test]
fn ingest_verifies_dedupes_and_moves_cursor() {
    let server = sid("srv_aaaaaaaaaaaa");
    let key = Ed25519Signer::generate().unwrap();
    let other = Ed25519Signer::generate().unwrap();
    let mut forged = signed(&server, &key, 3, 300, login("mallory"));
    forged.event = login("root");
    let page = SignedEventPage {
        events: vec![
            signed(&server, &key, 1, 100, login("alice")),
            signed(&server, &key, 2, 200, login("bob")),
            forged,
            // Signed by a key that is not pinned.
            signed(&server, &other, 4, 400, login("eve")),
            // Another server's event (right key).
            signed(&sid("srv_bbbbbbbbbbbb"), &key, 5, 500, login("x")),
        ],
        more: false,
    };
    let mut t = ServerTimeline::default();
    let n = t.ingest(&server, &key.public(), &page);
    assert_eq!(
        n,
        Ingested {
            accepted: 2,
            duplicates: 0,
            rejected: 3
        }
    );
    assert_eq!(t.rejected, 3);
    assert_eq!(
        t.cursor(),
        Cursor {
            run_id: Some(RUN),
            seq: 5
        }
    );
    let n = t.ingest(&server, &key.public(), &page);
    assert_eq!((n.accepted, n.duplicates), (0, 2));
    let titles: Vec<_> = t.items().map(|i| i.title.as_str()).collect();
    assert_eq!(titles, ["Login: alice", "Login: bob"]);
    let first = t.items().next().unwrap();
    assert_eq!(first.category, Category::Login);
    assert_eq!(first.detail, "from 192.0.2.1 (new source)");
    assert_eq!(first.severity, Some(Severity::Warning));
}

#[test]
fn ring_is_bounded() {
    let server = sid("srv_aaaaaaaaaaaa");
    let key = Ed25519Signer::generate().unwrap();
    let mut t = ServerTimeline::default();
    let events: Vec<_> = (0..MAX_ITEMS as u64 + 10)
        .map(|i| {
            signed(
                &server,
                &key,
                i,
                i,
                Event::HealthCheckChanged {
                    check_id: "web".into(),
                    ok: i % 2 == 0,
                },
            )
        })
        .collect();
    t.ingest(
        &server,
        &key.public(),
        &SignedEventPage {
            events,
            more: false,
        },
    );
    assert_eq!(t.len(), MAX_ITEMS);
    assert_eq!(t.items().next().unwrap().time_ms, 10);
}

#[test]
fn fetch_pages_follows_cursor() {
    let server = sid("srv_aaaaaaaaaaaa");
    let key = Ed25519Signer::generate().unwrap();
    let asked = RefCell::new(Vec::new());
    let pages = block_on(fetch_pages(Cursor::default(), 10, |op| {
        let Op::EventsQuery {
            since_run_id,
            since_seq,
            limit,
        } = op
        else {
            panic!("wrong op")
        };
        asked.borrow_mut().push((since_run_id, since_seq, limit));
        let events = if since_seq < 4 {
            vec![
                signed(&server, &key, since_seq + 1, 1, login("a")),
                signed(&server, &key, since_seq + 2, 2, login("b")),
            ]
        } else {
            vec![]
        };
        async move {
            Ok(Payload::SignedEvents(SignedEventPage {
                more: !events.is_empty(),
                events,
            }))
        }
    }))
    .unwrap();
    assert_eq!(pages.len(), 3);
    assert_eq!(
        *asked.borrow(),
        [(None, 0, PAGE), (Some(RUN), 2, PAGE), (Some(RUN), 4, PAGE)]
    );
    // Page cap.
    let pages = block_on(fetch_pages(Cursor::default(), 1, |_| async {
        Ok(Payload::SignedEvents(SignedEventPage {
            events: vec![],
            more: true,
        }))
    }))
    .unwrap();
    assert_eq!(pages.len(), 1);
    assert!(
        block_on(fetch_pages(Cursor::default(), 1, |_| async {
            Ok(Payload::Empty)
        }))
        .is_err()
    );
}

fn audit(seq: u64, time: u64, actor: Actor, phase: Phase, result: ResultSummary) -> AuditEntry {
    AuditEntry {
        seq,
        time,
        prev_hash: [0; 32],
        actor,
        device_id: DeviceId([1; 16]),
        command_hash: [0; 32],
        signature: Signature([0; 64]),
        op: OpSummary::from(&Op::PkgRefresh),
        phase,
        result,
    }
}

#[test]
fn audit_items_mark_ai() {
    let server = sid("srv_aaaaaaaaaaaa");
    let ai = Actor::Ai {
        client: BoundedString::new("claude").unwrap(),
        session: [0; 16],
    };
    assert!(
        from_audit(
            &server,
            &audit(1, 10, ai.clone(), Phase::Intent, ResultSummary::Pending)
        )
        .is_none()
    );
    let item = from_audit(
        &server,
        &audit(2, 11, ai, Phase::Result, ResultSummary::Done(Outcome::Ok)),
    )
    .unwrap();
    assert!(item.is_ai());
    assert_eq!(item.title, "pkg.refresh");
    assert_eq!(item.detail, "ok · AI (claude)");
    assert_eq!(item.category, Category::Action);
    let human = from_audit(
        &server,
        &audit(
            3,
            12,
            Actor::Human,
            Phase::Result,
            ResultSummary::Done(Outcome::Reverted),
        ),
    )
    .unwrap();
    assert!(!human.is_ai());
    assert_eq!(human.detail, "reverted · operator");
    assert_eq!(op_name(9999), "unknown");
}

#[test]
fn merge_newest_first() {
    let a = sid("srv_aaaaaaaaaaaa");
    let b = sid("srv_bbbbbbbbbbbb");
    let items = [
        from_event(&a, RUN, 1, 100, &login("x")),
        from_event(&b, RUN, 1, 300, &login("y")),
        from_event(&a, RUN, 2, 300, &login("z")),
        from_audit(
            &b,
            &audit(
                9,
                200,
                Actor::Human,
                Phase::Result,
                ResultSummary::Done(Outcome::Ok),
            ),
        )
        .unwrap(),
    ];
    let m = merge(&items, 3);
    let got: Vec<_> = m.iter().map(|i| (i.time_ms, i.server.as_str())).collect();
    assert_eq!(
        got,
        [
            (300, "srv_aaaaaaaaaaaa"),
            (300, "srv_bbbbbbbbbbbb"),
            (200, "srv_bbbbbbbbbbbb")
        ]
    );
}

#[test]
fn event_texts() {
    let s = sid("srv_aaaaaaaaaaaa");
    let i = from_event(
        &s,
        RUN,
        1,
        1,
        &Event::PackagesChanged {
            changes: (0..7)
                .map(|n| PackageChange {
                    name: format!("p{n}"),
                    action: PkgAction::Upgrade,
                    from: Some("1".into()),
                    to: Some("2".into()),
                })
                .collect(),
        },
    );
    assert_eq!(i.title, "7 package changes");
    assert!(i.detail.starts_with("upgrade p0 1 → 2, "));
    assert!(i.detail.ends_with("+2 more"));
    assert_eq!(i.name, "packages.changed");
    let i = from_event(
        &s,
        RUN,
        2,
        1,
        &Event::AlertFired {
            rule_id: "disk".into(),
            severity: Severity::Critical,
            subject: "/".into(),
            value: 97,
        },
    );
    assert_eq!(
        (i.category, i.severity),
        (Category::Alert, Some(Severity::Critical))
    );
}
