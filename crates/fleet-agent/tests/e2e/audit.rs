//! Catalog coverage of exec's production registry, `audit.query` verified
//! by the Mac's audit mirror, and policy re-verification at exec start
//! (design §4.2, §5.4, §5.8).

use super::*;
use fleet_agent::exec::StoredPolicy;
use fleet_agent::store::MetaKey;
use fleet_core::audit_mirror::{MirrorHead, Tamper, verify_page};
use fleet_proto::op::tag;
use fleet_proto::payload::AuditPage;

/// Ops another lane owns (agent self-update and uninstall).
fn owned_elsewhere(name: &str) -> bool {
    name.starts_with("agent.update.") || name == "agent.uninstall"
}

#[test]
fn every_catalog_op_has_a_handler() {
    let mut fx = Fixture::new(1, 0);
    fx.exec = None; // releases the database
    let mut cfg = ExecConfig::new(fx.paths.clone(), fsutil::current_uid().unwrap());
    cfg.sources.enabled = false;
    let tags = exec::registry_tags(cfg).unwrap();
    let missing: Vec<&str> = tag::ALL
        .iter()
        .zip(tag::NAMES)
        .filter(|(t, n)| !owned_elsewhere(n) && !tags.contains(t))
        .map(|(_, n)| *n)
        .collect();
    assert!(missing.is_empty(), "ops without a handler: {missing:?}");
}

async fn audit_page(s: &mut Session<'_, UnixStream>, fx: &Fixture, after: u64, limit: u32) -> AuditPage {
    let q = Op::AuditQuery {
        after_seq: after,
        limit,
    };
    let r = s.request(q, &fx.server, Actor::Human, None).await.unwrap();
    match r.result {
        Ok(Payload::AuditPage(p)) => *p,
        other => panic!("{other:?}"),
    }
}

#[test]
fn audit_query_pages_verify_in_the_mirror() {
    let mut fx = Fixture::new(1, 0);
    let key = fx.keys.signing_key;
    let mut known = MirrorHead::default();
    {
        let fx = &fx;
        let known = &mut known;
        run(async {
            let mut s = fx.connect(&fx.macs[0]).await;
            for _ in 0..3 {
                s.request(Op::SystemInfo, &fx.server, Actor::Human, None)
                    .await
                    .unwrap();
            }
            let p = audit_page(&mut s, fx, 0, 2).await;
            assert_eq!(p.entries.len(), 2);
            assert!(p.more);
            assert_eq!(p.anchor, None);
            let v = verify_page(&fx.server, &key, *known, &p).unwrap();
            *known = v.head;
            let p = audit_page(&mut s, fx, known.seq, 1000).await;
            assert!(!p.more);
            let v = verify_page(&fx.server, &key, *known, &p).unwrap();
            assert!(v.entries.len() >= 4, "reads and this query are audited");
            *known = v.head;
            // Bounds are checked.
            let q = Op::AuditQuery {
                after_seq: 0,
                limit: 0,
            };
            let r = s.request(q, &fx.server, Actor::Human, None).await.unwrap();
            assert_eq!(err(r), ErrorCode::InvalidArgument);
        });
    }
    // Root wipes the history (a fresh database, same keys): the chain is
    // shorter than what the Mac verified.
    fx.exec = None;
    std::fs::remove_file(&fx.paths.state_db).unwrap();
    install::install(
        &fx.paths,
        &InstallInput {
            genesis: fx.genesis.clone(),
            policy_toml: policy_toml(fx.fleet, 1, Pol::default()),
            server_id: fx.server.clone(),
            admin_user: Some("admin".into()),
        },
    )
    .unwrap();
    fx.start_exec();
    let fx = &fx;
    run(async {
        let mut s = fx.connect(&fx.macs[0]).await;
        let p = audit_page(&mut s, fx, known.seq, 1000).await;
        assert!(matches!(
            verify_page(&fx.server, &key, known, &p),
            Err(Tamper::Truncated { .. })
        ));
    });
}

#[test]
fn stored_policy_reverified_at_start() {
    let mut fx = Fixture::new(1, 0);
    {
        let fx = &fx;
        run(async {
            let mut s = fx.connect(&fx.macs[0]).await;
            let op = fx.policy_op(2);
            let approval = fx.approve(&fx.macs[0], &op);
            let r = s
                .request(op, &fx.server, Actor::Human, Some(approval))
                .await
                .unwrap();
            assert_eq!(r.result, Ok(Payload::Empty));
        });
    }
    // An approved policy survives a restart.
    fx.restart_exec();
    {
        let fx = &fx;
        run(async {
            let s = fx.connect(&fx.macs[0]).await;
            assert_eq!(s.status().health.as_ref().unwrap().policy_version, 2);
        });
    }
    // Edit the stored TOML (root with the database, no root key): exec
    // starts deny-all and raises a critical alert instead of enforcing it.
    fx.exec = None;
    {
        let store = Store::open(&fx.paths.state_db).unwrap();
        let raw = store.meta().get(MetaKey::Policy).unwrap().unwrap();
        let mut sp: StoredPolicy = fleet_proto::decode(&raw).unwrap();
        assert!(sp.approval.is_some() && sp.roster.is_some());
        sp.toml = sp.toml.replace(r#"allow = ["system"]"#, r#"allow = ["system", "users"]"#);
        store
            .meta()
            .set(MetaKey::Policy, &fleet_proto::encode(&sp))
            .unwrap();
    }
    fx.start_exec();
    let fx = &fx;
    run(async {
        let mut s = fx.connect(&fx.macs[0]).await;
        assert_eq!(s.status().health.as_ref().unwrap().policy_version, 0);
        let r = s
            .request(Op::SystemInfo, &fx.server, Actor::Human, None)
            .await
            .unwrap();
        assert_eq!(err(r), ErrorCode::PolicyDenied);
        let q = Op::EventsQuery {
            since_run_id: None,
            since_seq: 0,
            limit: 100,
        };
        let r = s.request(q, &fx.server, Actor::Human, None).await.unwrap();
        let Ok(Payload::SignedEvents(p)) = r.result else {
            panic!("{r:?}")
        };
        assert!(p.events.iter().any(|e| matches!(
            &e.event,
            Event::AlertFired { rule_id, .. } if rule_id == "policy.rejected"
        )));
        // A new approved policy is accepted again.
        let op = fx.policy_op(3);
        let approval = fx.approve(&fx.macs[0], &op);
        let r = s
            .request(op, &fx.server, Actor::Human, Some(approval))
            .await
            .unwrap();
        assert_eq!(r.result, Ok(Payload::Empty));
    });
}
