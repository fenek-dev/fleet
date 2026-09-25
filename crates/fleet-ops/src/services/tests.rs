use super::*;
use crate::FakeRunner;
use crate::handler::OpOutput;
use crate::testutil::{block, ctx, meta};
use proptest::prelude::*;

fn unit(s: &str) -> UnitName {
    UnitName::new(s).unwrap()
}

fn fake() -> Rc<FakeSystemd> {
    Rc::new(
        FakeSystemd::new()
            .with_unit("nginx.service", "active", "running", "enabled")
            .with_unit("ssh.service", "active", "running", "enabled")
            .with_unit("cron.service", "failed", "failed", "enabled")
            .with_unit("fleet-exec.service", "active", "running", "enabled"),
    )
}

fn run(api: Rc<FakeSystemd>, op: Op) -> Result<Payload, OpError> {
    let dir = tempfile::tempdir().unwrap();
    let c = ctx(dir.path(), Rc::new(FakeRunner::new()));
    let h = ServicesHandler::new(api);
    let m = meta(op.clone(), Some(1));
    h.validate(&c, &op, &m)?;
    match block(h.handle(&c, &op, &m))? {
        OpOutput::Payload(p) => Ok(p),
        OpOutput::Stream(_) => panic!("stream"),
    }
}

#[test]
fn list_merges_loaded_and_files() {
    let api = fake();
    api.files.borrow_mut().push((
        "/usr/lib/systemd/system/apache2.service".into(),
        "disabled".into(),
    ));
    api.files.borrow_mut().push((
        "/usr/lib/systemd/system/getty@.service".into(),
        "enabled".into(),
    ));
    api.units.borrow_mut().push(RawUnit {
        name: "dev-sda.device".into(),
        load_state: "loaded".into(),
        active_state: "active".into(),
        ..RawUnit::default()
    });
    api.units.borrow_mut().push(RawUnit {
        name: "gone.service".into(),
        load_state: "not-found".into(),
        active_state: "inactive".into(),
        ..RawUnit::default()
    });
    let Payload::Units(u) = run(api, Op::UnitList).unwrap() else {
        panic!()
    };
    let names: Vec<&str> = u.units.iter().map(|u| u.name.as_str()).collect();
    // Sorted; devices, templates and not-found units left out.
    assert_eq!(
        names,
        [
            "apache2.service",
            "cron.service",
            "fleet-exec.service",
            "nginx.service",
            "ssh.service"
        ]
    );
    let apache = &u.units[0];
    assert_eq!(apache.active, UnitActiveState::Inactive);
    assert_eq!(apache.file_state, "disabled");
    assert_eq!(u.units[1].active, UnitActiveState::Failed);
    assert_eq!(u.units[3].file_state, "enabled");
}

#[test]
fn status_maps_props() {
    let api = fake();
    {
        let mut p = api.props.borrow_mut();
        let n = p.get_mut("nginx.service").unwrap();
        n.main_pid = Some(812);
        n.active_enter_us = Some(1_700_000_000_123_456);
        n.memory_bytes = Some(12 << 20);
        n.cpu_ns = Some(5_000_000);
        n.tasks = Some(u64::MAX - 1);
        n.restarts = Some(2);
    }
    let Payload::UnitStatus(s) = run(
        api.clone(),
        Op::UnitStatus {
            unit: unit("nginx.service"),
        },
    )
    .unwrap() else {
        panic!()
    };
    assert_eq!(s.info.name, "nginx.service");
    assert_eq!(s.info.active, UnitActiveState::Active);
    assert_eq!(s.info.sub, "running");
    assert_eq!(s.main_pid, Some(812));
    assert_eq!(s.since_ms, Some(1_700_000_000_123));
    assert_eq!(s.memory_bytes, Some(12 << 20));
    assert_eq!(s.tasks, Some(u32::MAX));
    assert_eq!(s.restarts, 2);

    // Unknown unit: NotFound.
    let e = run(
        api,
        Op::UnitStatus {
            unit: unit("nope.service"),
        },
    )
    .unwrap_err();
    assert_eq!(e.code(), ErrorCode::NotFound);
}

#[test]
fn start_stop_restart_reload_run_jobs() {
    let api = fake();
    for (op, call) in [
        (
            Op::UnitStop {
                unit: unit("nginx.service"),
            },
            "StopUnit nginx.service",
        ),
        (
            Op::UnitStart {
                unit: unit("nginx.service"),
            },
            "StartUnit nginx.service",
        ),
        (
            Op::UnitRestart {
                unit: unit("nginx.service"),
            },
            "RestartUnit nginx.service",
        ),
        (
            Op::UnitReload {
                unit: unit("nginx.service"),
            },
            "ReloadUnit nginx.service",
        ),
    ] {
        let stop = matches!(op, Op::UnitStop { .. });
        let Payload::UnitStatus(s) = run(api.clone(), op).unwrap() else {
            panic!()
        };
        let want = if stop {
            UnitActiveState::Inactive
        } else {
            UnitActiveState::Active
        };
        assert_eq!(s.info.active, want);
        assert!(api.calls().contains(&call.to_owned()), "{call}");
    }
}

#[test]
fn enable_disable() {
    let api = fake();
    let Payload::UnitStatus(s) = run(
        api.clone(),
        Op::UnitDisable {
            unit: unit("nginx.service"),
        },
    )
    .unwrap() else {
        panic!()
    };
    assert_eq!(s.info.file_state, "disabled");
    let Payload::UnitStatus(s) = run(
        api.clone(),
        Op::UnitEnable {
            unit: unit("nginx.service"),
        },
    )
    .unwrap() else {
        panic!()
    };
    assert_eq!(s.info.file_state, "enabled");
    assert_eq!(
        api.calls()
            .into_iter()
            .filter(|c| c.contains("able "))
            .collect::<Vec<_>>(),
        ["disable nginx.service", "enable nginx.service"]
    );
    // SSH may be (re-)enabled, never disabled.
    assert!(
        run(
            api,
            Op::UnitEnable {
                unit: unit("ssh.service")
            }
        )
        .is_ok()
    );
}

#[test]
fn job_results_map_to_codes() {
    let api = fake();
    for (r, code) in [
        (Ok(JobResult::Failed), ErrorCode::Internal),
        (Ok(JobResult::Dependency), ErrorCode::Internal),
        (Ok(JobResult::Timeout), ErrorCode::Timeout),
        (Ok(JobResult::Canceled), ErrorCode::Busy),
        (Err(SdError::Timeout), ErrorCode::Timeout),
        (Err(SdError::NoSuchUnit), ErrorCode::NotFound),
        (Err(SdError::Bus("x".into())), ErrorCode::Internal),
    ] {
        api.push_job_result(r);
        let e = run(
            api.clone(),
            Op::UnitStart {
                unit: unit("cron.service"),
            },
        )
        .unwrap_err();
        assert_eq!(e.code(), code);
    }
    api.push_job_result(Ok(JobResult::Skipped));
    assert!(
        run(
            api,
            Op::UnitStart {
                unit: unit("cron.service")
            }
        )
        .is_ok()
    );
}

#[test]
fn critical_unit_refusals() {
    type Mk = fn(UnitName) -> Op;
    let stop: Mk = |unit| Op::UnitStop { unit };
    let disable: Mk = |unit| Op::UnitDisable { unit };
    let start: Mk = |unit| Op::UnitStart { unit };
    let restart: Mk = |unit| Op::UnitRestart { unit };
    let reload: Mk = |unit| Op::UnitReload { unit };
    let enable: Mk = |unit| Op::UnitEnable { unit };
    let cases: [(&str, Mk, bool); 20] = [
        ("dbus.service", stop, false),
        ("dbus.socket", disable, false),
        ("dbus-broker.service", stop, false),
        ("systemd-journald.service", stop, false),
        ("systemd-journald.socket", stop, false),
        ("systemd-journald-dev-log.socket", disable, false),
        ("systemd-networkd.service", stop, false),
        ("networking.service", disable, false),
        ("NetworkManager.service", stop, false),
        ("systemd-logind.service", stop, false),
        ("nftables.service", stop, false),
        ("nftables.service", disable, false),
        ("nftables.service", restart, false),
        ("nftables.service", reload, false),
        ("nftables.service", start, false),
        ("ssh.service", stop, false),
        // Allowed: restarts of critical units, enable of nftables, others.
        ("dbus.service", restart, true),
        ("systemd-journald.service", restart, true),
        ("nftables.service", enable, true),
        ("nginx.service", stop, true),
    ];
    for (name, mk, ok) in cases {
        let op = mk(unit(name));
        let r = check_unit_op(&op);
        assert_eq!(r.is_ok(), ok, "{name} {}", op.name());
        if let Err(e) = r {
            assert_eq!(e.code(), ErrorCode::PolicyDenied);
        }
    }
}

#[test]
fn refusals_touch_nothing() {
    let api = fake();
    let refused = [
        Op::UnitStop {
            unit: unit("ssh.service"),
        },
        Op::UnitStop {
            unit: unit("sshd.service"),
        },
        Op::UnitStop {
            unit: unit("ssh.socket"),
        },
        Op::UnitDisable {
            unit: unit("ssh.service"),
        },
        Op::UnitDisable {
            unit: unit("sshd.service"),
        },
        Op::UnitDisable {
            unit: unit("ssh.socket"),
        },
        Op::UnitStart {
            unit: unit("fleet-exec.service"),
        },
        Op::UnitStop {
            unit: unit("fleet-gate.service"),
        },
        Op::UnitRestart {
            unit: unit("fleet-exec.service"),
        },
        Op::UnitReload {
            unit: unit("fleet@x.service"),
        },
        Op::UnitEnable {
            unit: unit("fleet-revert.timer"),
        },
        Op::UnitDisable {
            unit: unit("fleet-exec.service"),
        },
    ];
    for op in refused {
        let name = op.name();
        let e = run(api.clone(), op).unwrap_err();
        assert_eq!(e.code(), ErrorCode::PolicyDenied, "{name}");
    }
    assert!(api.calls().is_empty(), "{:?}", api.calls());

    // Also refused in `handle` alone (defence in depth).
    let dir = tempfile::tempdir().unwrap();
    let c = ctx(dir.path(), Rc::new(FakeRunner::new()));
    let op = Op::UnitStop {
        unit: unit("ssh.service"),
    };
    let h = ServicesHandler::new(api.clone());
    let r = block(h.handle(&c, &op, &meta(op.clone(), Some(1))));
    assert_eq!(r.unwrap_err().code(), ErrorCode::PolicyDenied);
    assert!(api.calls().is_empty());

    // Restart of sshd and reads of fleet units stay allowed.
    assert!(
        run(
            api.clone(),
            Op::UnitRestart {
                unit: unit("ssh.service")
            }
        )
        .is_ok()
    );
    assert!(
        run(
            api,
            Op::UnitStatus {
                unit: unit("fleet-exec.service")
            }
        )
        .is_ok()
    );
}

#[test]
fn registry_routes_all_service_tags() {
    let mut r = Registry::new();
    register(&mut r, fake());
    for op in [
        Op::UnitList,
        Op::UnitStatus {
            unit: unit("a.service"),
        },
        Op::UnitStart {
            unit: unit("a.service"),
        },
        Op::UnitStop {
            unit: unit("a.service"),
        },
        Op::UnitRestart {
            unit: unit("a.service"),
        },
        Op::UnitReload {
            unit: unit("a.service"),
        },
        Op::UnitEnable {
            unit: unit("a.service"),
        },
        Op::UnitDisable {
            unit: unit("a.service"),
        },
    ] {
        assert!(r.get(&op).is_some(), "{}", op.name());
    }
    assert_eq!(r.tags().count(), 8);
}

#[test]
fn service_events_emit_only_changes() {
    let api = fake();
    block(async {
        let mut ev = ServiceEvents::start(&*api).await.unwrap();
        api.push_signal("nginx.service", "active"); // no change
        api.push_signal("nginx.service", "deactivating");
        api.push_signal("dev-sda.device", "inactive"); // not a listable unit
        api.push_signal("nginx.service", "failed");
        api.push_signal("new.service", "active"); // first seen
        let mut got = Vec::new();
        while let Some(e) = ev.next().await {
            got.push(e);
        }
        let s = |u: &str, from, to| Event::ServiceStateChanged {
            unit: u.into(),
            from,
            to,
        };
        use UnitActiveState::*;
        assert_eq!(
            got,
            [
                s("nginx.service", Active, Deactivating),
                s("nginx.service", Deactivating, Failed),
                s("new.service", Inactive, Active),
            ]
        );
    });
    // Watch before list, so nothing between them is lost.
    assert_eq!(api.calls()[..2], ["watch", "list_units"]);
}

#[test]
fn bus_label_unescape() {
    use super::zbus_impl::unescape_bus_label as u;
    assert_eq!(u("ssh_2eservice").as_deref(), Some("ssh.service"));
    assert_eq!(
        u("getty_40tty1_2eservice").as_deref(),
        Some("getty@tty1.service")
    );
    assert_eq!(u("_31foo_2dbar_2etimer").as_deref(), Some("1foo-bar.timer"));
    assert_eq!(u("bad_2"), None);
    assert_eq!(u("bad_zz"), None);
    assert_eq!(u("_ff"), None); // not UTF-8
}

#[test]
fn active_state_mapping() {
    assert_eq!(active_state("reloading"), UnitActiveState::Reloading);
    assert_eq!(active_state("maintenance"), UnitActiveState::Other);
    assert_eq!(JobResult::parse("done"), JobResult::Done);
    assert_eq!(JobResult::parse("weird"), JobResult::Other("weird".into()));
}

proptest! {
    #[test]
    fn unescape_never_panics(s in ".{0,64}") {
        let _ = super::zbus_impl::unescape_bus_label(&s);
    }
}
