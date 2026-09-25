use super::project::{self, ComposeHandler, DOCKER};
use super::streams::{LogsStream, StatsStream, compute};
use super::*;
use crate::ctx::SystemClock;
use crate::fswrite;
use crate::handler::OpStream;
use crate::runner::{CommandOutput, FakeRunner};
use crate::security::VecSink;
use crate::testutil::{block, ctx, meta};
use fleet_proto::args::{ComposeFile, ComposeProject, ContainerName, ImageRef, VolumeName};
use fleet_proto::payload::{ContainerState, DockerLogLine};
use fleet_proto::{ContainerAction, Event, Tier};

fn info(id: &str, name: &str, state: ContainerState) -> ContainerInfo {
    ContainerInfo {
        id: id.into(),
        name: name.into(),
        image: "nginx:1".into(),
        state,
        status: "Up".into(),
        created_ms: 0,
        ports: vec![],
        compose_project: None,
    }
}

fn fake() -> Rc<FakeDocker> {
    let f = FakeDocker::new();
    f.containers.borrow_mut().extend([
        info("aaaaaaaaaaaa1111", "web", ContainerState::Running),
        info("bbbbbbbbbbbb2222", "old", ContainerState::Exited),
    ]);
    Rc::new(f)
}

fn run(h: &DockerHandler, op: Op) -> Result<OpOutput, ErrorCode> {
    let c = crate::test_util::ctx();
    let m = meta(op.clone(), Some(1));
    h.validate(&c, &op, &m).map_err(|e| e.code())?;
    block(h.handle(&c, &op, &m)).map_err(|e| e.code())
}

fn payload(o: OpOutput) -> Payload {
    match o {
        OpOutput::Payload(p) => p,
        OpOutput::Stream(_) => panic!("stream"),
    }
}

fn name(s: &str) -> ContainerRef {
    ContainerRef::Name(ContainerName::new(s).unwrap())
}

#[test]
fn container_ops_through_api() {
    let f = fake();
    let h = DockerHandler { api: f.clone() };
    let Payload::Containers(c) = payload(run(&h, Op::DockerContainersList { all: false }).unwrap())
    else {
        panic!()
    };
    assert_eq!(c.containers.len(), 1);
    for op in [
        Op::DockerContainersStart {
            container: name("web"),
        },
        Op::DockerContainersStop {
            container: name("web"),
            timeout_s: 10,
        },
        Op::DockerContainersRestart {
            container: name("web"),
            timeout_s: 5,
        },
        Op::DockerContainersRemove {
            container: name("old"),
            force: true,
        },
    ] {
        assert_eq!(payload(run(&h, op).unwrap()), Payload::Empty);
    }
    assert_eq!(
        *f.calls.borrow(),
        [
            "start web",
            "stop web 10",
            "restart web 5",
            "remove old true"
        ]
    );
    assert_eq!(
        run(
            &h,
            Op::DockerContainersStart {
                container: name("nope")
            }
        )
        .unwrap_err(),
        ErrorCode::NotFound
    );
    // Streams only as streams.
    let logs = Op::DockerLogs {
        container: name("web"),
        tail: 10,
        since_ms: None,
        follow: false,
    };
    assert!(h.supports(&logs, Invocation::Stream));
    assert!(!h.supports(&logs, Invocation::Request));
    assert!(!h.supports(&Op::DockerImagesList, Invocation::Stream));
}

#[test]
fn images_volumes_networks() {
    let f = fake();
    f.images.borrow_mut().push(ImageInfo {
        id: "sha256:1".into(),
        tags: vec!["nginx:1".into()],
        digests: vec![],
        size_bytes: 1,
        created_ms: 0,
        in_use: true,
    });
    f.volumes.borrow_mut().push(VolumeInfo {
        name: "data".into(),
        driver: "local".into(),
        mountpoint: "/var/lib/docker/volumes/data/_data".into(),
        size_bytes: None,
        in_use: true,
    });
    let h = DockerHandler { api: f.clone() };
    let img = ImageRef::new("nginx:1").unwrap();
    run(&h, Op::DockerImagesPull { image: img.clone() }).unwrap();
    run(
        &h,
        Op::DockerImagesRemove {
            image: img,
            force: false,
        },
    )
    .unwrap();
    let Payload::Pruned(p) = payload(run(&h, Op::DockerImagesPrune { all_unused: true }).unwrap())
    else {
        panic!()
    };
    assert_eq!(p.removed, 2);
    assert_eq!(
        run(
            &h,
            Op::DockerVolumesRemove {
                volume: VolumeName::new("data").unwrap()
            }
        )
        .unwrap_err(),
        ErrorCode::Busy
    );
    assert!(matches!(
        payload(run(&h, Op::DockerNetworksList).unwrap()),
        Payload::Networks(_)
    ));
    assert_eq!(f.calls.borrow()[0], "pull nginx:1");
}

#[test]
fn inspect_redacts_env() {
    let f = fake();
    f.inspect.borrow_mut().insert(
        "web".into(),
        serde_json::json!({
            "Id": "aaaaaaaaaaaa1111",
            "Name": "/web",
            "Created": "2024-01-02T03:04:05.678901234Z",
            "State": {"Status": "running"},
            "Config": {
                "Image": "nginx:1",
                "Env": ["DB_PASSWORD=hunter2", "PATH=/usr/bin", "NOVALUE"],
                "Labels": {"com.docker.compose.project": "shop"}
            },
            "NetworkSettings": {"Ports": {
                "80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}],
                "53/udp": null,
                "9/sctp": [{"HostIp": "", "HostPort": "9"}]
            }}
        }),
    );
    let h = DockerHandler { api: f };
    let Payload::ContainerDetail(d) = payload(
        run(
            &h,
            Op::DockerContainersGet {
                container: name("web"),
            },
        )
        .unwrap(),
    ) else {
        panic!()
    };
    assert!(!d.inspect_json.contains("hunter2"));
    assert!(!d.inspect_json.contains("/usr/bin\""));
    assert!(d.inspect_json.contains("DB_PASSWORD=<redacted>"));
    assert_eq!(d.info.name, "web");
    assert_eq!(d.info.state, ContainerState::Running);
    assert_eq!(d.info.compose_project.as_deref(), Some("shop"));
    assert_eq!(d.info.created_ms, 1_704_164_645_678);
    assert_eq!(d.info.ports.len(), 1);
    assert_eq!(d.info.ports[0].host_port, 8080);
}

#[test]
fn rfc3339() {
    assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:01Z"), Some(1000));
    assert_eq!(parse_rfc3339_ms("1970-01-01T02:00:01.5+02:00"), Some(1500));
    assert_eq!(parse_rfc3339_ms("0001-01-01T00:00:00Z"), None);
    assert_eq!(parse_rfc3339_ms("garbage"), None);
    assert_eq!(parse_rfc3339_ms("2024-13-01T00:00:00Z"), None);
}

#[test]
fn logs_stream_batches_and_parses_timestamps() {
    let f = fake();
    f.logs.borrow_mut().extend([
        Ok(LogFrame {
            stream: LogStream::Stdout,
            bytes: b"1970-01-01T00:00:02.000000000Z hello\n".to_vec(),
        }),
        Ok(LogFrame {
            stream: LogStream::Stderr,
            bytes: b"no timestamp\r\n".to_vec(),
        }),
        Ok(LogFrame {
            stream: LogStream::Stdout,
            bytes: vec![b'x'; streams::MAX_LINE + 10],
        }),
    ]);
    let h = DockerHandler { api: f.clone() };
    let op = Op::DockerLogs {
        container: name("web"),
        tail: 100,
        since_ms: Some(5_500),
        follow: false,
    };
    let c = crate::test_util::ctx();
    let OpOutput::Stream(mut s) = block(h.handle(&c, &op, &meta(op.clone(), None))).unwrap() else {
        panic!()
    };
    let Some(Ok(Payload::DockerLogChunk(chunk))) = block(s.next()) else {
        panic!()
    };
    assert_eq!(chunk.lines.len(), 3);
    assert_eq!(
        chunk.lines[0],
        DockerLogLine {
            time_ms: Some(2000),
            stream: LogStream::Stdout,
            text: "hello".into()
        }
    );
    assert_eq!(chunk.lines[1].text, "no timestamp");
    assert_eq!(chunk.lines[1].stream, LogStream::Stderr);
    assert_eq!(chunk.lines[2].text.len(), streams::MAX_LINE);
    assert!(block(s.next()).is_none());
    assert_eq!(
        f.log_opts.borrow()[0],
        LogOptions {
            tail: 100,
            since_s: Some(5),
            follow: false
        }
    );
    // Errors end the stream after being reported.
    let mut ls = LogsStream::new(Box::pin(futures_util::stream::iter([Err(
        DockerError::Unavailable("x".into()),
    )])));
    assert!(matches!(block(ls.next()), Some(Err(_))));
    assert!(block(ls.next()).is_none());
    assert_eq!(
        run(
            &h,
            Op::DockerLogs {
                container: name("web"),
                tail: 10_001,
                since_ms: None,
                follow: true
            }
        )
        .err(),
        Some(ErrorCode::InvalidArgument)
    );
}

#[test]
fn stats_math_and_stream() {
    let a = RawStats {
        cpu_total_ns: 1_000,
        system_cpu_ns: 10_000,
        online_cpus: 4,
        mem_usage: 500,
        mem_inactive_file: 100,
        mem_limit: 1000,
        net_rx: 0,
        net_tx: 0,
        blk_read: 0,
        blk_write: 0,
        pids: 3,
    };
    let b = RawStats {
        cpu_total_ns: 3_000,
        system_cpu_ns: 20_000,
        net_rx: 2_000,
        blk_write: 500,
        ..a
    };
    let s0 = compute("x", None, &a);
    assert_eq!(s0.mem_bytes, 400);
    assert_eq!(s0.cpu_pct.0, 0.0);
    let s = compute("x", Some((&a, Duration::from_secs(2))), &b);
    assert_eq!(s.cpu_pct.0, 80.0); // 2000/10000 × 4 × 100
    assert_eq!(s.net_rx_bps, 1_000);
    assert_eq!(s.blk_write_bps, 250);
    assert_eq!(s.pids, 3);

    let f = fake();
    f.stats
        .borrow_mut()
        .insert("aaaaaaaaaaaa1111".into(), vec![a, b]);
    let mut st = StatsStream::new(f, Rc::new(SystemClock), vec!["web".into()])
        .with_interval(Duration::from_millis(5));
    assert!(st.latest_only());
    let Some(Ok(Payload::DockerStats(d))) = block(st.next()) else {
        panic!()
    };
    assert_eq!(d.containers.len(), 1);
    assert!(d.containers[0].cpu_pct.0 > 0.0);
}

#[test]
fn events_to_sink_and_alerts() {
    use crate::telemetry::{AlertInput, Observation};
    use std::cell::RefCell;
    #[derive(Default)]
    struct Obs(RefCell<Vec<Observation>>);
    impl AlertInput for Obs {
        fn observe(&self, o: Observation, _now: u64) {
            self.0.borrow_mut().push(o);
        }
    }
    let ev = |a: &str, code: Option<i32>| {
        Ok(ContainerEvent {
            id: "aaaaaaaaaaaa1111".into(),
            name: "web".into(),
            action: a.into(),
            exit_code: code,
        })
    };
    let f = fake();
    f.events.borrow_mut().extend([
        ev("exec_start: /bin/sh -c healthcheck", None),
        ev("die", Some(137)),
        ev("health_status: healthy", None),
        Err(DockerError::Unavailable("gone".into())),
        ev("start", None),
    ]);
    let sink = VecSink::default();
    let obs = Obs::default();
    let n = block(events::pump(f.events(), &sink, Some(&obs), &SystemClock));
    assert_eq!(n, 2, "stops at the error, skips exec_*");
    let got = sink.take();
    assert_eq!(
        got[0],
        Event::Container {
            id: "aaaaaaaaaaaa1111".into(),
            name: "web".into(),
            action: ContainerAction::Die,
            exit_code: Some(137)
        }
    );
    let levels: Vec<u64> = obs
        .0
        .borrow()
        .iter()
        .map(|o| match o {
            Observation::Level { value, .. } => *value,
            _ => panic!(),
        })
        .collect();
    assert_eq!(levels, [1, 0]);
}

#[test]
fn bollard_conversions() {
    use bollard::models::{ContainerSummary, PortSummary, PortSummaryTypeEnum};
    let c = ContainerSummary {
        id: Some("abc".into()),
        names: Some(vec!["/web".into()]),
        state: Some(bollard::models::ContainerSummaryStateEnum::RUNNING),
        created: Some(10),
        ports: Some(vec![
            PortSummary {
                ip: Some("0.0.0.0".into()),
                private_port: 80,
                public_port: Some(8080),
                typ: Some(PortSummaryTypeEnum::TCP),
            },
            PortSummary {
                ip: None,
                private_port: 81,
                public_port: None,
                typ: Some(PortSummaryTypeEnum::TCP),
            },
        ]),
        ..Default::default()
    };
    let i = bollard_api::container_info(&c);
    assert_eq!(i.name, "web");
    assert_eq!(i.state, ContainerState::Running);
    assert_eq!(i.created_ms, 10_000);
    assert_eq!(i.ports.len(), 1);
    assert_eq!(
        bollard_api::pull_parts("nginx"),
        ("nginx".into(), Some("latest".into()))
    );
    assert_eq!(
        bollard_api::pull_parts("reg:5000/app").1.as_deref(),
        Some("latest")
    );
    assert_eq!(bollard_api::pull_parts("reg:5000/app:2").1, None);
    assert_eq!(bollard_api::pull_parts("app@sha256:ab").1, None);
}

#[test]
fn unavailable_socket_is_an_error_not_a_panic() {
    let d = BollardDocker::with_socket("/nonexistent/docker.sock");
    let e = block(d.list_containers(true)).unwrap_err();
    assert!(matches!(e, DockerError::Unavailable(_)));
    assert_eq!(OpError::from(e).code(), ErrorCode::Internal);
}

// ---- compose ----

fn proj() -> ComposeProject {
    ComposeProject::new("shop").unwrap()
}

const YAML: &str = "services:\n  web:\n    image: nginx:1\n    volumes:\n      - ./data:/data\n";

fn prefix() -> Vec<String> {
    [
        "compose",
        "-f",
        "/srv/shop/compose.yaml",
        "--project-directory",
        "/srv/shop",
        "-p",
        "shop",
    ]
    .map(String::from)
    .to_vec()
}

fn scoped_argv(id: u64, rest: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = [
        "--scope",
        "--quiet",
        "--collect",
        "--unit",
        &format!("fleet-op-{id}"),
        "--",
        DOCKER,
    ]
    .map(String::from)
    .to_vec();
    v.extend(prefix());
    v.extend(rest.iter().map(|s| s.to_string()));
    v
}

fn expect(r: &FakeRunner, program: &'static str, argv: Vec<String>, out: CommandOutput) {
    let a: Vec<&str> = argv.iter().map(String::as_str).collect();
    r.expect(program, &a, Ok(out));
}

fn deploy_op(yaml: &str, pull: bool) -> Op {
    Op::ComposeDeploy {
        project: proj(),
        file: ComposeFile::new(yaml).unwrap(),
        pull,
    }
}

fn run_compose(c: &SysCtx, op: Op, expected: Option<u64>) -> Result<Payload, ErrorCode> {
    let mut m = meta(op.clone(), Some(42));
    m.command.body.expected_version = expected;
    ComposeHandler.validate(c, &op, &m).map_err(|e| e.code())?;
    block(ComposeHandler.handle(c, &op, &m))
        .map(payload)
        .map_err(|e| e.code())
}

const PS: &str =
    "{\"Name\":\"shop-web-1\",\"Service\":\"web\",\"State\":\"running\",\"Image\":\"nginx:1\"}\n";

#[test]
fn deploy_writes_file_and_runs_exact_argv() {
    let d = tempfile::tempdir().unwrap();
    let r = Rc::new(FakeRunner::new());
    expect(
        &r,
        "/usr/bin/systemd-run",
        scoped_argv(42, &["pull"]),
        CommandOutput::ok(""),
    );
    expect(
        &r,
        "/usr/bin/systemd-run",
        scoped_argv(42, &["up", "-d", "--remove-orphans"]),
        CommandOutput::ok(""),
    );
    let mut ps = prefix();
    ps.extend(["ps", "--all", "--format", "json"].map(String::from));
    expect(&r, DOCKER, ps, CommandOutput::ok(PS));
    let c = ctx(d.path(), r.clone());
    let Payload::ComposeProjects(p) =
        run_compose(&c, deploy_op(YAML, true), Some(fswrite::version_of(b""))).unwrap()
    else {
        panic!()
    };
    assert_eq!(r.pending(), 0);
    assert_eq!(p.projects[0].services[0].state, ContainerState::Running);
    assert_eq!(
        p.projects[0].file_hash,
        Some(*blake3::hash(YAML.as_bytes()).as_bytes())
    );
    let written = d.path().join("srv/shop/compose.yaml");
    assert_eq!(std::fs::read_to_string(&written).unwrap(), YAML);
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&written), 0o640);
    assert_eq!(mode(&d.path().join("srv/shop")), 0o750);
    // Environment: only HOME on top of the runner's base; no COMPOSE_*.
    for call in r.calls() {
        let names: Vec<&str> = call.env.iter().map(|(k, _)| *k).collect();
        assert_eq!(names, ["HOME"]);
    }
    // Stale expected_version → conflict before anything runs.
    let r2 = Rc::new(FakeRunner::new());
    let c2 = ctx(d.path(), r2.clone());
    assert_eq!(
        run_compose(&c2, deploy_op(YAML, false), Some(1)),
        Err(ErrorCode::VersionConflict {
            current: fswrite::version_of(YAML.as_bytes())
        })
    );
    assert!(r2.calls().is_empty());
}

#[test]
fn deploy_refuses_symlinks_and_compose_env() {
    // Symlinked project directory.
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("srv")).unwrap();
    std::fs::create_dir_all(d.path().join("elsewhere")).unwrap();
    std::os::unix::fs::symlink(d.path().join("elsewhere"), d.path().join("srv/shop")).unwrap();
    let r = Rc::new(FakeRunner::new());
    let c = ctx(d.path(), r.clone());
    assert_eq!(
        run_compose(&c, deploy_op(YAML, false), None),
        Err(ErrorCode::PolicyDenied)
    );
    assert!(!d.path().join("elsewhere/compose.yaml").exists());

    // Symlink inside the project that a relative bind source resolves through.
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("srv/shop")).unwrap();
    std::os::unix::fs::symlink("/etc", d.path().join("srv/shop/data")).unwrap();
    let c = ctx(d.path(), r.clone());
    assert_eq!(
        run_compose(&c, deploy_op(YAML, false), None),
        Err(ErrorCode::PolicyDenied)
    );
    assert!(!d.path().join("srv/shop/compose.yaml").exists());

    // .env overriding Compose itself.
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("srv/shop")).unwrap();
    std::fs::write(
        d.path().join("srv/shop/.env"),
        "DB=1\nexport COMPOSE_FILE=/etc/evil.yaml\n",
    )
    .unwrap();
    let c = ctx(d.path(), r.clone());
    assert_eq!(
        run_compose(&c, deploy_op(YAML, false), None),
        Err(ErrorCode::PolicyDenied)
    );
    assert!(r.calls().is_empty());
    assert_eq!(project::env_file_refused("A=1\n# COMPOSE_X=1\n"), None);
    assert_eq!(
        project::env_file_refused("docker_host=tcp://x\n").as_deref(),
        Some("docker_host")
    );
}

#[test]
fn deploy_escalation_and_errors() {
    let c = crate::test_util::ctx();
    let m = meta(Op::ComposeList, Some(1));
    assert_eq!(deploy_op(YAML, false).tier(), Tier::Change);
    assert!(
        ComposeHandler
            .requires_elevated(
                &c,
                &deploy_op("services:\n  w:\n    privileged: true\n", false),
                &m
            )
            .unwrap()
    );
    assert!(
        !ComposeHandler
            .requires_elevated(&c, &deploy_op(YAML, false), &m)
            .unwrap()
    );
    assert_eq!(
        ComposeHandler
            .validate(&c, &deploy_op("a: &x 1\n", false), &m)
            .unwrap_err()
            .code(),
        ErrorCode::InvalidArgument
    );
}

#[test]
fn down_status_list() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("srv/shop")).unwrap();
    std::fs::create_dir_all(d.path().join("srv/Not_A_Project")).unwrap();
    std::fs::create_dir_all(d.path().join("srv/empty")).unwrap();
    std::fs::write(d.path().join("srv/shop/compose.yaml"), YAML).unwrap();
    let r = Rc::new(FakeRunner::new());
    expect(
        &r,
        "/usr/bin/systemd-run",
        scoped_argv(42, &["down", "--remove-orphans", "--volumes"]),
        CommandOutput::ok(""),
    );
    let mut ps = prefix();
    ps.extend(["ps", "--all", "--format", "json"].map(String::from));
    expect(&r, DOCKER, ps.clone(), CommandOutput::ok("[]"));
    expect(
        &r,
        DOCKER,
        ps,
        CommandOutput::ok(format!("[{}]", PS.trim())),
    );
    let c = ctx(d.path(), r.clone());
    run_compose(
        &c,
        Op::ComposeDown {
            project: proj(),
            remove_volumes: true,
        },
        None,
    )
    .unwrap();
    let Payload::ComposeProjects(l) = run_compose(&c, Op::ComposeList, None).unwrap() else {
        panic!()
    };
    assert_eq!(l.projects.len(), 1);
    assert_eq!(l.projects[0].services[0].name, "web");
    assert_eq!(r.pending(), 0);
    assert_eq!(
        run_compose(
            &c,
            Op::ComposeStatus {
                project: ComposeProject::new("missing").unwrap()
            },
            None
        ),
        Err(ErrorCode::NotFound)
    );
}
