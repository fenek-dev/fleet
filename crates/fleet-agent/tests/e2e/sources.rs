//! Exec's event sources with fakes (design §4.5–§4.7): sshd journal lines
//! → nft ban argv, signed `login`/`ban.changed` events and a `BruteForce`
//! alert; a systemd signal → `ServiceDown`; an integrity violation; ban
//! state and the integrity baseline across an exec restart (bans put back
//! only into empty kernel sets); learned Mac addresses only when the
//! bridge's hint and sshd's journal agree.

use super::*;
use fleet_agent::authorized_keys::ecdsa_blob;
use fleet_agent::bridge::{BridgeMode, header_bytes};
use fleet_agent::exec::SourcesConfig;
use fleet_ops::logs::lines::{LineSource, LineSpawner};
use fleet_ops::security::ssh_fingerprint;
use fleet_ops::services::{
    JobKind, JobResult, RawUnit, SdError, SystemdApi, UnitProps, UnitSignal, UnitWatch,
};
use fleet_ops::telemetry::MetricsStore;
use fleet_ops::{CommandOutput, CommandRunner, CommandSpec, LocalBoxFuture, RunError, SysCtx};
use fleet_proto::alert::{AlertKind, AlertRule, AlertRuleSet, Severity};
use fleet_proto::args::{RuleId, UnitName};
use fleet_proto::payload::{BanReason, IntegrityKind, UnitActiveState};
use std::cell::RefCell;
use std::net::IpAddr;
use std::path::PathBuf;
use std::rc::Rc;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

type Calls = Arc<Mutex<Vec<Vec<String>>>>;

fn args_of(spec: &CommandSpec) -> Vec<String> {
    spec.args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
}

/// The context's runner (nft): records argv; `nft -j list set` answers
/// `list` (exit 1 when `None`), everything else succeeds.
struct Nft {
    calls: Calls,
    list: Option<&'static str>,
}

impl CommandRunner for Nft {
    fn run(&self, spec: CommandSpec) -> LocalBoxFuture<'_, Result<CommandOutput, RunError>> {
        let a = args_of(&spec);
        let out = match (a.first().map(String::as_str), self.list) {
            (Some("-j"), Some(l)) => CommandOutput::ok(l),
            (Some("-j"), None) => CommandOutput::exit(1),
            _ => CommandOutput::ok(""),
        };
        self.calls.lock().unwrap().push(a);
        Box::pin(std::future::ready(Ok(out)))
    }
}

/// `journalctl --follow`: lines from the test through a channel (first
/// spawn only; later spawns fail and back off).
struct Journal {
    rx: RefCell<Option<UnboundedReceiver<String>>>,
    calls: Calls,
}

struct Lines(UnboundedReceiver<String>);

impl LineSource for Lines {
    fn next_line(&mut self) -> LocalBoxFuture<'_, Option<Result<Vec<u8>, RunError>>> {
        Box::pin(async move { self.0.recv().await.map(|l| Ok(l.into_bytes())) })
    }
}

impl LineSpawner for Journal {
    fn spawn(&self, spec: CommandSpec) -> Result<Box<dyn LineSource>, RunError> {
        self.calls.lock().unwrap().push(args_of(&spec));
        let rx = self.rx.borrow_mut().take().ok_or(RunError::Unexpected)?;
        Ok(Box::new(Lines(rx)))
    }
}

/// systemd with one active `nginx.service`; signals from the test.
struct Systemd {
    rx: RefCell<Option<UnboundedReceiver<UnitSignal>>>,
}

struct Watch(UnboundedReceiver<UnitSignal>);

impl UnitWatch for Watch {
    fn next(&mut self) -> LocalBoxFuture<'_, Option<UnitSignal>> {
        Box::pin(async move { self.0.recv().await })
    }
}

impl SystemdApi for Systemd {
    fn list_units(&self) -> LocalBoxFuture<'_, Result<Vec<RawUnit>, SdError>> {
        Box::pin(std::future::ready(Ok(vec![RawUnit {
            name: "nginx.service".into(),
            load_state: "loaded".into(),
            active_state: "active".into(),
            sub_state: "running".into(),
            ..RawUnit::default()
        }])))
    }
    fn list_unit_files(&self) -> LocalBoxFuture<'_, Result<Vec<(String, String)>, SdError>> {
        Box::pin(std::future::ready(Ok(Vec::new())))
    }
    fn unit_props<'a>(&'a self, _: &'a str) -> LocalBoxFuture<'a, Result<UnitProps, SdError>> {
        Box::pin(std::future::ready(Ok(UnitProps {
            load_state: "loaded".into(),
            active_state: "active".into(),
            ..UnitProps::default()
        })))
    }
    fn run_job<'a>(
        &'a self,
        _: JobKind,
        _: &'a str,
        _: Duration,
    ) -> LocalBoxFuture<'a, Result<JobResult, SdError>> {
        Box::pin(std::future::ready(Err(SdError::Bus("fake".into()))))
    }
    fn set_enabled<'a>(&'a self, _: &'a str, _: bool) -> LocalBoxFuture<'a, Result<(), SdError>> {
        Box::pin(std::future::ready(Err(SdError::Bus("fake".into()))))
    }
    fn watch(&self) -> LocalBoxFuture<'_, Result<Box<dyn UnitWatch>, SdError>> {
        let rx = self.rx.borrow_mut().take();
        Box::pin(std::future::ready(match rx {
            Some(rx) => Ok(Box::new(Watch(rx)) as Box<dyn UnitWatch>),
            None => Err(SdError::Bus("gone".into())),
        }))
    }
}

/// Test side of one exec run's fakes.
struct Feeds {
    journal: UnboundedSender<String>,
    signals: UnboundedSender<UnitSignal>,
    nft: Calls,
    spawns: Calls,
}

const GROUPS: &str = r#""system", "security", "services", "packages""#;

const DPKG_LINE: &str = "2026-09-25 10:00:00 upgrade util-linux:amd64 2.38 2.39\n";

/// `pkg.install` stand-in: upgrades `/usr/bin/su` the way dpkg would
/// (new file, dpkg.log line).
struct FakeApt(PathBuf);

impl fleet_ops::OpHandler for FakeApt {
    fn handle<'a>(
        &'a self,
        _: &'a SysCtx,
        _: &'a Op,
        _: &'a fleet_ops::OpMeta,
    ) -> LocalBoxFuture<'a, Result<fleet_ops::OpOutput, fleet_ops::OpError>> {
        Box::pin(async move {
            fake_upgrade(&self.0, "su v2");
            Ok(fleet_ops::OpOutput::Payload(Payload::Empty))
        })
    }
}

fn fake_upgrade(root: &std::path::Path, su: &str) {
    std::fs::write(root.join("usr/bin/su"), su).unwrap();
    let mut log = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(root.join("var/log/dpkg.log"))
        .unwrap();
    std::io::Write::write_all(&mut log, DPKG_LINE.as_bytes()).unwrap();
}

/// Fixture whose exec runs the sources against fakes rooted at `root`.
fn fixture() -> (Fixture, tempfile::TempDir) {
    fixture_with(GROUPS)
}

fn fixture_with(groups: &'static str) -> (Fixture, tempfile::TempDir) {
    let fx = Fixture::with(
        1,
        0,
        Opts {
            pol: Pol {
                groups,
                ..Pol::default()
            },
            ..Opts::default()
        },
    );
    let root = tempfile::tempdir().unwrap();
    let r = root.path();
    for d in ["etc", "usr/bin", "var/log", "var/lib/dpkg/info"] {
        std::fs::create_dir_all(r.join(d)).unwrap();
    }
    std::fs::write(r.join("etc/passwd"), "root:x:0:0::/root:/bin/sh\n").unwrap();
    std::fs::write(
        r.join("var/lib/dpkg/info/util-linux:amd64.list"),
        "/bin/su\n",
    )
    .unwrap();
    (fx, root)
}

/// (Re)starts exec with the sources on fakes; `list` is what `nft -j list
/// set` answers.
fn start(fx: &mut Fixture, root: PathBuf, list: Option<&'static str>) -> Feeds {
    start_with(fx, root, list, |_| {})
}

fn start_with(
    fx: &mut Fixture,
    root: PathBuf,
    list: Option<&'static str>,
    tweak: impl FnOnce(&mut ExecConfig) + Send + 'static,
) -> Feeds {
    let (jtx, jrx) = unbounded_channel();
    let (stx, srx) = unbounded_channel();
    let (nft, spawns): (Calls, Calls) = Default::default();
    let (n, sp) = (nft.clone(), spawns.clone());
    fx.exec = None;
    fx.start_exec_with(move |cfg| {
        cfg.handlers.push((
            fleet_proto::op::tag::PKG_INSTALL,
            Rc::new(FakeApt(root.clone())),
        ));
        cfg.ctx = SysCtx::new(
            root,
            Rc::new(Nft { calls: n, list }),
            Rc::new(fleet_ops::SystemClock),
        );
        let fast = Duration::from_millis(50);
        cfg.sources = SourcesConfig {
            enabled: true,
            spawner: Rc::new(Journal {
                rx: RefCell::new(Some(jrx)),
                calls: sp,
            }),
            systemd: Some(Rc::new(Systemd {
                rx: RefCell::new(Some(srx)),
            })),
            ports_every: Duration::from_secs(3600),
            certs_every: Duration::from_secs(3600),
            integrity_every: fast,
            dpkg_every: fast,
            web_every: fast,
            persist_every: fast,
            backoff_min: fast,
            backoff_max: Duration::from_millis(200),
            web_logs: Vec::new(),
            web_bans_conf: "/etc/fleet/web-bans.conf".into(),
            own_addrs_every: Duration::from_secs(3600),
            integrity_paths: vec!["/etc/passwd".into(), "/usr/bin/su".into()],
            cert_patterns: Vec::new(),
            correlation_window: Duration::from_secs(60),
        };
        tweak(cfg);
    });
    Feeds {
        journal: jtx,
        signals: stx,
        nft,
        spawns,
    }
}

fn rules(fx: &mut Fixture) {
    fx.exec = None;
    let rule = |id: &str, kind, threshold| AlertRule {
        id: RuleId::new(id).unwrap(),
        kind,
        threshold,
        for_s: 0,
        severity: Severity::Warning,
        enabled: true,
    };
    let mut bf = rule("bf", AlertKind::BruteForce, 3);
    bf.for_s = 600;
    let set = AlertRuleSet {
        version: 1,
        rules: vec![
            bf,
            rule(
                "svc",
                AlertKind::ServiceDown {
                    unit: UnitName::new("nginx.service").unwrap(),
                },
                0,
            ),
            rule("integ", AlertKind::IntegrityViolation, 0),
        ],
    };
    Store::open(&fx.paths.state_db)
        .unwrap()
        .metrics()
        .save_rules(&set)
        .unwrap();
}

/// One `journalctl -o json` line from sshd (root, `_COMM=sshd`), logged now.
fn jline(n: u32, msg: &str) -> String {
    jline_from(n, msg, r#""_UID":"0","_COMM":"sshd","_PID":"77""#)
}

/// A line with these trusted fields (JSON members) instead.
fn jline_from(n: u32, msg: &str, fields: &str) -> String {
    format!(
        r#"{{"__CURSOR":"s=test;i={n}","__REALTIME_TIMESTAMP":"{}","SYSLOG_IDENTIFIER":"sshd",{fields},"MESSAGE":"{msg}"}}"#,
        now_ms() * 1000
    )
}

fn fp(mac: &Mac) -> String {
    ssh_fingerprint(&ecdsa_blob(&mac.device.public()).unwrap())
}

/// Events until one matches `done` (all of them, in order).
async fn events_until(
    s: &mut Session<'_, UnixStream>,
    done: impl Fn(&Event) -> bool,
) -> Vec<Event> {
    let mut v = Vec::new();
    loop {
        let (_, e) = s.next_event().await.unwrap();
        let stop = done(&e);
        v.push(e);
        if stop {
            return v;
        }
    }
}

async fn ask(s: &mut Session<'_, UnixStream>, fx: &Fixture, op: Op) -> Result<Payload, ErrorCode> {
    s.request(op, &fx.server, Actor::Human, None)
        .await
        .unwrap()
        .result
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

const ATTACKER: &str = "198.51.100.7";

#[test]
fn sshd_failures_ban_and_alert_services_and_integrity_report() {
    let (mut fx, root) = fixture();
    rules(&mut fx);
    let feeds = start(&mut fx, root.path().to_owned(), None);
    run(async {
        let mut s = fx.connect(&fx.macs[0]).await;
        // Let the first integrity pass record the baseline.
        tokio::time::sleep(Duration::from_millis(150)).await;

        for i in 0..5 {
            let m = format!("Failed password for root from {ATTACKER} port 4242 ssh2");
            feeds.journal.send(jline(i, &m)).unwrap();
        }
        let evs = events_until(&mut s, |e| matches!(e, Event::BanChanged { .. })).await;
        let failed = evs
            .iter()
            .filter(|e| matches!(e, Event::Login { success: false, .. }))
            .count();
        assert_eq!(failed, 5, "{evs:?}");
        assert!(
            evs.iter().any(|e| matches!(
                e,
                Event::AlertFired { rule_id, value: 3, .. } if rule_id == "bf"
            )),
            "{evs:?}"
        );
        assert!(matches!(
            evs.last(),
            Some(Event::BanChanged {
                banned: true,
                reason: BanReason::SshBruteForce,
                addr,
                ..
            }) if *addr == ip(ATTACKER)
        ));
        let want: Vec<String> = [
            "add", "element", "inet", "fleet", "banned4", "{", ATTACKER, "timeout", "3600s", "}",
        ]
        .map(String::from)
        .to_vec();
        assert!(feeds.nft.lock().unwrap().contains(&want));
        // The follower reads only root's sshd entries, new ones first time.
        let spawns = feeds.spawns.lock().unwrap().clone();
        assert!(spawns[0].contains(&"_UID=0".to_owned()));
        assert!(spawns[0].contains(&"--lines=0".to_owned()));

        let r = ask(&mut s, &fx, Op::BansList).await;
        let Ok(Payload::Bans(b)) = r else {
            panic!("{r:?}")
        };
        assert_eq!((b.bans.len(), b.bans[0].strikes), (1, 1));

        // Unit goes down → state event, then the ServiceDown alert.
        feeds
            .signals
            .send(UnitSignal {
                unit: "nginx.service".into(),
                active_state: "failed".into(),
            })
            .unwrap();
        let evs = events_until(
            &mut s,
            |e| matches!(e, Event::AlertFired { rule_id, .. } if rule_id == "svc"),
        )
        .await;
        assert!(evs.iter().any(|e| matches!(
            e,
            Event::ServiceStateChanged { to: UnitActiveState::Failed, unit, .. } if unit == "nginx.service"
        )));

        // A critical file changes → violation event and its alert.
        std::fs::write(root.path().join("etc/passwd"), "evil\n").unwrap();
        let evs = events_until(
            &mut s,
            |e| matches!(e, Event::AlertFired { rule_id, .. } if rule_id == "integ"),
        )
        .await;
        assert!(evs.iter().any(|e| matches!(
            e,
            Event::IntegrityViolation { path, kind: IntegrityKind::Modified } if path == "/etc/passwd"
        )));

        // A Mac's key accepted: a login event naming the device.
        let m = format!(
            "Accepted publickey for admin from 203.0.113.9 port 5000 ssh2: ECDSA {}",
            fp(&fx.macs[0])
        );
        feeds.journal.send(jline(9, &m)).unwrap();
        let evs = events_until(&mut s, |e| matches!(e, Event::Login { success: true, .. })).await;
        let Some(Event::Login {
            device_id, source, ..
        }) = evs.last()
        else {
            panic!()
        };
        assert_eq!(
            (*device_id, *source),
            (Some(fx.macs[0].id), Some(ip("203.0.113.9")))
        );
    });
}

#[test]
fn bans_and_baseline_survive_restart() {
    let (mut fx, root) = fixture();
    let feeds = start(&mut fx, root.path().to_owned(), None);
    run(async {
        let mut s = fx.connect(&fx.macs[0]).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        for i in 0..5 {
            let m = format!("Invalid user oracle from {ATTACKER} port 4242");
            feeds.journal.send(jline(i, &m)).unwrap();
        }
        events_until(&mut s, |e| matches!(e, Event::BanChanged { .. })).await;
    });
    std::fs::write(root.path().join("etc/passwd"), "evil\n").unwrap();

    // The kernel lost its bans (empty sets): exec puts them back.
    let empty = r#"{"nftables":[{"metainfo":{}},{"set":{"name":"x","type":"ipv4_addr"}}]}"#;
    let feeds = start(&mut fx, root.path().to_owned(), Some(empty));
    run(async {
        let mut s = fx.connect(&fx.macs[0]).await;
        let r = ask(&mut s, &fx, Op::BansList).await;
        let Ok(Payload::Bans(b)) = r else {
            panic!("{r:?}")
        };
        assert_eq!(b.bans.len(), 1);
        assert_eq!((b.bans[0].addr, b.bans[0].strikes), (ip(ATTACKER), 1));
        let restored = feeds.nft.lock().unwrap().iter().any(|a| {
            a.starts_with(
                &["add", "element", "inet", "fleet", "banned4", "{", ATTACKER].map(String::from),
            ) && a[8].trim_end_matches('s').parse::<u32>().unwrap() <= 3600
        });
        assert!(restored, "{:?}", feeds.nft.lock().unwrap());
        // The journal resumes after the last entry processed.
        let spawns = feeds.spawns.lock().unwrap().clone();
        assert!(spawns[0].contains(&"--after-cursor=s=test;i=4".to_owned()));
        // The baseline from the first run still stands: the edit made
        // while exec was down is a violation.
        let r = ask(&mut s, &fx, Op::IntegrityStatus).await;
        let Ok(Payload::IntegrityStatus(st)) = r else {
            panic!("{r:?}")
        };
        assert_eq!(st.violations.len(), 1);
        assert_eq!(st.violations[0].kind, IntegrityKind::Modified);
    });

    // Sets still populated (kernel kept them): nothing re-added.
    let full = r#"{"nftables":[{"set":{"name":"x","elem":["198.51.100.7"]}}]}"#;
    let feeds = start(&mut fx, root.path().to_owned(), Some(full));
    run(async {
        let mut s = fx.connect(&fx.macs[0]).await;
        let r = ask(&mut s, &fx, Op::BansList).await;
        assert!(matches!(r, Ok(Payload::Bans(b)) if b.bans.len() == 1));
        let calls = feeds.nft.lock().unwrap().clone();
        assert!(calls.iter().all(|a| a[0] == "-j"), "{calls:?}");
    });
}

/// A session whose bridge sent `hint` as the client address.
async fn hinted<'a>(fx: &Fixture, mac: &'a Mac, hint: &str) -> Session<'a, UnixStream> {
    let mut st = UnixStream::connect(&fx.paths.agent_sock).await.unwrap();
    st.write_all(&header_bytes(BridgeMode::Normal, Some(ip(hint))))
        .await
        .unwrap();
    Session::connect_bridged(st, fx.cfg(mac, KeyKind::Device))
        .await
        .unwrap()
}

#[test]
fn learned_mac_address_needs_journal_corroboration() {
    let (mut fx, root) = fixture();
    let feeds = start(&mut fx, root.path().to_owned(), None);
    let other_fp = ssh_fingerprint(&ecdsa_blob(&p256(99).public()).unwrap());
    run(async {
        let mac = &fx.macs[0];
        let mut watch = fx.connect(mac).await;
        let learned = |calls: &Calls| {
            calls
                .lock()
                .unwrap()
                .iter()
                .filter(|a| a.get(4).is_some_and(|s| s == "exempt4"))
                .map(|a| a[6].clone())
                .collect::<Vec<_>>()
        };

        // Spoofed hint: the verified session claims 198.51.100.66, but sshd
        // accepted the Mac's key from elsewhere, and the key accepted from
        // .66 isn't in the roster.
        let mut s = hinted(&fx, mac, "198.51.100.66").await;
        ask(&mut s, &fx, Op::SystemInfo).await.unwrap();
        for (n, from, key) in [
            (1, "192.0.2.10", fp(mac)),
            (2, "198.51.100.66", other_fp.clone()),
        ] {
            let m = format!("Accepted publickey for admin from {from} port 1 ssh2: ECDSA {key}");
            feeds.journal.send(jline(n, &m)).unwrap();
            events_until(&mut watch, |e| matches!(e, Event::Login { .. })).await;
        }
        assert!(learned(&feeds.nft).is_empty());

        // Genuine: hint and sshd agree on address and device.
        let mut s = hinted(&fx, mac, "203.0.113.50").await;
        ask(&mut s, &fx, Op::SystemInfo).await.unwrap();
        let m = format!(
            "Accepted publickey for admin from 203.0.113.50 port 2 ssh2: ECDSA {}",
            fp(mac)
        );
        feeds.journal.send(jline(3, &m)).unwrap();
        events_until(&mut watch, |e| matches!(e, Event::Login { .. })).await;
        assert_eq!(learned(&feeds.nft), ["203.0.113.50"]);
        let r = ask(&mut s, &fx, Op::BansList).await;
        let Ok(Payload::Bans(b)) = r else {
            panic!("{r:?}")
        };
        assert_eq!(b.learned_exempt, [ip("203.0.113.50")]);

        // Now exempt: its failures never ban.
        for i in 10..16 {
            let m = "Failed password for admin from 203.0.113.50 port 3 ssh2";
            feeds.journal.send(jline(i, m)).unwrap();
        }
        feeds
            .journal
            .send(jline(20, "Invalid user x from 192.0.2.99 port 4"))
            .unwrap();
        let evs = events_until(
            &mut watch,
            |e| matches!(e, Event::Login { source: Some(a), .. } if *a == ip("192.0.2.99")),
        )
        .await;
        assert!(!evs.iter().any(|e| matches!(e, Event::BanChanged { .. })));
    });
}

#[test]
fn fleet_package_op_rebaselines_its_files_only() {
    let (mut fx, root) = fixture();
    std::fs::write(root.path().join("usr/bin/su"), "su v1").unwrap();
    let _feeds = start(&mut fx, root.path().to_owned(), None);
    run(async {
        let mut s = fx.connect(&fx.macs[0]).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let violations = async |s: &mut Session<'_, UnixStream>| {
            let r = ask(s, &fx, Op::IntegrityStatus).await;
            let Ok(Payload::IntegrityStatus(st)) = r else {
                panic!("{r:?}")
            };
            st.violations
        };

        // Fleet upgrades util-linux: su changes, and is re-baselined.
        let op = Op::PkgInstall {
            packages: vec![fleet_proto::op::PkgSpec {
                name: fleet_proto::args::DebPackageName::new("util-linux").unwrap(),
                version: None,
            }],
        };
        assert_eq!(ask(&mut s, &fx, op).await, Ok(Payload::Empty));
        let evs = events_until(&mut s, |e| matches!(e, Event::PackagesChanged { .. })).await;
        assert!(
            !evs.iter()
                .any(|e| matches!(e, Event::IntegrityViolation { .. }))
        );
        assert!(violations(&mut s).await.is_empty());

        // The same change made outside Fleet stays a violation.
        fake_upgrade(root.path(), "su v3");
        events_until(&mut s, |e| matches!(e, Event::PackagesChanged { .. })).await;
        let v = violations(&mut s).await;
        assert_eq!(v.len(), 1);
        assert_eq!(
            (v[0].path.as_str(), v[0].kind),
            ("/usr/bin/su", IntegrityKind::Modified)
        );
    });
}

#[test]
fn services_without_bus_answer_internal() {
    // Default exec config: the real (lazy) system bus. Exec starts either
    // way; without a bus the unit ops fail cleanly.
    let fx = Fixture::with(
        1,
        0,
        Opts {
            pol: Pol {
                groups: GROUPS,
                ..Pol::default()
            },
            ..Opts::default()
        },
    );
    run(async {
        let mut s = fx.connect(&fx.macs[0]).await;
        let r = ask(&mut s, &fx, Op::UnitList).await;
        assert!(
            matches!(r, Ok(Payload::Units(_)) | Err(ErrorCode::Internal)),
            "{r:?}"
        );
        ask(&mut s, &fx, Op::SystemInfo).await.unwrap();
    });
}

/// Root lines that aren't sshd's own (another program, or a container's
/// sshd forwarded by dockerd) neither ban nor log in.
#[test]
fn sshd_lines_from_other_programs_or_containers_ignored() {
    let (mut fx, root) = fixture();
    let feeds = start(&mut fx, root.path().to_owned(), None);
    run(async {
        let mut watch = fx.connect(&fx.macs[0]).await;
        let m = format!("Failed password for admin from {ATTACKER} port 3 ssh2");
        for (i, fields) in [
            r#""_UID":"0","_COMM":"dockerd","_SYSTEMD_UNIT":"docker.service","CONTAINER_ID":"0123""#,
            r#""_UID":"0","_COMM":"sshd","CONTAINER_ID":"0123""#,
            r#""_UID":"0","_COMM":"logger""#,
            r#""_UID":"1000","_COMM":"sshd""#,
        ]
        .into_iter()
        .enumerate()
        {
            for k in 0..6 {
                let n = u32::try_from(i * 10 + k).unwrap();
                feeds.journal.send(jline_from(n, &m, fields)).unwrap();
            }
        }
        // sshd itself, identified by its unit.
        feeds
            .journal
            .send(jline_from(
                90,
                "Invalid user x from 192.0.2.99 port 4",
                r#""_UID":"0","_COMM":"sshd-auth","_SYSTEMD_UNIT":"ssh.service""#,
            ))
            .unwrap();
        let evs = events_until(
            &mut watch,
            |e| matches!(e, Event::Login { source: Some(a), .. } if *a == ip("192.0.2.99")),
        )
        .await;
        assert!(
            !evs.iter().any(|e| matches!(
                e,
                Event::Login { source: Some(a), .. } if *a == ip(ATTACKER)
            ) || matches!(e, Event::BanChanged { .. })),
            "{evs:?}"
        );
    });
}

/// Auto-revert op stand-in for the confirm test: applies nothing.
struct NoChange;
impl fleet_ops::OpHandler for NoChange {
    fn handle<'a>(
        &'a self,
        _: &'a SysCtx,
        _: &'a Op,
        _: &'a fleet_ops::OpMeta,
    ) -> LocalBoxFuture<'a, Result<fleet_ops::OpOutput, fleet_ops::OpError>> {
        Box::pin(async { Ok(fleet_ops::OpOutput::Payload(Payload::Empty)) })
    }
}
struct NoSnapshot;
impl fleet_ops::Revertible for NoSnapshot {
    fn snapshot(&self, _: &SysCtx, _: &Op) -> Result<Vec<u8>, fleet_ops::OpError> {
        Ok(Vec::new())
    }
    fn restore(&self, _: &SysCtx, _: &[u8]) -> Result<(), fleet_ops::OpError> {
        Ok(())
    }
}

/// `change.confirm` over a new session also needs sshd's journal to show
/// that device's key logging in after the change (design §4.10 step 3);
/// a container's forwarded line doesn't count.
#[test]
fn confirm_needs_sshd_login_after_the_change() {
    let (mut fx2, root2) = fixture_with(r#""system", "security", "mesh""#);
    let timers: Timers = Arc::default();
    let t = timers.clone();
    let feeds = start_with(&mut fx2, root2.path().to_owned(), None, move |cfg| {
        cfg.handlers
            .push((fleet_proto::op::tag::MESH_LEAVE, Rc::new(NoChange)));
        cfg.reverters = fleet_ops::Reverters::new();
        cfg.reverters
            .register(fleet_proto::payload::ChangeKind::Mesh, Rc::new(NoSnapshot));
        cfg.timers = Rc::new(SharedRecorder(t));
        cfg.confirm_sshd_login = Some(Duration::from_millis(300));
    });
    let fx = &fx2;
    run(async {
        let mac = &fx.macs[0];
        let mut s = fx.connect(mac).await;
        let r = ask(&mut s, fx, Op::MeshLeave).await;
        let Ok(Payload::ChangePending { change: p, .. }) = r else {
            panic!("{r:?}")
        };
        let confirm = Op::ChangeConfirm {
            change_id: p.change_id,
        };
        let accepted = format!(
            "Accepted publickey for admin from 203.0.113.9 port 5 ssh2: ECDSA {}",
            fp(mac)
        );
        // New session, but no login in the journal (or only a container's).
        feeds
            .journal
            .send(jline_from(
                1,
                &accepted,
                r#""_UID":"0","_COMM":"sshd","_PID":"4242","CONTAINER_ID":"ab""#,
            ))
            .unwrap();
        let mut s2 = fx.connect(mac).await;
        assert_eq!(
            ask(&mut s2, fx, confirm.clone()).await,
            Err(ErrorCode::PolicyDenied)
        );
        // sshd logs the Mac's key: the confirm goes through.
        feeds
            .journal
            .send(jline_from(
                2,
                &accepted,
                r#""_UID":"0","_COMM":"sshd-session","_PID":"4243""#,
            ))
            .unwrap();
        assert_eq!(ask(&mut s2, fx, confirm).await, Ok(Payload::Empty));
        let stop = timers.lock().unwrap().last().cloned().unwrap();
        assert_eq!(stop[..2], ["/usr/bin/systemctl", "stop"]);
    });
}

/// Web bans end to end (design §4.7): only the access log opted in by
/// `/etc/fleet/web-bans.conf` bans, capped at its step; the host's own
/// address (from `/proc/net/fib_trie`) and a log that isn't opted in
/// never ban.
#[test]
fn web_scanner_bans_only_from_opted_in_logs() {
    const CADDY: &str = "/var/log/caddy/access.log";
    const NGINX: &str = "/var/log/nginx/access.log";
    const OWN: &str = "203.0.113.7";
    const OTHER: &str = "198.51.100.8";
    let (mut fx, root) = fixture();
    let r = root.path().to_owned();
    for d in ["var/log/caddy", "var/log/nginx", "etc/fleet", "proc/net"] {
        std::fs::create_dir_all(r.join(d)).unwrap();
    }
    std::fs::write(r.join("var/log/caddy/access.log"), "").unwrap();
    std::fs::write(r.join("var/log/nginx/access.log"), "").unwrap();
    std::fs::write(r.join("etc/fleet/web-bans.conf"), format!("{CADDY} 600\n")).unwrap();
    std::fs::write(
        r.join("proc/net/fib_trie"),
        format!("Local:\n  +-- 0.0.0.0/0 3 0 5\n     |-- {OWN}\n        /32 host LOCAL\n"),
    )
    .unwrap();
    let feeds = start_with(&mut fx, r.clone(), None, |cfg| {
        cfg.sources.web_logs = vec![CADDY.into(), NGINX.into()];
    });
    let line = |ip: &str| {
        format!(r#"{{"request":{{"client_ip":"{ip}","uri":"/.env"}},"status":404}}"#) + "\n"
    };
    let append = |p: &str, text: &str| {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(r.join(p.trim_start_matches('/')))
            .unwrap();
        std::io::Write::write_all(&mut f, text.as_bytes()).unwrap();
    };
    run(async {
        let mut s = fx.connect(&fx.macs[0]).await;
        // First poll positions the tails at the end.
        tokio::time::sleep(Duration::from_millis(200)).await;
        append(NGINX, &line(OTHER).repeat(6));
        append(CADDY, &line(OWN).repeat(6));
        append(CADDY, &line(ATTACKER).repeat(6));
        let evs = events_until(&mut s, |e| matches!(e, Event::BanChanged { .. })).await;
        assert!(matches!(
            evs.last(),
            Some(Event::BanChanged {
                banned: true,
                reason: BanReason::WebScanner,
                addr,
                ..
            }) if *addr == ip(ATTACKER)
        ));
        // Capped at the source's 600 s step (the SSH default is 3600 s).
        let want: Vec<String> = [
            "add", "element", "inet", "fleet", "banned4", "{", ATTACKER, "timeout", "600s", "}",
        ]
        .map(String::from)
        .to_vec();
        assert!(feeds.nft.lock().unwrap().contains(&want));
        tokio::time::sleep(Duration::from_millis(200)).await;
        let r = ask(&mut s, &fx, Op::BansList).await;
        let Ok(Payload::Bans(b)) = r else {
            panic!("{r:?}")
        };
        let banned: Vec<IpAddr> = b.bans.iter().map(|b| b.addr).collect();
        assert_eq!(banned, vec![ip(ATTACKER)]);
    });
}
