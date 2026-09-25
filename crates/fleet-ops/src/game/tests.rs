use super::*;
use crate::ManualClock;
use crate::runner::FakeRunner;
use crate::scope::SYSTEMD_RUN;
use crate::testutil::{block, ctx, meta};
use fleet_proto::args::{GameTemplateId, RconCommand};
use template::{Rcon, Schedule};

const HARDENING: &str = "Restart=on-failure
RestartSec=10
TimeoutStopSec=90
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
";

fn valheim_unit() -> String {
    format!(
        "# Managed by Fleet (game.install). Changes are overwritten.
[Unit]
Description=Fleet game server vh (valheim)
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=game-vh
Group=game-vh
WorkingDirectory=/srv/games/vh/server
EnvironmentFile=/var/lib/fleet/games/vh.env
Environment=SteamAppId=892970
Environment=LD_LIBRARY_PATH=/srv/games/vh/server/linux64
ExecStart=/srv/games/vh/server/valheim_server.x86_64 -nographics -batchmode -name vh -port 2456 -world vh -password ${{FLEET_GAME_PASSWORD}} -public 0
CapabilityBoundingSet=
AmbientCapabilities=
PrivateDevices=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
SystemCallArchitectures=native
ProtectProc=invisible
ProtectKernelLogs=yes
ProtectClock=yes
UMask=0027
{HARDENING}ReadWritePaths=/srv/games/vh
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryMax=6G
TasksMax=512
CPUQuota=400%

[Install]
WantedBy=multi-user.target
"
    )
}

fn minecraft_unit() -> String {
    format!(
        "# Managed by Fleet (game.install). Changes are overwritten.
[Unit]
Description=Fleet game server mc (minecraft-paper)
Wants=network-online.target
After=network-online.target docker.service
Requires=docker.service

[Service]
Type=simple
WorkingDirectory=/srv/games/mc
EnvironmentFile=/var/lib/fleet/games/mc.env
ExecStart=/usr/bin/docker run --rm --name game-mc --user 998:997 --cap-drop ALL --security-opt no-new-privileges --memory 4G --pids-limit 1024 --cpus 3 -p 0.0.0.0:25565:25565/tcp -p [::]:25565:25565/tcp -p 127.0.0.1:27100:25575/tcp -v /srv/games/mc/data:/data -e TYPE=PAPER -e MEMORY=3G -e ENABLE_RCON=true -e RCON_PORT=25575 -e EULA -e RCON_PASSWORD docker.io/itzg/minecraft-server:java21@{DIGEST}
ExecStop=/usr/bin/docker stop --time 30 game-mc
{HARDENING}ReadWritePaths=/srv/games/mc
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryMax=4G
TasksMax=1024
CPUQuota=300%

[Install]
WantedBy=multi-user.target
"
    )
}

/// A made-up digest for tests (the shipped template has none).
const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// The Minecraft template with a digest set.
fn pinned_minecraft() -> Template {
    let text = template::BUILTIN[0].replacen(
        "image = \"docker.io/itzg/minecraft-server:java21\"",
        &format!("image = \"docker.io/itzg/minecraft-server:java21\"\ndigest = \"{DIGEST}\""),
        1,
    );
    Template::parse(&text).unwrap()
}

fn gn(s: &str) -> GameName {
    GameName::new(s).unwrap()
}

fn tpl(id: &str) -> Template {
    template::builtin()
        .into_iter()
        .find(|t| t.id == id)
        .unwrap()
}

#[test]
fn builtin_templates_parse_and_render_golden_units() {
    assert_eq!(template::builtin().len(), template::BUILTIN.len());
    assert_eq!(template::BUILTIN.len(), 2);
    let v = tpl("valheim");
    assert!(matches!(
        v.install,
        Install::Steamcmd { app_id: 896660, .. }
    ));
    assert!(v.rcon.is_none());
    assert_eq!(
        template::render_unit(&v, &gn("vh"), 999, 999, None).unwrap(),
        valheim_unit()
    );
    let m = tpl("minecraft-paper");
    assert!(m.is_container());
    // Shipped without a digest: no unit (and no install) until pinned.
    assert!(m.pinned_image().is_none());
    assert_eq!(
        template::render_unit(&m, &gn("mc"), 998, 997, Some(27100))
            .unwrap_err()
            .code(),
        ErrorCode::PolicyDenied
    );
    assert_eq!(
        template::render_unit(&pinned_minecraft(), &gn("mc"), 998, 997, Some(27100)).unwrap(),
        minecraft_unit()
    );
    assert_eq!(m.schedule.as_ref().unwrap().minute_of_day(), Some(300));
    assert_eq!(template::cpus_of("300%").as_deref(), Some("3"));
    assert_eq!(template::cpus_of("150%").as_deref(), Some("1.5"));
    assert_eq!(template::cpus_of("25%").as_deref(), Some("0.25"));
}

#[test]
fn image_digests() {
    let base = template::BUILTIN[0];
    let img = "image = \"docker.io/itzg/minecraft-server:java21\"";
    let with = |line: &str| Template::parse(&base.replacen(img, line, 1));
    assert!(
        with(&format!(
            "image = \"docker.io/itzg/minecraft-server@{DIGEST}\""
        ))
        .is_ok()
    );
    assert!(with("image = \"docker.io/x@sha256:abc\"").is_err());
    assert!(with(&format!("{img}\ndigest = \"sha256:XYZ\"")).is_err());
    assert!(
        with(&format!("image = \"x@{DIGEST}\"\ndigest = \"{DIGEST}\"")).is_err(),
        "both forms"
    );
    let t = with(&format!("image = \"docker.io/x@{DIGEST}\"")).unwrap();
    assert_eq!(t.pinned_image().unwrap(), format!("docker.io/x@{DIGEST}"));
    // An unpinned container template can't be installed.
    let d = root_dir(PASSWD);
    let c = ctx(d.path(), Rc::new(FakeRunner::new()));
    let op = Op::GameInstall {
        name: gn("new"),
        template: GameTemplateId::new("minecraft-paper").unwrap(),
    };
    assert_eq!(
        GameOps(svc())
            .validate(&c, &op, &meta(op.clone(), None))
            .unwrap_err()
            .code(),
        ErrorCode::PolicyDenied
    );
}

#[test]
fn restore_listing_checks() {
    let ok = "-rw-r----- game-vh/game-vh 5 2024-01-01 00:00 \"data/world/level.dat\"\n\
drwxr-x--- game-vh/game-vh 0 2024-01-01 00:00 \"data/with space/\"\n\
lrwxrwxrwx game-vh/game-vh 0 2024-01-01 00:00 \"data/link\" -> \"world/level.dat\"\n\
hrw-r----- game-vh/game-vh 0 2024-01-01 00:00 \"data/hard\" link to \"data/world/level.dat\"\n";
    assert_eq!(check_listing(ok, false), Ok(()));
    assert!(check_listing(ok, true).is_err());
    for bad in [
        "-rw-r--r-- a/a 1 2024-01-01 00:00 \"/etc/passwd\"\n",
        "-rw-r--r-- a/a 1 2024-01-01 00:00 \"data/../../etc/cron.d/x\"\n",
        "-rw-r--r-- a/a 1 2024-01-01 00:00 \"..\"\n",
        "lrwxrwxrwx a/a 0 2024-01-01 00:00 \"data/l\" -> \"/etc\"\n",
        "lrwxrwxrwx a/a 0 2024-01-01 00:00 \"data/l\" -> \"../../../etc\"\n",
        "hrw-r--r-- a/a 0 2024-01-01 00:00 \"data/h\" link to \"/etc/shadow\"\n",
        // Escaped: `\057` is `/`.
        "-rw-r--r-- a/a 1 2024-01-01 00:00 \"\\057etc/x\"\n",
        "garbage\n",
    ] {
        assert!(check_listing(bad, false).is_err(), "{bad}");
    }
}

#[test]
fn template_validation_rejects_unit_injection() {
    let base = template::BUILTIN[1];
    let bad = [
        (
            "\"-public\", \"0\",",
            "\"-public\", \"0\\nExecStartPre=/bin/evil\",",
        ),
        ("\"-public\", \"0\",", "\"-public 0\","),
        ("\"-public\", \"0\",", "\"%h\","),
        ("\"-public\", \"0\",", "\"$HOME\","),
        ("valheim_server.x86_64", "../../bin/sh"),
        ("memory_max = \"6G\"", "memory_max = \"6G\\nUser=root\""),
        ("keep = 7", "keep = 0"),
        ("restart_utc = \"05:00\"", "restart_utc = \"25:00\""),
        (
            "\".config/unity3d/IronGate/Valheim/worlds_local\"",
            "\"../etc\"",
        ),
        ("id = \"valheim\"", "id = \"Valheim\""),
    ];
    for (from, to) in bad {
        let text = base.replacen(from, to, 1);
        assert_ne!(text, base, "{to}");
        assert!(Template::parse(&text).is_err(), "accepted: {to}");
    }
    assert!(Template::parse(&format!("{base}\nunknown = 1\n")).is_err());
}

const PASSWD: &str = "root:x:0:0::/root:/bin/sh\n\
game-vh:x:999:999::/srv/games/vh:/usr/sbin/nologin\n\
game-mc:x:998:997::/srv/games/mc:/usr/sbin/nologin\n";

fn root_dir(passwd: &str) -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    for p in ["etc/systemd/system", "usr/games", "usr/bin"] {
        std::fs::create_dir_all(d.path().join(p)).unwrap();
    }
    std::fs::write(d.path().join("etc/passwd"), passwd).unwrap();
    std::fs::write(d.path().join("usr/games/steamcmd"), "").unwrap();
    std::fs::write(d.path().join("usr/bin/docker"), "").unwrap();
    d
}

fn svc() -> Rc<GameService> {
    GameService::builtin(Rc::new(crate::telemetry::NoGauges))
}

fn argv(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| (*s).to_owned()).collect()
}

fn scope_user(seq: u64, uid: u32, program: &str, rest: &[&str]) -> Vec<String> {
    let mut v = argv(&[
        "--scope",
        "--quiet",
        "--collect",
        "--unit",
        &format!("fleet-op-{seq}"),
        "-p",
        "MemoryMax=4096M",
        "-p",
        "TasksMax=1024",
        "-p",
        "CPUQuota=200%",
        "--",
        crate::shell::SETPRIV,
        &format!("--reuid={uid}"),
        &format!("--regid={uid}"),
        &format!("--groups={uid}"),
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-all",
        "--reset-env",
        "--",
        program,
    ]);
    v.extend(argv(rest));
    v
}

fn expect(r: &FakeRunner, program: &'static str, a: &[String], out: CommandOutput) {
    let refs: Vec<&str> = a.iter().map(String::as_str).collect();
    r.expect(program, &refs, Ok(out));
}

fn mode(d: &tempfile::TempDir, p: &str) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(d.path().join(p.trim_start_matches('/')))
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

/// Installs `vh` (Valheim) with a passwd that already has its user (the
/// fake useradd doesn't create it).
fn installed_vh(passwd: &str) -> (tempfile::TempDir, Rc<GameService>) {
    let d = root_dir(passwd);
    let s = svc();
    let r = Rc::new(FakeRunner::new());
    let c = ctx(d.path(), r.clone());
    // Validate sees no user yet.
    std::fs::write(d.path().join("etc/passwd"), "root:x:0:0::/root:/bin/sh\n").unwrap();
    let op = Op::GameInstall {
        name: gn("vh"),
        template: GameTemplateId::new("valheim").unwrap(),
    };
    let h = GameOps(s.clone());
    h.validate(&c, &op, &meta(op.clone(), None)).unwrap();
    std::fs::write(d.path().join("etc/passwd"), passwd).unwrap();
    // Handle re-checks, so the user must not exist then either: install
    // through the service directly with the user "created" by useradd.
    expect(
        &r,
        USERADD,
        &argv(&[
            "--system",
            "--user-group",
            "--home-dir",
            "/srv/games/vh",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            "--",
            "game-vh",
        ]),
        CommandOutput::ok(""),
    );
    expect(
        &r,
        SYSTEMCTL,
        &argv(&["daemon-reload"]),
        CommandOutput::ok(""),
    );
    expect(
        &r,
        SYSTEMD_RUN,
        &scope_user(
            7,
            999,
            STEAMCMD,
            &[
                "+force_install_dir",
                "/srv/games/vh/server",
                "+login",
                "anonymous",
                "+app_update",
                "896660",
                "validate",
                "+quit",
            ],
        ),
        CommandOutput::ok(""),
    );
    expect(
        &r,
        SYSTEMCTL,
        &argv(&["enable", "--now", "game-vh.service"]),
        CommandOutput::ok(""),
    );
    expect(
        &r,
        SYSTEMCTL,
        &argv(&["is-active", "--quiet", "game-vh.service"]),
        CommandOutput::ok(""),
    );
    let t = s.template("valheim").unwrap().clone();
    let info = block(s.install(&c, &gn("vh"), &t, 7, 1_000)).unwrap();
    assert!(info.running);
    assert_eq!(r.pending(), 0);
    let calls = r.calls();
    assert_eq!(calls[2].timeout, INSTALL_TIMEOUT);
    assert_eq!(calls[2].scope_unit.as_deref(), Some("fleet-op-7"));
    (d, s)
}

#[test]
fn install_argv_files_and_modes() {
    let (d, s) = installed_vh(PASSWD);
    let c = ctx(d.path(), Rc::new(FakeRunner::new()));
    let unit =
        std::fs::read_to_string(d.path().join("etc/systemd/system/game-vh.service")).unwrap();
    assert_eq!(unit, valheim_unit());
    assert_eq!(mode(&d, "/etc/systemd/system/game-vh.service"), 0o644);
    assert_eq!(mode(&d, "/var/lib/fleet/games/vh.env"), 0o600);
    assert_eq!(mode(&d, "/var/lib/fleet/games"), 0o700);
    for p in [
        "/srv/games/vh",
        "/srv/games/vh/server",
        "/srv/games/vh/data",
    ] {
        assert_eq!(mode(&d, p), 0o750, "{p}");
    }
    let pw = s.env_value(&c, &gn("vh"), GAME_PASSWORD).unwrap().unwrap();
    assert_eq!(pw.len(), SECRET_LEN);
    assert!(pw.bytes().all(|b| b.is_ascii_alphanumeric()));
    let inst = s.load(&c, &gn("vh")).unwrap().unwrap();
    assert_eq!(
        inst,
        Instance {
            template: "valheim".into(),
            uid: 999,
            gid: 999,
            installed_ms: 1_000,
            rcon_port: None,
        }
    );
    assert_eq!(s.instances(&c).len(), 1);

    // A second install of the same name is refused before anything runs.
    let op = Op::GameInstall {
        name: gn("vh"),
        template: GameTemplateId::new("valheim").unwrap(),
    };
    let e = GameOps(s.clone())
        .validate(&c, &op, &meta(op.clone(), None))
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::Busy);
    // Unknown template.
    let op = Op::GameInstall {
        name: gn("other"),
        template: GameTemplateId::new("doom").unwrap(),
    };
    let e = GameOps(s)
        .validate(&c, &op, &meta(op.clone(), None))
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
}

const GAME_PASSWORD: &str = template::GAME_PASSWORD_ENV;

#[test]
fn installer_must_be_present() {
    let d = root_dir(PASSWD);
    std::fs::remove_file(d.path().join("usr/games/steamcmd")).unwrap();
    let c = ctx(d.path(), Rc::new(FakeRunner::new()));
    let op = Op::GameInstall {
        name: gn("new"),
        template: GameTemplateId::new("valheim").unwrap(),
    };
    let e = GameOps(svc())
        .validate(&c, &op, &meta(op.clone(), None))
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::NotFound);
}

#[test]
fn backup_copies_out_and_keeps_retention_then_restore() {
    let (d, s) = installed_vh(PASSWD);
    let bdir = d.path().join("var/backups/fleet-games/vh");
    std::fs::create_dir_all(&bdir).unwrap();
    for id in 1..=7u64 {
        std::fs::write(bdir.join(format!("{id}.tar.zst")), "old").unwrap();
    }
    std::fs::write(bdir.join("notes.txt"), "ignored").unwrap();
    let stage = d.path().join("srv/games/vh/.fleet-backup.tar.zst");
    // A stale stage from an interrupted run is removed before tar runs.
    std::fs::write(&stage, "STALE").unwrap();
    let op = Op::GameBackup { name: gn("vh") };
    let h = GameOps(s.clone());
    h.validate(&crate::testutil::ctx_empty(), &op, &meta(op.clone(), None))
        .unwrap_err(); // not installed there
    let r2 = Rc::new(FakeRunner::new());
    /// The game user's (faked) tar writes the staged archive.
    struct TarWrites(std::path::PathBuf, Rc<FakeRunner>);
    impl crate::CommandRunner for TarWrites {
        fn run(&self, spec: CommandSpec) -> LocalBoxFuture<'_, Result<CommandOutput, RunError>> {
            if spec.args.iter().any(|a| a == "-cf") {
                assert!(!self.0.exists(), "stale stage removed first");
                std::fs::write(&self.0, "ARCHIVE").unwrap();
            }
            self.1.run(spec)
        }
    }
    expect(
        &r2,
        SYSTEMD_RUN,
        &scope_user(
            9,
            999,
            TAR,
            &[
                "--zstd",
                "--ignore-failed-read",
                "-cf",
                "/srv/games/vh/.fleet-backup.tar.zst",
                "-C",
                "/srv/games/vh",
                "--",
                ".config/unity3d/IronGate/Valheim/worlds_local",
            ],
        ),
        CommandOutput::ok(""),
    );
    let c2 = crate::SysCtx::new(
        d.path(),
        Rc::new(TarWrites(stage.clone(), r2.clone())),
        Rc::new(ManualClock::new(50_000)),
    );
    let m = crate::testutil::meta_at(op.clone(), Some(9), 50_000);
    let out = block(h.handle(&c2, &op, &m)).unwrap();
    let OpOutput::Payload(Payload::GameBackups(b)) = out else {
        panic!()
    };
    // 7 kept: the oldest (id 1) went, the new one (id 50000) is last.
    let ids: Vec<u64> = b.backups.iter().map(|b| b.id).collect();
    assert_eq!(ids, vec![2, 3, 4, 5, 6, 7, 50_000]);
    assert_eq!(
        std::fs::read_to_string(bdir.join("50000.tar.zst")).unwrap(),
        "ARCHIVE"
    );
    assert_eq!(mode(&d, "/var/backups/fleet-games/vh/50000.tar.zst"), 0o640);
    assert_eq!(mode(&d, "/var/backups/fleet-games/vh"), 0o750);
    assert!(!stage.exists(), "stage removed");
    assert!(!bdir.join("50000.tar.zst.tmp").exists());
    assert_eq!(r2.pending(), 0);

    // Restore: list and check, stop, extract as the game user, start.
    let r3 = Rc::new(FakeRunner::new());
    let list = scope_user(
        10,
        999,
        TAR,
        &[
            "--zstd",
            "--list",
            "--verbose",
            "--quoting-style=c",
            "-f",
            "/var/backups/fleet-games/vh/3.tar.zst",
        ],
    );
    expect(
        &r3,
        SYSTEMD_RUN,
        &list,
        CommandOutput::ok("-rw-r----- game-vh/game-vh 5 2024-01-01 00:00 \"data/x\"\n"),
    );
    expect(
        &r3,
        SYSTEMCTL,
        &argv(&["stop", "game-vh.service"]),
        CommandOutput::ok(""),
    );
    expect(
        &r3,
        SYSTEMD_RUN,
        &scope_user(
            10,
            999,
            TAR,
            &[
                "--zstd",
                "-xf",
                "/var/backups/fleet-games/vh/3.tar.zst",
                "--no-same-owner",
                "--no-same-permissions",
                "--delay-directory-restore",
                "-C",
                "/srv/games/vh",
            ],
        ),
        CommandOutput::ok(""),
    );
    expect(
        &r3,
        SYSTEMCTL,
        &argv(&["start", "game-vh.service"]),
        CommandOutput::ok(""),
    );
    let c3 = ctx(d.path(), r3.clone());
    let op = Op::GameRestore {
        name: gn("vh"),
        backup_id: 3,
    };
    h.validate(&c3, &op, &meta(op.clone(), None)).unwrap();
    block(h.handle(&c3, &op, &meta(op.clone(), Some(10)))).unwrap();
    assert_eq!(r3.pending(), 0);
    assert_eq!(r3.calls()[0].output_cap, LIST_CAP);
    // A listing with a member outside the directory: nothing is stopped
    // or extracted.
    let r4 = Rc::new(FakeRunner::new());
    expect(
        &r4,
        SYSTEMD_RUN,
        &list,
        CommandOutput::ok("-rw-r--r-- a/a 1 2024-01-01 00:00 \"../../etc/cron.d/x\"\n"),
    );
    let c4 = ctx(d.path(), r4.clone());
    let e = block(h.handle(&c4, &op, &meta(op.clone(), Some(10)))).unwrap_err();
    assert_eq!(e.code(), ErrorCode::PolicyDenied);
    assert_eq!(r4.calls().len(), 1);
    let missing = Op::GameRestore {
        name: gn("vh"),
        backup_id: 1,
    };
    assert_eq!(
        h.validate(&c3, &missing, &meta(missing.clone(), None))
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );
}

#[test]
fn symlinked_stage_is_refused() {
    let (d, s) = installed_vh(PASSWD);
    let stage = d.path().join("srv/games/vh/.fleet-backup.tar.zst");
    let secret = d.path().join("etc/shadow");
    std::fs::write(&secret, "root:HASH").unwrap();
    struct Plant(std::path::PathBuf, std::path::PathBuf);
    impl crate::CommandRunner for Plant {
        fn run(&self, _: CommandSpec) -> LocalBoxFuture<'_, Result<CommandOutput, RunError>> {
            // The game user's tar leaves a symlink instead of an archive.
            std::os::unix::fs::symlink(&self.1, &self.0).unwrap();
            Box::pin(std::future::ready(Ok(CommandOutput::ok(""))))
        }
    }
    let c = crate::SysCtx::new(
        d.path(),
        Rc::new(Plant(stage, secret)),
        Rc::new(ManualClock::new(60_000)),
    );
    let op = Op::GameBackup { name: gn("vh") };
    let e = block(GameOps(s.clone()).handle(&c, &op, &meta(op.clone(), Some(3)))).unwrap_err();
    assert!(
        matches!(
            e.code(),
            ErrorCode::InvalidArgument | ErrorCode::PolicyDenied
        ),
        "{e}"
    );
    assert!(s.backups(&c, &gn("vh")).is_empty());
}

#[test]
fn remove_argv() {
    let (d, s) = installed_vh(PASSWD);
    let r = Rc::new(FakeRunner::new());
    expect(
        &r,
        SYSTEMCTL,
        &argv(&["disable", "--now", "game-vh.service"]),
        CommandOutput::ok(""),
    );
    expect(
        &r,
        SYSTEMCTL,
        &argv(&["daemon-reload"]),
        CommandOutput::ok(""),
    );
    expect(
        &r,
        crate::users::USERDEL,
        &argv(&["--", "game-vh"]),
        CommandOutput::ok(""),
    );
    expect(
        &r,
        RM,
        &argv(&["-rf", "--one-file-system", "--", "/srv/games/vh"]),
        CommandOutput::ok(""),
    );
    expect(
        &r,
        RM,
        &argv(&[
            "-rf",
            "--one-file-system",
            "--",
            "/var/backups/fleet-games/vh",
        ]),
        CommandOutput::ok(""),
    );
    let c = ctx(d.path(), r.clone());
    let op = Op::GameRemove {
        name: gn("vh"),
        keep_data: false,
    };
    let h = GameOps(s.clone());
    h.validate(&c, &op, &meta(op.clone(), None)).unwrap();
    block(h.handle(&c, &op, &meta(op.clone(), Some(4)))).unwrap();
    assert_eq!(r.pending(), 0);
    assert!(!d.path().join("etc/systemd/system/game-vh.service").exists());
    assert!(!d.path().join("var/lib/fleet/games/vh.env").exists());
    assert!(s.instances(&c).is_empty());
}

/// Minecraft-like instance whose RCON port is a live fake server.
fn rcon_rig(port: u16) -> (tempfile::TempDir, Rc<GameService>) {
    let d = root_dir(PASSWD);
    let mut t = tpl("minecraft-paper");
    t.rcon = Some(Rcon {
        port,
        password_env: "RCON_PASSWORD".into(),
        players_command: Some("list".into()),
        players_prefix: Some("There are ".into()),
        save_command: Some("save-all flush".into()),
        say_command: Some("say".into()),
    });
    t.schedule = Some(Schedule {
        restart_utc: "05:00".into(),
        warnings_s: vec![60],
    });
    let gauges = Rc::new(Gauges::default());
    let s = GameService::new(vec![t], gauges);
    let games = d.path().join("var/lib/fleet/games");
    std::fs::create_dir_all(&games).unwrap();
    std::fs::write(
        games.join("mc.toml"),
        "template = \"minecraft-paper\"\nuid = 998\ngid = 997\ninstalled_ms = 1\n",
    )
    .unwrap();
    std::fs::write(
        games.join("mc.env"),
        "FLEET_GAME_PASSWORD=x\nRCON_PASSWORD=sekrit\n",
    )
    .unwrap();
    (d, s)
}

#[derive(Default)]
struct Gauges(RefCell<BTreeMap<String, f32>>);
impl GaugeSink for Gauges {
    fn set_gauge(&self, name: &str, _: MetricUnit, v: f32) {
        self.0.borrow_mut().insert(name.to_owned(), v);
    }
    fn clear_gauge(&self, name: &str) {
        self.0.borrow_mut().remove(name);
    }
}

/// Minimal RCON server: accepts `sekrit`, answers each command with
/// `reply(cmd)`, echoes the terminator; records commands.
async fn rcon_server(reply: fn(&str) -> String) -> (u16, Rc<RefCell<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let seen = Rc::new(RefCell::new(Vec::new()));
    let log = seen.clone();
    tokio::task::spawn_local(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = Vec::new();
            let next = async |s: &mut tokio::net::TcpStream, buf: &mut Vec<u8>| loop {
                if let Some((p, n)) = rcon::decode(buf).unwrap() {
                    buf.drain(..n);
                    return p;
                }
                let mut c = [0u8; 1024];
                let n = s.read(&mut c).await.unwrap();
                assert!(n > 0);
                buf.extend_from_slice(&c[..n]);
            };
            let auth = next(&mut s, &mut buf).await;
            let id = if auth.body == b"sekrit" { auth.id } else { -1 };
            let pkt = |id, ty, body: &str| {
                rcon::encode(&rcon::Packet {
                    id,
                    ty,
                    body: body.as_bytes().to_vec(),
                })
                .unwrap()
            };
            s.write_all(&pkt(id, rcon::AUTH_RESPONSE, ""))
                .await
                .unwrap();
            let cmd = next(&mut s, &mut buf).await;
            let text = String::from_utf8(cmd.body.clone()).unwrap();
            log.borrow_mut().push(text.clone());
            s.write_all(&pkt(cmd.id, rcon::RESPONSE, &reply(&text)))
                .await
                .unwrap();
            let end = next(&mut s, &mut buf).await;
            s.write_all(&pkt(end.id, rcon::RESPONSE, "")).await.unwrap();
        }
    });
    (port, seen)
}

fn local<F: std::future::Future>(f: F) -> F::Output {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    tokio::task::LocalSet::new().block_on(&rt, f)
}

#[test]
fn rcon_op_players_and_scheduled_restart() {
    local(async {
        let (port, seen) = rcon_server(|c| {
            if c == "list" {
                "There are 4 of a max of 20 players online:".into()
            } else {
                format!("ok: {c}")
            }
        })
        .await;
        let (d, s) = rcon_rig(port);
        let r = Rc::new(FakeRunner::new());
        let c = ctx(d.path(), r.clone());
        let op = Op::GameRcon {
            name: gn("mc"),
            command: RconCommand::new("whitelist add alice").unwrap(),
        };
        let h = GameOps(s.clone());
        h.validate(&c, &op, &meta(op.clone(), None)).unwrap();
        let out = h.handle(&c, &op, &meta(op.clone(), Some(1))).await.unwrap();
        let OpOutput::Payload(Payload::RconOutput { text }) = out else {
            panic!()
        };
        assert_eq!(text, "ok: whitelist add alice");

        // Scheduler: first tick polls players; crossing 04:59 warns,
        // crossing 05:00 restarts a running server.
        const DAY: u64 = 86_400_000;
        let t0 = 20_000 * DAY + (4 * 60 + 58) * 60_000;
        let clock = Rc::new(ManualClock::new(t0));
        let mut c = ctx(d.path(), r.clone());
        c.clock = clock.clone();
        s.tick(&c).await;
        assert_eq!(s.players.borrow().get("mc"), Some(&4));
        clock.advance(Duration::from_secs(61));
        s.tick(&c).await; // 04:59:01: the 60 s warning (then a players poll)
        let says = |v: &[String]| {
            v.iter()
                .filter(|c| c.as_str() == "say Server restarting in 1 minute")
                .count()
        };
        assert_eq!(says(&seen.borrow()), 1, "{:?}", seen.borrow());
        r.expect(
            SYSTEMCTL,
            &["is-active", "--quiet", "game-mc.service"],
            Ok(CommandOutput::ok("")),
        )
        .expect(
            SYSTEMCTL,
            &["restart", "game-mc.service"],
            Ok(CommandOutput::ok("")),
        );
        clock.advance(Duration::from_secs(60));
        s.tick(&c).await; // 05:00:01: restart, no second warning
        assert_eq!(r.pending(), 0);
        assert_eq!(says(&seen.borrow()), 1);
    });
}

/// `/proc/net/tcp` with listeners `(port, uid)` on 127.0.0.1.
fn proc_tcp(d: &tempfile::TempDir, socks: &[(u16, u32)]) {
    let mut t = String::from(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
    );
    for (i, (port, uid)) in socks.iter().enumerate() {
        t.push_str(&format!(
            "   {i}: 0100007F:{port:04X} 00000000:0000 0A 00000000:00000000 00:00000000 00000000  {uid}        0 {} 1 0000000000000000 100 0 0 10 0\n",
            1000 + i
        ));
    }
    std::fs::create_dir_all(d.path().join("proc/net")).unwrap();
    std::fs::write(d.path().join("proc/net/tcp"), t).unwrap();
}

#[test]
fn rcon_ports_and_listener_owner() {
    let d = root_dir(PASSWD);
    let c = ctx(d.path(), Rc::new(FakeRunner::new()));
    proc_tcp(&d, &[(27100, 0), (27102, 1000)]);
    // Taken by another instance (27101) or listening (27100, 27102).
    assert_eq!(allocate_rcon_port(&c, &[27101]), Some(27103));
    let inst = Instance {
        template: "x".into(),
        uid: 998,
        gid: 997,
        installed_ms: 0,
        rcon_port: Some(27104),
    };
    let mut native = tpl("valheim");
    native.rcon = Some(Rcon {
        port: 25575,
        password_env: "RCON_PASSWORD".into(),
        players_command: None,
        players_prefix: None,
        save_command: None,
        say_command: None,
    });
    assert_eq!(rcon_port(&inst, native.rcon.as_ref().unwrap()), 27104);
    // Native: the game user must own the listener.
    assert_eq!(
        check_rcon_listener(&c, &native, &inst, 27104)
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );
    proc_tcp(&d, &[(27104, 1000)]);
    assert_eq!(
        check_rcon_listener(&c, &native, &inst, 27104)
            .unwrap_err()
            .code(),
        ErrorCode::PolicyDenied
    );
    proc_tcp(&d, &[(27104, 998)]);
    assert!(check_rcon_listener(&c, &native, &inst, 27104).is_ok());
    // Container: DNAT (no listener) is fine; a non-root listener isn't.
    let mc = pinned_minecraft();
    proc_tcp(&d, &[]);
    assert!(check_rcon_listener(&c, &mc, &inst, 27104).is_ok());
    proc_tcp(&d, &[(27104, 1000)]);
    assert_eq!(
        check_rcon_listener(&c, &mc, &inst, 27104)
            .unwrap_err()
            .code(),
        ErrorCode::PolicyDenied
    );
}

#[test]
fn rcon_unsupported_without_rcon() {
    let (d, s) = installed_vh(PASSWD);
    let c = ctx(d.path(), Rc::new(FakeRunner::new()));
    let op = Op::GameRcon {
        name: gn("vh"),
        command: RconCommand::new("list").unwrap(),
    };
    assert_eq!(
        GameOps(s)
            .validate(&c, &op, &meta(op.clone(), None))
            .unwrap_err()
            .code(),
        ErrorCode::Unsupported
    );
}
