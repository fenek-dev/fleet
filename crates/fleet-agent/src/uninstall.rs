//! Uninstalling (design §10.3), lockout-safe.
//!
//! 1. **`agent.uninstall.prepare`** (auto-revert, `ChangeKind::Ssh`): every
//!    user with a file in `/etc/fleet/authorized_keys/` gets its plain key
//!    lines (no forced-command lines: the monitor and recovery keys only
//!    open agent bridges, useless once the agent is gone) merged into
//!    `~/.ssh/authorized_keys`, **as that user** ([`crate::userkeys`]);
//!    Fleet's `AuthorizedKeysFile` line leaves its `sshd_config.d` drop-ins
//!    (the rest of the hardening stays); `sshd -t`, reload. The Mac
//!    confirms from a fresh connection, so SSH provably works without
//!    Fleet's key files before anything is removed; unconfirmed, the timer
//!    restores both.
//! 2. **`agent.uninstall`** (only once no `Ssh` change is pending and no
//!    Fleet drop-in names `/etc/fleet/authorized_keys`): schedules
//!    `fleet-agent uninstall --ssh-restored [--keep-audit]
//!    [--remove-firewall]` in a transient unit and answers; the mode stops
//!    exec, so it can't run inside it.
//! 3. **`fleet-agent uninstall`** (also runnable by root locally, then it
//!    restores SSH itself first, without a confirmation): disables and
//!    stops the units and Fleet's timers, deletes `table inet fleet` only
//!    with `--remove-firewall` (it may be the only firewall), keeps the
//!    database under `/var/lib/fleet-audit/` with `--keep-audit`, removes
//!    Fleet's directories, then `dpkg --purge fleet-agent` when the package
//!    is installed (its `postrm` removes users and files) or removes the
//!    users, groups and files itself.

use crate::fsutil::{self, UserEntry};
use crate::paths::{AGENT_BIN, Paths, SYSTEMCTL, SYSTEMD_RUN};
use crate::userkeys::{UserKeys, UserKeysMode};
use fleet_ops::{CommandRunner, CommandSpec, OpError, Revertible, SysCtx};
use fleet_proto::{ErrorCode, Op, decode, encode};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Fleet's sshd drop-ins (`ssh.hardening`, and its older name).
pub const FLEET_SSHD_CONFS: [&str; 2] = [
    "/etc/ssh/sshd_config.d/00-fleet.conf",
    "/etc/ssh/sshd_config.d/10-fleet.conf",
];
pub const SSHD: &str = "/usr/sbin/sshd";
pub const NFT: &str = "/usr/sbin/nft";
pub const USERDEL: &str = "/usr/sbin/userdel";
pub const GROUPDEL: &str = "/usr/sbin/groupdel";
pub const DPKG: &str = "/usr/bin/dpkg";
pub const DPKG_QUERY: &str = "/usr/bin/dpkg-query";
/// Package name (`scripts/build-deb.sh`).
pub const PACKAGE: &str = "fleet-agent";
/// Where `--keep-audit` leaves the database.
pub const AUDIT_KEEP_DIR: &str = "/var/lib/fleet-audit";
/// Delay before the scheduled uninstall runs (exec answers first).
pub const UNINSTALL_DELAY_S: u32 = 3;

const CMD_TIMEOUT: Duration = Duration::from_secs(30);

/// `abs` below the paths' root.
pub fn host(paths: &Paths, abs: &str) -> PathBuf {
    paths.root.join(abs.trim_start_matches('/'))
}

fn is_fleet_akf(line: &str) -> bool {
    let t = line.trim();
    let mut w = t.split_whitespace();
    w.next()
        .is_some_and(|k| k.eq_ignore_ascii_case("AuthorizedKeysFile"))
        && t.contains("/etc/fleet/authorized_keys")
}

/// `text` without Fleet's `AuthorizedKeysFile` line (sshd's default,
/// `~/.ssh/authorized_keys`, applies again).
pub fn strip_fleet_akf(text: &str) -> String {
    let mut out = String::new();
    for l in text.lines().filter(|l| !is_fleet_akf(l)) {
        out.push_str(l);
        out.push('\n');
    }
    out
}

/// A Fleet drop-in still points sshd at `/etc/fleet/authorized_keys`.
pub fn fleet_keys_active(paths: &Paths) -> bool {
    FLEET_SSHD_CONFS
        .iter()
        .any(|c| fs::read_to_string(host(paths, c)).is_ok_and(|t| t.lines().any(is_fleet_akf)))
}

/// Key lines of a Fleet `authorized_keys` file that work without the
/// agent: no markers or comments, no forced-command (bridge) lines.
pub fn portable_lines(text: &str) -> String {
    let mut out = String::new();
    for l in text.lines().map(str::trim) {
        if l.is_empty() || l.starts_with('#') || l.contains("command=") {
            continue;
        }
        out.push_str(l);
        out.push('\n');
    }
    out
}

/// Users with a Fleet key file, their passwd entry and portable lines.
pub fn users_plan(paths: &Paths) -> Result<Vec<(String, UserEntry, String)>, OpError> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(&paths.authorized_keys_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(OpError::internal(format!("authorized_keys dir: {e}"))),
    };
    for e in entries.flatten() {
        let Some(user) = e.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if user.starts_with('.') || !e.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let Some(entry) = fsutil::lookup_user(&paths.passwd, &user) else {
            continue;
        };
        let text = fs::read_to_string(e.path())
            .map_err(|e| OpError::internal(format!("read keys of {user}: {e}")))?;
        // Users without portable keys stay in the plan: their own
        // `~/.ssh/authorized_keys` may still hold Fleet monitor lines.
        out.push((user, entry, portable_lines(&text)));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// What prepare changes, for its revert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshSnapshot {
    /// `(user, previous ~/.ssh/authorized_keys)`.
    pub users: Vec<(String, Option<Vec<u8>>)>,
    /// `(drop-in path, previous content)`.
    pub confs: Vec<(String, Option<Vec<u8>>)>,
}

pub fn snapshot(paths: &Paths, users: &dyn UserKeys) -> Result<SshSnapshot, OpError> {
    let mut snap = SshSnapshot {
        users: Vec::new(),
        confs: Vec::new(),
    };
    for (name, entry, _) in users_plan(paths)? {
        snap.users.push((name, users.get(&entry)?));
    }
    for c in FLEET_SSHD_CONFS {
        let prev = match fs::read(host(paths, c)) {
            Ok(b) => Some(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(OpError::internal(format!("read {c}: {e}"))),
        };
        snap.confs.push((c.to_owned(), prev));
    }
    Ok(snap)
}

fn sshd_reload(runner: &dyn CommandRunner) -> Result<(), OpError> {
    let check = runner
        .run_blocking(CommandSpec::new(SSHD).arg("-t").timeout(CMD_TIMEOUT))
        .map_err(|e| OpError::internal(format!("sshd -t: {e}")))?;
    if !check.success() {
        return Err(
            OpError::new(ErrorCode::InvalidArgument).with_detail(format!(
                "sshd -t refused the configuration: {}",
                String::from_utf8_lossy(&check.stderr).trim()
            )),
        );
    }
    let reload = runner
        .run_blocking(
            CommandSpec::new(SYSTEMCTL)
                .args(["try-reload-or-restart", "--", "ssh.service"])
                .timeout(CMD_TIMEOUT),
        )
        .map_err(|e| OpError::internal(format!("reload ssh: {e}")))?;
    if !reload.success() {
        return Err(OpError::internal("reload ssh.service failed"));
    }
    Ok(())
}

/// Prepare's change: keys to `~/.ssh`, Fleet's `AuthorizedKeysFile` out,
/// `sshd -t`, reload.
pub fn apply_ssh(
    paths: &Paths,
    runner: &dyn CommandRunner,
    users: &dyn UserKeys,
) -> Result<(), OpError> {
    for (_, entry, lines) in users_plan(paths)? {
        if !lines.is_empty() {
            users.merge(&entry, &lines)?;
        }
        // The monitor lines install (and roster syncs) put there point at
        // the agent being removed.
        users.sync_monitor(&entry, "")?;
    }
    for c in FLEET_SSHD_CONFS {
        let p = host(paths, c);
        let Ok(text) = fs::read_to_string(&p) else {
            continue;
        };
        let stripped = strip_fleet_akf(&text);
        if stripped != text {
            let mode = fs::metadata(&p).map_or(0o644, |m| m.permissions().mode() & 0o7777);
            fsutil::write_atomic(&p, stripped.as_bytes(), mode)
                .map_err(|e| OpError::internal(format!("write {c}: {e}")))?;
        }
    }
    sshd_reload(runner)
}

/// Puts back what [`snapshot`] captured and reloads sshd.
pub fn restore_ssh(
    paths: &Paths,
    runner: &dyn CommandRunner,
    users: &dyn UserKeys,
    snap: &SshSnapshot,
) -> Result<(), OpError> {
    for (c, prev) in &snap.confs {
        if !FLEET_SSHD_CONFS.contains(&c.as_str()) {
            continue;
        }
        let p = host(paths, c);
        let res = match prev {
            Some(b) => fsutil::write_atomic(&p, b, 0o644),
            None => match fs::remove_file(&p) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            },
        };
        res.map_err(|e| OpError::internal(format!("restore {c}: {e}")))?;
    }
    for (name, prev) in &snap.users {
        let Some(entry) = fsutil::lookup_user(&paths.passwd, name) else {
            continue;
        };
        users.set(&entry, prev.as_deref())?;
    }
    sshd_reload(runner)
}

/// `Revertible` for `ChangeKind::Ssh` (uninstall prepare).
pub struct SshRestoreRevert {
    pub paths: Paths,
    pub mode: UserKeysMode,
}

impl Revertible for SshRestoreRevert {
    fn snapshot(&self, ctx: &SysCtx, op: &Op) -> Result<Vec<u8>, OpError> {
        if !matches!(op, Op::AgentUninstallPrepare) {
            return Err(OpError::new(ErrorCode::Internal));
        }
        let users = crate::userkeys::user_keys(self.mode, ctx.runner.as_ref());
        Ok(encode(&snapshot(&self.paths, users.as_ref())?))
    }

    fn restore(&self, ctx: &SysCtx, bytes: &[u8]) -> Result<(), OpError> {
        let snap: SshSnapshot =
            decode(bytes).map_err(|_| OpError::internal("corrupt ssh snapshot"))?;
        let users = crate::userkeys::user_keys(self.mode, ctx.runner.as_ref());
        restore_ssh(&self.paths, ctx.runner.as_ref(), users.as_ref(), &snap)
    }
}

/// `fleet-agent uninstall` flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UninstallOpts {
    /// Prepare ran and was confirmed (the scheduled path).
    pub ssh_restored: bool,
    pub keep_audit: bool,
    pub remove_firewall: bool,
}

impl UninstallOpts {
    pub fn args(self) -> Vec<String> {
        let mut a = vec!["uninstall".to_owned()];
        for (on, flag) in [
            (self.ssh_restored, "--ssh-restored"),
            (self.keep_audit, "--keep-audit"),
            (self.remove_firewall, "--remove-firewall"),
        ] {
            if on {
                a.push(flag.to_owned());
            }
        }
        a
    }

    pub fn parse(flags: &[&str]) -> Option<Self> {
        let mut o = Self::default();
        for f in flags {
            let slot = match *f {
                "--ssh-restored" => &mut o.ssh_restored,
                "--keep-audit" => &mut o.keep_audit,
                "--remove-firewall" => &mut o.remove_firewall,
                _ => return None,
            };
            *slot = true;
        }
        Some(o)
    }
}

/// `agent.uninstall`'s transient unit: `systemd-run --on-active=3
/// --unit=fleet-uninstall /usr/lib/fleet/fleet-agent uninstall
/// --ssh-restored …`.
pub fn schedule_spec(keep_audit: bool, remove_firewall: bool) -> CommandSpec {
    let mut args = vec![
        format!("--on-active={UNINSTALL_DELAY_S}"),
        "--timer-property=AccuracySec=100ms".to_owned(),
        "--unit=fleet-uninstall".to_owned(),
        AGENT_BIN.to_owned(),
    ];
    args.extend(
        UninstallOpts {
            ssh_restored: true,
            keep_audit,
            remove_firewall,
        }
        .args(),
    );
    CommandSpec::new(SYSTEMD_RUN)
        .args(args)
        .timeout(Duration::from_secs(10))
}

fn run_logged(runner: &dyn CommandRunner, log: &mut Vec<String>, spec: CommandSpec) -> bool {
    let what = format!(
        "{} {}",
        spec.program,
        spec.args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ")
    );
    let ok = matches!(runner.run_blocking(spec), Ok(o) if o.success());
    log.push(format!("{what}: {}", if ok { "ok" } else { "failed" }));
    ok
}

fn remove_path(p: &Path, log: &mut Vec<String>) {
    let res = match fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => fs::remove_dir_all(p),
        Ok(_) => fs::remove_file(p),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => Err(e),
    };
    log.push(format!(
        "remove {}: {}",
        p.display(),
        match res {
            Ok(()) => "ok".to_owned(),
            Err(e) => e.to_string(),
        }
    ));
}

/// `fleet-agent uninstall` (module docs). Returns a log of what it did;
/// fails only if restoring SSH access fails (then nothing is removed).
pub fn run_uninstall(
    paths: &Paths,
    opts: UninstallOpts,
    runner: &dyn CommandRunner,
    users: &dyn UserKeys,
) -> Result<Vec<String>, OpError> {
    let mut log = Vec::new();
    if !opts.ssh_restored {
        apply_ssh(paths, runner, users)?;
        log.push("ssh: keys restored to ~/.ssh/authorized_keys".into());
    }
    let cmd = |p: &'static str, a: &[&str]| {
        CommandSpec::new(p)
            .args(a.iter().copied())
            .timeout(CMD_TIMEOUT)
    };
    run_logged(
        runner,
        &mut log,
        cmd(
            SYSTEMCTL,
            &[
                "disable",
                "--now",
                "fleet-gate.service",
                "fleet-exec.service",
            ],
        ),
    );
    run_logged(
        runner,
        &mut log,
        cmd(
            SYSTEMCTL,
            &[
                "stop",
                "fleet-revert-*.timer",
                "fleet-agent-restart-*.timer",
            ],
        ),
    );
    if opts.remove_firewall {
        run_logged(
            runner,
            &mut log,
            cmd(NFT, &["delete", "table", "inet", "fleet"]),
        );
    }
    let exec_dir = &paths.exec_dir;
    if opts.keep_audit {
        let keep = host(paths, AUDIT_KEEP_DIR);
        if fsutil::ensure_dir(&keep, 0o700).is_ok() {
            for e in fs::read_dir(exec_dir).into_iter().flatten().flatten() {
                let name = e.file_name();
                if name.to_str().is_some_and(|n| n.starts_with("state.redb")) {
                    let r = fs::rename(e.path(), keep.join(&name));
                    log.push(format!("keep {}: {}", name.to_string_lossy(), r.is_ok()));
                }
            }
        }
    }
    let lib = paths
        .exec_dir
        .parent()
        .map_or_else(|| host(paths, "/var/lib/fleet"), Path::to_path_buf);
    for p in [
        lib,
        paths
            .authorized_keys_dir
            .parent()
            .map_or_else(|| host(paths, "/etc/fleet"), Path::to_path_buf),
        paths.run_dir.clone(),
        paths.exec_run_dir.clone(),
    ] {
        remove_path(&p, &mut log);
    }
    let packaged = runner
        .run_blocking(cmd(DPKG_QUERY, &["-W", "-f=${Status}", PACKAGE]))
        .is_ok_and(|o| o.success() && String::from_utf8_lossy(&o.stdout).contains("ok installed"));
    if packaged {
        run_logged(runner, &mut log, cmd(DPKG, &["--purge", PACKAGE]));
    } else {
        for f in [
            "/etc/systemd/system/fleet-exec.service",
            "/etc/systemd/system/fleet-gate.service",
            "/etc/tmpfiles.d/fleet.conf",
            "/usr/lib/tmpfiles.d/fleet.conf",
            "/etc/needrestart/conf.d/fleet.conf",
            "/usr/lib/fleet",
        ] {
            remove_path(&host(paths, f), &mut log);
        }
        run_logged(runner, &mut log, cmd(USERDEL, &["fleet-gate"]));
        run_logged(runner, &mut log, cmd(GROUPDEL, &["fleet-gate"]));
        run_logged(runner, &mut log, cmd(GROUPDEL, &["fleet"]));
        run_logged(runner, &mut log, cmd(SYSTEMCTL, &["daemon-reload"]));
    }
    Ok(log)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::userkeys::Direct;
    use fleet_ops::{CommandOutput, LocalBoxFuture, RunError};
    use std::cell::RefCell;

    /// Records argv; everything succeeds with empty output.
    #[derive(Default)]
    struct Rec(RefCell<Vec<String>>);
    impl CommandRunner for Rec {
        fn run(&self, spec: CommandSpec) -> LocalBoxFuture<'_, Result<CommandOutput, RunError>> {
            Box::pin(std::future::ready(self.run_blocking(spec)))
        }
        fn run_blocking(&self, spec: CommandSpec) -> Result<CommandOutput, RunError> {
            let mut s = spec.program.to_owned();
            for a in &spec.args {
                s.push(' ');
                s.push_str(&a.to_string_lossy());
            }
            self.0.borrow_mut().push(s);
            Ok(CommandOutput::ok(""))
        }
    }

    const FLEET_FILE: &str = "# BEGIN fleet roster (managed)\n\
        ecdsa-sha2-nistp256 AAAA fleet-device-1\n\
        restrict,command=\"/usr/lib/fleet/fleet-agent bridge --monitor\" ecdsa-sha2-nistp256 BBBB fleet-monitor-1\n\
        restrict,command=\"/usr/lib/fleet/fleet-agent bridge --recovery\" ssh-ed25519 CCCC fleet-recovery\n\
        # END fleet roster\n\
        ssh-ed25519 DDDD laptop\n";

    fn setup() -> (tempfile::TempDir, Paths, String) {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::under(d.path());
        let home = d.path().join("home/admin");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(paths.passwd.parent().unwrap()).unwrap();
        fs::write(
            &paths.passwd,
            format!("admin:x:1000:1000::{}:/bin/bash\n", home.display()),
        )
        .unwrap();
        fs::create_dir_all(&paths.authorized_keys_dir).unwrap();
        fs::write(paths.authorized_keys_dir.join("admin"), FLEET_FILE).unwrap();
        fs::write(paths.authorized_keys_dir.join("ghost"), "ssh-ed25519 X y\n").unwrap();
        let conf = host(&paths, FLEET_SSHD_CONFS[0]);
        fs::create_dir_all(conf.parent().unwrap()).unwrap();
        fs::write(
            &conf,
            "PermitRootLogin no\nAuthorizedKeysFile /etc/fleet/authorized_keys/%u\nAllowUsers admin\n",
        )
        .unwrap();
        (d, paths, home.display().to_string())
    }

    #[test]
    fn portable_lines_drop_bridges_and_markers() {
        assert_eq!(
            portable_lines(FLEET_FILE),
            "ecdsa-sha2-nistp256 AAAA fleet-device-1\nssh-ed25519 DDDD laptop\n"
        );
        assert_eq!(
            strip_fleet_akf("A b\n  authorizedkeysfile /etc/fleet/authorized_keys/%u\nC d\n"),
            "A b\nC d\n"
        );
        assert_eq!(
            strip_fleet_akf("AuthorizedKeysFile .ssh/authorized_keys\n"),
            "AuthorizedKeysFile .ssh/authorized_keys\n"
        );
    }

    #[test]
    fn prepare_applies_and_reverts() {
        let (_d, paths, home) = setup();
        fs::create_dir_all(format!("{home}/.ssh")).unwrap();
        fs::write(
            format!("{home}/.ssh/authorized_keys"),
            "ssh-ed25519 OLD old\n",
        )
        .unwrap();
        let rec = Rec::default();
        let snap = snapshot(&paths, &Direct).unwrap();
        assert!(fleet_keys_active(&paths));
        apply_ssh(&paths, &rec, &Direct).unwrap();
        assert!(!fleet_keys_active(&paths));
        assert_eq!(
            fs::read_to_string(format!("{home}/.ssh/authorized_keys")).unwrap(),
            "ssh-ed25519 OLD old\necdsa-sha2-nistp256 AAAA fleet-device-1\nssh-ed25519 DDDD laptop\n"
        );
        assert_eq!(
            *rec.0.borrow(),
            [
                format!("{SSHD} -t"),
                format!("{SYSTEMCTL} try-reload-or-restart -- ssh.service")
            ]
        );
        restore_ssh(&paths, &rec, &Direct, &snap).unwrap();
        assert!(fleet_keys_active(&paths));
        assert_eq!(
            fs::read_to_string(format!("{home}/.ssh/authorized_keys")).unwrap(),
            "ssh-ed25519 OLD old\n"
        );
    }

    #[test]
    fn uninstall_removes_state_and_keeps_audit_on_request() {
        let (_d, paths, home) = setup();
        fs::create_dir_all(&paths.exec_dir).unwrap();
        fs::write(paths.exec_dir.join("state.redb"), b"db").unwrap();
        fs::write(paths.exec_dir.join("signing.key"), [1u8; 32]).unwrap();
        fs::create_dir_all(paths.agent_bin.parent().unwrap()).unwrap();
        fs::write(&paths.agent_bin, b"bin").unwrap();
        let rec = Rec::default();
        let opts = UninstallOpts {
            ssh_restored: false,
            keep_audit: true,
            remove_firewall: false,
        };
        run_uninstall(&paths, opts, &rec, &Direct).unwrap();
        assert!(
            fs::read_to_string(format!("{home}/.ssh/authorized_keys"))
                .unwrap()
                .contains("fleet-device-1")
        );
        assert!(!paths.exec_dir.exists());
        assert!(!paths.authorized_keys_dir.exists());
        assert!(!paths.agent_bin.exists());
        assert_eq!(
            fs::read(host(&paths, AUDIT_KEEP_DIR).join("state.redb")).unwrap(),
            b"db"
        );
        let calls = rec.0.borrow();
        assert!(
            calls
                .iter()
                .any(|c| c.contains("disable --now fleet-gate.service"))
        );
        assert!(calls.iter().any(|c| c.starts_with(USERDEL)));
        assert!(!calls.iter().any(|c| c.starts_with(NFT)), "firewall kept");
    }

    #[test]
    fn scheduled_uninstall_command() {
        let s = schedule_spec(true, true);
        let a: Vec<String> = s
            .args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(s.program, SYSTEMD_RUN);
        assert_eq!(
            &a[3..],
            [
                AGENT_BIN,
                "uninstall",
                "--ssh-restored",
                "--keep-audit",
                "--remove-firewall"
            ]
        );
        assert_eq!(
            UninstallOpts::parse(&["--keep-audit"]),
            Some(UninstallOpts {
                keep_audit: true,
                ..Default::default()
            })
        );
        assert_eq!(UninstallOpts::parse(&["--bogus"]), None);
    }
}
