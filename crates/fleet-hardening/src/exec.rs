//! The generic executor behind `Module::apply` and `Module::revert`.
//!
//! Files: `fleet_ops::fswrite` (fd-relative, symlink-refusing, atomic).
//! Commands: fixed absolute paths plus argv via the context's runner.
//! A failing [`Action::Validate`] puts back every file the module wrote so
//! far, so a bad `sshd_config.d` or sudoers drop-in never stays in place.

use crate::module::{Action, Applied, Change, Cmd, Ctx, FileSnap, read_file};
use fleet_ops::files::walk;
use fleet_ops::firewall::{self, Table, model, render};
use fleet_ops::handler::OpError;
use fleet_ops::runner::{CommandOutput, CommandSpec};
use fleet_ops::{SysCtx, fswrite, nftlock, packages};
use fleet_proto::ErrorCode;
use fleet_proto::args::FirewallRuleSet;
use rustix::fs::{self as rfs, AtFlags, Mode, OFlags};
use std::io::Write as _;
use std::time::Duration;

const T_CMD: Duration = Duration::from_secs(120);
const T_APT_UPDATE: Duration = Duration::from_secs(600);
const T_APT_INSTALL: Duration = Duration::from_secs(1800);

/// Runs the actions of `plan` that belong to `module`, in order.
pub async fn execute(
    ctx: &mut Ctx,
    module: &'static str,
    plan: &[Change],
) -> Result<Applied, OpError> {
    let mut applied = Applied {
        module,
        ..Applied::default()
    };
    for change in plan.iter().filter(|c| c.module == module) {
        for action in &change.actions {
            if let Err(e) = run_action(ctx, action, &mut applied).await {
                if matches!(action, Action::Validate(_)) {
                    restore_files(&ctx.sys, &applied.files)?;
                }
                return Err(e);
            }
            // New sources or keys: the next install needs a fresh update.
            if let Action::Write { path, .. } | Action::FetchKey { dest: path, .. } = action
                && [
                    "/etc/apt/sources.list.d/",
                    "/etc/apt/keyrings/",
                    "/etc/apt/preferences.d/",
                ]
                .iter()
                .any(|d| path.starts_with(d))
            {
                ctx.apt_updated = false;
            }
            applied.actions += 1;
        }
    }
    Ok(applied)
}

async fn run_action(ctx: &mut Ctx, action: &Action, applied: &mut Applied) -> Result<(), OpError> {
    if let Action::AptUpdate = action {
        if !ctx.apt_updated {
            apt(ctx, &["update".to_owned()], T_APT_UPDATE).await?;
            ctx.apt_updated = true;
        }
        return Ok(());
    }
    let ctx = &*ctx;
    let sys = &ctx.sys;
    match action {
        Action::Write {
            path,
            content,
            mode,
        } => {
            remember(sys, path, applied)?;
            write_file(sys, path, content, *mode)
        }
        Action::Remove { path } => {
            remember(sys, path, applied)?;
            remove_file(sys, path)
        }
        Action::RootOwn {
            user,
            name,
            content,
            immutable,
        } => {
            let pw = fleet_ops::users::passwd(sys)?;
            let e = fleet_ops::users::parse::lookup(&pw, user).ok_or_else(|| {
                OpError::new(ErrorCode::NotFound).with_detail(format!("user {user}"))
            })?;
            if !e.home.starts_with("/home/") {
                return Err(OpError::new(ErrorCode::PolicyDenied)
                    .with_detail(format!("{user}: home outside /home")));
            }
            root_own(sys, &e.home, name, e.uid, content.as_deref(), *immutable)
        }
        Action::Run(c) => run_checked(sys, c).await.map(drop),
        Action::Purge(names) => {
            let mut verb = vec!["purge".to_owned()];
            verb.extend(names.iter().cloned());
            apt(ctx, &verb, T_APT_INSTALL).await
        }
        Action::FetchKey {
            url,
            fingerprint,
            dest,
        } => {
            remember(sys, dest, applied)?;
            fetch_key(sys, url, fingerprint, dest).await
        }
        Action::Validate(c) => run_checked(sys, c).await.map(drop).map_err(|e| {
            OpError::new(ErrorCode::InvalidArgument).with_detail(format!(
                "validation failed, files restored: {}",
                e.detail().unwrap_or("")
            ))
        }),
        Action::AptUpdate => Ok(()),
        Action::Install(names) => {
            let mut verb = vec!["install".to_owned(), "--no-install-recommends".to_owned()];
            verb.extend(names.iter().cloned());
            apt(ctx, &verb, T_APT_INSTALL).await
        }
        Action::Firewall(set) => apply_firewall(sys, set).await,
        Action::VerifyFstab(text) => verify_fstab(sys, text).await,
    }
}

pub const FINDMNT: &str = "/usr/bin/findmnt";
/// Scratch copy of a planned `/etc/fstab` (root-only directory).
pub const FSTAB_CHECK: &str = "/var/lib/fleet/hardening/fstab.check";

/// `findmnt --verify --tab-file <tmp>` of `text`; the temp file is removed
/// either way.
pub async fn verify_fstab(sys: &SysCtx, text: &[u8]) -> Result<(), OpError> {
    fswrite::ensure_dir(sys, "/var/lib/fleet/hardening", 0o700)?;
    write_file(sys, FSTAB_CHECK, text, 0o600)?;
    let out = run_checked(
        sys,
        &Cmd::new(FINDMNT, ["--verify", "--tab-file", FSTAB_CHECK]),
    )
    .await;
    let _ = remove_file(sys, FSTAB_CHECK);
    out.map(drop).map_err(|e| {
        OpError::new(ErrorCode::InvalidArgument).with_detail(format!(
            "fstab verification failed, nothing written: {}",
            e.detail().unwrap_or("")
        ))
    })
}

/// Records `path`'s prior state once per module.
fn remember(sys: &SysCtx, path: &str, applied: &mut Applied) -> Result<(), OpError> {
    if !applied.files.iter().any(|f| f.path == path) {
        applied.files.push(FileSnap {
            path: path.to_owned(),
            prior: read_file(sys, path)?,
        });
    }
    Ok(())
}

fn parent_of(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some(("", _)) | None => "/",
        Some((p, _)) => p,
    }
}

/// Atomic replace, creating missing parents (0755).
pub fn write_file(sys: &SysCtx, path: &str, content: &[u8], mode: u32) -> Result<(), OpError> {
    let parent = parent_of(path);
    if parent != "/" {
        fswrite::ensure_dir(sys, parent, 0o755)?;
    }
    fswrite::write_atomic(sys, path, content, mode)
}

/// Removes `path` (not following a symlink); missing is fine.
pub fn remove_file(sys: &SysCtx, path: &str) -> Result<(), OpError> {
    let (dir, name) = match walk::open_parent(sys, path) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(OpError::internal(format!("{path}: {e}"))),
    };
    match rfs::unlinkat(&dir, name, AtFlags::empty()) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(e) => Err(OpError::internal(format!("unlink {path}: {e}"))),
    }
}

/// Puts files back as recorded (reverse order).
pub fn restore_files(sys: &SysCtx, files: &[FileSnap]) -> Result<(), OpError> {
    for f in files.iter().rev() {
        match &f.prior {
            Some((bytes, mode)) => write_file(sys, &f.path, bytes, *mode)?,
            None => remove_file(sys, &f.path)?,
        }
    }
    Ok(())
}

pub fn spec_of(c: &Cmd, timeout: Duration) -> CommandSpec {
    let mut s = CommandSpec::new(c.program)
        .args(c.args.iter())
        .timeout(timeout);
    if let Some(i) = &c.stdin {
        s = s.stdin(i.clone());
    }
    s
}

fn stderr_tail(out: &CommandOutput) -> String {
    let s = String::from_utf8_lossy(&out.stderr);
    let t: String = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect();
    let t = t.trim();
    let start = t.len().saturating_sub(400);
    let start = (start..=t.len())
        .find(|&i| t.is_char_boundary(i))
        .unwrap_or(t.len());
    t[start..].to_owned()
}

/// Runs `c`; a non-zero exit is `Internal` with stderr's tail (local log).
pub async fn run_checked(sys: &SysCtx, c: &Cmd) -> Result<CommandOutput, OpError> {
    let out = sys.runner.run(spec_of(c, T_CMD)).await?;
    if out.success() {
        Ok(out)
    } else {
        Err(OpError::internal(format!(
            "{} failed: {}",
            c.program,
            stderr_tail(&out)
        )))
    }
}

/// Blocking [`run_checked`] (the synchronous `Revertible::restore`).
pub fn run_checked_blocking(sys: &SysCtx, c: &Cmd) -> Result<CommandOutput, OpError> {
    let out = sys.runner.run_blocking(spec_of(c, T_CMD))?;
    if out.success() {
        Ok(out)
    } else {
        Err(OpError::internal(format!(
            "{} failed: {}",
            c.program,
            stderr_tail(&out)
        )))
    }
}

async fn apt(ctx: &Ctx, verb: &[String], timeout: Duration) -> Result<(), OpError> {
    let out = ctx
        .sys
        .runner
        .run(packages::apt_cmd(ctx.op_id, verb, timeout))
        .await?;
    if out.success() {
        Ok(())
    } else {
        Err(packages::apt_failure(&out))
    }
}

pub const CURL: &str = "/usr/bin/curl";
pub const GPG: &str = "/usr/bin/gpg";
/// Throwaway gpg home (`--show-keys` only reads, but gpg wants a home).
pub const GNUPG_HOME: &str = "/var/lib/fleet/hardening/gnupg";
const KEY_CAP: usize = 64 << 10;

pub fn curl_spec(url: &str) -> CommandSpec {
    CommandSpec::new(CURL)
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--max-time",
            "60",
            "--max-filesize",
            "65536",
            "--",
            url,
        ])
        .timeout(Duration::from_secs(90))
        .output_cap(KEY_CAP)
}

pub fn gpg_show_spec(key: Vec<u8>) -> CommandSpec {
    CommandSpec::new(GPG)
        .args([
            "--homedir",
            GNUPG_HOME,
            "--batch",
            "--no-autostart",
            "--with-colons",
            "--show-keys",
        ])
        .stdin(key)
        .timeout(Duration::from_secs(30))
}

/// Primary-key fingerprints in `gpg --with-colons` output: the `fpr`
/// record right after each `pub` record.
pub fn primary_fingerprints(colons: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut after_pub = false;
    for l in colons.lines() {
        let f: Vec<&str> = l.split(':').collect();
        match f.first() {
            Some(&"pub") => after_pub = true,
            Some(&"fpr") if after_pub => {
                out.push(f.get(9).copied().unwrap_or("").to_ascii_uppercase());
                after_pub = false;
            }
            _ => {}
        }
    }
    out
}

/// Downloads a key, requires exactly one primary key with `fingerprint`,
/// writes it to `dest`.
pub async fn fetch_key(
    sys: &SysCtx,
    url: &str,
    fingerprint: &str,
    dest: &str,
) -> Result<(), OpError> {
    let out = sys.runner.run(curl_spec(url)).await?;
    if !out.success() || out.truncated {
        return Err(OpError::internal(format!(
            "curl {url}: {}",
            stderr_tail(&out)
        )));
    }
    fswrite::ensure_dir(sys, GNUPG_HOME, 0o700)?;
    let shown = sys.runner.run(gpg_show_spec(out.stdout.clone())).await?;
    if !shown.success() {
        return Err(OpError::internal(format!("gpg: {}", stderr_tail(&shown))));
    }
    let fprs = primary_fingerprints(&String::from_utf8_lossy(&shown.stdout));
    if fprs != [fingerprint.to_owned()] {
        return Err(OpError::new(ErrorCode::PolicyDenied).with_detail(format!(
            "{url}: key fingerprint {fprs:?}, want {fingerprint}"
        )));
    }
    write_file(sys, dest, &out.stdout, 0o644)
}

/// Replaces `table inet fleet` with `set` after the same lockout checks as
/// `firewall.apply` (design §4.8). An unrecognized table is left alone.
pub async fn apply_firewall(sys: &SysCtx, set: &FirewallRuleSet) -> Result<(), OpError> {
    let invalid = |d: &str| OpError::new(ErrorCode::InvalidArgument).with_detail(d.to_owned());
    let set = model::canonical(set);
    let ssh = model::ssh_info(sys).map_err(invalid)?;
    model::check(&set, &ssh).map_err(invalid)?;
    let _table = nftlock::lock().await;
    let table = firewall::table_from(sys.runner.run(firewall::list_table_spec()).await)?;
    if let Table::Present(p) = &table
        && p.model.is_none()
    {
        return Err(invalid(
            "inet fleet is not in rendered form; replace it with firewall.apply",
        ));
    }
    let script = render::render(&set, &ssh.ports);
    let out = sys.runner.run(firewall::apply_spec(script)).await?;
    if out.success() {
        Ok(())
    } else {
        Err(OpError::internal(format!("nft: {}", stderr_tail(&out))))
    }
}

/// The owner a managed file must have: root in production, the test
/// user when running unprivileged (fswrite applies the same rule).
pub fn root_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn io_err(what: &str, e: impl std::fmt::Display) -> OpError {
    OpError::internal(format!("{what}: {e}"))
}

/// Makes `home/name` owned by root (0644), creating it (empty) when
/// missing or replacing its content when `content` is set. The home is
/// opened component by component without following symlinks; the file is
/// opened `O_NOFOLLOW` and must be a regular file with one link owned by
/// the user or root, so a planted symlink or hard link can't redirect the
/// `fchown` (and `fs.protected_hardlinks` keeps the user from linking
/// files they don't own). An existing `chattr +i` is cleared first (an
/// immutable file can't be replaced or re-owned); `immutable` sets it
/// again at the end (Strict, design §9.5).
pub fn root_own(
    sys: &SysCtx,
    home: &str,
    name: &str,
    uid: u32,
    content: Option<&[u8]>,
    immutable: bool,
) -> Result<(), OpError> {
    let dir = walk::open_dir(sys, home).map_err(|e| io_err(home, e))?;
    let what = format!("{home}/{name}");
    clear_immutable_at(&dir, name);
    let finish = |fd: &rustix::fd::OwnedFd| -> Result<(), OpError> {
        rfs::fchmod(fd, Mode::from_raw_mode(0o644)).map_err(|e| io_err(&what, e))?;
        if rustix::process::geteuid().is_root() {
            rfs::fchown(
                fd,
                Some(rustix::process::Uid::ROOT),
                Some(rustix::process::Gid::ROOT),
            )
            .map_err(|e| io_err(&what, e))?;
        }
        Ok(())
    };
    let seal = |fd: rustix::fd::BorrowedFd<'_>| -> Result<(), OpError> {
        if immutable {
            set_immutable(fd, true).map_err(|e| io_err(&what, e))?;
        }
        Ok(())
    };
    if let Some(bytes) = content {
        let mut rnd = [0u8; 8];
        fleet_crypto::random_bytes(&mut rnd).map_err(OpError::internal)?;
        let tmp = format!(
            ".{name}.fleet-{}.tmp",
            rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        let fd = rfs::openat(
            &dir,
            tmp.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|e| io_err(&what, e))?;
        let res = (|| -> Result<(), OpError> {
            finish(&fd)?;
            let mut f = std::fs::File::from(fd);
            f.write_all(bytes).map_err(|e| io_err(&what, e))?;
            f.sync_all().map_err(|e| io_err(&what, e))?;
            rfs::renameat(&dir, tmp.as_str(), &dir, name).map_err(|e| io_err(&what, e))?;
            // After the rename: an immutable file can't be renamed.
            seal(rustix::fd::AsFd::as_fd(&f))
        })();
        if res.is_err() {
            let _ = rfs::unlinkat(&dir, tmp.as_str(), AtFlags::empty());
        }
        return res;
    }
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = match rfs::openat(&dir, name, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => rfs::openat(
            &dir,
            name,
            flags | OFlags::CREATE | OFlags::EXCL,
            Mode::from_raw_mode(0o644),
        )
        .map_err(|e| io_err(&what, e))?,
        Err(e) => return Err(io_err(&what, e)),
    };
    let meta = walk::meta_of(&rfs::fstat(&fd).map_err(|e| io_err(&what, e))?);
    if meta.kind != walk::Kind::File
        || meta.nlink != 1
        || (meta.uid != uid && meta.uid != root_uid())
    {
        return Err(OpError::new(ErrorCode::PolicyDenied).with_detail(format!(
            "{what}: not a single-link regular file of the user"
        )));
    }
    finish(&fd)?;
    seal(rustix::fd::AsFd::as_fd(&fd))
}

/// Sets or clears the immutable inode flag (`chattr ±i`) through the fd
/// (`FS_IOC_{GET,SET}FLAGS`). Linux only; a no-op elsewhere (tests).
#[cfg(target_os = "linux")]
pub fn set_immutable<Fd: rustix::fd::AsFd>(fd: Fd, on: bool) -> rustix::io::Result<()> {
    let f = rfs::ioctl_getflags(&fd)?;
    let want = if on {
        f | rfs::IFlags::IMMUTABLE
    } else {
        f - rfs::IFlags::IMMUTABLE
    };
    if want != f {
        rfs::ioctl_setflags(fd, want)?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn set_immutable<Fd: rustix::fd::AsFd>(_fd: Fd, _on: bool) -> rustix::io::Result<()> {
    Ok(())
}

/// Whether the file behind `fd` is immutable (always `false` off Linux).
#[cfg(target_os = "linux")]
pub fn is_immutable(fd: &rustix::fd::OwnedFd) -> bool {
    rfs::ioctl_getflags(fd).is_ok_and(|f| f.contains(rfs::IFlags::IMMUTABLE))
}

#[cfg(not(target_os = "linux"))]
pub fn is_immutable(_fd: &rustix::fd::OwnedFd) -> bool {
    false
}

/// Clears `chattr +i` on an existing `name` in `dir` (opened without
/// following symlinks) so it can be replaced or re-owned.
fn clear_immutable_at(dir: &rustix::fd::OwnedFd, name: &str) {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    if let Ok(fd) = rfs::openat(dir, name, flags, Mode::empty())
        && is_immutable(&fd)
    {
        let _ = set_immutable(&fd, false);
    }
}

/// Whether `home/name` is immutable (`chattr +i`); `false` when missing.
pub fn home_file_immutable(sys: &SysCtx, home: &str, name: &str) -> bool {
    let Ok(dir) = walk::open_dir(sys, home) else {
        return false;
    };
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    rfs::openat(&dir, name, flags, Mode::empty()).is_ok_and(|fd| is_immutable(&fd))
}

/// Whether `home/name` is already root-owned 0644 (and has `content`).
pub fn is_root_owned(sys: &SysCtx, home: &str, name: &str, content: Option<&[u8]>) -> bool {
    let path = format!("{home}/{name}");
    let Ok(meta) = walk::stat_path(sys, &path) else {
        return false;
    };
    if meta.kind != walk::Kind::File || meta.uid != root_uid() || meta.mode & 0o7777 != 0o644 {
        return false;
    }
    match content {
        None => true,
        // Not fswrite (its ancestor checks refuse a user-owned home).
        Some(c) => walk::open_file(sys, &path).is_ok_and(|(f, m)| {
            use std::io::Read as _;
            let mut b = Vec::new();
            m.size <= crate::module::MAX_FILE
                && f.take(crate::module::MAX_FILE).read_to_end(&mut b).is_ok()
                && b == c
        }),
    }
}
