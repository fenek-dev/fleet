//! `packages` group (design §2.5, §4.2): apt/dpkg with fixed binaries and
//! argument vectors.
//!
//! - Reads: `pkg.list` (`dpkg-query -W -f=<fixed>` + apt's
//!   `extended_states`), `pkg.upgradable` (`apt-get -s dist-upgrade` with
//!   `Debug::NoLocking`, so it never waits for or blocks a running apt),
//!   `pkg.history` (`/var/log/apt/history.log` plus `dpkg.log` entries apt
//!   didn't log).
//! - Mutations (`pkg.refresh/upgrade/install/remove/hold`) run in a
//!   `fleet-op-<id>` scope ([`crate::scope::scoped`]) with
//!   `DEBIAN_FRONTEND=noninteractive`, `--force-confdef --force-confold`
//!   (local config edits are always kept), `-y`, and
//!   `DPkg::Lock::Timeout=60`: apt waits up to a minute for the dpkg lock,
//!   then the op answers `Busy`.
//! - Before any apt transaction, the same command is simulated (`-s`); if
//!   it would remove a [`PROTECTED`] package (sshd, sudo, systemd, the
//!   agent, …) the op is refused with `PolicyDenied`, whatever the reason
//!   (a conflict pulled in by an install, a cascading remove).
//! - Results are the diff of `dpkg-query` before and after, so they are
//!   exact whatever apt did.
//!
//! **`pkg.upgrade`:** `All` is `apt-get upgrade --with-new-pkgs` (new
//! dependencies are installed, nothing is ever removed; upgrades that need
//! removals stay back and `pkg.upgradable` keeps listing them).
//! `SecurityOnly` upgrades exactly the packages `pkg.upgradable` marks
//! security, pinned to the listed candidate (`apt-get install
//! --only-upgrade name=version…`); new dependencies resolve to their normal
//! candidates. `unattended-upgrade` was rejected: its behaviour depends on
//! local configuration (allowed origins, automatic reboot). `Packages` is
//! `install --only-upgrade` of the named packages. `install` marks every
//! named package manual, so the auto flags apt had before are restored
//! with `apt-mark auto`.

mod parse;
mod watch;

#[cfg(test)]
mod tests;

pub use parse::{
    DPKG_QUERY_FORMAT, Installed, Sim, SimInst, compare_versions, diff_installed, merge_history,
    parse_apt_sim, parse_datetime, parse_dpkg_log, parse_dpkg_query, parse_extended_states,
    parse_history_log,
};
pub use watch::DpkgLogWatcher;

use crate::ctx::SysCtx;
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, Registry};
use crate::runner::{CommandOutput, CommandSpec};
use crate::scope;
use fleet_proto::args::DebPackageName;
use fleet_proto::op::{PkgSpec, UpgradeScope, tag};
use fleet_proto::payload::{
    PackageChanges, PackageHistory, PackageInfo, Packages, Upgradable, UpgradablePackage,
};
use fleet_proto::{ErrorCode, Op, Payload};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, UNIX_EPOCH};

pub const APT_GET: &str = "/usr/bin/apt-get";
pub const APT_MARK: &str = "/usr/bin/apt-mark";
pub const DPKG_QUERY: &str = "/usr/bin/dpkg-query";

pub const DPKG_LOG: &str = "/var/log/dpkg.log";
pub const HISTORY_LOGS: [&str; 2] = ["/var/log/apt/history.log.1", "/var/log/apt/history.log"];
pub const DPKG_LOGS: [&str; 2] = ["/var/log/dpkg.log.1", DPKG_LOG];
pub const EXTENDED_STATES: &str = "/var/lib/apt/extended_states";
pub const REBOOT_REQUIRED: &str = "/run/reboot-required";
const UPDATE_STAMP: &str = "/var/lib/apt/periodic/update-success-stamp";
const LISTS_DIR: &str = "/var/lib/apt/lists";

/// Never removed by any op (lockout, or the agent itself). Names starting
/// with `fleet` are protected too.
pub const PROTECTED: &[&str] = &[
    "openssh-server",
    "openssh-sftp-server",
    "sudo",
    "systemd",
    "systemd-sysv",
    "dbus",
    "nftables",
];

/// Options of every mutating `apt-get` call.
pub const APT_OPTS: &[&str] = &[
    "-q",
    "-y",
    "-o",
    "Dpkg::Options::=--force-confdef",
    "-o",
    "Dpkg::Options::=--force-confold",
    "-o",
    "DPkg::Lock::Timeout=60",
];
/// Options of every simulation.
pub const SIM_OPTS: &[&str] = &["-s", "-q", "-o", "Debug::NoLocking=1"];
/// `apt-mark` waits for the lock the same way.
const MARK_OPTS: &[&str] = &["-o", "DPkg::Lock::Timeout=60"];

const T_QUERY: Duration = Duration::from_secs(60);
const T_SIM: Duration = Duration::from_secs(120);
const T_MARK: Duration = Duration::from_secs(120);
const T_REFRESH: Duration = Duration::from_secs(600);
const T_INSTALL: Duration = Duration::from_secs(1800);
const T_UPGRADE: Duration = Duration::from_secs(3600);
/// Largest log file read by `pkg.history`.
const MAX_LOG_BYTES: u64 = 16 << 20;

pub fn is_protected(name: &str) -> bool {
    let n = parse::strip_arch(name);
    PROTECTED.contains(&n) || n.starts_with("fleet")
}

/// stderr of apt/dpkg when another process holds the lock.
pub fn is_lock_error(stderr: &str) -> bool {
    [
        "Could not get lock",
        "Unable to acquire the dpkg frontend lock",
        "Unable to lock the administration directory",
        "Unable to lock directory",
        "is locked by another process",
    ]
    .iter()
    .any(|p| stderr.contains(p))
}

fn noninteractive(spec: CommandSpec) -> CommandSpec {
    spec.env("DEBIAN_FRONTEND", "noninteractive")
        .env("APT_LISTCHANGES_FRONTEND", "none")
        .env("UCF_FORCE_CONFFOLD", "1")
}

/// `apt-get <APT_OPTS> <verb…>` in the op's scope.
pub fn apt_cmd(op_id: u64, verb: &[String], timeout: Duration) -> CommandSpec {
    let spec = CommandSpec::new(APT_GET)
        .args(APT_OPTS)
        .args(verb)
        .timeout(timeout);
    scope::scoped(op_id, noninteractive(spec))
}

/// `apt-get <SIM_OPTS> <verb…>` (no scope, no lock).
pub fn sim_cmd(verb: &[String]) -> CommandSpec {
    noninteractive(CommandSpec::new(APT_GET).args(SIM_OPTS).args(verb)).timeout(T_SIM)
}

pub fn dpkg_query_cmd() -> CommandSpec {
    CommandSpec::new(DPKG_QUERY)
        .args(["-W", &format!("-f={DPKG_QUERY_FORMAT}")])
        .timeout(T_QUERY)
}

/// `apt-mark <hold|unhold|auto> names…` in the op's scope.
pub fn mark_cmd(op_id: u64, verb: &str, names: &[String]) -> CommandSpec {
    let spec = CommandSpec::new(APT_MARK)
        .args(MARK_OPTS)
        .arg(verb)
        .args(names)
        .timeout(T_MARK);
    scope::scoped(op_id, noninteractive(spec))
}

fn stderr_tail(out: &CommandOutput) -> String {
    let s = String::from_utf8_lossy(&out.stderr);
    let t = s.trim();
    let start = t.len().saturating_sub(512);
    let start = (start..=t.len())
        .find(|&i| t.is_char_boundary(i))
        .unwrap_or(t.len());
    t[start..].to_owned()
}

/// Maps a failed apt/apt-mark run to a code.
pub fn apt_failure(out: &CommandOutput) -> OpError {
    let err = String::from_utf8_lossy(&out.stderr);
    let code = if is_lock_error(&err) {
        ErrorCode::Busy
    } else if err.contains("Unable to locate package")
        || (err.contains("Version '") && err.contains("was not found"))
    {
        ErrorCode::NotFound
    } else {
        ErrorCode::Internal
    };
    OpError::new(code).with_detail(format!("exit {:?}: {}", out.code, stderr_tail(out)))
}

async fn run_ok(ctx: &SysCtx, spec: CommandSpec) -> Result<CommandOutput, OpError> {
    let out = ctx.runner.run(spec).await?;
    if out.success() {
        Ok(out)
    } else {
        Err(apt_failure(&out))
    }
}

async fn installed(ctx: &SysCtx) -> Result<Vec<Installed>, OpError> {
    let out = run_ok(ctx, dpkg_query_cmd()).await?;
    Ok(parse_dpkg_query(&String::from_utf8_lossy(&out.stdout)))
}

async fn simulate(ctx: &SysCtx, verb: &[String]) -> Result<Sim, OpError> {
    let out = run_ok(ctx, sim_cmd(verb)).await?;
    Ok(parse_apt_sim(&String::from_utf8_lossy(&out.stdout)))
}

/// A regular file of at most [`MAX_LOG_BYTES`] (lossy UTF-8).
fn read_path(p: &Path) -> Option<String> {
    let meta = std::fs::metadata(p).ok()?;
    if !meta.is_file() || meta.len() > MAX_LOG_BYTES {
        return None;
    }
    std::fs::read(p)
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
}

fn read_file(ctx: &SysCtx, abs: &str) -> Option<String> {
    read_path(&ctx.path(abs)?)
}

fn exists(ctx: &SysCtx, abs: &str) -> bool {
    ctx.path(abs).is_some_and(|p| p.exists())
}

fn mtime_ms(ctx: &SysCtx, abs: &str) -> Option<u64> {
    let t = std::fs::metadata(ctx.path(abs)?).ok()?.modified().ok()?;
    let d = t.duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(d.as_millis()).ok()
}

pub fn reboot_required(ctx: &SysCtx) -> bool {
    exists(ctx, REBOOT_REQUIRED)
}

fn auto_installed(ctx: &SysCtx) -> HashSet<(String, String)> {
    read_file(ctx, EXTENDED_STATES)
        .map(|t| parse_extended_states(&t))
        .unwrap_or_default()
}

fn op_id(meta: &OpMeta) -> Result<u64, OpError> {
    meta.op_id()
        .ok_or_else(|| OpError::internal("mutating package op without audit seq"))
}

/// `pkg.list`.
pub async fn list(ctx: &SysCtx, filter: Option<&str>) -> Result<Packages, OpError> {
    let auto = auto_installed(ctx);
    let filter = filter.map(str::to_ascii_lowercase);
    let mut packages: Vec<PackageInfo> = installed(ctx)
        .await?
        .into_iter()
        .filter(|p| filter.as_deref().is_none_or(|f| p.name.contains(f)))
        .map(|p| PackageInfo {
            auto_installed: auto.contains(&(p.name.clone(), p.arch.clone())),
            name: p.name,
            version: p.version,
            arch: p.arch,
            held: p.held,
        })
        .collect();
    packages.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.arch.cmp(&b.arch)));
    Ok(Packages { packages })
}

/// Upgrades `apt-get -s dist-upgrade` would make (new installs skipped).
async fn upgradable_sim(ctx: &SysCtx) -> Result<Vec<SimInst>, OpError> {
    let sim = simulate(ctx, &["dist-upgrade".to_owned()]).await?;
    Ok(sim
        .inst
        .into_iter()
        .filter(|i| i.current.is_some())
        .collect())
}

/// `pkg.upgradable`.
pub async fn upgradable(ctx: &SysCtx) -> Result<Upgradable, OpError> {
    let packages = upgradable_sim(ctx)
        .await?
        .into_iter()
        .map(|i| UpgradablePackage {
            name: parse::strip_arch(&i.name).to_owned(),
            current: i.current.unwrap_or_default(),
            candidate: i.candidate,
            security: i.security,
            origin: i.origins,
        })
        .collect();
    Ok(Upgradable {
        packages,
        reboot_required: reboot_required(ctx),
        lists_updated_ms: mtime_ms(ctx, UPDATE_STAMP).or_else(|| mtime_ms(ctx, LISTS_DIR)),
    })
}

/// `pkg.history`. Reading and parsing (up to 4 × 16 MiB) runs on the
/// blocking pool.
pub async fn history(
    ctx: &SysCtx,
    since: Option<u64>,
    until: Option<u64>,
    limit: u32,
) -> Result<PackageHistory, OpError> {
    let paths = |abs: &[&str]| -> Vec<PathBuf> { abs.iter().filter_map(|p| ctx.path(p)).collect() };
    let (apt_paths, dpkg_paths) = (paths(&HISTORY_LOGS), paths(&DPKG_LOGS));
    tokio::task::spawn_blocking(move || {
        let read_all = |paths: &[PathBuf]| -> String {
            paths
                .iter()
                .filter_map(|p| read_path(p))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let apt = parse_history_log(&read_all(&apt_paths));
        let dpkg = parse_dpkg_log(&read_all(&dpkg_paths));
        PackageHistory {
            entries: merge_history(apt, dpkg, since, until, limit as usize),
        }
    })
    .await
    .map_err(OpError::internal)
}

/// `name[:arch]=version` for an apt argument, only from validated parts.
fn pinned_arg(name: &str, version: &str) -> Option<String> {
    let (n, arch) = match name.split_once(':') {
        Some((n, a)) => (n, Some(a)),
        None => (name, None),
    };
    DebPackageName::new(n).ok()?;
    fleet_proto::args::DebVersion::new(version).ok()?;
    if let Some(a) = arch
        && (a.is_empty()
            || !a
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'))
    {
        return None;
    }
    Some(match arch {
        Some(a) => format!("{n}:{a}={version}"),
        None => format!("{n}={version}"),
    })
}

fn spec_arg(p: &PkgSpec) -> String {
    match &p.version {
        Some(v) => format!("{}={}", p.name.as_str(), v.as_str()),
        None => p.name.as_str().to_owned(),
    }
}

/// Simulate, refuse protected removals, run, restore auto flags, diff.
async fn transaction(
    ctx: &SysCtx,
    meta: &OpMeta,
    verb: Vec<String>,
    timeout: Duration,
    restore_auto: bool,
    purge: bool,
) -> Result<PackageChanges, OpError> {
    let id = op_id(meta)?;
    let before = installed(ctx).await?;
    let sim = simulate(ctx, &verb).await?;
    if let Some(p) = sim.remove.iter().find(|n| is_protected(n)) {
        return Err(OpError::new(ErrorCode::PolicyDenied).with_detail(format!("would remove {p}")));
    }
    let auto = if restore_auto {
        auto_installed(ctx)
    } else {
        HashSet::new()
    };
    run_ok(ctx, apt_cmd(id, &verb, timeout)).await?;
    if restore_auto {
        let touched: HashSet<&str> = sim
            .inst
            .iter()
            .map(|i| parse::strip_arch(&i.name))
            .collect();
        let mut back: Vec<String> = auto
            .iter()
            .filter(|(n, _)| touched.contains(n.as_str()))
            .map(|(n, _)| n.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        back.sort();
        if !back.is_empty() {
            run_ok(ctx, mark_cmd(id, "auto", &back)).await?;
        }
    }
    let after = installed(ctx).await?;
    Ok(PackageChanges {
        changes: diff_installed(&before, &after, purge),
        reboot_required: reboot_required(ctx),
    })
}

fn names(p: &[DebPackageName]) -> Vec<String> {
    p.iter().map(|n| n.as_str().to_owned()).collect()
}

async fn upgrade(
    ctx: &SysCtx,
    meta: &OpMeta,
    scope: &UpgradeScope,
) -> Result<PackageChanges, OpError> {
    let only_upgrade = |args: Vec<String>| {
        let mut v = vec!["install".to_owned(), "--only-upgrade".to_owned()];
        v.extend(args);
        v
    };
    match scope {
        UpgradeScope::All => {
            let verb = vec!["upgrade".to_owned(), "--with-new-pkgs".to_owned()];
            transaction(ctx, meta, verb, T_UPGRADE, false, false).await
        }
        UpgradeScope::SecurityOnly => {
            let mut set: Vec<String> = upgradable_sim(ctx)
                .await?
                .iter()
                .filter(|i| i.security)
                .filter_map(|i| pinned_arg(&i.name, &i.candidate))
                .collect();
            set.sort();
            set.dedup();
            if set.is_empty() {
                return Ok(PackageChanges {
                    changes: Vec::new(),
                    reboot_required: reboot_required(ctx),
                });
            }
            transaction(ctx, meta, only_upgrade(set), T_UPGRADE, true, false).await
        }
        UpgradeScope::Packages(p) => {
            transaction(ctx, meta, only_upgrade(names(p)), T_UPGRADE, true, false).await
        }
    }
}

async fn hold(
    ctx: &SysCtx,
    meta: &OpMeta,
    p: &[DebPackageName],
    on: bool,
) -> Result<PackageChanges, OpError> {
    let id = op_id(meta)?;
    let before = installed(ctx).await?;
    run_ok(
        ctx,
        mark_cmd(id, if on { "hold" } else { "unhold" }, &names(p)),
    )
    .await?;
    let after = installed(ctx).await?;
    Ok(PackageChanges {
        changes: diff_installed(&before, &after, false),
        reboot_required: reboot_required(ctx),
    })
}

/// Refusals that need no system state (before the nonce is consumed).
pub fn check_pkg_op(op: &Op) -> Result<(), OpError> {
    if let Op::PkgRemove { packages, .. } = op
        && let Some(p) = packages.iter().find(|p| is_protected(p.as_str()))
    {
        return Err(OpError::new(ErrorCode::PolicyDenied).with_detail(format!("protected {p}")));
    }
    Ok(())
}

/// Handler for every `packages` op (tags 500–599).
pub struct PackagesHandler;

impl PackagesHandler {
    async fn run(ctx: &SysCtx, op: &Op, meta: &OpMeta) -> Result<Payload, OpError> {
        check_pkg_op(op)?;
        Ok(match op {
            Op::PkgList { filter } => {
                Payload::Packages(list(ctx, filter.as_ref().map(|f| f.as_str())).await?)
            }
            Op::PkgUpgradable => Payload::Upgradable(upgradable(ctx).await?),
            Op::PkgHistory { range, limit } => {
                Payload::PackageHistory(history(ctx, range.since_ms, range.until_ms, *limit).await?)
            }
            Op::PkgRefresh => {
                let id = op_id(meta)?;
                run_ok(ctx, apt_cmd(id, &["update".to_owned()], T_REFRESH)).await?;
                Payload::Upgradable(upgradable(ctx).await?)
            }
            Op::PkgUpgrade { scope } => Payload::PackageChanges(upgrade(ctx, meta, scope).await?),
            Op::PkgInstall { packages } => {
                let mut verb = vec!["install".to_owned()];
                verb.extend(packages.iter().map(spec_arg));
                Payload::PackageChanges(
                    transaction(ctx, meta, verb, T_INSTALL, false, false).await?,
                )
            }
            Op::PkgRemove { packages, purge } => {
                let mut verb = vec![if *purge { "purge" } else { "remove" }.to_owned()];
                verb.extend(names(packages));
                Payload::PackageChanges(
                    transaction(ctx, meta, verb, T_INSTALL, false, *purge).await?,
                )
            }
            Op::PkgHold { packages, hold: on } => {
                Payload::PackageChanges(hold(ctx, meta, packages, *on).await?)
            }
            _ => return Err(ErrorCode::Unsupported.into()),
        })
    }
}

impl OpHandler for PackagesHandler {
    fn validate(&self, _ctx: &SysCtx, op: &Op, _meta: &OpMeta) -> Result<(), OpError> {
        check_pkg_op(op)
    }

    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        op: &'a Op,
        meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move { Self::run(ctx, op, meta).await.map(OpOutput::Payload) })
    }
}

/// Registers [`PackagesHandler`] for every packages tag.
pub fn register(r: &mut Registry) {
    let h: Rc<dyn OpHandler> = Rc::new(PackagesHandler);
    for t in [
        tag::PKG_LIST,
        tag::PKG_UPGRADABLE,
        tag::PKG_HISTORY,
        tag::PKG_REFRESH,
        tag::PKG_UPGRADE,
        tag::PKG_INSTALL,
        tag::PKG_REMOVE,
        tag::PKG_HOLD,
    ] {
        r.register(t, h.clone());
    }
}
