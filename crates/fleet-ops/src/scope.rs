//! Transient systemd scopes for long-running children (design §4.1): apt,
//! SteamCMD, `docker compose pull` run as `fleet-op-<id>.scope`, outside
//! exec's own `MemoryMax`/`CPUQuota`, and file changes can be attributed to
//! the operation (§4.9). `<id>` is the audit intent seq ([`OpMeta::op_id`]).
//!
//! [`OpMeta::op_id`]: crate::OpMeta::op_id

use crate::runner::CommandSpec;
use std::ffi::OsString;

pub const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";

/// `fleet-op-<id>` (systemd appends `.scope`).
pub fn unit_name(op_id: u64) -> String {
    format!("fleet-op-{op_id}")
}

/// Wraps `inner` as `systemd-run --scope --quiet --collect --unit
/// fleet-op-<id> -- <program> <args…>`. Timeout, output cap and extra
/// environment carry over (systemd-run passes the caller's environment to a
/// scope). On timeout the runner kills the child's process group and then
/// `systemctl kill --signal=SIGKILL fleet-op-<id>.scope`, which also reaches
/// descendants that called `setsid` (see [`crate::runner::scope_kill_spec`]).
pub fn scoped(op_id: u64, inner: CommandSpec) -> CommandSpec {
    let unit = unit_name(op_id);
    let mut args: Vec<OsString> = vec![
        "--scope".into(),
        "--quiet".into(),
        "--collect".into(),
        "--unit".into(),
        unit.clone().into(),
        "--".into(),
        inner.program.into(),
    ];
    args.extend(inner.args);
    CommandSpec {
        program: SYSTEMD_RUN,
        args,
        scope_unit: Some(unit),
        ..inner
    }
}

/// Resource limits of a transient scope that runs operator- or
/// template-supplied code (`shell.exec`, SteamCMD, game backup tar):
/// systemd `MemoryMax`, `TasksMax` and `CPUQuota` properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeLimits {
    pub memory_max_mb: u32,
    pub tasks_max: u32,
    /// Percent of one CPU (200 = two CPUs).
    pub cpu_quota_pct: u32,
}

impl ScopeLimits {
    /// `shell.exec` default: 2 GiB, 512 tasks, two CPUs.
    pub const SHELL: Self = Self {
        memory_max_mb: 2048,
        tasks_max: 512,
        cpu_quota_pct: 200,
    };
    /// SteamCMD / archive tools of `game.*`: 4 GiB, 1024 tasks, two CPUs.
    pub const GAME_TOOL: Self = Self {
        memory_max_mb: 4096,
        tasks_max: 1024,
        cpu_quota_pct: 200,
    };

    fn properties(self) -> [String; 6] {
        [
            "-p".into(),
            format!("MemoryMax={}M", self.memory_max_mb.max(64)),
            "-p".into(),
            format!("TasksMax={}", self.tasks_max.max(16)),
            "-p".into(),
            format!("CPUQuota={}%", self.cpu_quota_pct.max(10)),
        ]
    }
}

/// [`scoped`] with resource limits, and the scope stopped as soon as the
/// main process exits ([`CommandSpec::stop_scope_on_exit`]): background
/// processes it started don't outlive the op.
pub fn scoped_limited(op_id: u64, inner: CommandSpec, limits: ScopeLimits) -> CommandSpec {
    let mut s = scoped(op_id, inner);
    // Properties go before `--`, after `--unit <name>`.
    let at = s
        .args
        .iter()
        .position(|a| a == "--")
        .unwrap_or(s.args.len());
    let props = limits.properties();
    s.args.splice(at..at, props.into_iter().map(OsString::from));
    s.stop_scope_on_exit = true;
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn limited_scope_argv_and_stop() {
        let s = scoped_limited(
            9,
            CommandSpec::new("/usr/bin/setpriv").arg("--"),
            ScopeLimits::SHELL,
        );
        let argv: Vec<&str> = s.args.iter().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(
            argv,
            [
                "--scope",
                "--quiet",
                "--collect",
                "--unit",
                "fleet-op-9",
                "-p",
                "MemoryMax=2048M",
                "-p",
                "TasksMax=512",
                "-p",
                "CPUQuota=200%",
                "--",
                "/usr/bin/setpriv",
                "--"
            ]
        );
        let stop = crate::runner::scope_stop_spec(&s).unwrap();
        let argv: Vec<&str> = stop.args.iter().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(argv, ["stop", "fleet-op-9.scope"]);
        assert!(crate::runner::scope_stop_spec(&scoped(9, CommandSpec::new("/x"))).is_none());
    }

    #[test]
    fn scoped_argv() {
        let inner = CommandSpec::new("/usr/bin/apt-get")
            .args(["-y", "upgrade"])
            .env("DEBIAN_FRONTEND", "noninteractive")
            .timeout(Duration::from_secs(900));
        let s = scoped(42, inner);
        assert_eq!(s.program, "/usr/bin/systemd-run");
        let argv: Vec<&str> = s.args.iter().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(
            argv,
            [
                "--scope",
                "--quiet",
                "--collect",
                "--unit",
                "fleet-op-42",
                "--",
                "/usr/bin/apt-get",
                "-y",
                "upgrade"
            ]
        );
        assert_eq!(s.timeout, Duration::from_secs(900));
        assert_eq!(s.env.len(), 1);
        assert_eq!(s.scope_unit.as_deref(), Some("fleet-op-42"));
    }

    #[test]
    fn timeout_kills_scope_unit() {
        let k = crate::runner::scope_kill_spec(&scoped(7, CommandSpec::new("/usr/bin/apt-get")))
            .unwrap();
        assert_eq!(k.program, "/usr/bin/systemctl");
        let argv: Vec<&str> = k.args.iter().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(argv, ["kill", "--signal=SIGKILL", "fleet-op-7.scope"]);
        assert!(crate::runner::scope_kill_spec(&CommandSpec::new("/usr/bin/apt-get")).is_none());
    }
}
