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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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
