//! Who wrote a change (design §4.9).
//!
//! With the writer's pid (fanotify): exec's own pid → the operation exec
//! is running ([`AttributionContext::current_op`]); a process in
//! `fleet-op-<seq>.scope` → that operation; anything else → `External`
//! with its `comm`. A pid that is already gone can't be classified, so it
//! is `Unknown`.
//!
//! Without a pid (inotify, which is what the agent uses: `rustix` has no
//! fanotify and the agent adds no FFI): `External` while exec runs no
//! operation, `Unknown` while one is in flight (the write may be Fleet's
//! or not; it is not guessed). Handlers that write config files report
//! their writes directly (`ConfigTracker::note_write`), which records
//! them as `Fleet` before the watch event arrives. A full-scan catch-up
//! is always `Unknown`.

use crate::ctx::SysCtx;
use fleet_proto::payload::ChangeSource;

/// Exec's view of running operations. Exec implements it; tests use
/// fixed values.
pub trait AttributionContext {
    /// Exec's own pid.
    fn exec_pid(&self) -> u32;
    /// The one operation exec is executing right now: `(op tag, audit
    /// seq)`. `None` when idle or when several run at once.
    fn current_op(&self) -> Option<(u16, u64)>;
    /// Whether any operation (including a transient scope) is in flight.
    fn busy(&self) -> bool;
    /// Op tag of the operation with audit intent `seq`, if exec knows it.
    fn op_tag(&self, seq: u64) -> Option<u16>;
}

/// No knowledge of exec's operations: every pid-less change is `Unknown`.
/// Used until exec wires its own implementation.
pub struct Unattributed;

impl AttributionContext for Unattributed {
    fn exec_pid(&self) -> u32 {
        std::process::id()
    }

    fn current_op(&self) -> Option<(u16, u64)> {
        None
    }

    fn busy(&self) -> bool {
        true
    }

    fn op_tag(&self, _seq: u64) -> Option<u16> {
        None
    }
}

/// The op seq of a `fleet-op-<seq>.scope` in `/proc/<pid>/cgroup` text
/// (cgroup v2 `0::/…` or a v1 hierarchy line). Nested cgroups below the
/// scope count; a scope name must match exactly (`fleet-op-12x.scope` and
/// `fleet-op-.scope` don't).
pub fn parse_op_scope(cgroup: &str) -> Option<u64> {
    cgroup.lines().find_map(|line| {
        let path = line.splitn(3, ':').nth(2)?;
        path.split('/').find_map(|c| {
            let digits = c.strip_prefix("fleet-op-")?.strip_suffix(".scope")?;
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            digits.parse().ok()
        })
    })
}

/// Classifies a write by `pid` (if known).
pub fn attribute(ctx: &SysCtx, pid: Option<u32>, att: &dyn AttributionContext) -> ChangeSource {
    let Some(pid) = pid else {
        return if att.busy() {
            ChangeSource::Unknown
        } else {
            ChangeSource::External { process: None }
        };
    };
    if pid == att.exec_pid() {
        return match att.current_op() {
            Some((op_tag, audit_seq)) => ChangeSource::Fleet { op_tag, audit_seq },
            None => ChangeSource::Unknown,
        };
    }
    let Some(cgroup) = ctx.procfs.read(&format!("/proc/{pid}/cgroup")) else {
        return ChangeSource::Unknown;
    };
    if let Some(seq) = parse_op_scope(&cgroup) {
        return ChangeSource::Fleet {
            op_tag: att.op_tag(seq).unwrap_or(0),
            audit_seq: seq,
        };
    }
    let process = ctx
        .procfs
        .read(&format!("/proc/{pid}/comm"))
        .map(|c| c.trim().chars().take(64).collect());
    ChangeSource::External { process }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ctx;
    use std::rc::Rc;

    struct Fixed {
        busy: bool,
        current: Option<(u16, u64)>,
    }

    impl AttributionContext for Fixed {
        fn exec_pid(&self) -> u32 {
            100
        }
        fn current_op(&self) -> Option<(u16, u64)> {
            self.current
        }
        fn busy(&self) -> bool {
            self.busy
        }
        fn op_tag(&self, seq: u64) -> Option<u16> {
            (seq == 42).then_some(505)
        }
    }

    #[test]
    fn cgroup_parsing() {
        assert_eq!(
            parse_op_scope("0::/system.slice/fleet-op-42.scope\n"),
            Some(42)
        );
        assert_eq!(
            parse_op_scope("0::/system.slice/fleet-op-7.scope/sub/child\n"),
            Some(7)
        );
        assert_eq!(
            parse_op_scope(
                "12:pids:/user.slice\n1:name=systemd:/system.slice/fleet-op-9.scope\n0::/\n"
            ),
            Some(9)
        );
        for bad in [
            "0::/system.slice/ssh.service",
            "0::/system.slice/fleet-op-.scope",
            "0::/system.slice/fleet-op-12x.scope",
            "0::/system.slice/fleet-op-12.service",
            "0::/user.slice/xfleet-op-3.scope",
            "garbage",
            "",
        ] {
            assert_eq!(parse_op_scope(bad), None, "{bad}");
        }
    }

    #[test]
    fn attribution_from_proc_fixture() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        for (pid, cg, comm) in [
            (200, "0::/system.slice/fleet-op-42.scope\n", "apt-get\n"),
            (
                300,
                "0::/user.slice/user-1000.slice/session-3.scope\n",
                "vim\n",
            ),
        ] {
            std::fs::create_dir_all(r.join(format!("proc/{pid}"))).unwrap();
            std::fs::write(r.join(format!("proc/{pid}/cgroup")), cg).unwrap();
            std::fs::write(r.join(format!("proc/{pid}/comm")), comm).unwrap();
        }
        let c = ctx(r, Rc::new(crate::FakeRunner::new()));
        let idle = Fixed {
            busy: false,
            current: None,
        };
        let running = Fixed {
            busy: true,
            current: Some((1002, 77)),
        };
        assert_eq!(
            attribute(&c, Some(200), &idle),
            ChangeSource::Fleet {
                op_tag: 505,
                audit_seq: 42
            }
        );
        assert_eq!(
            attribute(&c, Some(300), &idle),
            ChangeSource::External {
                process: Some("vim".into())
            }
        );
        assert_eq!(attribute(&c, Some(999), &idle), ChangeSource::Unknown);
        assert_eq!(
            attribute(&c, Some(100), &running),
            ChangeSource::Fleet {
                op_tag: 1002,
                audit_seq: 77
            }
        );
        assert_eq!(attribute(&c, Some(100), &idle), ChangeSource::Unknown);
        assert_eq!(
            attribute(&c, None, &idle),
            ChangeSource::External { process: None }
        );
        assert_eq!(attribute(&c, None, &running), ChangeSource::Unknown);
        assert_eq!(attribute(&c, None, &Unattributed), ChangeSource::Unknown);
    }
}
