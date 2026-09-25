//! Process table from `/proc/<pid>/{stat,status,io,cmdline}` under the
//! context root: `processes.list`, the per-minute top 10 (design §4.3),
//! and the guard that keeps `process.signal`/`renice` off init, kernel
//! threads and Fleet itself.

use super::collect::{Syscalls, read_into};
use super::parse::{self, PidStat, USER_HZ};
use crate::ctx::SysCtx;
use crate::handler::OpError;
use fleet_proto::args::Signal;
use fleet_proto::payload::{ProcessInfo, TopProcess};
use fleet_proto::{ErrorCode, F32, op::ProcessSort};
use std::collections::HashMap;

/// Processes read per scan (a fork bomb must not stall exec).
pub const MAX_SCAN: usize = 16_384;
/// `cmdline` bytes kept (wire type documents 4 KiB).
pub const MAX_CMDLINE: usize = 4096;
/// Top processes stored per minute and ranking.
pub const TOP_N: usize = 10;
/// comm of every Fleet process (gate, exec, bridge, revert).
pub const AGENT_COMM: &str = "fleet-agent";

/// One scanned process.
#[derive(Debug, Clone)]
pub struct ProcSample {
    pub stat: PidStat,
    pub uid: u32,
    pub rss_bytes: u64,
    /// Storage I/O (`None` when `io` wasn't read or isn't readable).
    pub io: Option<(u64, u64)>,
}

/// Previous counters of one process, for rates.
#[derive(Debug, Clone, Copy)]
struct Prev {
    cpu_ticks: u64,
    start_ticks: u64,
    io: Option<(u64, u64)>,
}

/// Numeric `/proc` entries.
pub fn pids(ctx: &SysCtx) -> Vec<u32> {
    let Some(rd) = ctx.path("/proc").and_then(|p| std::fs::read_dir(p).ok()) else {
        return Vec::new();
    };
    let mut v: Vec<u32> = rd
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .take(MAX_SCAN)
        .collect();
    v.sort_unstable();
    v
}

pub fn read_one(ctx: &SysCtx, pid: u32, with_io: bool, buf: &mut String) -> Option<ProcSample> {
    if !read_into(ctx, &format!("/proc/{pid}/stat"), buf) {
        return None;
    }
    let stat = parse::pid_stat(buf)?;
    if stat.pid != pid {
        return None;
    }
    let (uid, rss_bytes) = if read_into(ctx, &format!("/proc/{pid}/status"), buf) {
        parse::pid_status(buf)?
    } else {
        return None;
    };
    let io = if with_io && read_into(ctx, &format!("/proc/{pid}/io"), buf) {
        parse::pid_io(buf)
    } else {
        None
    };
    Some(ProcSample {
        stat,
        uid,
        rss_bytes,
        io,
    })
}

/// Rates of one process between two scans.
#[derive(Debug, Clone, Copy, Default)]
pub struct Rates {
    /// Percent of one core (top semantics: 4 busy threads = 400).
    pub cpu_pct: f32,
    pub read_bps: u64,
    pub write_bps: u64,
}

/// Remembers the last scan so the next one yields rates.
#[derive(Default)]
pub struct ProcTracker {
    prev: HashMap<u32, Prev>,
    prev_ms: Option<u64>,
    buf: String,
}

impl ProcTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Age of the last scan, if any.
    pub fn last_scan_ms(&self) -> Option<u64> {
        self.prev_ms
    }

    /// Scans every process; rates are against the previous scan (zero for
    /// processes new since then, or on the first scan).
    pub fn scan(&mut self, ctx: &SysCtx, now_ms: u64, with_io: bool) -> Vec<(ProcSample, Rates)> {
        let dt_s = self
            .prev_ms
            .map(|p| now_ms.saturating_sub(p) as f64 / 1000.0)
            .filter(|d| *d > 0.0);
        let mut next = HashMap::with_capacity(self.prev.len());
        let mut out = Vec::with_capacity(self.prev.len());
        for pid in pids(ctx) {
            let Some(s) = read_one(ctx, pid, with_io, &mut self.buf) else {
                continue;
            };
            let mut r = Rates::default();
            // Same pid, same start time: the same process.
            if let (Some(p), Some(dt)) = (
                self.prev
                    .get(&pid)
                    .filter(|p| p.start_ticks == s.stat.start_ticks),
                dt_s,
            ) {
                let ticks = s.stat.cpu_ticks.saturating_sub(p.cpu_ticks);
                r.cpu_pct = (ticks as f64 / USER_HZ as f64 / dt * 100.0) as f32;
                if let (Some((r0, w0)), Some((r1, w1))) = (p.io, s.io) {
                    r.read_bps = (r1.saturating_sub(r0) as f64 / dt) as u64;
                    r.write_bps = (w1.saturating_sub(w0) as f64 / dt) as u64;
                }
            }
            next.insert(
                pid,
                Prev {
                    cpu_ticks: s.stat.cpu_ticks,
                    start_ticks: s.stat.start_ticks,
                    io: s.io,
                },
            );
            out.push((s, r));
        }
        self.prev = next;
        self.prev_ms = Some(now_ms);
        out
    }
}

fn top(sample: &(ProcSample, Rates)) -> TopProcess {
    TopProcess {
        pid: sample.0.stat.pid,
        name: sample.0.stat.comm.clone(),
        cpu_pct: F32(sample.1.cpu_pct),
        rss_bytes: sample.0.rss_bytes,
    }
}

/// Top [`TOP_N`] by CPU and by memory (kernel threads excluded; idle
/// processes don't make the CPU list).
pub fn top_n(scan: &[(ProcSample, Rates)]) -> (Vec<TopProcess>, Vec<TopProcess>) {
    let mut user: Vec<&(ProcSample, Rates)> = scan
        .iter()
        .filter(|(s, _)| !s.stat.is_kernel_thread())
        .collect();
    user.sort_by(|a, b| b.1.cpu_pct.total_cmp(&a.1.cpu_pct));
    let by_cpu = user
        .iter()
        .filter(|s| s.1.cpu_pct > 0.0)
        .take(TOP_N)
        .map(|s| top(s))
        .collect();
    user.sort_by_key(|s| std::cmp::Reverse(s.0.rss_bytes));
    let by_mem = user.iter().take(TOP_N).map(|s| top(s)).collect();
    (by_cpu, by_mem)
}

/// `processes.list`: sorted, cut to `limit`, with user names, cmdlines and
/// start times filled in for the returned rows only.
pub fn list(
    ctx: &SysCtx,
    scan: Vec<(ProcSample, Rates)>,
    sort: ProcessSort,
    limit: usize,
) -> (u32, Vec<ProcessInfo>) {
    let total = u32::try_from(scan.len()).unwrap_or(u32::MAX);
    let mut scan = scan;
    match sort {
        ProcessSort::Cpu => scan.sort_by(|a, b| b.1.cpu_pct.total_cmp(&a.1.cpu_pct)),
        ProcessSort::Memory => scan.sort_by_key(|(s, _)| std::cmp::Reverse(s.rss_bytes)),
        ProcessSort::Io => {
            scan.sort_by_key(|(_, r)| std::cmp::Reverse(r.read_bps.saturating_add(r.write_bps)))
        }
        ProcessSort::Pid => scan.sort_by_key(|(s, _)| s.stat.pid),
    }
    scan.truncate(limit);
    let users: HashMap<u32, String> = ctx
        .procfs
        .read("/etc/passwd")
        .map(|t| crate::users::parse::uid_names(&t))
        .unwrap_or_default();
    let btime_ms = ctx
        .procfs
        .read("/proc/stat")
        .and_then(|t| {
            let mut s = parse::ProcStat::default();
            parse::proc_stat(&t, &mut s);
            s.btime_s
        })
        .map_or(0, |b| b.saturating_mul(1000));
    let rows = scan
        .into_iter()
        .map(|(s, r)| {
            let pid = s.stat.pid;
            let cmdline = ctx
                .path(&format!("/proc/{pid}/cmdline"))
                .and_then(|p| std::fs::read(p).ok())
                .map(|b| parse::cmdline(&b, MAX_CMDLINE))
                .unwrap_or_default();
            ProcessInfo {
                pid,
                ppid: s.stat.ppid,
                user: users
                    .get(&s.uid)
                    .cloned()
                    .unwrap_or_else(|| s.uid.to_string()),
                name: s.stat.comm,
                cmdline,
                state: s.stat.state,
                nice: s.stat.nice,
                threads: s.stat.threads,
                cpu_pct: F32(r.cpu_pct),
                rss_bytes: s.rss_bytes,
                read_bps: r.read_bps,
                write_bps: r.write_bps,
                start_ms: btime_ms
                    .saturating_add(s.stat.start_ticks.saturating_mul(1000) / USER_HZ),
            }
        })
        .collect();
    (total, rows)
}

/// Whether `pid` may be signalled or reniced: it exists (`NotFound`
/// otherwise), and it isn't init, a kernel thread, exec itself or another
/// Fleet process (`InvalidArgument`). Checked in `validate` and again in
/// `handle`; a pid reused between the two is the remaining (tiny) race.
pub fn check_target(ctx: &SysCtx, self_pid: u32, pid: u32) -> Result<PidStat, ErrorCode> {
    if pid <= 1 || pid == self_pid {
        return Err(ErrorCode::InvalidArgument);
    }
    let mut buf = String::new();
    if !read_into(ctx, &format!("/proc/{pid}/stat"), &mut buf) {
        return Err(ErrorCode::NotFound);
    }
    let stat = parse::pid_stat(&buf).ok_or(ErrorCode::NotFound)?;
    if stat.pid != pid {
        return Err(ErrorCode::NotFound);
    }
    if stat.is_kernel_thread() || stat.comm == AGENT_COMM {
        return Err(ErrorCode::InvalidArgument);
    }
    // Same executable as exec (catches a renamed comm).
    let exe = |p: &str| ctx.path(p).and_then(|p| std::fs::read_link(p).ok());
    if let Some(own) = exe("/proc/self/exe")
        && exe(&format!("/proc/{pid}/exe")).as_ref() == Some(&own)
    {
        return Err(ErrorCode::InvalidArgument);
    }
    Ok(stat)
}

/// Units whose processes `process.signal` never stops or terminates: the
/// only way in (sshd), and what the system can't run without. `fleet-*`
/// services are matched by [`protected_unit`].
pub const PROTECTED_SIGNAL_UNITS: &[&str] = &[
    "ssh.service",
    "sshd.service",
    "ssh.socket",
    "systemd-journald.service",
    "dbus.service",
    "dbus-broker.service",
    "systemd-logind.service",
];

/// One cgroup path component (`ssh.service`, `ssh@3-1.2.3.4:22.service`).
pub fn protected_unit(unit: &str) -> bool {
    PROTECTED_SIGNAL_UNITS.contains(&unit)
        || (unit.starts_with("ssh@") && unit.ends_with(".service"))
        || (unit.starts_with("fleet-") && unit.ends_with(".service"))
}

/// `/proc/<pid>/cgroup` (v2 `0::/system.slice/ssh.service`, or v1 hybrid
/// lines): any component of any hierarchy's path naming a protected unit.
pub fn cgroup_protected(text: &str) -> bool {
    text.lines()
        .filter_map(|l| l.splitn(3, ':').nth(2))
        .flat_map(|path| path.split('/'))
        .any(protected_unit)
}

/// Only `Cont` is harmless to a protected process: every other signal the
/// enum carries stops it, ends it, or (`Usr1`/`Usr2`, `Hup` where
/// unhandled) may terminate it by default action.
fn signal_harmless(s: Signal) -> bool {
    matches!(s, Signal::Cont)
}

/// [`check_target`] plus the protected-unit guard for `signal`. The
/// cgroup must be readable (fail closed; unreadable means gone).
pub fn check_signal_target(
    ctx: &SysCtx,
    self_pid: u32,
    pid: u32,
    signal: Signal,
) -> Result<PidStat, OpError> {
    let stat = check_target(ctx, self_pid, pid)?;
    if !signal_harmless(signal) {
        let mut buf = String::new();
        if !read_into(ctx, &format!("/proc/{pid}/cgroup"), &mut buf) {
            return Err(OpError::new(ErrorCode::NotFound));
        }
        if cgroup_protected(&buf) {
            return Err(OpError::new(ErrorCode::PolicyDenied).with_detail("protected unit"));
        }
    }
    Ok(stat)
}

/// Checks and signals `pid` without racing PID reuse. On Linux against
/// the real `/proc` (root `/`): `pidfd_open`, then re-check the target
/// through `/proc` and require the start time seen by the first check, then
/// `pidfd_send_signal` — the fd names the process that passed the second
/// check or one already dead. Elsewhere (tests with a fixture root, macOS
/// dev builds) the second check runs and `sys.kill` delivers.
pub fn send_signal(
    ctx: &SysCtx,
    sys: &dyn Syscalls,
    pid: u32,
    signal: Signal,
) -> Result<(), OpError> {
    let self_pid = sys.self_pid();
    let first = check_signal_target(ctx, self_pid, pid, signal)?;
    let recheck = || -> Result<(), OpError> {
        let again = check_signal_target(ctx, self_pid, pid, signal)?;
        if again.start_ticks != first.start_ticks {
            return Err(OpError::new(ErrorCode::NotFound));
        }
        Ok(())
    };
    #[cfg(target_os = "linux")]
    if ctx.root() == std::path::Path::new("/") {
        return pidfd_signal(pid, signal, recheck);
    }
    recheck()?;
    sys.kill(pid, signal).map_err(|e| signal_io(&e))
}

fn signal_io(e: &std::io::Error) -> OpError {
    // ESRCH: the process exited in between.
    if e.raw_os_error() == Some(3) {
        OpError::new(ErrorCode::NotFound)
    } else {
        OpError::internal(e)
    }
}

#[cfg(target_os = "linux")]
fn pidfd_signal(
    pid: u32,
    signal: Signal,
    recheck: impl FnOnce() -> Result<(), OpError>,
) -> Result<(), OpError> {
    use rustix::process::{self as rp, Signal as R};
    let raw = i32::try_from(pid)
        .ok()
        .and_then(rp::Pid::from_raw)
        .ok_or_else(|| OpError::new(ErrorCode::InvalidArgument))?;
    let fd = rp::pidfd_open(raw, rp::PidfdFlags::empty())
        .map_err(|e| signal_io(&std::io::Error::from(e)))?;
    recheck()?;
    let sig = match signal {
        Signal::Hup => R::HUP,
        Signal::Int => R::INT,
        Signal::Quit => R::QUIT,
        Signal::Kill => R::KILL,
        Signal::Usr1 => R::USR1,
        Signal::Usr2 => R::USR2,
        Signal::Term => R::TERM,
        Signal::Cont => R::CONT,
        Signal::Stop => R::STOP,
    };
    rp::pidfd_send_signal(&fd, sig).map_err(|e| signal_io(&std::io::Error::from(e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::collect::tests::{ctx_at, fixture_root, temp_root};

    #[test]
    fn scan_rates_and_top() {
        let d = temp_root();
        let ctx = ctx_at(d.path());
        let mut t = ProcTracker::new();
        let s0 = t.scan(&ctx, 0, true);
        assert_eq!(s0.len(), 2);
        assert!(s0.iter().all(|(_, r)| r.cpu_pct == 0.0));
        // 200 more ticks (2 s of CPU) and 1 MiB written over 4 s.
        let stat = std::fs::read_to_string(d.path().join("proc/4242/stat"))
            .unwrap()
            .replace(" 1500 500 ", " 1600 600 ");
        std::fs::write(d.path().join("proc/4242/stat"), stat).unwrap();
        let io = std::fs::read_to_string(d.path().join("proc/4242/io"))
            .unwrap()
            .replace("write_bytes: 8192", "write_bytes: 4202496");
        std::fs::write(d.path().join("proc/4242/io"), io).unwrap();
        let s1 = t.scan(&ctx, 4000, true);
        let (_, r) = s1.iter().find(|(s, _)| s.stat.pid == 4242).unwrap();
        assert_eq!(r.cpu_pct, 50.0);
        assert_eq!(r.write_bps, 1 << 20);
        let (by_cpu, by_mem) = top_n(&s1);
        assert_eq!(by_cpu.len(), 1); // the kernel thread is excluded
        assert_eq!(by_cpu[0].pid, 4242);
        assert_eq!(by_mem[0].rss_bytes, 10_240 * 1024);
    }

    #[test]
    fn list_fills_rows() {
        let ctx = ctx_at(&fixture_root());
        let scan = ProcTracker::new().scan(&ctx, 0, true);
        let (total, rows) = list(&ctx, scan, ProcessSort::Pid, 1);
        assert_eq!(total, 2);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pid, 7);
        let scan = ProcTracker::new().scan(&ctx, 0, true);
        let (_, rows) = list(&ctx, scan, ProcessSort::Memory, 10);
        let r = &rows[0];
        assert_eq!((r.pid, r.user.as_str()), (4242, "www-data"));
        assert_eq!(r.cmdline, "nginx: worker process -g daemon off;");
        assert_eq!(r.start_ms, 1_700_000_000_000 + 1_234_560);
        assert_eq!(r.nice, -5);
    }

    #[test]
    fn target_guard() {
        let d = temp_root();
        let ctx = ctx_at(d.path());
        assert!(check_target(&ctx, 99, 4242).is_ok());
        assert_eq!(check_target(&ctx, 99, 1), Err(ErrorCode::InvalidArgument));
        assert_eq!(
            check_target(&ctx, 4242, 4242),
            Err(ErrorCode::InvalidArgument)
        );
        assert_eq!(check_target(&ctx, 99, 7), Err(ErrorCode::InvalidArgument));
        assert_eq!(check_target(&ctx, 99, 5555), Err(ErrorCode::NotFound));
        // Same executable as exec.
        std::fs::create_dir_all(d.path().join("proc/self")).unwrap();
        std::os::unix::fs::symlink("/usr/bin/fleet-agent", d.path().join("proc/self/exe")).unwrap();
        std::os::unix::fs::symlink("/usr/bin/fleet-agent", d.path().join("proc/4242/exe")).unwrap();
        assert_eq!(
            check_target(&ctx, 99, 4242),
            Err(ErrorCode::InvalidArgument)
        );
        // Renamed to the agent's comm.
        let d2 = temp_root();
        let stat = std::fs::read_to_string(d2.path().join("proc/4242/stat"))
            .unwrap()
            .replace("(nginx: worker (x))", "(fleet-agent)");
        std::fs::write(d2.path().join("proc/4242/stat"), stat).unwrap();
        assert_eq!(
            check_target(&ctx_at(d2.path()), 99, 4242),
            Err(ErrorCode::InvalidArgument)
        );
    }

    #[test]
    fn cgroup_protection_table() {
        for (text, want) in [
            ("0::/system.slice/ssh.service\n", true),
            ("0::/system.slice/sshd.service\n", true),
            (
                "0::/system.slice/system-sshd.slice/ssh@3-10.0.0.1:22.service",
                true,
            ),
            ("0::/system.slice/fleet-agent.service", true),
            ("0::/system.slice/fleet-exec.service/sub", true),
            ("0::/system.slice/dbus.service", true),
            ("0::/system.slice/systemd-journald.service", true),
            (
                "12:pids:/\n1:name=systemd:/system.slice/systemd-logind.service\n0::/",
                true,
            ),
            ("0::/system.slice/nginx.service", false),
            ("0::/system.slice/fleet-op-7.scope", false),
            ("0::/user.slice/user-0.slice/session-1.scope", false),
            ("0::/system.slice/my-ssh.service", false),
            ("garbage", false),
        ] {
            assert_eq!(cgroup_protected(text), want, "{text}");
        }
    }
}
