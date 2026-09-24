//! One system snapshot per tick from `/proc`, `/sys` and `statvfs`, all
//! under the context root. Counters (CPU ticks, disk and network bytes)
//! become percentages and rates against the previous tick, so the first
//! tick after start carries gauges only.
//!
//! Buffers are reused across ticks: a steady-state tick allocates only the
//! device-name strings of changed layouts and the output vectors.

use super::parse::{self, CpuTimes, IoCounters, MemInfo, ProcStat};
use crate::ctx::SysCtx;
use fleet_proto::args::Signal;
use std::io::Read;
use std::path::PathBuf;

/// Kernel facilities that aren't files: `statvfs`, signals, priorities.
/// Injectable so ops are tested without touching real processes.
pub trait Syscalls {
    /// Usage of the filesystem mounted at `mount` (an absolute system
    /// path; implementations apply their own root).
    fn statvfs(&self, mount: &str) -> Option<FsStat>;
    fn kill(&self, pid: u32, signal: Signal) -> std::io::Result<()>;
    fn renice(&self, pid: u32, nice: i8) -> std::io::Result<()>;
    /// This process (exec) — never signalled.
    fn self_pid(&self) -> u32;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FsStat {
    pub total_bytes: u64,
    /// Available to unprivileged users (df's "Avail").
    pub avail_bytes: u64,
    pub used_bytes: u64,
    pub files: u64,
    pub files_free: u64,
}

/// The real kernel, through `rustix` (no first-party `unsafe`).
pub struct RealSys {
    root: PathBuf,
}

impl RealSys {
    /// `root` prefixes `statvfs` paths, like [`SysCtx::root`].
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

fn rustix_signal(s: Signal) -> rustix::process::Signal {
    use rustix::process::Signal as R;
    match s {
        Signal::Hup => R::HUP,
        Signal::Int => R::INT,
        Signal::Quit => R::QUIT,
        Signal::Kill => R::KILL,
        Signal::Usr1 => R::USR1,
        Signal::Usr2 => R::USR2,
        Signal::Term => R::TERM,
        Signal::Cont => R::CONT,
        Signal::Stop => R::STOP,
    }
}

fn rustix_pid(pid: u32) -> std::io::Result<rustix::process::Pid> {
    i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))
}

impl Syscalls for RealSys {
    fn statvfs(&self, mount: &str) -> Option<FsStat> {
        let p = crate::ctx::rooted(&self.root, mount)?;
        let s = rustix::fs::statvfs(&p).ok()?;
        let frsize = if s.f_frsize > 0 {
            s.f_frsize
        } else {
            s.f_bsize
        };
        let total = s.f_blocks.saturating_mul(frsize);
        let free = s.f_bfree.saturating_mul(frsize);
        Some(FsStat {
            total_bytes: total,
            avail_bytes: s.f_bavail.saturating_mul(frsize),
            used_bytes: total.saturating_sub(free),
            files: s.f_files,
            files_free: s.f_ffree,
        })
    }

    fn kill(&self, pid: u32, signal: Signal) -> std::io::Result<()> {
        rustix::process::kill_process(rustix_pid(pid)?, rustix_signal(signal))?;
        Ok(())
    }

    fn renice(&self, pid: u32, nice: i8) -> std::io::Result<()> {
        rustix::process::setpriority_process(Some(rustix_pid(pid)?), i32::from(nice))?;
        Ok(())
    }

    fn self_pid(&self) -> u32 {
        u32::try_from(rustix::process::getpid().as_raw_nonzero().get()).unwrap_or(0)
    }
}

/// CPU split in percent (0..=100) of the interval.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct CpuPct {
    pub user: f32,
    pub system: f32,
    pub iowait: f32,
    pub steal: f32,
    pub idle: f32,
}

impl CpuPct {
    /// Everything but idle and iowait.
    pub fn busy(&self) -> f32 {
        (self.user + self.system + self.steal).clamp(0.0, 100.0)
    }

    fn between(a: &CpuTimes, b: &CpuTimes) -> Option<Self> {
        let total = b.total().checked_sub(a.total())?;
        if total == 0 {
            return None;
        }
        let pct = |x: u64, y: u64| (y.saturating_sub(x) as f64 * 100.0 / total as f64) as f32;
        Some(Self {
            user: pct(a.user, b.user),
            system: pct(a.system, b.system),
            iowait: pct(a.iowait, b.iowait),
            steal: pct(a.steal, b.steal),
            idle: pct(a.idle, b.idle),
        })
    }
}

/// Rates of one device or interface over the last interval.
#[derive(Debug, Clone, PartialEq)]
pub struct IoRate {
    pub name: String,
    /// Read / received bytes per second.
    pub rx_bps: f32,
    /// Written / sent bytes per second.
    pub tx_bps: f32,
    /// Cumulative bytes both ways (busiest-first ordering).
    pub total: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FsUsage {
    pub mount: String,
    pub stat: FsStat,
}

impl FsUsage {
    /// Used space in permille of what's usable (df semantics: root-reserved
    /// blocks count as unavailable).
    pub fn used_permille(&self) -> u64 {
        let usable = self.stat.used_bytes + self.stat.avail_bytes;
        if usable == 0 {
            return 0;
        }
        (u128::from(self.stat.used_bytes) * 1000 / u128::from(usable)) as u64
    }

    pub fn inode_permille(&self) -> u64 {
        if self.stat.files == 0 {
            return 0;
        }
        let used = self.stat.files.saturating_sub(self.stat.files_free);
        (u128::from(used) * 1000 / u128::from(self.stat.files)) as u64
    }
}

/// Everything sampled in one tick. Absent sources are `None`/empty.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Snapshot {
    pub time_ms: u64,
    pub cpu: Option<CpuPct>,
    /// Per core, by core number.
    pub cores: Vec<CpuPct>,
    /// Online cores (from `/proc/stat`), for per-core load.
    pub ncpu: usize,
    pub mem: Option<MemInfo>,
    pub load: Option<[f32; 3]>,
    /// Whole disks only, busiest first.
    pub disks: Vec<IoRate>,
    /// Interfaces except `lo`, busiest first.
    pub nets: Vec<IoRate>,
    /// Largest first.
    pub fs: Vec<FsUsage>,
    /// `chip/label` → °C.
    pub temps: Vec<(String, f32)>,
}

impl Snapshot {
    /// 5-minute load per core × 100 (the `Load` alert unit).
    pub fn load_per_core_x100(&self) -> Option<u64> {
        let l = self.load?;
        let n = self.ncpu.max(1) as f32;
        Some((l[1] / n * 100.0).round().max(0.0) as u64)
    }
}

/// Reads `abs` under the root into `buf` (cleared first), size-capped.
pub(crate) fn read_into(ctx: &SysCtx, abs: &str, buf: &mut String) -> bool {
    buf.clear();
    let Some(p) = ctx.path(abs) else { return false };
    let Ok(f) = std::fs::File::open(p) else {
        return false;
    };
    f.take(crate::procfs::MAX_READ).read_to_string(buf).is_ok()
}

/// Largest temperature list kept per tick.
const MAX_TEMPS: usize = 32;
/// Longest device, interface, mount or sensor name kept.
pub const MAX_NAME: usize = 48;

fn clip_name(s: &str) -> String {
    let mut out: String = s
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME)
        .collect();
    if out.is_empty() {
        out.push('?');
    }
    out
}

/// Holds previous counters between ticks.
#[derive(Default)]
pub struct Collector {
    buf: String,
    stat: ProcStat,
    prev_stat: ProcStat,
    io: Vec<IoCounters>,
    prev_disks: Vec<IoCounters>,
    prev_nets: Vec<IoCounters>,
    prev_ms: Option<u64>,
    /// `/sys/block` names (whole disks), refreshed with the mount list.
    whole_disks: Option<Vec<String>>,
    mounts: Vec<parse::Mount>,
    mounts_read_ms: Option<u64>,
}

/// Mounts and `/sys/block` change rarely; re-read at most this often.
const MOUNTS_EVERY_MS: u64 = 30_000;

impl Collector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn collect(&mut self, ctx: &SysCtx, sys: &dyn Syscalls, now_ms: u64) -> Snapshot {
        let mut s = Snapshot {
            time_ms: now_ms,
            ..Snapshot::default()
        };
        let dt_s = self
            .prev_ms
            .map(|p| now_ms.saturating_sub(p) as f32 / 1000.0)
            .filter(|d| *d > 0.0);

        // CPU.
        if read_into(ctx, "/proc/stat", &mut self.buf) {
            parse::proc_stat(&self.buf, &mut self.stat);
            s.ncpu = self.stat.cores.len();
            if let (Some(a), Some(b)) = (&self.prev_stat.total, &self.stat.total) {
                s.cpu = CpuPct::between(a, b);
            }
            for (n, b) in &self.stat.cores {
                let prev = self.prev_stat.cores.iter().find(|(m, _)| m == n);
                if let Some(p) = prev.and_then(|(_, a)| CpuPct::between(a, b)) {
                    s.cores.push(p);
                }
            }
            // Keep per-core only if every core has a value (hotplug skips a tick).
            if s.cores.len() != self.stat.cores.len() {
                s.cores.clear();
            }
            std::mem::swap(&mut self.stat, &mut self.prev_stat);
        }

        if read_into(ctx, "/proc/meminfo", &mut self.buf) {
            s.mem = parse::meminfo(&self.buf);
        }
        if read_into(ctx, "/proc/loadavg", &mut self.buf) {
            s.load = parse::loadavg(&self.buf);
        }

        self.refresh_mounts(ctx, now_ms);

        // Disks: whole disks only (partitions would double count).
        if read_into(ctx, "/proc/diskstats", &mut self.buf) {
            parse::diskstats(&self.buf, &mut self.io);
            let whole = self.whole_disks.as_deref();
            // `/sys/block` lists loop and ram devices too.
            self.io.retain(|d| {
                whole.is_none_or(|w| w.contains(&d.name))
                    && !d.name.starts_with("loop")
                    && !d.name.starts_with("ram")
            });
            s.disks = rates(&self.io, &self.prev_disks, dt_s);
            std::mem::swap(&mut self.io, &mut self.prev_disks);
        }

        if read_into(ctx, "/proc/net/dev", &mut self.buf) {
            parse::net_dev(&self.buf, &mut self.io);
            self.io.retain(|n| n.name != "lo");
            s.nets = rates(&self.io, &self.prev_nets, dt_s);
            std::mem::swap(&mut self.io, &mut self.prev_nets);
        }

        for m in &self.mounts {
            if let Some(stat) = sys.statvfs(&m.path)
                && stat.total_bytes > 0
            {
                s.fs.push(FsUsage {
                    mount: clip_name(&m.path),
                    stat,
                });
            }
        }
        s.fs.sort_by_key(|f| std::cmp::Reverse(f.stat.total_bytes));

        self.temps(ctx, &mut s.temps);
        self.prev_ms = Some(now_ms);
        s
    }

    fn refresh_mounts(&mut self, ctx: &SysCtx, now_ms: u64) {
        if self
            .mounts_read_ms
            .is_some_and(|t| now_ms.saturating_sub(t) < MOUNTS_EVERY_MS)
        {
            return;
        }
        self.mounts_read_ms = Some(now_ms);
        self.mounts = if read_into(ctx, "/proc/self/mounts", &mut self.buf) {
            parse::mounts(&self.buf)
        } else {
            Vec::new()
        };
        self.whole_disks = ctx
            .path("/sys/block")
            .and_then(|p| std::fs::read_dir(p).ok())
            .map(|rd| {
                rd.filter_map(|e| e.ok()?.file_name().into_string().ok())
                    .collect()
            });
    }

    fn temps(&mut self, ctx: &SysCtx, out: &mut Vec<(String, f32)>) {
        let Some(rd) = ctx
            .path("/sys/class/hwmon")
            .and_then(|p| std::fs::read_dir(p).ok())
        else {
            return;
        };
        let mut chips: Vec<String> = rd
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| n.starts_with("hwmon") && !n.contains(['/', '.']))
            .collect();
        chips.sort();
        for chip in chips {
            let base = format!("/sys/class/hwmon/{chip}");
            let chip_name = if read_into(ctx, &format!("{base}/name"), &mut self.buf) {
                clip_name(self.buf.trim())
            } else {
                chip.clone()
            };
            for i in 1..=16 {
                if out.len() >= MAX_TEMPS {
                    return;
                }
                if !read_into(ctx, &format!("{base}/temp{i}_input"), &mut self.buf) {
                    continue;
                }
                let Ok(milli) = self.buf.trim().parse::<i64>() else {
                    continue;
                };
                let label = if read_into(ctx, &format!("{base}/temp{i}_label"), &mut self.buf) {
                    clip_name(self.buf.trim())
                } else {
                    format!("temp{i}")
                };
                out.push((format!("{chip_name}/{label}"), milli as f32 / 1000.0));
            }
        }
    }
}

/// Busiest first (cumulative bytes, which is stable tick to tick).
fn rates(cur: &[IoCounters], prev: &[IoCounters], dt_s: Option<f32>) -> Vec<IoRate> {
    let mut out: Vec<IoRate> = cur
        .iter()
        .filter_map(|c| {
            let p = prev.iter().find(|p| p.name == c.name)?;
            let dt = dt_s?;
            // A counter going backwards (device re-added) skips one tick.
            let rx = c.rx.checked_sub(p.rx)?;
            let tx = c.tx.checked_sub(p.tx)?;
            Some(IoRate {
                name: clip_name(&c.name),
                rx_bps: rx as f32 / dt,
                tx_bps: tx as f32 / dt,
                total: c.rx.saturating_add(c.tx),
            })
        })
        .collect();
    out.sort_by(|a, b| b.total.cmp(&a.total).then_with(|| a.name.cmp(&b.name)));
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{FakeRunner, ManualClock};
    use std::cell::RefCell;
    use std::path::Path;
    use std::rc::Rc;

    pub(crate) fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/root")
    }

    /// Copies the fixture root into a temp dir (tests then edit counters).
    pub(crate) fn temp_root() -> tempfile::TempDir {
        fn copy(from: &Path, to: &Path) {
            std::fs::create_dir_all(to).unwrap();
            for e in std::fs::read_dir(from).unwrap() {
                let e = e.unwrap();
                let t = to.join(e.file_name());
                if e.file_type().unwrap().is_dir() {
                    copy(&e.path(), &t);
                } else {
                    std::fs::copy(e.path(), t).unwrap();
                }
            }
        }
        let d = tempfile::tempdir().unwrap();
        copy(&fixture_root(), d.path());
        d
    }

    pub(crate) fn ctx_at(root: &Path) -> SysCtx {
        SysCtx::new(
            root,
            Rc::new(FakeRunner::new()),
            Rc::new(ManualClock::new(1_000_000)),
        )
    }

    /// Canned kernel: statvfs per mount, records signals.
    #[derive(Default)]
    pub(crate) struct FakeSys {
        pub fs: Vec<(String, FsStat)>,
        pub calls: RefCell<Vec<String>>,
        pub pid: u32,
    }

    impl Syscalls for FakeSys {
        fn statvfs(&self, mount: &str) -> Option<FsStat> {
            self.fs.iter().find(|(m, _)| m == mount).map(|(_, s)| *s)
        }
        fn kill(&self, pid: u32, signal: Signal) -> std::io::Result<()> {
            self.calls
                .borrow_mut()
                .push(format!("kill {pid} {}", signal.number()));
            Ok(())
        }
        fn renice(&self, pid: u32, nice: i8) -> std::io::Result<()> {
            self.calls.borrow_mut().push(format!("renice {pid} {nice}"));
            Ok(())
        }
        fn self_pid(&self) -> u32 {
            self.pid
        }
    }

    pub(crate) fn fake_sys() -> FakeSys {
        let gib = 1u64 << 30;
        FakeSys {
            fs: vec![
                (
                    "/".into(),
                    FsStat {
                        total_bytes: 100 * gib,
                        avail_bytes: 5 * gib,
                        used_bytes: 90 * gib,
                        files: 1000,
                        files_free: 100,
                    },
                ),
                (
                    "/boot/efi".into(),
                    FsStat {
                        total_bytes: gib / 2,
                        avail_bytes: gib / 4,
                        used_bytes: gib / 4,
                        files: 0,
                        files_free: 0,
                    },
                ),
            ],
            calls: RefCell::default(),
            pid: 99,
        }
    }

    /// Adds `add` ticks to every field of every cpu line.
    pub(crate) fn bump_stat(root: &Path, user: u64, idle: u64, steal: u64) {
        let p = root.join("proc/stat");
        let text = std::fs::read_to_string(&p).unwrap();
        let out: Vec<String> = text
            .lines()
            .map(|l| {
                let mut f: Vec<String> = l.split_ascii_whitespace().map(str::to_owned).collect();
                if f.first().is_some_and(|k| k.starts_with("cpu")) {
                    let mul = if f[0] == "cpu" { 4 } else { 1 };
                    let add = |f: &mut Vec<String>, i: usize, v: u64| {
                        let n: u64 = f[i].parse().unwrap();
                        f[i] = (n + v * mul).to_string();
                    };
                    add(&mut f, 1, user);
                    add(&mut f, 4, idle);
                    add(&mut f, 8, steal);
                }
                f.join(" ")
            })
            .collect();
        std::fs::write(p, out.join("\n")).unwrap();
    }

    #[test]
    fn two_ticks_give_rates() {
        let d = temp_root();
        let ctx = ctx_at(d.path());
        let sys = fake_sys();
        let mut c = Collector::new();
        let s0 = c.collect(&ctx, &sys, 10_000);
        assert!(s0.cpu.is_none() && s0.disks.is_empty() && s0.nets.is_empty());
        assert_eq!(s0.ncpu, 4);
        assert_eq!(s0.mem.unwrap().total, 8_148_000 * 1024);
        assert_eq!(s0.load, Some([0.52, 1.25, 0.98]));
        assert_eq!(s0.load_per_core_x100(), Some(31));
        let mounts: Vec<&str> = s0.fs.iter().map(|f| f.mount.as_str()).collect();
        assert_eq!(mounts, ["/", "/boot/efi"]); // no statvfs for /srv/game data
        assert_eq!(s0.fs[0].used_permille(), 947);
        assert_eq!(s0.fs[0].inode_permille(), 900);
        assert_eq!(
            s0.temps,
            [
                ("coretemp/Package id 0".to_owned(), 45.0),
                ("coretemp/temp2".to_owned(), 43.5),
                ("nvme/temp1".to_owned(), 38.85)
            ]
        );

        bump_stat(d.path(), 60, 30, 10);
        let dev = std::fs::read_to_string(d.path().join("proc/net/dev"))
            .unwrap()
            .replace("987654321", "987664321");
        std::fs::write(d.path().join("proc/net/dev"), dev).unwrap();
        let s1 = c.collect(&ctx, &sys, 12_000);
        let cpu = s1.cpu.unwrap();
        assert!((cpu.user - 60.0).abs() < 0.01, "{cpu:?}");
        assert!((cpu.steal - 10.0).abs() < 0.01);
        assert!((cpu.busy() - 70.0).abs() < 0.01);
        assert_eq!(s1.cores.len(), 4);
        let names: Vec<&str> = s1.disks.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["sda", "nvme0n1"]); // whole disks, busiest first
        let eth0 = s1.nets.iter().find(|n| n.name == "eth0").unwrap();
        assert_eq!(eth0.rx_bps, 5000.0); // 10000 bytes over 2 s
        assert!(s1.nets.iter().all(|n| n.name != "lo"));
    }

    #[test]
    fn empty_root_is_empty_snapshot() {
        let d = tempfile::tempdir().unwrap();
        let mut c = Collector::new();
        let s = c.collect(&ctx_at(d.path()), &FakeSys::default(), 1);
        assert_eq!(
            s,
            Snapshot {
                time_ms: 1,
                ..Snapshot::default()
            }
        );
    }
}
