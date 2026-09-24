//! Pure parsers for `/proc` and `/sys` text. No I/O: every function takes
//! the file's contents, tolerates malformed lines (skips them) and never
//! panics on untrusted input.

/// Linux `USER_HZ` (clock ticks per second in `/proc`); 100 on every
/// architecture Fleet supports.
pub const USER_HZ: u64 = 100;

/// `PF_KTHREAD` in `/proc/<pid>/stat` flags.
pub const PF_KTHREAD: u64 = 0x0020_0000;

/// Cumulative CPU ticks of one `cpu` line of `/proc/stat`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuTimes {
    /// user + nice (guest time is already included in user).
    pub user: u64,
    /// system + irq + softirq.
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub steal: u64,
}

impl CpuTimes {
    pub fn total(&self) -> u64 {
        self.user
            .saturating_add(self.system)
            .saturating_add(self.idle)
            .saturating_add(self.iowait)
            .saturating_add(self.steal)
    }
}

/// `/proc/stat`: the aggregate line, per-core lines (index = core number,
/// missing cores are absent) and `btime`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcStat {
    pub total: Option<CpuTimes>,
    pub cores: Vec<(u32, CpuTimes)>,
    pub btime_s: Option<u64>,
}

fn cpu_times(fields: &mut std::str::SplitAsciiWhitespace<'_>) -> Option<CpuTimes> {
    let mut v = [0u64; 8];
    let mut n = 0;
    for (slot, f) in v.iter_mut().zip(fields) {
        *slot = f.parse().ok()?;
        n += 1;
    }
    if n < 4 {
        return None;
    }
    let [user, nice, system, idle, iowait, irq, softirq, steal] = v;
    Some(CpuTimes {
        user: user.saturating_add(nice),
        system: system.saturating_add(irq).saturating_add(softirq),
        idle,
        iowait,
        steal,
    })
}

pub fn proc_stat(text: &str, out: &mut ProcStat) {
    out.total = None;
    out.cores.clear();
    out.btime_s = None;
    for line in text.lines() {
        let mut f = line.split_ascii_whitespace();
        let Some(key) = f.next() else { continue };
        if key == "cpu" {
            out.total = cpu_times(&mut f);
        } else if let Some(n) = key.strip_prefix("cpu") {
            if let (Ok(n), Some(t)) = (n.parse::<u32>(), cpu_times(&mut f)) {
                out.cores.push((n, t));
            }
        } else if key == "btime" {
            out.btime_s = f.next().and_then(|v| v.parse().ok());
        }
    }
}

/// `/proc/meminfo` fields Fleet uses, in bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemInfo {
    pub total: u64,
    pub available: u64,
    /// Buffers + Cached.
    pub cached: u64,
    pub swap_total: u64,
    pub swap_free: u64,
}

impl MemInfo {
    pub fn used(&self) -> u64 {
        self.total.saturating_sub(self.available)
    }

    pub fn swap_used(&self) -> u64 {
        self.swap_total.saturating_sub(self.swap_free)
    }
}

pub fn meminfo(text: &str) -> Option<MemInfo> {
    let mut m = MemInfo::default();
    let (mut have_total, mut have_avail) = (false, false);
    let (mut free, mut buffers, mut cached) = (0, 0, 0);
    for line in text.lines() {
        let mut f = line.split_ascii_whitespace();
        let (Some(k), Some(v)) = (f.next(), f.next()) else {
            continue;
        };
        let Ok(kib) = v.parse::<u64>() else { continue };
        let b = kib.saturating_mul(1024);
        match k {
            "MemTotal:" => {
                m.total = b;
                have_total = true;
            }
            "MemAvailable:" => {
                m.available = b;
                have_avail = true;
            }
            "MemFree:" => free = b,
            "Buffers:" => buffers = b,
            "Cached:" => cached = b,
            "SwapTotal:" => m.swap_total = b,
            "SwapFree:" => m.swap_free = b,
            _ => {}
        }
    }
    if !have_total {
        return None;
    }
    m.cached = buffers.saturating_add(cached);
    if !have_avail {
        // Kernels before 3.14; not on supported distributions, but cheap.
        m.available = free.saturating_add(m.cached).min(m.total);
    }
    Some(m)
}

/// `/proc/loadavg`: 1-, 5- and 15-minute load averages.
pub fn loadavg(text: &str) -> Option<[f32; 3]> {
    let mut f = text.split_ascii_whitespace();
    let mut out = [0f32; 3];
    for slot in &mut out {
        let v: f32 = f.next()?.parse().ok()?;
        if !v.is_finite() || v < 0.0 {
            return None;
        }
        *slot = v;
    }
    Some(out)
}

/// Cumulative counters of one block device or interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoCounters {
    pub name: String,
    /// Bytes read / received.
    pub rx: u64,
    /// Bytes written / sent.
    pub tx: u64,
}

/// `/proc/diskstats` (sectors are always 512 bytes there).
pub fn diskstats(text: &str, out: &mut Vec<IoCounters>) {
    out.clear();
    for line in text.lines() {
        let f: Vec<&str> = line.split_ascii_whitespace().take(10).collect();
        if f.len() < 10 {
            continue;
        }
        let (Ok(rd), Ok(wr)) = (f[5].parse::<u64>(), f[9].parse::<u64>()) else {
            continue;
        };
        out.push(IoCounters {
            name: f[2].to_owned(),
            rx: rd.saturating_mul(512),
            tx: wr.saturating_mul(512),
        });
    }
}

/// `/proc/net/dev`.
pub fn net_dev(text: &str, out: &mut Vec<IoCounters>) {
    out.clear();
    for line in text.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() || name.contains(' ') {
            continue;
        }
        let mut f = rest.split_ascii_whitespace();
        let rx = f.next().and_then(|v| v.parse::<u64>().ok());
        let tx = f.nth(7).and_then(|v| v.parse::<u64>().ok());
        if let (Some(rx), Some(tx)) = (rx, tx) {
            out.push(IoCounters {
                name: name.to_owned(),
                rx,
                tx,
            });
        }
    }
}

/// One line of `/proc/self/mounts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub device: String,
    /// Octal escapes (`\040`) decoded.
    pub path: String,
    pub fstype: String,
}

/// Filesystems that hold data (not pseudo, not overlay/container layers).
fn real_fs(m: &Mount) -> bool {
    const TYPES: [&str; 11] = [
        "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "vfat", "exfat", "jfs", "reiserfs",
    ];
    TYPES.contains(&m.fstype.as_str())
}

fn unescape_mount(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && let Some(oct) = b.get(i + 1..i + 4)
            && oct.iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = oct.iter().fold(0u16, |a, c| a * 8 + u16::from(c - b'0'));
            out.push(u8::try_from(v).unwrap_or(b'?'));
            i += 4;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Real filesystems from `/proc/self/mounts`, first mount of each device
/// only (bind mounts and btrfs subvolumes would double count).
pub fn mounts(text: &str) -> Vec<Mount> {
    let mut out: Vec<Mount> = Vec::new();
    for line in text.lines() {
        let mut f = line.split_ascii_whitespace();
        let (Some(dev), Some(path), Some(fstype)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        let m = Mount {
            device: unescape_mount(dev),
            path: unescape_mount(path),
            fstype: fstype.to_owned(),
        };
        if real_fs(&m) && m.path.starts_with('/') && !out.iter().any(|o| o.device == m.device) {
            out.push(m);
        }
    }
    out
}

/// `/proc/<pid>/stat` fields Fleet uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PidStat {
    pub pid: u32,
    /// `comm`, at most 15 bytes, untrusted.
    pub comm: String,
    pub state: u8,
    pub ppid: u32,
    pub flags: u64,
    /// utime + stime, in `USER_HZ` ticks.
    pub cpu_ticks: u64,
    pub nice: i8,
    pub threads: u32,
    /// Ticks after boot.
    pub start_ticks: u64,
}

impl PidStat {
    pub fn is_kernel_thread(&self) -> bool {
        self.flags & PF_KTHREAD != 0 || self.pid == 2 || self.ppid == 2
    }
}

/// `comm` may contain spaces and `)`, so fields are counted from the last `)`.
pub fn pid_stat(text: &str) -> Option<PidStat> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    if close < open {
        return None;
    }
    let pid = text[..open].trim().parse().ok()?;
    let comm = text[open + 1..close].to_owned();
    let rest: Vec<&str> = text[close + 1..]
        .split_ascii_whitespace()
        .take(20)
        .collect();
    if rest.len() < 20 {
        return None;
    }
    let num = |i: usize| rest[i].parse::<u64>().ok();
    Some(PidStat {
        pid,
        comm,
        state: *rest[0].as_bytes().first()?,
        ppid: rest[1].parse().ok()?,
        flags: num(6)?,
        cpu_ticks: num(11)?.saturating_add(num(12)?),
        nice: rest[16].parse::<i64>().ok()?.clamp(-20, 19) as i8,
        threads: rest[17].parse().ok()?,
        start_ticks: num(19)?,
    })
}

/// `/proc/<pid>/status`: real uid and resident set size (bytes; 0 for
/// kernel threads, which have no `VmRSS`).
pub fn pid_status(text: &str) -> Option<(u32, u64)> {
    let mut uid = None;
    let mut rss = 0;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("Uid:") {
            uid = v
                .split_ascii_whitespace()
                .next()
                .and_then(|u| u.parse().ok());
        } else if line.starts_with("VmRSS:") {
            rss = crate::procfs::kib_field(line, "VmRSS:")
                .unwrap_or(0)
                .saturating_mul(1024);
        }
    }
    Some((uid?, rss))
}

/// `/proc/<pid>/io`: storage bytes read and written.
pub fn pid_io(text: &str) -> Option<(u64, u64)> {
    let (mut r, mut w) = (None, None);
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("read_bytes:") {
            r = v.trim().parse().ok();
        } else if let Some(v) = line.strip_prefix("write_bytes:") {
            w = v.trim().parse().ok();
        }
    }
    Some((r?, w?))
}

/// `/proc/<pid>/cmdline`: NUL-separated argv joined with spaces, at most
/// `max` bytes (cut on a char boundary).
pub fn cmdline(raw: &[u8], max: usize) -> String {
    let raw = raw.strip_suffix(&[0]).unwrap_or(raw);
    let mut s = String::from_utf8_lossy(&raw[..raw.len().min(max)]).replace('\0', " ");
    while s.len() > max {
        s.pop();
    }
    s
}

/// `/etc/passwd` uid → name.
pub fn passwd(text: &str) -> Vec<(u32, String)> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.split(':');
            let name = f.next()?;
            let uid = f.nth(1)?.parse().ok()?;
            Some((uid, name.to_owned()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(rel: &str) -> String {
        let p = format!("{}/tests/fixtures/root/{rel}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
    }

    #[test]
    fn stat_fixture() {
        let mut s = ProcStat::default();
        proc_stat(&fixture("proc/stat"), &mut s);
        let t = s.total.unwrap();
        assert_eq!(t.user, 1_000_000 + 2_000);
        assert_eq!(t.system, 300_000 + 1_000 + 4_000);
        assert_eq!(t.steal, 500);
        assert_eq!(s.cores.len(), 4);
        assert_eq!(s.cores[3].0, 3);
        assert_eq!(s.btime_s, Some(1_700_000_000));
        // Malformed input: nothing, no panic.
        proc_stat("cpu x y\ncpu0 1 2\nbtime z", &mut s);
        assert_eq!(s, ProcStat::default());
    }

    #[test]
    fn meminfo_fixture() {
        let m = meminfo(&fixture("proc/meminfo")).unwrap();
        assert_eq!(m.total, 8_148_000 * 1024);
        assert_eq!(m.available, 5_120_000 * 1024);
        assert_eq!(m.cached, (200_000 + 2_400_000) * 1024);
        assert_eq!(m.swap_used(), 1_048_576 * 1024);
        assert_eq!(meminfo("garbage"), None);
    }

    #[test]
    fn loadavg_fixture() {
        assert_eq!(loadavg(&fixture("proc/loadavg")), Some([0.52, 1.25, 0.98]));
        assert_eq!(loadavg("1 2"), None);
        assert_eq!(loadavg("NaN 1 1"), None);
    }

    #[test]
    fn diskstats_fixture() {
        let mut d = Vec::new();
        diskstats(&fixture("proc/diskstats"), &mut d);
        let sda = d.iter().find(|c| c.name == "sda").unwrap();
        assert_eq!((sda.rx, sda.tx), (4_000_000 * 512, 9_000_000 * 512));
        assert!(d.iter().any(|c| c.name == "loop0"));
    }

    #[test]
    fn net_dev_fixture() {
        let mut n = Vec::new();
        net_dev(&fixture("proc/net/dev"), &mut n);
        let names: Vec<&str> = n.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["lo", "eth0", "docker0", "veth1a2b"]);
        assert_eq!((n[1].rx, n[1].tx), (987_654_321, 123_456_789));
    }

    #[test]
    fn mounts_fixture() {
        let m = mounts(&fixture("proc/self/mounts"));
        let paths: Vec<&str> = m.iter().map(|m| m.path.as_str()).collect();
        // proc/sysfs/tmpfs/overlay skipped; bind mount of sda1 deduplicated;
        // octal escape decoded.
        assert_eq!(paths, ["/", "/boot/efi", "/srv/game data"]);
    }

    #[test]
    fn pid_files_fixture() {
        let s = pid_stat(&fixture("proc/4242/stat")).unwrap();
        assert_eq!(s.comm, "nginx: worker (x)");
        assert_eq!((s.state, s.ppid, s.nice, s.threads), (b'S', 4241, -5, 3));
        assert_eq!(s.cpu_ticks, 1500 + 500);
        assert_eq!(s.start_ticks, 123_456);
        assert!(!s.is_kernel_thread());
        let k = pid_stat(&fixture("proc/7/stat")).unwrap();
        assert!(k.is_kernel_thread());
        assert_eq!(
            pid_status(&fixture("proc/4242/status")),
            Some((33, 10_240 * 1024))
        );
        assert_eq!(pid_status(&fixture("proc/7/status")), Some((0, 0)));
        assert_eq!(pid_io(&fixture("proc/4242/io")), Some((4096, 8192)));
        assert_eq!(pid_stat("1 (x) S"), None);
        assert_eq!(pid_stat(")( 1"), None);
    }

    #[test]
    fn cmdline_and_passwd() {
        assert_eq!(
            cmdline(b"nginx\0-g\0daemon off;\0", 100),
            "nginx -g daemon off;"
        );
        assert_eq!(cmdline(b"abcdef", 3), "abc");
        assert_eq!(cmdline("é".as_bytes(), 1), "");
        let p = passwd(&fixture("etc/passwd"));
        assert!(p.contains(&(33, "www-data".to_owned())));
    }

    #[test]
    fn mount_unescape() {
        assert_eq!(unescape_mount(r"/a\040b"), "/a b");
        assert_eq!(unescape_mount(r"/a\04"), r"/a\04");
        assert_eq!(unescape_mount(r"\"), r"\");
    }
}
