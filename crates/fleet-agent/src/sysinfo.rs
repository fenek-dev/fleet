//! `system.info` and memory figures from fixed `/proc` and `/etc` paths.
//! Every source is optional so this also runs on macOS during development.

use fleet_proto::SystemInfo;

/// Longest string field sent (server strings are untrusted on the Mac anyway).
const MAX_FIELD: usize = 256;

fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn clip(s: &str) -> String {
    s.trim().chars().take(MAX_FIELD).collect()
}

fn os_release_field(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let v = l.strip_prefix(key)?.strip_prefix('=')?;
        Some(clip(v.trim_matches('"')))
    })
}

pub fn collect() -> SystemInfo {
    let hostname = read("/proc/sys/kernel/hostname")
        .or_else(|| read("/etc/hostname"))
        .map(|s| clip(&s))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into());
    let os = read("/etc/os-release").unwrap_or_default();
    let os_id = os_release_field(&os, "ID").unwrap_or_else(|| std::env::consts::OS.into());
    let os_version = os_release_field(&os, "VERSION_ID").unwrap_or_default();
    let kernel = read("/proc/sys/kernel/osrelease")
        .map(|s| clip(&s))
        .unwrap_or_else(|| "unknown".into());
    let uptime_s = read("/proc/uptime")
        .and_then(|s| s.split('.').next()?.trim().parse().ok())
        .unwrap_or(0);
    SystemInfo {
        hostname,
        os_id,
        os_version,
        kernel,
        arch: std::env::consts::ARCH.into(),
        cpu_count: std::thread::available_parallelism().map_or(0, |n| n.get() as u32),
        mem_total_bytes: meminfo_kib("/proc/meminfo", "MemTotal:").map_or(0, |k| k * 1024),
        uptime_s,
    }
}

/// This process's resident set size in bytes (0 where `/proc` is missing).
pub fn self_rss_bytes() -> u64 {
    meminfo_kib("/proc/self/status", "VmRSS:").map_or(0, |k| k * 1024)
}

fn meminfo_kib(path: &str, key: &str) -> Option<u64> {
    read(path)?.lines().find_map(|l| {
        l.strip_prefix(key)?
            .trim()
            .strip_suffix("kB")?
            .trim()
            .parse()
            .ok()
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn os_release_parsing() {
        let t = "NAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nID=debian\n";
        assert_eq!(super::os_release_field(t, "ID").as_deref(), Some("debian"));
        assert_eq!(
            super::os_release_field(t, "VERSION_ID").as_deref(),
            Some("12")
        );
        super::collect();
    }
}
