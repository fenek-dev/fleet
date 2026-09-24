//! `system.info` from fixed `/proc` and `/etc` paths under the context
//! root. Every source is optional (the agent also runs on macOS during
//! development).

use crate::ctx::SysCtx;
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput};
use fleet_proto::{Op, Payload, SystemInfo};

/// Longest string field sent (server strings are untrusted on the Mac anyway).
const MAX_FIELD: usize = 256;

fn clip(s: &str) -> String {
    s.trim().chars().take(MAX_FIELD).collect()
}

fn os_release_field(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let v = l.strip_prefix(key)?.strip_prefix('=')?;
        Some(clip(v.trim_matches('"')))
    })
}

pub fn collect(ctx: &SysCtx) -> SystemInfo {
    let p = &ctx.procfs;
    let hostname = p
        .read("/proc/sys/kernel/hostname")
        .or_else(|| p.read("/etc/hostname"))
        .map(|s| clip(&s))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into());
    let os = p.read("/etc/os-release").unwrap_or_default();
    let os_id = os_release_field(&os, "ID").unwrap_or_else(|| std::env::consts::OS.into());
    let os_version = os_release_field(&os, "VERSION_ID").unwrap_or_default();
    let kernel = p
        .read("/proc/sys/kernel/osrelease")
        .map(|s| clip(&s))
        .unwrap_or_else(|| "unknown".into());
    SystemInfo {
        hostname,
        os_id,
        os_version,
        kernel,
        arch: std::env::consts::ARCH.into(),
        cpu_count: std::thread::available_parallelism()
            .map_or(0, |n| u32::try_from(n.get()).unwrap_or(u32::MAX)),
        mem_total_bytes: p.mem_total_bytes().unwrap_or(0),
        uptime_s: p.uptime_s().unwrap_or(0),
    }
}

/// `system.info` (tier Read, requests only).
pub struct SystemInfoHandler;

impl OpHandler for SystemInfoHandler {
    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        _op: &'a Op,
        _meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move { Ok(OpOutput::Payload(Payload::SystemInfo(collect(ctx)))) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FakeRunner, ManualClock};
    use std::rc::Rc;

    #[test]
    fn collect_from_root() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::create_dir_all(d.join("proc/sys/kernel")).unwrap();
        std::fs::create_dir_all(d.join("etc")).unwrap();
        std::fs::write(d.join("proc/sys/kernel/hostname"), "web-1\n").unwrap();
        std::fs::write(d.join("proc/sys/kernel/osrelease"), "6.1.0-18-amd64\n").unwrap();
        std::fs::write(
            d.join("etc/os-release"),
            "NAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nID=debian\n",
        )
        .unwrap();
        std::fs::write(d.join("proc/meminfo"), "MemTotal: 2048 kB\n").unwrap();
        std::fs::write(d.join("proc/uptime"), "77.1 1.0\n").unwrap();
        let ctx = SysCtx::new(d, Rc::new(FakeRunner::new()), Rc::new(ManualClock::new(0)));
        let i = collect(&ctx);
        assert_eq!(i.hostname, "web-1");
        assert_eq!((i.os_id.as_str(), i.os_version.as_str()), ("debian", "12"));
        assert_eq!(i.kernel, "6.1.0-18-amd64");
        assert_eq!(i.mem_total_bytes, 2048 * 1024);
        assert_eq!(i.uptime_s, 77);

        // Empty root: defaults, no panic.
        let empty = tempfile::tempdir().unwrap();
        let ctx = SysCtx::new(
            empty.path(),
            Rc::new(FakeRunner::new()),
            Rc::new(ManualClock::new(0)),
        );
        assert_eq!(collect(&ctx).hostname, "unknown");
    }
}
