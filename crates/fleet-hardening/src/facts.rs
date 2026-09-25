//! Server facts modules plan against that aren't plain config files.
//! Gathered once per request, read-only, in a fixed order:
//!
//! 1. `/usr/bin/ssh -Q kex` (key exchanges the installed OpenSSH supports)
//! 2. `/usr/bin/systemctl show --property=… -- <units>`
//! 3. `/usr/sbin/auditctl -s` (only when `auditd` is installed)
//! 4. `/usr/sbin/nft -j list table inet fleet`
//!
//! Plus files: `/etc/os-release`, `/var/lib/dpkg/status`, `/proc/meminfo`,
//! `/proc/swaps`, `/sys/module/apparmor/parameters/enabled`,
//! `/proc/sys/kernel/random/boot_id`. Command output is untrusted and only
//! parsed.

use fleet_ops::SysCtx;
use fleet_ops::firewall::{self, Table};
use fleet_ops::runner::CommandSpec;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

pub const SSH: &str = "/usr/bin/ssh";
pub const SYSTEMCTL: &str = "/usr/bin/systemctl";
pub const AUDITCTL: &str = "/usr/sbin/auditctl";
pub const DPKG_STATUS: &str = "/var/lib/dpkg/status";
/// Largest `/var/lib/dpkg/status` read (a big server has a few MiB).
const DPKG_STATUS_CAP: u64 = 32 << 20;
const T_FACT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsRelease {
    /// `debian` or `ubuntu`.
    pub id: String,
    pub version_id: String,
    pub codename: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnitState {
    pub load: String,
    pub file_state: String,
    pub active: String,
}

impl UnitState {
    pub fn exists(&self) -> bool {
        !self.load.is_empty() && self.load != "not-found"
    }

    pub fn enabled(&self) -> bool {
        matches!(
            self.file_state.as_str(),
            "enabled" | "enabled-runtime" | "static" | "alias" | "indirect" | "generated"
        )
    }

    pub fn active(&self) -> bool {
        matches!(self.active.as_str(), "active" | "activating" | "reloading")
    }
}

#[derive(Debug, Clone, Default)]
pub struct Facts {
    pub os: OsRelease,
    /// By the name queried.
    pub units: BTreeMap<String, UnitState>,
    /// Installed packages (`install ok installed`).
    pub packages: BTreeSet<String>,
    pub ssh_kex: Vec<String>,
    pub mem_total_kib: u64,
    pub swap_active: bool,
    /// `None`: AppArmor isn't built into the kernel.
    pub apparmor_enabled: Option<bool>,
    /// `auditctl -s` `enabled` (0, 1, or 2 = immutable); `None` unknown.
    pub audit_enabled: Option<u8>,
    pub boot_id: String,
    /// `Err`: nft failed or the listing didn't parse.
    pub firewall: Option<Result<Table, String>>,
}

impl Facts {
    pub fn unit(&self, name: &str) -> UnitState {
        self.units.get(name).cloned().unwrap_or_default()
    }

    pub fn installed(&self, pkg: &str) -> bool {
        self.packages.contains(pkg)
    }
}

/// `/proc`, `/sys` and small `/etc` files (no size in `stat` for procfs,
/// so not through `fswrite`); empty when unreadable.
pub fn read_small(sys: &SysCtx, abs: &str) -> String {
    use std::io::Read as _;
    let Some(p) = sys.path(abs) else {
        return String::new();
    };
    let mut s = String::new();
    if let Ok(f) = std::fs::File::open(p) {
        let _ = f.take(1 << 20).read_to_string(&mut s);
    }
    s
}

pub fn parse_os_release(text: &str) -> OsRelease {
    let mut os = OsRelease::default();
    for l in text.lines() {
        let Some((k, v)) = l.split_once('=') else {
            continue;
        };
        let v = v.trim().trim_matches('"').to_owned();
        match k.trim() {
            "ID" => os.id = v,
            "VERSION_ID" => os.version_id = v,
            "VERSION_CODENAME" => os.codename = v,
            _ => {}
        }
    }
    os
}

/// Installed package names from dpkg's status file.
pub fn parse_dpkg_status(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for para in text.split("\n\n") {
        let mut name = None;
        let mut ok = false;
        for l in para.lines() {
            if let Some(n) = l.strip_prefix("Package: ") {
                name = Some(n.trim());
            } else if let Some(s) = l.strip_prefix("Status: ") {
                ok = s.trim() == "install ok installed";
            }
        }
        if let (Some(n), true) = (name, ok) {
            out.insert(n.to_owned());
        }
    }
    out
}

/// `systemctl show` blocks (blank-line separated, in argument order).
pub fn parse_units(text: &str, names: &[String]) -> BTreeMap<String, UnitState> {
    let blocks = text.split("\n\n").filter(|b| !b.trim().is_empty());
    let mut out = BTreeMap::new();
    for (name, block) in names.iter().zip(blocks) {
        let mut u = UnitState::default();
        for l in block.lines() {
            match l.split_once('=') {
                Some(("LoadState", v)) => u.load = v.to_owned(),
                Some(("UnitFileState", v)) => u.file_state = v.to_owned(),
                Some(("ActiveState", v)) => u.active = v.to_owned(),
                _ => {}
            }
        }
        out.insert(name.clone(), u);
    }
    out
}

pub fn parse_meminfo_total(text: &str) -> u64 {
    text.lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))
        .and_then(|v| v.split_whitespace().next()?.parse().ok())
        .unwrap_or(0)
}

/// `auditctl -s`: the `enabled` value.
pub fn parse_audit_enabled(text: &str) -> Option<u8> {
    text.lines()
        .find_map(|l| l.strip_prefix("enabled "))
        .and_then(|v| v.trim().parse().ok())
}

pub fn units_spec(names: &[String]) -> CommandSpec {
    CommandSpec::new(SYSTEMCTL)
        .args([
            "show",
            "--property=LoadState,UnitFileState,ActiveState",
            "--",
        ])
        .args(names)
        .timeout(T_FACT)
}

/// Reads every fact; `units` are the unit names modules ask about.
pub async fn gather(sys: &SysCtx, units: &[String]) -> Facts {
    let mut f = Facts {
        os: parse_os_release(&read_small(sys, "/etc/os-release")),
        mem_total_kib: parse_meminfo_total(&read_small(sys, "/proc/meminfo")),
        swap_active: read_small(sys, "/proc/swaps")
            .lines()
            .skip(1)
            .any(|l| !l.trim().is_empty()),
        apparmor_enabled: {
            let s = read_small(sys, "/sys/module/apparmor/parameters/enabled");
            (!s.is_empty()).then(|| s.trim() == "Y")
        },
        boot_id: read_small(sys, "/proc/sys/kernel/random/boot_id")
            .trim()
            .to_owned(),
        ..Facts::default()
    };
    if let Ok(Some(b)) = fleet_ops::fswrite::read_regular(sys, DPKG_STATUS, DPKG_STATUS_CAP) {
        f.packages = parse_dpkg_status(&String::from_utf8_lossy(&b));
    }
    let kex = CommandSpec::new(SSH).args(["-Q", "kex"]).timeout(T_FACT);
    if let Ok(o) = sys.runner.run(kex).await
        && o.success()
    {
        f.ssh_kex = String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty())
            .collect();
    }
    if !units.is_empty()
        && let Ok(o) = sys.runner.run(units_spec(units)).await
        && o.success()
    {
        f.units = parse_units(&String::from_utf8_lossy(&o.stdout), units);
    }
    if f.installed("auditd")
        && let Ok(o) = sys
            .runner
            .run(CommandSpec::new(AUDITCTL).arg("-s").timeout(T_FACT))
            .await
        && o.success()
    {
        f.audit_enabled = parse_audit_enabled(&String::from_utf8_lossy(&o.stdout));
    }
    f.firewall = Some(
        firewall::table_from(sys.runner.run(firewall::list_table_spec()).await)
            .map_err(|e| e.detail().unwrap_or("nft failed").to_owned()),
    );
    f
}
