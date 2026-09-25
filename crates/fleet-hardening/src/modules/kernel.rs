//! Kernel settings (design §9.4): sysctl, module blacklist, core dumps.

use crate::facts::read_small;
use crate::module::{Action, Change, Cmd, Ctx, Module, file_change, remove_change, run_change};
use crate::profile::Resolved;
use fleet_ops::handler::OpError;
use fleet_proto::alert::Severity;

pub const SYSCTL: &str = "/usr/sbin/sysctl";
pub const MODPROBE: &str = "/usr/sbin/modprobe";
pub const SYSCTL_CONF: &str = "/etc/sysctl.d/90-fleet.conf";
pub const MODPROBE_CONF: &str = "/etc/modprobe.d/fleet.conf";
pub const MODULES_LOAD: &str = "/etc/modules-load.d/fleet.conf";
pub const LIMITS_CONF: &str = "/etc/security/limits.d/10-fleet-coredump.conf";
pub const COREDUMP_CONF: &str = "/etc/systemd/coredump.conf.d/10-fleet.conf";

pub fn sysctl_conf(p: &Resolved) -> String {
    let mut s = String::from("# Managed by Fleet (design §9.4). Changes are overwritten.\n");
    for (k, v) in &p.settings.sysctl {
        s.push_str(&format!("{k} = {v}\n"));
    }
    s
}

/// `--ignore`: a key this kernel lacks is skipped, not fatal.
pub fn sysctl_load() -> Cmd {
    Cmd::new(SYSCTL, ["--ignore", "--system"])
}

/// Live value of `key` (`/proc/sys/...`), whitespace-normalized; `None`
/// when this kernel lacks it.
fn live(ctx: &Ctx, key: &str) -> Option<String> {
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    let v = read_small(&ctx.sys, &path);
    (!v.is_empty()).then(|| v.split_whitespace().collect::<Vec<_>>().join(" "))
}

pub struct Sysctl;

impl Module for Sysctl {
    fn id(&self) -> &'static str {
        "sysctl"
    }
    fn title(&self) -> &'static str {
        "Kernel and network sysctl hardening"
    }
    fn weight(&self) -> u8 {
        10
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn plan(&self, ctx: &Ctx) -> Result<Vec<Change>, OpError> {
        let conf = sysctl_conf(&ctx.profile);
        if let Some(mut c) = file_change(&ctx.sys, self.id(), SYSCTL_CONF, &conf, 0o644)? {
            c.diff.push_str(&format!("$ {}\n", sysctl_load().display()));
            c.actions.push(Action::Run(sysctl_load()));
            return Ok(vec![c]);
        }
        let stale: Vec<String> = ctx
            .profile
            .settings
            .sysctl
            .iter()
            .filter_map(|(k, v)| {
                let now = live(ctx, k)?;
                (now != *v).then(|| format!("{k} = {now} (want {v})"))
            })
            .collect();
        if stale.is_empty() {
            return Ok(Vec::new());
        }
        let mut c = run_change(self.id(), "load sysctl settings", vec![sysctl_load()]);
        c.diff = stale.iter().map(|s| format!("~ {s}\n")).collect();
        Ok(vec![c])
    }

    fn paths(&self, _p: &Resolved) -> Vec<String> {
        vec![SYSCTL_CONF.into()]
    }

    fn reload(&self, _p: &Resolved) -> Vec<Cmd> {
        vec![sysctl_load()]
    }
}

pub fn modprobe_conf(p: &Resolved) -> String {
    let mut s = String::from("# Managed by Fleet (design §9.4). Changes are overwritten.\n");
    for m in &p.settings.blacklist {
        s.push_str(&format!("blacklist {m}\ninstall {m} /bin/false\n"));
    }
    s
}

/// Kernel module names from the built-in files: `[a-z0-9_-]`.
fn valid_module(m: &str) -> bool {
    !m.is_empty()
        && m.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

pub struct KernelModules;

impl Module for KernelModules {
    fn id(&self) -> &'static str {
        "kernel.modules"
    }
    fn title(&self) -> &'static str {
        "Unneeded kernel modules blacklisted"
    }

    fn plan(&self, ctx: &Ctx) -> Result<Vec<Change>, OpError> {
        let p = &ctx.profile;
        let mut plan: Vec<Change> =
            file_change(&ctx.sys, self.id(), MODPROBE_CONF, &modprobe_conf(p), 0o644)?
                .into_iter()
                .collect();
        if p.settings.modules_load.is_empty() {
            plan.extend(remove_change(&ctx.sys, self.id(), MODULES_LOAD)?);
        } else {
            let mut s =
                String::from("# Managed by Fleet: loaded at boot for the server's roles.\n");
            for m in &p.settings.modules_load {
                s.push_str(m);
                s.push('\n');
            }
            if let Some(mut c) = file_change(&ctx.sys, self.id(), MODULES_LOAD, &s, 0o644)? {
                for m in p.settings.modules_load.iter().filter(|m| valid_module(m)) {
                    let cmd = Cmd::new(MODPROBE, ["--", m.as_str()]);
                    c.diff.push_str(&format!("$ {}\n", cmd.display()));
                    c.actions.push(Action::Run(cmd));
                }
                plan.push(c);
            }
        }
        Ok(plan)
    }

    fn paths(&self, _p: &Resolved) -> Vec<String> {
        vec![MODPROBE_CONF.into(), MODULES_LOAD.into()]
    }
}

pub const LIMITS: &str = "# Managed by Fleet (design §9.4): no core dumps.\n* hard core 0\n";
pub const COREDUMP: &str = "# Managed by Fleet (design §9.4): no core dumps.\n[Coredump]\nStorage=none\nProcessSizeMax=0\n";

pub struct Coredump;

impl Module for Coredump {
    fn id(&self) -> &'static str {
        "coredump"
    }
    fn title(&self) -> &'static str {
        "Core dumps disabled"
    }
    fn weight(&self) -> u8 {
        3
    }

    fn plan(&self, ctx: &Ctx) -> Result<Vec<Change>, OpError> {
        let mut plan = Vec::new();
        plan.extend(file_change(
            &ctx.sys,
            self.id(),
            LIMITS_CONF,
            LIMITS,
            0o644,
        )?);
        plan.extend(file_change(
            &ctx.sys,
            self.id(),
            COREDUMP_CONF,
            COREDUMP,
            0o644,
        )?);
        Ok(plan)
    }

    fn paths(&self, _p: &Resolved) -> Vec<String> {
        vec![LIMITS_CONF.into(), COREDUMP_CONF.into()]
    }
}
