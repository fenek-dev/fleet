//! Every module (design §9.4–§9.6), looked up by id.

pub mod access;
pub mod kernel;
pub mod network;
pub mod roles;
pub mod ssh;
pub mod system;

use crate::module::{Action, Change, Cmd, Ctx, Module};

pub const SYSTEMCTL: &str = "/usr/bin/systemctl";

/// Every module id in the built-in profiles and roles.
pub const ALL: &[&str] = &[
    "admin.user",
    "admin.shell",
    "sudo.policy",
    "sudo.pwquality",
    "ssh.hardening",
    "firewall.baseline",
    "sysctl",
    "kernel.modules",
    "coredump",
    "updates",
    "services.disable",
    "auditd",
    "journald",
    "apparmor",
    "umask",
    "accounts.lock",
    "time",
    "basics",
    "swap",
    "mounts.tmp",
    "cron.allow",
    "role.docker",
    "role.web",
    "role.game",
];

pub fn by_id(id: &str) -> Option<Box<dyn Module>> {
    Some(match id {
        "admin.user" => Box::new(access::AdminUser),
        "admin.shell" => Box::new(access::AdminShell),
        "sudo.policy" => Box::new(access::SudoPolicy),
        "sudo.pwquality" => Box::new(access::PwQuality),
        "accounts.lock" => Box::new(access::AccountsLock),
        "ssh.hardening" => Box::new(ssh::SshHardening),
        "firewall.baseline" => Box::new(network::FirewallBaseline),
        "sysctl" => Box::new(kernel::Sysctl),
        "kernel.modules" => Box::new(kernel::KernelModules),
        "coredump" => Box::new(kernel::Coredump),
        "updates" => Box::new(system::Updates),
        "services.disable" => Box::new(system::ServicesDisable),
        "auditd" => Box::new(system::Auditd),
        "journald" => Box::new(system::Journald),
        "apparmor" => Box::new(system::AppArmor),
        "umask" => Box::new(system::Umask),
        "time" => Box::new(system::Time),
        "basics" => Box::new(system::Basics),
        "swap" => Box::new(system::Swap),
        "mounts.tmp" => Box::new(system::MountsTmp),
        "cron.allow" => Box::new(system::CronAllow),
        "role.docker" => Box::new(roles::Docker),
        "role.web" => Box::new(roles::Web),
        "role.game" => Box::new(roles::Game),
        _ => return None,
    })
}

/// Units whose state modules read (facts), besides `services.disable`'s.
pub const UNITS: &[&str] = &[
    "ssh.service",
    "apparmor.service",
    "auditd.service",
    "chrony.service",
    "unattended-upgrades.service",
    "fleet-reboot-window.timer",
    "docker.service",
    "caddy.service",
    "nginx.service",
];

pub fn systemctl<I, S>(args: I) -> Cmd
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    Cmd::new(SYSTEMCTL, args)
}

/// `apt-get update` + install of the packages in `pkgs` not yet installed.
pub fn install_change(ctx: &Ctx, module: &'static str, pkgs: &[String]) -> Option<Change> {
    let missing: Vec<String> = pkgs
        .iter()
        .filter(|p| !ctx.facts.installed(p))
        .cloned()
        .collect();
    if missing.is_empty() {
        return None;
    }
    Some(Change {
        module,
        description: format!("install {}", missing.join(" ")),
        diff: format!("+ packages: {}\n", missing.join(" ")),
        actions: vec![Action::AptUpdate, Action::Install(missing)],
    })
}

/// `systemctl enable --now <unit>` unless it is enabled and running (or
/// its package is about to be installed: planned all the same).
pub fn enable_change(ctx: &Ctx, module: &'static str, unit: &str) -> Option<Change> {
    let u = ctx.facts.unit(unit);
    if u.enabled() && u.active() {
        return None;
    }
    Some(crate::module::run_change(
        module,
        format!("enable and start {unit}"),
        vec![systemctl(["enable", "--now", "--", unit])],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_id_resolves_to_itself() {
        for id in ALL {
            assert_eq!(by_id(id).map(|m| m.id()), Some(*id));
        }
        assert!(by_id("nope").is_none());
    }
}
