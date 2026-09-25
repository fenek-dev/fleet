//! System modules (design §9.4, §9.5): updates, services, auditd,
//! journald, AppArmor, umask, time, basics, swap, and Strict's `/tmp`
//! mounts and cron/at allow-lists.

use crate::facts::read_small;
use crate::module::{
    Action, Change, Cmd, Ctx, Module, Status, file_change, line_diff, read_file, read_text,
    remove_change, run_change, status_of,
};
use crate::modules::{enable_change, install_change, systemctl};
use crate::profile::Resolved;
use fleet_ops::handler::OpError;
use fleet_proto::alert::Severity;

// ---- updates ----

pub const AUTO_UPGRADES: &str = "/etc/apt/apt.conf.d/20auto-upgrades";
pub const UNATTENDED_FLEET: &str = "/etc/apt/apt.conf.d/52fleet-unattended-upgrades";
pub const NEEDRESTART_CONF: &str = "/etc/needrestart/conf.d/50-fleet-profile.conf";
pub const REBOOT_SERVICE: &str = "/etc/systemd/system/fleet-reboot-window.service";
pub const REBOOT_TIMER: &str = "/etc/systemd/system/fleet-reboot-window.timer";
pub const REBOOT_UNIT: &str = "fleet-reboot-window.timer";

pub const AUTO_UPGRADES_CONF: &str = "// Managed by Fleet (design §9.4).\n\
APT::Periodic::Update-Package-Lists \"1\";\n\
APT::Periodic::Unattended-Upgrade \"1\";\n";

/// Security origins come from the package's own 50unattended-upgrades;
/// reboots only in Fleet's window (timer below), never mid-day.
pub const UNATTENDED_CONF: &str = "// Managed by Fleet (design §9.4).\n\
Unattended-Upgrade::Automatic-Reboot \"false\";\n\
Unattended-Upgrade::Remove-Unused-Kernel-Packages \"true\";\n\
Unattended-Upgrade::Remove-Unused-Dependencies \"true\";\n";

/// Automatic restarts; `fleet-*` units are excluded by the installer's
/// `/etc/needrestart/conf.d/fleet.conf` (design §9.4), left untouched here.
pub const NEEDRESTART: &str = "# Managed by Fleet (design §9.4).\n$nrconf{restart} = 'a';\n";

pub const REBOOT_SERVICE_UNIT: &str = "# Managed by Fleet (design §9.4).\n\
[Unit]\n\
Description=Fleet reboot window: reboot if an update needs it\n\
ConditionPathExists=/run/reboot-required\n\
\n\
[Service]\n\
Type=oneshot\n\
ExecStart=/usr/bin/systemctl reboot\n";

pub fn reboot_timer(w: &crate::profile::RebootWindow) -> String {
    format!(
        "# Managed by Fleet (design §9.4).\n\
         [Unit]\n\
         Description=Fleet reboot window\n\
         \n\
         [Timer]\n\
         OnCalendar={}\n\
         RandomizedDelaySec={}min\n\
         AccuracySec=1min\n\
         \n\
         [Install]\n\
         WantedBy=timers.target\n",
        w.on_calendar(),
        w.len_min.saturating_sub(5)
    )
}

pub struct Updates;

impl Module for Updates {
    fn id(&self) -> &'static str {
        "updates"
    }
    fn title(&self) -> &'static str {
        "Automatic security updates and service restarts"
    }
    fn weight(&self) -> u8 {
        10
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn plan(&self, ctx: &Ctx) -> Result<Vec<Change>, OpError> {
        let id = self.id();
        let sys = &ctx.sys;
        let mut plan = Vec::new();
        plan.extend(install_change(
            ctx,
            id,
            &["unattended-upgrades".to_owned(), "needrestart".to_owned()],
        ));
        plan.extend(file_change(
            sys,
            id,
            AUTO_UPGRADES,
            AUTO_UPGRADES_CONF,
            0o644,
        )?);
        plan.extend(file_change(
            sys,
            id,
            UNATTENDED_FLEET,
            UNATTENDED_CONF,
            0o644,
        )?);
        plan.extend(file_change(sys, id, NEEDRESTART_CONF, NEEDRESTART, 0o644)?);
        match &ctx.profile.reboot_window {
            Some(w) => {
                let mut units: Vec<Change> = Vec::new();
                units.extend(file_change(
                    sys,
                    id,
                    REBOOT_SERVICE,
                    REBOOT_SERVICE_UNIT,
                    0o644,
                )?);
                units.extend(file_change(sys, id, REBOOT_TIMER, &reboot_timer(w), 0o644)?);
                let u = ctx.facts.unit(REBOOT_UNIT);
                if !units.is_empty() || !u.enabled() || !u.active() {
                    units.push(run_change(
                        id,
                        format!("enable the reboot window timer ({})", w.on_calendar()),
                        vec![
                            systemctl(["daemon-reload"]),
                            systemctl(["enable", "--now", "--", REBOOT_UNIT]),
                        ],
                    ));
                }
                plan.extend(units);
            }
            None => {
                let mut gone: Vec<Change> = Vec::new();
                gone.extend(remove_change(sys, id, REBOOT_TIMER)?);
                gone.extend(remove_change(sys, id, REBOOT_SERVICE)?);
                if !gone.is_empty() {
                    gone.insert(
                        0,
                        run_change(
                            id,
                            "disable the reboot window timer",
                            vec![systemctl(["disable", "--now", "--", REBOOT_UNIT])],
                        ),
                    );
                    gone.push(run_change(
                        id,
                        "reload systemd",
                        vec![systemctl(["daemon-reload"])],
                    ));
                }
                plan.extend(gone);
            }
        }
        plan.extend(enable_change(ctx, id, "unattended-upgrades.service"));
        Ok(plan)
    }

    fn paths(&self, _p: &Resolved) -> Vec<String> {
        [
            AUTO_UPGRADES,
            UNATTENDED_FLEET,
            NEEDRESTART_CONF,
            REBOOT_SERVICE,
            REBOOT_TIMER,
        ]
        .map(String::from)
        .to_vec()
    }
}

// ---- services.disable ----

/// Packages of legacy remote shells, purged when installed.
pub const LEGACY_PACKAGES: &[&str] = &[
    "rsh-server",
    "rsh-redone-server",
    "telnetd",
    "inetutils-telnetd",
    "telnetd-ssl",
    "nis",
    "talkd",
];

pub struct ServicesDisable;

impl Module for ServicesDisable {
    fn id(&self) -> &'static str {
        "services.disable"
    }
    fn title(&self) -> &'static str {
        "Unneeded network services disabled"
    }
    fn weight(&self) -> u8 {
        6
    }

    fn plan(&self, ctx: &Ctx) -> Result<Vec<Change>, OpError> {
        let mut plan = Vec::new();
        let legacy: Vec<String> = LEGACY_PACKAGES
            .iter()
            .filter(|p| ctx.facts.installed(p))
            .map(|p| (*p).to_owned())
            .collect();
        if !legacy.is_empty() {
            plan.push(Change {
                module: self.id(),
                description: format!("purge {}", legacy.join(" ")),
                diff: format!("- packages: {}\n", legacy.join(" ")),
                actions: vec![Action::Purge(legacy)],
            });
        }
        for unit in &ctx.profile.settings.disable {
            let u = ctx.facts.unit(unit);
            if u.exists() && (u.enabled() || u.active()) {
                plan.push(run_change(
                    self.id(),
                    format!("stop and disable {unit}"),
                    vec![systemctl(["disable", "--now", "--", unit.as_str()])],
                ));
            }
        }
        Ok(plan)
    }
}

// ---- auditd ----

pub const AUDIT_RULES: &str = "/etc/audit/rules.d/fleet.rules";
pub const AUDIT_FINAL: &str = "/etc/audit/rules.d/99-fleet-finalize.rules";
pub const AUGENRULES: &str = "/usr/sbin/augenrules";
/// Boot id written when rules changed while immutable (`-e 2`).
pub const AUDIT_REBOOT_MARKER: &str = "/var/lib/fleet/hardening/auditd-pending-reboot";

pub const AUDIT_RULES_TEXT: &str = "## Managed by Fleet (design §9.4). Changes are overwritten.\n\
-w /etc/passwd -p wa -k identity\n\
-w /etc/group -p wa -k identity\n\
-w /etc/shadow -p wa -k identity\n\
-w /etc/gshadow -p wa -k identity\n\
-w /etc/security/opasswd -p wa -k identity\n\
-w /etc/sudoers -p wa -k sudoers\n\
-w /etc/sudoers.d/ -p wa -k sudoers\n\
-w /etc/ssh/sshd_config -p wa -k sshd\n\
-w /etc/ssh/sshd_config.d/ -p wa -k sshd\n\
-w /etc/fleet/authorized_keys/ -p wa -k sshd\n\
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change\n\
-w /etc/localtime -p wa -k time-change\n\
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules\n\
-w /usr/bin/kmod -p x -k modules\n\
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k privileged\n\
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged\n\
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged\n\
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=unset -k privileged\n\
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=unset -k privileged\n\
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=unset -k privileged\n";

pub const AUDIT_FINAL_TEXT: &str =
    "## Managed by Fleet (design §9.5): rules immutable until reboot.\n-e 2\n";

pub struct Auditd;

impl Auditd {
    fn immutable_now(ctx: &Ctx) -> bool {
        ctx.facts.audit_enabled == Some(2)
    }

    fn marker_current(ctx: &Ctx) -> bool {
        !ctx.facts.boot_id.is_empty()
            && read_text(&ctx.sys, AUDIT_REBOOT_MARKER).is_ok_and(|m| m.trim() == ctx.facts.boot_id)
    }

    fn file_changes(&self, ctx: &Ctx) -> Result<Vec<Change>, OpError> {
        let sys = &ctx.sys;
        let mut plan = Vec::new();
        plan.extend(file_change(
            sys,
            self.id(),
            AUDIT_RULES,
            AUDIT_RULES_TEXT,
            0o640,
        )?);
        if ctx.profile.settings.auditd_immutable {
            plan.extend(file_change(
                sys,
                self.id(),
                AUDIT_FINAL,
                AUDIT_FINAL_TEXT,
                0o640,
            )?);
        } else {
            plan.extend(remove_change(sys, self.id(), AUDIT_FINAL)?);
        }
        Ok(plan)
    }
}

impl Module for Auditd {
    fn id(&self) -> &'static str {
        "auditd"
    }
    fn title(&self) -> &'static str {
        "auditd rules for identity, sudo, sshd, time and modules"
    }
    fn weight(&self) -> u8 {
        6
    }

    /// Rule files that can't load until a reboot (immutable now) are
    /// `PendingReboot`, not `Drifted` (design §9.5).
    fn check(&self, ctx: &Ctx) -> Result<Status, OpError> {
        let plan = self.plan(ctx)?;
        let files_differ = !self.file_changes(ctx)?.is_empty();
        if files_differ && Self::immutable_now(ctx) && ctx.facts.installed("auditd") {
            return Ok(Status::PendingReboot(
                "audit rules are immutable (-e 2); changed rules load at the next reboot".into(),
            ));
        }
        if plan.is_empty() && Self::marker_current(ctx) {
            return Ok(Status::PendingReboot(
                "new audit rules load at the next reboot".into(),
            ));
        }
        Ok(status_of(&plan))
    }

    fn plan(&self, ctx: &Ctx) -> Result<Vec<Change>, OpError> {
        let mut plan: Vec<Change> = install_change(ctx, self.id(), &["auditd".to_owned()])
            .into_iter()
            .collect();
        let mut files = self.file_changes(ctx)?;
        if !files.is_empty() {
            if Self::immutable_now(ctx) {
                // Loading would fail; the new rules load at boot.
                files.push(Change {
                    module: self.id(),
                    description: "rules are immutable until reboot: record a pending reboot".into(),
                    diff: String::new(),
                    actions: vec![Action::Write {
                        path: AUDIT_REBOOT_MARKER.into(),
                        content: format!("{}\n", ctx.facts.boot_id).into_bytes(),
                        mode: 0o600,
                    }],
                });
            } else {
                crate::module::then_run(
                    &mut files,
                    [Action::Run(Cmd::new(AUGENRULES, ["--load"]))],
                );
            }
        }
        plan.extend(files);
        plan.extend(enable_change(ctx, self.id(), "auditd.service"));
        Ok(plan)
    }

    fn paths(&self, _p: &Resolved) -> Vec<String> {
        vec![
            AUDIT_RULES.into(),
            AUDIT_FINAL.into(),
            AUDIT_REBOOT_MARKER.into(),
        ]
    }
}

// ---- journald ----

pub const JOURNALD_CONF: &str = "/etc/systemd/journald.conf.d/10-fleet.conf";

pub fn journald_conf(p: &Resolved) -> String {
    format!(
        "# Managed by Fleet (design §9.4).\n[Journal]\nStorage=persistent\nSystemMaxUse={}\n",
        p.settings.journald_max_use
    )
}

pub struct Journald;

impl Module for Journald {
    fn id(&self) -> &'static str {
        "journald"
    }
    fn title(&self) -> &'static str {
        "Persistent journal with a size cap"
    }
    fn weight(&self) -> u8 {
        3
    }

    fn plan(&self, ctx: &Ctx) -> Result<Vec<Change>, OpError> {
        let mut plan: Vec<Change> = file_change(
            &ctx.sys,
            self.id(),
            JOURNALD_CONF,
            &journald_conf(&ctx.profile),
            0o644,
        )?
        .into_iter()
        .collect();
        crate::module::then_run(
            &mut plan,
            [Action::Run(systemctl([
                "restart",
                "--",
                "systemd-journald.service",
            ]))],
        );
        Ok(plan)
    }

    fn paths(&self, _p: &Resolved) -> Vec<String> {
        vec![JOURNALD_CONF.into()]
    }
}

// ---- apparmor ----

pub struct AppArmor;

impl Module for AppArmor {
    fn id(&self) -> &'static str {
        "apparmor"
    }
    fn title(&self) -> &'static str {
        "AppArmor enforcing"
    }

    fn check(&self, ctx: &Ctx) -> Result<Status, OpError> {
        if ctx.facts.apparmor_enabled != Some(true) {
            return Ok(Status::Drifted(
                "AppArmor is disabled in the kernel (boot parameters); fix manually and reboot"
                    .into(),
            ));
        }
        Ok(status_of(&self.plan(ctx)?))
    }

    fn fixable(&self, ctx: &Ctx) -> bool {
        ctx.facts.apparmor_enabled == Some(true)
    }

    fn plan(&self, ctx: &Ctx) -> Result<Vec<Change>, OpError> {
        if ctx.facts.apparmor_enabled != Some(true) {
            return Ok(Vec::new());
        }
        let mut plan: Vec<Change> = install_change(ctx, self.id(), &["apparmor".to_owned()])
            .into_iter()
            .collect();
        plan.extend(enable_change(ctx, self.id(), "apparmor.service"));
        Ok(plan)
    }
}

// ---- umask ----

/// PAM stacks of interactive logins; not `common-session` (design §9.4:
/// a system-wide 027 breaks package-installed files).
pub const PAM_INTERACTIVE: &[&str] = &["/etc/pam.d/sshd", "/etc/pam.d/login"];
pub const UMASK_LINE: &str = "session optional pam_umask.so umask=0027";
const UMASK_COMMENT: &str = "# Fleet: umask 027 for interactive logins (design §9.4)";

pub struct Umask;

impl Module for Umask {
    fn id(&self) -> &'static str {
        "umask"
    }
    fn title(&self) -> &'static str {
        "umask 027 for interactive logins"
    }
    fn weight(&self) -> u8 {
        2
    }

    fn plan(&self, ctx: &Ctx) -> Result<Vec<Change>, OpError> {
        let mut plan = Vec::new();
        for path in PAM_INTERACTIVE {
            let Some((bytes, mode)) = read_file(&ctx.sys, path)? else {
                continue;
            };
            let text = String::from_utf8_lossy(&bytes);
            if text.lines().any(|l| l.trim() == UMASK_LINE) {
                continue;
            }
            let mut new = text.into_owned();
            if !new.is_empty() && !new.ends_with('\n') {
                new.push('\n');
            }
            new.push_str(&format!("{UMASK_COMMENT}\n{UMASK_LINE}\n"));
            plan.push(Change {
                module: self.id(),
                description: format!("{path}: pam_umask 027"),
                diff: format!("+ {UMASK_LINE}\n"),
                actions: vec![Action::Write {
                    path: (*path).to_owned(),
                    content: new.into_bytes(),
                    mode,
                }],
            });
        }
        Ok(plan)
    }

    fn paths(&self, _p: &Resolved) -> Vec<String> {
        PAM_INTERACTIVE.iter().map(|p| (*p).to_owned()).collect()
    }
}

// ---- time ----

pub const TIMEDATECTL: &str = "/usr/bin/timedatectl";

pub struct Time;

impl Time {
    fn is_utc(ctx: &Ctx) -> bool {
        let Some(p) = ctx.sys.path("/etc/localtime") else {
            return false;
        };
        std::fs::read_link(p).is_ok_and(|t| {
            let t = t.to_string_lossy();
            t.ends_with("/UTC") || t.ends_with("/Etc/UTC") || t.ends_with("/UCT")
        })
    }
}

impl Module for Time {
    fn id(&self) -> &'static str {
        "time"
    }
    fn title(&self) -> &'static str {
        "UTC time zone and chrony"
    }
    fn weight(&self) -> u8 {
        3
    }

    fn plan(&self, ctx: &Ctx) -> Result<Vec<Change>, OpError> {
        let mut plan = Vec::new();
        if !Self::is_utc(ctx) {
            plan.push(run_change(
                self.id(),
                "set the time zone to UTC",
                vec![Cmd::new(TIMEDATECTL, ["set-timezone", "UTC"])],
            ));
        }
        plan.extend(install_change(ctx, self.id(), &["chrony".to_owned()]));
        plan.extend(enable_change(ctx, self.id(), "chrony.service"));
        Ok(plan)
    }
}

// ---- basics ----

pub struct Basics;

impl Module for Basics {
    fn id(&self) -> &'static str {
        "basics"
    }
    fn title(&self) -> &'static str {
        "Basic tools (tmux, logrotate)"
    }
    fn weight(&self) -> u8 {
        1
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn plan(&self, ctx: &Ctx) -> Result<Vec<Change>, OpError> {
        Ok(
            install_change(ctx, self.id(), &ctx.profile.settings.packages)
                .into_iter()
                .collect(),
        )
    }
}

// ---- swap ----

pub const SWAPFILE: &str = "/swapfile";
pub const FSTAB: &str = "/etc/fstab";
pub const FALLOCATE: &str = "/usr/bin/fallocate";
pub const CHMOD: &str = "/usr/bin/chmod";
pub const MKSWAP: &str = "/usr/sbin/mkswap";
pub const SWAPON: &str = "/usr/sbin/swapon";
pub const MOUNT: &str = "/usr/bin/mount";
const GIB: u64 = 1 << 30;

/// `fstab` with every line whose field `field` equals `key` replaced by
/// `line` (appended when none). Other lines are kept byte for byte.
pub fn fstab_with(text: &str, field: usize, key: &str, line: &str) -> String {
    let mut out = String::new();
    for l in text.lines() {
        let t = l.trim_start();
        if !t.starts_with('#') && t.split_whitespace().nth(field) == Some(key) {
            continue;
        }
        out.push_str(l);
        out.push('\n');
    }
    out.push_str(line);
    out.push('\n');
    out
}

fn fstab_has(text: &str, line: &str) -> bool {
    let want: Vec<&str> = line.split_whitespace().collect();
    text.lines()
        .any(|l| l.split_whitespace().collect::<Vec<_>>() == want)
}

/// The smaller of RAM or 4 GiB, in whole MiB (1 GiB when RAM is unknown).
pub fn swap_bytes(mem_kib: u64) -> u64 {
    let ram = mem_kib.saturating_mul(1024);
    let b = if ram == 0 { GIB } else { ram.min(4 * GIB) };
    b / (1 << 20) * (1 << 20)
}

pub const SWAP_LINE: &str = "/swapfile none swap sw 0 0";

pub struct Swap;

impl Module for Swap {
    fn id(&self) -> &'static str {
        "swap"
    }
    fn title(&self) -> &'static str {
        "Swap file (the smaller of RAM or 4 GB)"
    }
    fn weight(&self) -> u8 {
        1
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn plan(&self, ctx: &Ctx) -> Result<Vec<Change>, OpError> {
        if ctx.facts.swap_active {
            return Ok(Vec::new());
        }
        let mut cmds = Vec::new();
        if read_file(&ctx.sys, SWAPFILE)?.is_none() {
            let size = swap_bytes(ctx.facts.mem_total_kib).to_string();
            cmds.push(Cmd::new(FALLOCATE, ["--length", size.as_str(), SWAPFILE]));
            cmds.push(Cmd::new(CHMOD, ["0600", SWAPFILE]));
            cmds.push(Cmd::new(MKSWAP, [SWAPFILE]));
        }
        cmds.push(Cmd::new(SWAPON, [SWAPFILE]));
        let mut c = run_change(self.id(), format!("create and enable {SWAPFILE}"), cmds);
        let fstab = read_text(&ctx.sys, FSTAB)?;
        if !fstab_has(&fstab, SWAP_LINE) {
            let mode = read_file(&ctx.sys, FSTAB)?.map_or(0o644, |f| f.1);
            c.diff.push_str(&format!("+ {FSTAB}: {SWAP_LINE}\n"));
            c.actions.push(Action::Write {
                path: FSTAB.into(),
                content: fstab_with(&fstab, 0, SWAPFILE, SWAP_LINE).into_bytes(),
                mode,
            });
        }
        Ok(vec![c])
    }

    fn paths(&self, _p: &Resolved) -> Vec<String> {
        vec![FSTAB.into()]
    }
}

// ---- mounts.tmp (Strict) ----

pub const TMP_MOUNTS: &[(&str, &str)] = &[
    (
        "/tmp",
        "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime,size=25%,mode=1777 0 0",
    ),
    (
        "/dev/shm",
        "tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime 0 0",
    ),
    (
        "/var/tmp",
        "/tmp /var/tmp none rw,bind,nosuid,nodev,noexec 0 0",
    ),
];

pub struct MountsTmp;

impl MountsTmp {
    /// Mount points not (yet) mounted `noexec,nosuid,nodev`.
    fn unmounted(ctx: &Ctx) -> Vec<&'static str> {
        let mounts = read_small(&ctx.sys, "/proc/mounts");
        TMP_MOUNTS
            .iter()
            .map(|(mp, _)| *mp)
            .filter(|mp| {
                !mounts.lines().any(|l| {
                    let f: Vec<&str> = l.split_whitespace().collect();
                    f.get(1) == Some(mp)
                        && f.get(3).is_some_and(|o| {
                            let o: Vec<&str> = o.split(',').collect();
                            ["noexec", "nosuid", "nodev"].iter().all(|x| o.contains(x))
                        })
                })
            })
            .collect()
    }
}

impl Module for MountsTmp {
    fn id(&self) -> &'static str {
        "mounts.tmp"
    }
    fn title(&self) -> &'static str {
        "/tmp, /dev/shm, /var/tmp mounted noexec,nosuid,nodev"
    }
    fn weight(&self) -> u8 {
        4
    }

    fn check(&self, ctx: &Ctx) -> Result<Status, OpError> {
        let plan = self.plan(ctx)?;
        if !plan.is_empty() {
            return Ok(status_of(&plan));
        }
        let left = Self::unmounted(ctx);
        Ok(if left.is_empty() {
            Status::Compliant
        } else {
            Status::PendingReboot(format!("{} mounted at the next reboot", left.join(", ")))
        })
    }

    fn plan(&self, ctx: &Ctx) -> Result<Vec<Change>, OpError> {
        let old = read_text(&ctx.sys, FSTAB)?;
        let mut text = old.clone();
        for (mp, line) in TMP_MOUNTS {
            if !fstab_has(&text, line) {
                text = fstab_with(&text, 1, mp, line);
            }
        }
        if text == old {
            return Ok(Vec::new());
        }
        let mode = read_file(&ctx.sys, FSTAB)?.map_or(0o644, |f| f.1);
        let mut actions = vec![Action::Write {
            path: FSTAB.into(),
            content: text.clone().into_bytes(),
            mode,
        }];
        // /dev/shm can be tightened live; /tmp and /var/tmp at boot (a
        // live mount would hide files in use).
        let remount = Cmd::new(MOUNT, ["-o", "remount,nosuid,nodev,noexec", "/dev/shm"]);
        let mut diff = line_diff(&old, &text);
        diff.push_str(&format!("$ {}\n", remount.display()));
        actions.push(Action::Run(remount));
        Ok(vec![Change {
            module: self.id(),
            description: format!("{FSTAB}: tmpfs /tmp, /dev/shm, /var/tmp noexec,nosuid,nodev"),
            diff,
            actions,
        }])
    }

    fn paths(&self, _p: &Resolved) -> Vec<String> {
        vec![FSTAB.into()]
    }
}

// ---- cron.allow (Strict) ----

pub const CRON_ALLOW: &str = "/etc/cron.allow";
pub const AT_ALLOW: &str = "/etc/at.allow";

pub struct CronAllow;

impl Module for CronAllow {
    fn id(&self) -> &'static str {
        "cron.allow"
    }
    fn title(&self) -> &'static str {
        "cron and at restricted to an allow-list"
    }
    fn weight(&self) -> u8 {
        2
    }

    fn plan(&self, ctx: &Ctx) -> Result<Vec<Change>, OpError> {
        let mut users = String::from("root\n");
        if let Some(a) = &ctx.profile.admin {
            users.push_str(&a.name);
            users.push('\n');
        }
        let mut plan = Vec::new();
        plan.extend(file_change(&ctx.sys, self.id(), CRON_ALLOW, &users, 0o640)?);
        plan.extend(file_change(&ctx.sys, self.id(), AT_ALLOW, "root\n", 0o640)?);
        Ok(plan)
    }

    fn paths(&self, _p: &Resolved) -> Vec<String> {
        vec![CRON_ALLOW.into(), AT_ALLOW.into()]
    }
}
