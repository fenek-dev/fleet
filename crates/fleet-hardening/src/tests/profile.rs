use super::Env;
use crate::modules;
use crate::profile::*;
use fleet_proto::args::{ModuleId, ProfileToml};
use fleet_proto::op::{ProfileLevel, ProfileRole, ProfileSource, ProfileSpec};

#[test]
fn builtins_parse_and_every_module_exists() {
    for level in [ProfileLevel::Baseline, ProfileLevel::Strict] {
        let p = builtin(
            level,
            &[ProfileRole::Docker, ProfileRole::Web, ProfileRole::Game],
        )
        .unwrap();
        for m in &p.modules {
            assert!(modules::by_id(m).is_some(), "{m}");
        }
        let mut uniq = p.modules.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(uniq.len(), p.modules.len());
    }
}

#[test]
fn strict_extends_baseline() {
    let b = builtin(ProfileLevel::Baseline, &[]).unwrap();
    let s = builtin(ProfileLevel::Strict, &[]).unwrap();
    assert_eq!(s.name, "strict");
    assert!(b.modules.iter().all(|m| s.modules.contains(m)));
    assert!(s.modules.iter().any(|m| m == "mounts.tmp"));
    assert_eq!(b.settings.sysctl["kernel.yama.ptrace_scope"], "1");
    assert_eq!(s.settings.sysctl["kernel.yama.ptrace_scope"], "2");
    assert!(
        s.settings.blacklist.contains("usb-storage")
            && !b.settings.blacklist.contains("usb-storage")
    );
    assert!(s.settings.auditd_immutable && !b.settings.auditd_immutable);
    assert!(s.settings.sudo_log_io);
    assert_eq!(
        (b.settings.ssh_max_sessions, s.settings.ssh_max_sessions),
        (10, 4)
    );
    assert_eq!(b.settings.journald_max_use, "1G");
}

#[test]
fn docker_role_overrides_and_exceptions() {
    let p = builtin(ProfileLevel::Baseline, &[ProfileRole::Docker]).unwrap();
    assert_eq!(p.settings.sysctl["net.ipv4.ip_forward"], "1");
    assert!(p.settings.modules_load.contains("br_netfilter"));
    assert!(p.exceptions.contains_key("sysctl.net.ipv4.ip_forward"));
    let r = p.role(ProfileRole::Docker).unwrap();
    assert_eq!(
        r.apt_repo.as_ref().unwrap().fingerprint,
        "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
    );
    // Role modules come last, in role order.
    assert_eq!(p.modules.last().map(String::as_str), Some("role.docker"));
}

#[test]
fn web_role_declares_ports() {
    let p = builtin(ProfileLevel::Baseline, &[ProfileRole::Web]).unwrap();
    let fw = &p.role(ProfileRole::Web).unwrap().firewall;
    assert_eq!(fw.len(), 2);
    assert_eq!(fw[0].comment.as_str(), "profile:web:web");
    assert!(fw.iter().all(|r| r.rate_limit.is_some()));
}

const CUSTOM: &str = r#"
[profile]
name = "web-docker-prod"
extends = "strict"
roles = ["docker", "web"]

[admin]
user = "ops"

[ssh]
allow_from = ["203.0.113.0/24", "2001:db8::/32"]

[updates]
reboot_window = "Sun 04:00-05:00 UTC"

[skip]
modules = ["kernel.modules.usb-storage", "swap", "sysctl.kernel.dmesg_restrict"]

[exceptions]
"services.cups.service" = "print server"
"#;

#[test]
fn custom_profile_parses() {
    let p = parse_custom(CUSTOM).unwrap();
    assert_eq!(p.name, "web-docker-prod");
    assert_eq!(p.level, ProfileLevel::Strict);
    assert_eq!(p.roles, vec![ProfileRole::Docker, ProfileRole::Web]);
    assert_eq!(p.admin.as_ref().unwrap().name, "ops");
    assert_eq!(p.allow_from.len(), 2);
    let w = p.reboot_window.as_ref().unwrap();
    assert_eq!(w.on_calendar(), "Sun *-*-* 04:00:00 UTC");
    assert_eq!(w.len_min, 60);
    assert!(p.is_skipped("swap"));
    assert!(!p.settings.blacklist.contains("usb-storage"));
    assert!(!p.settings.sysctl.contains_key("kernel.dmesg_restrict"));
    assert!(!p.settings.disable.iter().any(|d| d == "cups.service"));
    // The role's exception stays.
    assert!(p.exceptions.contains_key("sysctl.net.ipv4.ip_forward"));
    assert!(p.admin.as_ref().unwrap().password_hash.is_none());
}

#[test]
fn custom_profile_rejects() {
    let cases = [
        ("[profile]\nextends = \"custom\"\n", "extends"),
        (
            "[profile]\nextends = \"baseline\"\nmodules = [\"x\"]\n",
            "unknown field",
        ),
        (
            "[profile]\nextends = \"baseline\"\n[sysctl]\n\"a\" = \"1\"\n",
            "unknown field",
        ),
        (
            "[profile]\nextends = \"baseline\"\nroles = [\"k8s\"]\n",
            "role",
        ),
        (
            "[profile]\nextends = \"baseline\"\nroles = [\"web\", \"web\"]\n",
            "duplicate",
        ),
        (
            "[profile]\nextends = \"baseline\"\n[admin]\nuser = \"root\"\n",
            "root",
        ),
        (
            "[profile]\nextends = \"baseline\"\n[admin]\nuser = \"ops\"\npassword_hash = \"hunter2hunter2hunter2\"\n",
            "unknown field",
        ),
        // Only the op field carries the hash (Elevated, redacted in audit).
        (
            "[profile]\nextends = \"baseline\"\n[admin]\nuser = \"ops\"\npassword_hash = \"$y$j9T$abcdefghijklmnop$ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abc\"\n",
            "unknown field",
        ),
        (
            "[profile]\nextends = \"baseline\"\n[ssh]\nallow_from = [\"10.0.0.1/8\"]\n",
            "cidr",
        ),
        (
            "[profile]\nextends = \"baseline\"\n[skip]\nmodules = [\"nope\"]\n",
            "unknown module",
        ),
        (
            "[profile]\nextends = \"baseline\"\n[exceptions]\n\"swap\" = \"\"\n",
            "reason",
        ),
        (
            "[profile]\nextends = \"baseline\"\n[updates]\nreboot_window = \"Sun 4-5\"\n",
            "reboot window",
        ),
        (
            "[profile]\nextends = \"baseline\"\nname = \"a b\"\n",
            "name",
        ),
    ];
    for (toml, want) in cases {
        let e = parse_custom(toml).unwrap_err();
        assert!(e.0.contains(want), "{toml:?}: {e}");
    }
}

#[test]
fn reboot_window_forms() {
    assert_eq!(
        RebootWindow::parse("daily 23:30-00:30 UTC")
            .unwrap()
            .len_min,
        60
    );
    assert!(RebootWindow::parse("Sun 04:00-04:05 UTC").is_err());
    assert!(RebootWindow::parse("Sun 04:00-05:00 CET").is_err());
    assert!(RebootWindow::parse("Sunday 04:00-05:00 UTC").is_err());
}

#[test]
fn hashes() {
    assert!(valid_hash(
        "$6$rounds=5000$saltsalt$abcdefghijklmnopqrstuvwxyz"
    ));
    assert!(!valid_hash("$1$old$md5md5md5md5md5md5"));
    assert!(!valid_hash("$y$j9T$salt$hash:with:colons"));
    assert!(!valid_hash("$y$j9T$salt$hash\nroot:x"));
}

#[test]
fn resolve_detects_admin_and_checks_only() {
    let env = Env::new().with_admin();
    let spec = |only: &[&str]| ProfileSpec {
        source: ProfileSource::Builtin {
            level: ProfileLevel::Baseline,
            roles: vec![],
        },
        only: only.iter().map(|o| ModuleId::new(*o).unwrap()).collect(),
    };
    let p = resolve(&spec(&["ssh.hardening"]), &env.sys).unwrap();
    assert_eq!(p.admin.as_ref().unwrap().name, "ops");
    assert!(p.in_scope("ssh.hardening") && !p.in_scope("sysctl"));
    let e = resolve(&spec(&["mounts.tmp"]), &env.sys).unwrap_err();
    assert_eq!(e.code(), fleet_proto::ErrorCode::InvalidArgument);
    let custom = ProfileSpec {
        source: ProfileSource::Custom(ProfileToml::new("[profile]\nextends = \"nope\"\n").unwrap()),
        only: vec![],
    };
    assert!(resolve(&custom, &env.sys).is_err());
}
