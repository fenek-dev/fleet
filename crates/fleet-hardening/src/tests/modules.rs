use super::*;
use crate::module::{Action, Status};
use crate::modules::{access, kernel, network, roles, ssh, system};
use fleet_ops::runner::CommandOutput;
use fleet_proto::ErrorCode;
use fleet_proto::args::{FirewallMode, FwChain};

const SYSTEMCTL: &str = "/usr/bin/systemctl";

// ---- ssh.hardening ----

#[test]
fn ssh_plan_apply_idempotent() {
    let env = Env::new().with_admin();
    let mut c = ctx(&env, baseline(), facts());
    let m = ssh::SshHardening;
    assert!(matches!(m.check(&c).unwrap(), Status::Drifted(_)));
    // An old drop-in of an earlier agent is removed.
    env.put(ssh::OLD_FLEET_CONF, "PermitRootLogin yes\n");
    env.ok(ssh::SSHD, &["-t"]);
    env.ok(SYSTEMCTL, &["try-reload-or-restart", "--", "ssh.service"]);
    env.expect_sshd_t(&baseline());
    let plan = plan_apply(&m, &mut c);
    assert_eq!(plan.len(), 2);
    assert_done(&env);
    assert!(env.read(ssh::OLD_FLEET_CONF).is_none());
    assert!(ssh::FLEET_CONF.ends_with("/00-fleet.conf"));
    let conf = env.read(ssh::FLEET_CONF).unwrap();
    for line in [
        "PermitRootLogin no",
        "PasswordAuthentication no",
        "KbdInteractiveAuthentication no",
        "AuthenticationMethods publickey",
        "AuthorizedKeysFile /etc/fleet/authorized_keys/%u",
        "PermitUserEnvironment no",
        "LogLevel VERBOSE",
        "AllowUsers ops",
        "MaxAuthTries 3",
        "LoginGraceTime 20",
        "MaxSessions 10",
        "AllowTcpForwarding no",
        "AllowStreamLocalForwarding no",
        "PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,ssh-ed25519",
        // sntrup is installed, mlkem isn't.
        "KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org",
    ] {
        assert!(conf.lines().any(|l| l == line), "missing {line}");
    }
    assert_eq!(env.mode(ssh::FLEET_CONF), 0o644);
    assert!(m.plan(&c).unwrap().is_empty());
    assert_eq!(m.check(&c).unwrap(), Status::Compliant);
    // Files in place but sshd's effective value differs (e.g. a Match
    // block or an earlier drop-in): drifted.
    let mut eff = crate::facts::parse_sshd_t(&sshd_t_output(&baseline()));
    eff.retain(|(k, _)| k != "permitrootlogin");
    eff.push(("permitrootlogin".into(), "yes".into()));
    c.facts.sshd_effective = Some(eff);
    assert!(matches!(m.check(&c).unwrap(), Status::Drifted(d) if d.contains("permitrootlogin")));
}

#[test]
fn ssh_apply_fails_when_effective_config_differs() {
    let env = Env::new().with_admin();
    let mut c = ctx(&env, baseline(), facts());
    let m = ssh::SshHardening;
    env.ok(ssh::SSHD, &["-t"]);
    env.ok(SYSTEMCTL, &["try-reload-or-restart", "--", "ssh.service"]);
    env.runner.expect(
        ssh::SSHD,
        &["-T", "-C", "user=ops,host=localhost,addr=127.0.0.1"],
        Ok(CommandOutput::ok(sshd_t_output(&baseline()).replace(
            "allowusers ops\n",
            "allowusers ops\nallowusers eve\n",
        ))),
    );
    let plan = m.plan(&c).unwrap();
    let e = block(m.apply(&mut c, &plan)).unwrap_err();
    assert!(e.detail().unwrap().contains("allowusers"), "{e:?}");
    assert_done(&env);
}

#[test]
fn ssh_include_moves_before_first_directive() {
    let main = "# comment\nPort 2222\nInclude /etc/ssh/sshd_config.d/*.conf\nUsePAM yes\nMatch User x\n  Include /etc/ssh/sshd_config.d/*.conf\n";
    assert!(!ssh::include_first(main));
    let new = ssh::with_include_first(main);
    assert_eq!(
        new,
        "Include /etc/ssh/sshd_config.d/*.conf\n# comment\nPort 2222\nUsePAM yes\nMatch User x\n  Include /etc/ssh/sshd_config.d/*.conf\n"
    );
    assert!(ssh::include_first(&new));
    assert!(ssh::include_first(
        "# x\n\nInclude /etc/ssh/sshd_config.d/*.conf\nPort 22\n"
    ));
}

#[test]
fn ssh_kex_prefers_mlkem_when_supported() {
    let k: Vec<String> = [
        "mlkem768x25519-sha256",
        "sntrup761x25519-sha512@openssh.com",
        "curve25519-sha256",
    ]
    .map(String::from)
    .to_vec();
    assert_eq!(
        ssh::kex(&k),
        "mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org"
    );
    assert_eq!(
        ssh::kex(&[]),
        "curve25519-sha256,curve25519-sha256@libssh.org"
    );
}

#[test]
fn ssh_adds_missing_include() {
    let env = Env::new().with_admin();
    env.put(ssh::SSHD_CONFIG, "Port 22\n");
    let c = ctx(&env, baseline(), facts());
    let plan = ssh::SshHardening.plan(&c).unwrap();
    assert_eq!(plan.len(), 2);
    assert!(matches!(&plan[0].actions[0], Action::Write { content, .. }
        if content.starts_with(b"Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n")));
}

#[test]
fn ssh_refuses_without_roster_keys() {
    let env = Env::new().with_admin();
    env.put("/etc/fleet/authorized_keys/ops", "ssh-ed25519 AAAA extra\n");
    let mut c = ctx(&env, baseline(), facts());
    let m = ssh::SshHardening;
    let plan = m.plan(&c).unwrap();
    let e = block(m.apply(&mut c, &plan)).unwrap_err();
    assert_eq!(e.code(), ErrorCode::PolicyDenied);
    assert!(env.read(ssh::FLEET_CONF).is_none());
    assert!(env.runner.calls().is_empty());
}

#[test]
fn ssh_failed_validation_restores() {
    let env = Env::new().with_admin();
    env.put(ssh::FLEET_CONF, "# old\n");
    let mut c = ctx(&env, baseline(), facts());
    let m = ssh::SshHardening;
    env.runner
        .expect(ssh::SSHD, &["-t"], Ok(CommandOutput::exit(255)));
    let plan = m.plan(&c).unwrap();
    let e = block(m.apply(&mut c, &plan)).unwrap_err();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    assert_eq!(env.read(ssh::FLEET_CONF).unwrap(), "# old\n");
    // No reload after a failed `sshd -t`.
    assert_eq!(env.runner.calls().len(), 1);
}

#[test]
fn module_revert_restores_files() {
    let env = Env::new().with_admin();
    let mut c = ctx(&env, baseline(), facts());
    let m = ssh::SshHardening;
    env.ok(ssh::SSHD, &["-t"]);
    env.ok(SYSTEMCTL, &["try-reload-or-restart", "--", "ssh.service"]);
    env.expect_sshd_t(&baseline());
    let plan = m.plan(&c).unwrap();
    let applied = block(m.apply(&mut c, &plan)).unwrap();
    assert!(env.read(ssh::FLEET_CONF).is_some());
    env.ok(ssh::SSHD, &["-t"]);
    env.ok(SYSTEMCTL, &["try-reload-or-restart", "--", "ssh.service"]);
    block(m.revert(&mut c, &applied)).unwrap();
    assert!(env.read(ssh::FLEET_CONF).is_none());
    assert_done(&env);
}

// ---- admin ----

#[test]
fn admin_user_created_with_password_hash() {
    let env = Env::new();
    env.put("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n");
    env.put("/etc/group", "sudo:x:27:\n");
    env.put("/etc/shadow", "root:*:1:0:99999:7:::\n");
    let hash = "$y$j9T$abcdefghijklmnop$ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abc";
    let mut p = baseline();
    admin(&mut p, Some(hash));
    let mut c = ctx(&env, p, facts());
    let m = access::AdminUser;
    env.ok(
        access::USERADD,
        &[
            "--create-home",
            "--user-group",
            "--groups",
            "sudo",
            "--shell",
            "/bin/bash",
            "--comment",
            "Fleet admin",
            "--",
            "ops",
        ],
    );
    env.ok(access::CHPASSWD, &["--encrypted"]);
    let plan = plan_apply(&m, &mut c);
    assert_done(&env);
    // The hash goes over stdin, never argv, and never into the diff.
    let calls = env.runner.calls();
    assert_eq!(
        calls[1].stdin.as_deref(),
        Some(format!("ops:{hash}\n").as_bytes())
    );
    assert!(
        plan.iter()
            .all(|c| !c.diff.contains(hash) && !c.description.contains(hash))
    );
    assert!(!format!("{plan:?}").contains(hash));
    // As useradd/chpasswd would leave it: nothing left to do.
    env.put(
        "/etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\nops:x:1000:1000::/home/ops:/bin/bash\n",
    );
    env.put("/etc/group", "sudo:x:27:ops\n");
    env.put("/etc/shadow", &format!("ops:{hash}:1:0:99999:7:::\n"));
    assert!(m.plan(&c).unwrap().is_empty());
    // No roster keys yet: drifted, not fixable by this module.
    assert!(matches!(m.check(&c).unwrap(), Status::Drifted(d) if d.contains("roster")));
}

#[test]
fn admin_user_not_applicable_without_admin() {
    let env = Env::new();
    let mut p = baseline();
    p.admin = None;
    let c = ctx(&env, p, facts());
    assert!(matches!(
        access::AdminUser.check(&c).unwrap(),
        Status::NotApplicable(_)
    ));
    assert!(matches!(
        ssh::SshHardening.check(&c).unwrap(),
        Status::NotApplicable(_)
    ));
}

#[test]
fn admin_shell_files_root_owned() {
    let env = Env::new().with_admin();
    env.put("/home/ops/.bashrc", "alias ll='ls -l'\n");
    {
        use std::os::unix::fs::PermissionsExt;
        let p = env.host("/home/ops/.bashrc");
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut c = ctx(&env, baseline(), facts());
    let m = access::AdminShell;
    let plan = plan_apply(&m, &mut c);
    assert_eq!(plan.len(), access::SHELL_FILES.len());
    assert_eq!(env.read("/home/ops/.profile").unwrap(), access::PROFILE);
    assert_eq!(env.read("/home/ops/.bashrc").unwrap(), "alias ll='ls -l'\n");
    for f in access::SHELL_FILES {
        assert_eq!(env.mode(&format!("/home/ops/{f}")), 0o644, "{f}");
    }
    assert!(m.plan(&c).unwrap().is_empty());
}

#[test]
fn admin_shell_immutable_in_strict_only() {
    let env = Env::new().with_admin();
    let imm = |p| {
        let c = ctx(&env, p, facts());
        access::AdminShell
            .plan(&c)
            .unwrap()
            .iter()
            .flat_map(|ch| ch.actions.clone())
            .all(|a| {
                matches!(
                    a,
                    Action::RootOwn {
                        immutable: true,
                        ..
                    }
                )
            })
    };
    assert!(imm(strict()));
    assert!(!imm(baseline()));
}

#[test]
fn admin_shell_refuses_symlink() {
    let env = Env::new().with_admin();
    env.put("/etc/secret", "s\n");
    {
        use std::os::unix::fs::PermissionsExt;
        let p = env.host("/etc/secret");
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::os::unix::fs::symlink(env.host("/etc/secret"), env.host("/home/ops/.bashrc")).unwrap();
    let mut c = ctx(&env, baseline(), facts());
    let m = access::AdminShell;
    let plan = m.plan(&c).unwrap();
    assert!(block(m.apply(&mut c, &plan)).is_err());
    // The symlink's target was not chmod'ed through the link.
    assert_eq!(env.mode("/etc/secret"), 0o600);
    assert_eq!(env.read("/etc/secret").unwrap(), "s\n");
}

#[test]
fn sudo_policy_validates_and_drops_cloud_init_grant() {
    let env = Env::new().with_admin();
    env.put(access::SUDOERS_CLOUD_INIT, "ops ALL=(ALL) NOPASSWD:ALL\n");
    let mut p = strict();
    admin(&mut p, Some("$6$saltsalt$abcdefghijklmnopqrstuv"));
    let mut c = ctx(&env, p, facts());
    let m = access::SudoPolicy;
    env.ok(access::VISUDO, &["-c", "-q"]);
    plan_apply(&m, &mut c);
    assert_done(&env);
    let s = env.read(access::SUDOERS_FLEET).unwrap();
    assert!(s.contains("Defaults use_pty") && s.contains("log_input, log_output"));
    assert_eq!(env.mode(access::SUDOERS_FLEET), 0o440);
    assert!(env.read(access::SUDOERS_CLOUD_INIT).is_none());
    assert!(m.plan(&c).unwrap().is_empty());
    assert_eq!(m.check(&c).unwrap(), Status::Compliant);
    // Someone else's passwordless grant for the admin's group: reported,
    // never removed. One for another user: fine.
    env.put("/etc/sudoers.d/50-ops", "%sudo ALL=(ALL) NOPASSWD: ALL\n");
    env.put("/etc/sudoers.d/60-web", "web ALL=(ALL) NOPASSWD: ALL\n");
    env.put("/etc/sudoers.d/70-x.bak", "ops ALL=(ALL) NOPASSWD: ALL\n");
    assert!(m.plan(&c).unwrap().is_empty());
    assert!(matches!(m.check(&c).unwrap(),
        Status::Drifted(d) if d.contains("/etc/sudoers.d/50-ops") && !d.contains("60-web") && !d.contains("70-x")));
}

#[test]
fn sudo_policy_keeps_cloud_grant_until_a_password_is_set() {
    let env = Env::new().with_admin();
    env.put(
        "/etc/sudoers.d/google_sudoers",
        "ops ALL=(ALL:ALL) NOPASSWD:ALL\n",
    );
    let c = ctx(&env, baseline(), facts());
    let plan = access::SudoPolicy.plan(&c).unwrap();
    assert!(
        !plan
            .iter()
            .any(|ch| ch.description.contains("google_sudoers"))
    );
    let mut p = baseline();
    admin(&mut p, Some("$6$saltsalt$abcdefghijklmnopqrstuv"));
    let c = ctx(&env, p, facts());
    let plan = access::SudoPolicy.plan(&c).unwrap();
    assert!(
        plan.iter()
            .any(|ch| ch.description.contains("google_sudoers")),
        "{plan:?}"
    );
}

#[test]
fn accounts_lock_system_accounts() {
    let env = Env::new();
    env.put("/etc/login.defs", "UID_MIN 1000\n");
    env.put(
        "/etc/passwd",
        "root:x:0:0::/root:/bin/bash\ndaemon:x:1:1::/:/usr/sbin/nologin\ngames:x:5:60::/:/bin/sh\nsync:x:4:65534::/bin:/bin/sync\nops:x:1000:1000::/home/ops:/bin/bash\n",
    );
    env.put("/etc/shadow", "daemon:*:1::::::\ngames:$6$x$y:1::::::\n");
    let mut c = ctx(&env, baseline(), facts());
    env.ok(
        access::USERMOD,
        &["--shell", "/usr/sbin/nologin", "--", "games"],
    );
    env.ok(access::USERMOD, &["--lock", "--", "games"]);
    let plan = plan_apply(&access::AccountsLock, &mut c);
    assert_eq!(plan.len(), 2);
    assert_done(&env);
}

#[test]
fn accounts_lock_skips_admin_and_roster_users() {
    let env = Env::new().with_admin();
    env.put("/etc/login.defs", "UID_MIN 1000\n");
    // A (misconfigured) admin and a roster user below UID_MIN.
    env.put(
        "/etc/passwd",
        "root:x:0:0::/root:/bin/bash\nops:x:999:999::/home/ops:/bin/bash\ndeploy:x:998:998::/home/deploy:/bin/bash\n",
    );
    env.put("/etc/shadow", "ops:$6$x$y:1::::::\ndeploy:$6$x$y:1::::::\n");
    env.put(
        "/etc/fleet/authorized_keys/deploy",
        &format!(
            "{}\necdsa-sha2-nistp256 AAAA fleet-device-x\n{}\n",
            fleet_ops::users::authorized_keys::BEGIN,
            fleet_ops::users::authorized_keys::END
        ),
    );
    let c = ctx(&env, baseline(), facts());
    assert!(access::AccountsLock.plan(&c).unwrap().is_empty());
}

#[test]
fn admin_must_be_a_regular_login_account() {
    let cases = [
        // (passwd line, /etc/shells, reason)
        ("ops:x:999:999::/home/ops:/bin/bash", "", "uid"),
        ("ops:x:0:0::/home/ops:/bin/bash", "", "uid"),
        (
            "ops:x:1000:1000::/home/ops:/usr/sbin/nologin",
            "",
            "login shell",
        ),
        (
            "ops:x:1000:1000::/home/ops:/bin/zsh",
            "/bin/sh\n/bin/bash\n",
            "login shell",
        ),
    ];
    for (line, shells, want) in cases {
        let env = Env::new().with_admin();
        env.put("/etc/login.defs", "UID_MIN 1000\n");
        env.put(
            "/etc/passwd",
            &format!("root:x:0:0::/root:/bin/bash\n{line}\n"),
        );
        if !shells.is_empty() {
            env.put("/etc/shells", shells);
        }
        let c = ctx(&env, baseline(), facts());
        let e = access::AdminUser.plan(&c).unwrap_err();
        assert_eq!(e.code(), ErrorCode::PolicyDenied, "{line}");
        assert!(e.detail().unwrap().contains(want), "{line}: {e:?}");
        assert!(matches!(
            access::AdminUser.check(&c).unwrap(),
            Status::Drifted(_)
        ));
        assert!(access::AdminShell.plan(&c).is_err());
    }
    // A fleet* account is never the admin.
    let env = Env::new().with_admin();
    let mut p = baseline();
    p.admin.as_mut().unwrap().name = "fleet-exec".into();
    let c = ctx(&env, p, facts());
    assert!(access::AdminUser.plan(&c).is_err());
    // /etc/shells listing the shell is fine.
    let env = Env::new().with_admin();
    env.put("/etc/shells", "/bin/sh\n/bin/bash\n");
    let c = ctx(&env, baseline(), facts());
    assert!(access::admin_problem(&c, "ops").unwrap().is_none());
}

// ---- kernel ----

#[test]
fn sysctl_file_and_live_values() {
    let env = Env::new();
    let mut c = ctx(&env, baseline(), facts());
    let m = kernel::Sysctl;
    env.ok(kernel::SYSCTL, &["--ignore", "--system"]);
    plan_apply(&m, &mut c);
    let conf = env.read(kernel::SYSCTL_CONF).unwrap();
    assert!(
        conf.contains("kernel.kptr_restrict = 2\n") && conf.contains("net.ipv4.ip_forward = 0\n")
    );
    assert!(m.plan(&c).unwrap().is_empty());
    // A live value that differs: reload only.
    env.put("/proc/sys/kernel/kptr_restrict", "0\n");
    let plan = m.plan(&c).unwrap();
    assert_eq!(plan.len(), 1);
    assert!(plan[0].diff.contains("kernel.kptr_restrict = 0 (want 2)"));
    assert!(matches!(&plan[0].actions[..], [Action::Run(_)]));
}

#[test]
fn kernel_modules_blacklist_and_role_load() {
    let env = Env::new();
    let mut c = ctx(
        &env,
        with_roles(&[fleet_proto::op::ProfileRole::Docker]),
        facts(),
    );
    let m = kernel::KernelModules;
    env.ok(kernel::MODPROBE, &["--", "br_netfilter"]);
    plan_apply(&m, &mut c);
    assert_done(&env);
    let bl = env.read(kernel::MODPROBE_CONF).unwrap();
    assert!(bl.contains("blacklist dccp\ninstall dccp /bin/false\n"));
    assert_eq!(
        env.read(kernel::MODULES_LOAD).unwrap().lines().last(),
        Some("br_netfilter")
    );
    assert!(m.plan(&c).unwrap().is_empty());
}

// ---- system ----

#[test]
fn file_only_modules_idempotent() {
    let env = Env::new();
    env.put("/etc/pam.d/sshd", "@include common-session\n");
    let mut c = ctx(&env, strict(), facts());
    env.ok(SYSTEMCTL, &["restart", "--", "systemd-journald.service"]);
    env.ok(
        crate::exec::FINDMNT,
        &["--verify", "--tab-file", crate::exec::FSTAB_CHECK],
    );
    env.ok(
        "/usr/bin/mount",
        &["-o", "remount,nosuid,nodev,noexec", "/dev/shm"],
    );
    let mods: [&dyn Module; 5] = [
        &kernel::Coredump,
        &system::Journald,
        &system::Umask,
        &system::CronAllow,
        &system::MountsTmp,
    ];
    for m in mods {
        let plan = plan_apply(m, &mut c);
        assert!(!plan.is_empty(), "{}", m.id());
        assert!(m.plan(&c).unwrap().is_empty(), "{} not idempotent", m.id());
    }
    assert_done(&env);
    assert!(
        env.read("/etc/pam.d/sshd")
            .unwrap()
            .ends_with(&format!("{}\n", system::UMASK_LINE))
    );
    assert!(
        env.read(system::JOURNALD_CONF)
            .unwrap()
            .contains("SystemMaxUse=1G")
    );
    assert_eq!(env.read(system::CRON_ALLOW).unwrap(), "root\nops\n");
    // fstab written, /tmp not mounted yet: pending reboot.
    assert!(matches!(
        system::MountsTmp.check(&c).unwrap(),
        Status::PendingReboot(_)
    ));
    env.put(
        "/proc/mounts",
        "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\ntmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec 0 0\n/dev/sda1 /var/tmp ext4 rw,nosuid,nodev,noexec 0 0\n",
    );
    assert_eq!(system::MountsTmp.check(&c).unwrap(), Status::Compliant);
}

#[test]
fn mounts_tmp_keeps_separate_filesystems_and_verifies_first() {
    let env = Env::new();
    let fstab = "UUID=1 / ext4 defaults 0 1\nUUID=2 /var/tmp ext4 defaults 0 2\n";
    env.put(system::FSTAB, fstab);
    let mut c = ctx(&env, strict(), facts());
    // A failing `findmnt --verify`: nothing written.
    env.runner.expect(
        crate::exec::FINDMNT,
        &["--verify", "--tab-file", crate::exec::FSTAB_CHECK],
        Ok(CommandOutput::exit(1)),
    );
    let plan = system::MountsTmp.plan(&c).unwrap();
    let e = block(system::MountsTmp.apply(&mut c, &plan)).unwrap_err();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    assert_eq!(env.read(system::FSTAB).unwrap(), fstab);
    env.ok(
        crate::exec::FINDMNT,
        &["--verify", "--tab-file", crate::exec::FSTAB_CHECK],
    );
    env.ok(
        "/usr/bin/mount",
        &["-o", "remount,nosuid,nodev,noexec", "/dev/shm"],
    );
    plan_apply(&system::MountsTmp, &mut c);
    assert_done(&env);
    let out = env.read(system::FSTAB).unwrap();
    // The /var/tmp partition stays; /tmp and /dev/shm are added.
    assert!(out.contains("UUID=2 /var/tmp ext4 defaults 0 2\n"));
    assert!(!out.contains("/tmp /var/tmp none"));
    assert!(out.contains("tmpfs /tmp tmpfs"));
    assert!(matches!(system::MountsTmp.check(&c).unwrap(),
        Status::Drifted(d) if d.contains("/var/tmp")));
}

#[test]
fn fstab_edit_keeps_other_lines() {
    let t = "# comment /tmp\nUUID=1 / ext4 defaults 0 1\ntmpfs /tmp tmpfs defaults 0 0\n";
    let out = system::fstab_with(t, 1, "/tmp", "tmpfs /tmp tmpfs rw,noexec 0 0");
    assert_eq!(
        out,
        "# comment /tmp\nUUID=1 / ext4 defaults 0 1\ntmpfs /tmp tmpfs rw,noexec 0 0\n"
    );
}

#[test]
fn auditd_immutable_is_pending_reboot() {
    let env = Env::new();
    let mut f = facts();
    f.packages.insert("auditd".into());
    f.units.insert("auditd.service".into(), running());
    f.audit_enabled = Some(2);
    let mut c = ctx(&env, strict(), f);
    let m = system::Auditd;
    assert!(matches!(m.check(&c).unwrap(), Status::PendingReboot(_)));
    // Apply writes the files and records the reboot; no augenrules.
    plan_apply(&m, &mut c);
    assert!(env.runner.calls().is_empty());
    assert!(env.read(system::AUDIT_FINAL).unwrap().contains("-e 2"));
    assert_eq!(env.read(system::AUDIT_REBOOT_MARKER).unwrap(), "boot-1\n");
    assert!(m.plan(&c).unwrap().is_empty());
    assert!(matches!(m.check(&c).unwrap(), Status::PendingReboot(_)));
    // After the reboot (new boot id): compliant.
    c.facts.boot_id = "boot-2".into();
    assert_eq!(m.check(&c).unwrap(), Status::Compliant);
}

#[test]
fn auditd_baseline_loads_rules() {
    let env = Env::new();
    let mut f = facts();
    f.packages.insert("auditd".into());
    f.audit_enabled = Some(1);
    env.put(system::AUDIT_FINAL, "-e 2\n");
    let mut c = ctx(&env, baseline(), f);
    env.ok(system::AUGENRULES, &["--load"]);
    env.ok(SYSTEMCTL, &["enable", "--now", "--", "auditd.service"]);
    plan_apply(&system::Auditd, &mut c);
    assert_done(&env);
    assert!(env.read(system::AUDIT_FINAL).is_none());
    assert_eq!(env.mode(system::AUDIT_RULES), 0o640);
}

#[test]
fn services_disable_only_present_units() {
    let env = Env::new();
    let mut f = facts();
    f.units.insert("avahi-daemon.service".into(), running());
    f.units.insert(
        "cups.service".into(),
        crate::facts::UnitState {
            load: "not-found".into(),
            ..Default::default()
        },
    );
    f.packages.insert("telnetd".into());
    let mut c = ctx(&env, baseline(), f);
    env.expect_spec(
        &fleet_ops::packages::apt_cmd(
            7,
            &["purge".into(), "telnetd".into()],
            std::time::Duration::from_secs(1800),
        ),
        Ok(CommandOutput::ok("")),
    );
    env.ok(
        SYSTEMCTL,
        &["disable", "--now", "--", "avahi-daemon.service"],
    );
    let plan = plan_apply(&system::ServicesDisable, &mut c);
    assert_eq!(plan.len(), 2);
    assert_done(&env);
}

#[test]
fn updates_with_reboot_window() {
    let env = Env::new();
    let mut p = baseline();
    p.reboot_window = Some(crate::profile::RebootWindow::parse("Sun 04:00-05:00 UTC").unwrap());
    let mut f = facts();
    f.packages
        .extend(["unattended-upgrades".into(), "needrestart".into()]);
    f.units
        .insert("unattended-upgrades.service".into(), running());
    let mut c = ctx(&env, p, f);
    env.ok(SYSTEMCTL, &["daemon-reload"]);
    env.ok(SYSTEMCTL, &["enable", "--now", "--", system::REBOOT_UNIT]);
    plan_apply(&system::Updates, &mut c);
    assert_done(&env);
    let t = env.read(system::REBOOT_TIMER).unwrap();
    assert!(t.contains("OnCalendar=Sun *-*-* 04:00:00 UTC\nRandomizedDelaySec=55min\n"));
    assert!(
        env.read(system::REBOOT_SERVICE)
            .unwrap()
            .contains("ConditionPathExists=/run/reboot-required")
    );
    assert!(
        env.read(system::NEEDRESTART_CONF)
            .unwrap()
            .contains("$nrconf{restart} = 'a';")
    );
    c.facts.units.insert(system::REBOOT_UNIT.into(), running());
    assert!(system::Updates.plan(&c).unwrap().is_empty());
}

#[test]
fn updates_installs_packages_once_updated() {
    let env = Env::new();
    let mut c = ctx(&env, baseline(), facts());
    let t = |s| std::time::Duration::from_secs(s);
    env.expect_spec(
        &fleet_ops::packages::apt_cmd(7, &["update".into()], t(600)),
        Ok(CommandOutput::ok("")),
    );
    env.expect_spec(
        &fleet_ops::packages::apt_cmd(
            7,
            &[
                "install",
                "--no-install-recommends",
                "unattended-upgrades",
                "needrestart",
            ]
            .map(String::from),
            t(1800),
        ),
        Ok(CommandOutput::ok("")),
    );
    env.ok(
        SYSTEMCTL,
        &["enable", "--now", "--", "unattended-upgrades.service"],
    );
    plan_apply(&system::Updates, &mut c);
    assert_done(&env);
    assert!(c.apt_updated);
}

#[test]
fn swap_file_created() {
    let env = Env::new();
    env.put(system::FSTAB, "UUID=1 / ext4 defaults 0 1\n");
    let mut c = ctx(&env, baseline(), facts());
    env.ok(system::FALLOCATE, &["--length", "2147483648", "/swapfile"]);
    env.ok(system::CHMOD, &["0600", "/swapfile"]);
    env.ok(system::MKSWAP, &["/swapfile"]);
    env.ok(system::SWAPON, &["/swapfile"]);
    env.ok(
        crate::exec::FINDMNT,
        &["--verify", "--tab-file", crate::exec::FSTAB_CHECK],
    );
    plan_apply(&system::Swap, &mut c);
    assert_done(&env);
    assert!(env.read(crate::exec::FSTAB_CHECK).is_none());
    assert!(
        env.read(system::FSTAB)
            .unwrap()
            .ends_with("/swapfile none swap sw 0 0\n")
    );
    c.facts.swap_active = true;
    assert!(system::Swap.plan(&c).unwrap().is_empty());
    assert_eq!(system::swap_bytes(16 * 1024 * 1024), 4 << 30);
}

#[test]
fn apparmor_disabled_in_kernel_not_fixable() {
    let env = Env::new();
    let mut f = facts();
    f.apparmor_enabled = Some(false);
    let c = ctx(&env, baseline(), f);
    assert!(matches!(
        system::AppArmor.check(&c).unwrap(),
        Status::Drifted(_)
    ));
    assert!(!system::AppArmor.fixable(&c));
    assert!(system::AppArmor.plan(&c).unwrap().is_empty());
}

#[test]
fn time_sets_utc() {
    let env = Env::new();
    let mut f = facts();
    f.packages.insert("chrony".into());
    f.units.insert("chrony.service".into(), running());
    let mut c = ctx(&env, baseline(), f);
    env.ok(system::TIMEDATECTL, &["set-timezone", "UTC"]);
    plan_apply(&system::Time, &mut c);
    std::fs::create_dir_all(env.host("/etc")).unwrap();
    std::os::unix::fs::symlink("/usr/share/zoneinfo/Etc/UTC", env.host("/etc/localtime")).unwrap();
    assert!(system::Time.plan(&c).unwrap().is_empty());
    assert_done(&env);
}

// ---- firewall ----

#[test]
fn firewall_managed_with_ssh_and_role_ports() {
    let env = Env::new().with_admin();
    let mut p = with_roles(&[fleet_proto::op::ProfileRole::Web]);
    p.allow_from = vec!["203.0.113.0/24".parse().unwrap()];
    let mut c = ctx(&env, p, facts());
    let m = network::FirewallBaseline;
    let plan = m.plan(&c).unwrap();
    let Action::Firewall(set) = &plan[0].actions[0] else {
        panic!("not a firewall change")
    };
    assert_eq!(set.mode, FirewallMode::Managed);
    assert_eq!(set.rules.len(), 3);
    let ssh = &set.rules[0];
    assert_eq!(ssh.comment.as_str(), "profile:ssh");
    // allow_from is sshd's job (the lockout check wants SSH from anywhere).
    assert_eq!(ssh.source, None);
    assert_eq!(ssh.rate_limit.unwrap().per_minute, 30);
    assert!(
        plan[0]
            .diff
            .contains("+ Input accept tcp/22 from any [profile:ssh]")
    );
    let conf = ssh::config("ops", &c.profile, &[]);
    assert!(conf.contains("\nAllowUsers ops@203.0.113.0/24\n"));
    // Apply: re-read the table, then one nft transaction.
    env.runner.expect(
        fleet_ops::firewall::NFT,
        &["-j", "list", "table", "inet", "fleet"],
        Ok(CommandOutput {
            code: Some(1),
            stdout: Vec::new(),
            stderr: b"Error: No such file or directory".to_vec(),
            truncated: false,
        }),
    );
    env.ok(fleet_ops::firewall::NFT, &["-f", "-"]);
    block(m.apply(&mut c, &plan)).unwrap();
    assert_done(&env);
    let script = String::from_utf8(env.runner.calls()[1].stdin.clone().unwrap()).unwrap();
    assert!(script.contains("table inet fleet") && script.contains("policy drop"));
}

#[test]
fn firewall_keeps_operator_rules() {
    let env = Env::new().with_admin();
    let c0 = ctx(&env, baseline(), facts());
    let Action::Firewall(mut set) =
        network::FirewallBaseline.plan(&c0).unwrap()[0].actions[0].clone()
    else {
        panic!()
    };
    let mut op_rule = set.rules[0].clone();
    op_rule.comment = fleet_proto::args::FwComment::new("r0 mesh").unwrap();
    op_rule.chain = FwChain::Input;
    op_rule.rate_limit = None;
    op_rule.ports = vec![fleet_proto::args::PortRange::single(
        fleet_proto::args::Port::new(51820).unwrap(),
    )];
    set.rules.insert(0, op_rule.clone());
    // A table that already is exactly that: compliant, rule kept.
    let parsed = fleet_ops::firewall::parse::Parsed {
        mode: FirewallMode::Managed,
        model: Some(set.clone()),
        unrecognized: None,
        banned: 0,
        version: 1,
        cleanup: Ok(Default::default()),
    };
    let mut f = facts();
    f.firewall = Some(Ok(fleet_ops::firewall::Table::Present(parsed)));
    let c = ctx(&env, baseline(), f);
    assert!(network::FirewallBaseline.plan(&c).unwrap().is_empty());
}

#[test]
fn firewall_unrecognized_table_is_an_error() {
    let env = Env::new().with_admin();
    let mut f = facts();
    f.firewall = Some(Err("nft failed".into()));
    let c = ctx(&env, baseline(), f);
    assert!(network::FirewallBaseline.plan(&c).is_err());
}

// ---- roles ----

const COLONS: &str = "pub:-:4096:1:8D81803C0EBFCD88:1487788586:::-:::scESA::::::23::0:\nfpr:::::::::9DC858229FC7DD38854AE2D88D81803C0EBFCD88:\nuid:-::::1487792064::B5A08F01796E7F521861B449372D3F6ECC7B9C39::Docker Release (CE deb) <docker@docker.com>::::::::::0:\nsub:-:4096:1:7EA0A9C3F273FCD8:1487788586::::::s::::::23:\nfpr:::::::::D3306A018370199E527AE7997EA0A9C3F273FCD8:\n";

#[test]
fn gpg_primary_fingerprints() {
    assert_eq!(
        crate::exec::primary_fingerprints(COLONS),
        vec!["9DC858229FC7DD38854AE2D88D81803C0EBFCD88".to_owned()]
    );
}

fn docker_ready(f: &mut crate::facts::Facts) {
    for p in [
        "docker-ce",
        "docker-ce-cli",
        "containerd.io",
        "docker-buildx-plugin",
        "docker-compose-plugin",
    ] {
        f.packages.insert(p.into());
    }
    f.units.insert("docker.service".into(), running());
}

#[test]
fn docker_fetches_pinned_key_then_configures() {
    let env = Env::new();
    let mut f = facts();
    docker_ready(&mut f);
    f.packages
        .extend(["ca-certificates".into(), "curl".into(), "gnupg".into()]);
    let mut c = ctx(&env, with_roles(&[fleet_proto::op::ProfileRole::Docker]), f);
    let url = "https://download.docker.com/linux/debian/gpg";
    env.expect_spec(
        &crate::exec::curl_spec(url),
        Ok(CommandOutput::ok(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n",
        )),
    );
    env.expect_spec(
        &crate::exec::gpg_show_spec(Vec::new()),
        Ok(CommandOutput::ok(COLONS)),
    );
    env.ok(SYSTEMCTL, &["restart", "--", "docker.service"]);
    plan_apply(&roles::Docker, &mut c);
    assert_done(&env);
    assert!(
        env.read("/etc/apt/keyrings/fleet-docker.asc")
            .unwrap()
            .starts_with("-----BEGIN PGP")
    );
    let src = env
        .read("/etc/apt/sources.list.d/fleet-docker.sources")
        .unwrap();
    assert!(src.contains("URIs: https://download.docker.com/linux/debian\nSuites: bookworm\n"));
    assert!(src.contains("Signed-By: /etc/apt/keyrings/fleet-docker.asc"));
    let pin = env.read("/etc/apt/preferences.d/fleet-docker").unwrap();
    assert!(pin.contains("Pin: version 5:28.*"));
    // Only the role's packages come from Docker's origin; everything
    // else from it is never installed. Package-specific records first.
    assert!(pin.contains(
        "Package: containerd.io docker-buildx-plugin docker-ce docker-ce-cli docker-compose-plugin\nPin: origin \"download.docker.com\"\nPin-Priority: 500\n"
    ));
    assert!(pin.ends_with("Package: *\nPin: origin \"download.docker.com\"\nPin-Priority: -1\n"));
    assert_eq!(
        env.read(roles::DAEMON_JSON).unwrap(),
        roles::DAEMON_JSON_TEXT
    );
    assert!(roles::Docker.plan(&c).unwrap().is_empty());
    // Fingerprint of the existing key read as a fact: the pinned one is
    // compliant, any other is drift and the key is fetched again.
    let key = "/etc/apt/keyrings/fleet-docker.asc".to_owned();
    c.facts.key_fingerprints.insert(
        key.clone(),
        vec!["9DC858229FC7DD38854AE2D88D81803C0EBFCD88".into()],
    );
    assert!(roles::Docker.plan(&c).unwrap().is_empty());
    c.facts
        .key_fingerprints
        .insert(key, vec!["0000000000000000000000000000000000000000".into()]);
    assert!(matches!(
        roles::Docker.check(&c).unwrap(),
        Status::Drifted(_)
    ));
    let plan = roles::Docker.plan(&c).unwrap();
    assert!(plan.iter().any(|ch| {
        ch.actions
            .iter()
            .any(|a| matches!(a, Action::FetchKey { .. }))
            && ch.description.contains("mismatch")
    }));
}

#[test]
fn gathered_key_fingerprints() {
    let env = Env::new();
    env.put("/etc/apt/keyrings/fleet-docker.asc", "key\n");
    env.expect_spec(
        &crate::exec::gpg_show_spec(b"key\n".to_vec()),
        Ok(CommandOutput::ok(COLONS)),
    );
    let want = crate::facts::Wanted {
        key_files: vec![
            "/etc/apt/keyrings/fleet-docker.asc".into(),
            "/etc/apt/keyrings/fleet-absent.asc".into(),
        ],
        ..Default::default()
    };
    let f = block(crate::facts::gather(&env.sys, &want));
    assert_eq!(f.key_fingerprints.len(), 1);
    assert_eq!(
        f.key_fingerprints["/etc/apt/keyrings/fleet-docker.asc"],
        crate::exec::primary_fingerprints(COLONS)
    );
}

#[test]
fn docker_key_with_wrong_fingerprint_is_refused() {
    let env = Env::new();
    let mut f = facts();
    docker_ready(&mut f);
    f.packages
        .extend(["ca-certificates".into(), "curl".into(), "gnupg".into()]);
    let mut c = ctx(&env, with_roles(&[fleet_proto::op::ProfileRole::Docker]), f);
    env.expect_spec(
        &crate::exec::curl_spec("https://download.docker.com/linux/debian/gpg"),
        Ok(CommandOutput::ok("key")),
    );
    env.expect_spec(
        &crate::exec::gpg_show_spec(Vec::new()),
        Ok(CommandOutput::ok(
            "pub:-:1:1:X:1:::-:\nfpr:::::::::0000000000000000000000000000000000000000:\n",
        )),
    );
    let plan = roles::Docker.plan(&c).unwrap();
    let e = block(roles::Docker.apply(&mut c, &plan)).unwrap_err();
    assert_eq!(e.code(), ErrorCode::PolicyDenied);
    assert!(env.read("/etc/apt/keyrings/fleet-docker.asc").is_none());
}

#[test]
fn web_caddy_validated_then_reloaded() {
    let env = Env::new();
    env.put("/etc/apt/keyrings/fleet-caddy.asc", "key\n");
    let mut f = facts();
    f.packages.insert("caddy".into());
    f.units.insert("caddy.service".into(), running());
    let mut c = ctx(&env, with_roles(&[fleet_proto::op::ProfileRole::Web]), f);
    env.ok(
        roles::CADDY,
        &[
            "validate",
            "--config",
            roles::CADDYFILE,
            "--adapter",
            "caddyfile",
        ],
    );
    env.ok(SYSTEMCTL, &["try-reload-or-restart", "--", "caddy.service"]);
    plan_apply(&roles::Web, &mut c);
    assert_done(&env);
    let h = env.read(roles::CADDY_SNIPPETS).unwrap();
    assert!(h.contains("Strict-Transport-Security \"max-age=31536000\"") && h.contains("-Server"));
    assert!(h.contains("max_size 16MB"));
    assert!(
        env.read("/etc/apt/sources.list.d/fleet-caddy.sources")
            .unwrap()
            .contains("Suites: any-version")
    );
    assert!(roles::Web.plan(&c).unwrap().is_empty());
}
