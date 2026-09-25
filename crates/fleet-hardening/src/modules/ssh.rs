//! `ssh.hardening` (design §5.9, §9.4): `sshd_config.d/10-fleet.conf`,
//! validated with `sshd -t` before the reload. Phase 2: applied under
//! auto-revert and only when the admin can already log in with roster
//! keys (the lockout guard below).

use crate::module::{
    Action, Applied, Change, Cmd, Ctx, Module, Phase, Status, file_change, read_text,
};
use crate::modules::systemctl;
use crate::profile::Resolved;
use fleet_ops::handler::{LocalBoxFuture, OpError};
use fleet_ops::users::{self, authorized_keys, parse};
use fleet_proto::ErrorCode;
use fleet_proto::alert::Severity;

pub const SSHD: &str = "/usr/sbin/sshd";
pub const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";
pub const FLEET_CONF: &str = "/etc/ssh/sshd_config.d/10-fleet.conf";
pub const INCLUDE: &str = "Include /etc/ssh/sshd_config.d/*.conf";

/// Post-quantum hybrids first, where the installed OpenSSH has them.
pub const PQ_KEX: &[&str] = &[
    "mlkem768x25519-sha256",
    "sntrup761x25519-sha512@openssh.com",
];
pub const CLASSIC_KEX: &[&str] = &["curve25519-sha256", "curve25519-sha256@libssh.org"];
pub const CIPHERS: &str =
    "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com";
pub const MACS: &str =
    "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com";
/// Secure Enclave keys are P-256; the recovery key is Ed25519 (design §5.9).
pub const PUBKEY_ALGOS: &str = "ecdsa-sha2-nistp256,ssh-ed25519";

pub fn kex(supported: &[String]) -> String {
    PQ_KEX
        .iter()
        .filter(|k| supported.iter().any(|s| s == *k))
        .chain(CLASSIC_KEX)
        .copied()
        .collect::<Vec<_>>()
        .join(",")
}

/// `AllowUsers` value: the admin, from `ssh.allow_from` only when set
/// (sshd matches `user@cidr`).
pub fn allow_users(admin: &str, p: &Resolved) -> String {
    if p.allow_from.is_empty() {
        return admin.to_owned();
    }
    p.allow_from
        .iter()
        .map(|c| format!("{admin}@{c}"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn config(admin: &str, p: &Resolved, supported_kex: &[String]) -> String {
    let admin = allow_users(admin, p);
    format!(
        "# Managed by Fleet (design §5.9, §9.4). Changes are overwritten.\n\
         PermitRootLogin no\n\
         PasswordAuthentication no\n\
         KbdInteractiveAuthentication no\n\
         AuthenticationMethods publickey\n\
         PubkeyAuthentication yes\n\
         AuthorizedKeysFile /etc/fleet/authorized_keys/%u\n\
         PermitUserEnvironment no\n\
         LogLevel VERBOSE\n\
         AllowUsers {admin}\n\
         MaxAuthTries 3\n\
         LoginGraceTime 20\n\
         MaxSessions {sessions}\n\
         X11Forwarding no\n\
         AllowTcpForwarding no\n\
         AllowStreamLocalForwarding no\n\
         AllowAgentForwarding no\n\
         PermitTunnel no\n\
         KexAlgorithms {kex}\n\
         Ciphers {CIPHERS}\n\
         MACs {MACS}\n\
         PubkeyAcceptedAlgorithms {PUBKEY_ALGOS}\n",
        sessions = p.settings.ssh_max_sessions,
        kex = kex(supported_kex),
    )
}

/// `sshd_config` reads the drop-in directory first (first value wins).
fn has_include(main: &str) -> bool {
    main.lines().any(|l| {
        let mut w = l.split_whitespace();
        w.next().is_some_and(|k| k.eq_ignore_ascii_case("include"))
            && w.any(|p| p == "/etc/ssh/sshd_config.d/*.conf" || p == "sshd_config.d/*.conf")
    })
}

pub fn reload_cmds() -> Vec<Cmd> {
    vec![
        Cmd::new(SSHD, ["-t"]),
        systemctl(["try-reload-or-restart", "--", "ssh.service"]),
    ]
}

/// Lockout guard: the admin exists and its authorized-keys file carries
/// the roster section, so the Mac's keys (and the recovery key) work once
/// `AllowUsers`/`AuthorizedKeysFile` take effect.
pub fn admin_can_log_in(ctx: &Ctx, admin: &str) -> Result<(), OpError> {
    let pw = users::passwd(&ctx.sys)?;
    let deny = |d: String| OpError::new(ErrorCode::PolicyDenied).with_detail(d);
    let e =
        parse::lookup(&pw, admin).ok_or_else(|| deny(format!("admin {admin} doesn't exist")))?;
    if !e.can_login() {
        return Err(deny(format!("admin {admin} has no login shell")));
    }
    if !authorized_keys::has_roster_section(&ctx.sys, admin)? {
        return Err(deny(format!(
            "no roster keys in {}/{admin}: refusing to lock SSH to it",
            authorized_keys::DIR
        )));
    }
    Ok(())
}

pub struct SshHardening;

impl Module for SshHardening {
    fn id(&self) -> &'static str {
        "ssh.hardening"
    }
    fn title(&self) -> &'static str {
        "sshd: keys only, no root, modern algorithms, no forwarding"
    }
    fn phase(&self) -> Phase {
        Phase::Remote
    }
    fn weight(&self) -> u8 {
        15
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn check(&self, ctx: &Ctx) -> Result<Status, OpError> {
        if ctx.profile.admin.is_none() {
            return Ok(Status::NotApplicable(
                "no admin user (AllowUsers needs one)".into(),
            ));
        }
        Ok(crate::module::status_of(&self.plan(ctx)?))
    }

    fn fixable(&self, ctx: &Ctx) -> bool {
        ctx.profile.admin.is_some()
    }

    fn plan(&self, ctx: &Ctx) -> Result<Vec<Change>, OpError> {
        let Some(admin) = &ctx.profile.admin else {
            return Ok(Vec::new());
        };
        let mut plan = Vec::new();
        let main = read_text(&ctx.sys, SSHD_CONFIG)?;
        if !has_include(&main) {
            let mode = crate::module::read_file(&ctx.sys, SSHD_CONFIG)?.map_or(0o644, |f| f.1);
            plan.push(Change {
                module: self.id(),
                description: format!("{SSHD_CONFIG}: include sshd_config.d first"),
                diff: format!("+ {INCLUDE}\n"),
                actions: vec![Action::Write {
                    path: SSHD_CONFIG.into(),
                    content: format!("{INCLUDE}\n{main}").into_bytes(),
                    mode,
                }],
            });
        }
        let conf = config(&admin.name, &ctx.profile, &ctx.facts.ssh_kex);
        plan.extend(file_change(&ctx.sys, self.id(), FLEET_CONF, &conf, 0o644)?);
        let [validate, reload]: [Cmd; 2] = reload_cmds()
            .try_into()
            .map_err(|_| OpError::internal("reload commands"))?;
        crate::module::then_run(&mut plan, [Action::Validate(validate), Action::Run(reload)]);
        Ok(plan)
    }

    fn apply<'a>(
        &'a self,
        ctx: &'a mut Ctx,
        plan: &'a [Change],
    ) -> LocalBoxFuture<'a, Result<Applied, OpError>> {
        Box::pin(async move {
            if plan.iter().any(|c| c.module == self.id()) {
                let admin = ctx
                    .profile
                    .admin
                    .as_ref()
                    .map(|a| a.name.clone())
                    .ok_or_else(|| OpError::new(ErrorCode::PolicyDenied).with_detail("no admin"))?;
                admin_can_log_in(ctx, &admin)?;
            }
            crate::exec::execute(ctx, self.id(), plan).await
        })
    }

    fn paths(&self, _p: &Resolved) -> Vec<String> {
        vec![SSHD_CONFIG.into(), FLEET_CONF.into()]
    }

    fn reload(&self, _p: &Resolved) -> Vec<Cmd> {
        reload_cmds()
    }
}
