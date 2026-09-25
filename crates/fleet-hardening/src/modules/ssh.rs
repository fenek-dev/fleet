//! `ssh.hardening` (design §5.9, §9.4): `sshd_config.d/00-fleet.conf`,
//! validated with `sshd -t` before the reload, and the effective values
//! verified with `sshd -T` (check and after apply). Phase 2: applied
//! under auto-revert and only when the admin can already log in with
//! roster keys (the lockout guard below).
//!
//! sshd keeps the first value it reads for most keywords, so the drop-in
//! sorts first (`00-`, before cloud-init's `50-cloud-init.conf` and
//! Fleet's own `05-fleet-bootstrap.conf`) and the `Include` must come
//! before the first directive of `sshd_config`.

use crate::module::{
    Action, Applied, Change, Cmd, Ctx, Module, Phase, Status, file_change, read_text, remove_change,
};
use crate::modules::systemctl;
use crate::profile::Resolved;
use fleet_ops::handler::{LocalBoxFuture, OpError};
use fleet_ops::runner::CommandSpec;
use fleet_ops::users::{self, authorized_keys, parse};
use fleet_proto::ErrorCode;
use fleet_proto::alert::Severity;

pub const SSHD: &str = "/usr/sbin/sshd";
pub const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";
pub const FLEET_CONF: &str = "/etc/ssh/sshd_config.d/00-fleet.conf";
/// Where earlier agents wrote the drop-in; removed on apply.
pub const OLD_FLEET_CONF: &str = "/etc/ssh/sshd_config.d/10-fleet.conf";
pub const INCLUDE: &str = "Include /etc/ssh/sshd_config.d/*.conf";

/// `sshd -T -C user=<admin>,host=localhost,addr=127.0.0.1`: the effective
/// configuration for an admin login (`admin` is a validated user name,
/// so it can't add connection-spec fields).
pub fn effective_spec(admin: &str) -> CommandSpec {
    CommandSpec::new(SSHD).args([
        "-T".to_owned(),
        "-C".to_owned(),
        format!("user={admin},host=localhost,addr=127.0.0.1"),
    ])
}

/// Single-valued settings whose effective value `sshd -T` must show
/// (lowercase keyword, value as sshd prints it).
pub const EFFECTIVE: &[(&str, &str)] = &[
    ("permitrootlogin", "no"),
    ("passwordauthentication", "no"),
    ("kbdinteractiveauthentication", "no"),
    ("authenticationmethods", "publickey"),
    ("pubkeyauthentication", "yes"),
    ("authorizedkeysfile", "/etc/fleet/authorized_keys/%u"),
    ("permituserenvironment", "no"),
    ("maxauthtries", "3"),
    ("x11forwarding", "no"),
    ("allowtcpforwarding", "no"),
    ("allowstreamlocalforwarding", "no"),
    ("allowagentforwarding", "no"),
    ("permittunnel", "no"),
];

/// The first difference between what `ssh.hardening` sets and sshd's
/// effective configuration, or `None` when they agree. `AllowUsers` must
/// list exactly the profile's entries.
pub fn effective_mismatch(admin: &str, p: &Resolved, eff: &[(String, String)]) -> Option<String> {
    let get = |k: &str| {
        eff.iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.as_str())
    };
    for (k, want) in EFFECTIVE {
        match get(k) {
            Some(v) if v.eq_ignore_ascii_case(want) => {}
            got => return Some(format!("effective {k} is {got:?}, want {want:?}")),
        }
    }
    let mut want: Vec<String> = allow_users(admin, p)
        .split(' ')
        .map(str::to_owned)
        .collect();
    let mut got: Vec<String> = eff
        .iter()
        .filter(|(k, _)| k == "allowusers")
        .flat_map(|(_, v)| v.split(' ').map(str::to_owned))
        .collect();
    want.sort();
    got.sort();
    got.dedup();
    (want != got).then(|| format!("effective allowusers is {got:?}, want {want:?}"))
}

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

fn is_dropin_include(l: &str) -> bool {
    let mut w = l.split_whitespace();
    w.next().is_some_and(|k| k.eq_ignore_ascii_case("include"))
        && w.any(|p| p == "/etc/ssh/sshd_config.d/*.conf" || p == "sshd_config.d/*.conf")
}

fn is_directive(l: &str) -> bool {
    let t = l.trim();
    !t.is_empty() && !t.starts_with('#')
}

/// `sshd_config` reads the drop-in directory before any other directive
/// (first value wins, so a directive above the `Include` would beat the
/// drop-in).
pub fn include_first(main: &str) -> bool {
    main.lines()
        .find(|l| is_directive(l))
        .is_some_and(is_dropin_include)
}

/// `main` with the drop-in `Include` as its first line: top-level copies
/// of it (before any `Match`) are dropped so the directory isn't read
/// twice; everything else is kept byte for byte.
pub fn with_include_first(main: &str) -> String {
    let mut out = format!("{INCLUDE}\n");
    let mut in_match = false;
    for l in main.split_inclusive('\n') {
        let first = l.split_whitespace().next().unwrap_or("");
        in_match |= first.eq_ignore_ascii_case("match");
        if !in_match && is_dropin_include(l) {
            continue;
        }
        out.push_str(l);
    }
    out
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
    crate::modules::access::ensure_admin_ok(ctx, admin)?;
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
        Phase::Access
    }
    fn weight(&self) -> u8 {
        15
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn check(&self, ctx: &Ctx) -> Result<Status, OpError> {
        let Some(admin) = &ctx.profile.admin else {
            return Ok(Status::NotApplicable(
                "no admin user (AllowUsers needs one)".into(),
            ));
        };
        let plan = self.plan(ctx)?;
        if !plan.is_empty() {
            return Ok(crate::module::status_of(&plan));
        }
        // Files match; sshd's effective values must too (a drop-in sorting
        // earlier or a `Match` block can override them).
        if let Some(eff) = &ctx.facts.sshd_effective
            && let Some(d) = effective_mismatch(&admin.name, &ctx.profile, eff)
        {
            return Ok(Status::Drifted(d));
        }
        Ok(Status::Compliant)
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
        if !include_first(&main) {
            let mode = crate::module::read_file(&ctx.sys, SSHD_CONFIG)?.map_or(0o644, |f| f.1);
            let new = with_include_first(&main);
            plan.push(Change {
                module: self.id(),
                description: format!("{SSHD_CONFIG}: include sshd_config.d before any directive"),
                diff: crate::module::line_diff(&main, &new),
                actions: vec![Action::Write {
                    path: SSHD_CONFIG.into(),
                    content: new.into_bytes(),
                    mode,
                }],
            });
        }
        let conf = config(&admin.name, &ctx.profile, &ctx.facts.ssh_kex);
        plan.extend(file_change(&ctx.sys, self.id(), FLEET_CONF, &conf, 0o644)?);
        plan.extend(remove_change(&ctx.sys, self.id(), OLD_FLEET_CONF)?);
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
            if !plan.iter().any(|c| c.module == self.id()) {
                return crate::exec::execute(ctx, self.id(), plan).await;
            }
            let admin = ctx
                .profile
                .admin
                .as_ref()
                .map(|a| a.name.clone())
                .ok_or_else(|| OpError::new(ErrorCode::PolicyDenied).with_detail("no admin"))?;
            admin_can_log_in(ctx, &admin)?;
            let applied = crate::exec::execute(ctx, self.id(), plan).await?;
            // The files are in place and sshd reloaded: its effective
            // configuration must now be what the drop-in says. A failure
            // fails the op, so exec restores the snapshot at once.
            let o = ctx
                .sys
                .runner
                .run(effective_spec(&admin))
                .await
                .map_err(|_| OpError::internal("sshd -T failed to run"))?;
            if !o.success() {
                return Err(OpError::internal("sshd -T failed"));
            }
            let eff = crate::facts::parse_sshd_t(&String::from_utf8_lossy(&o.stdout));
            if let Some(d) = effective_mismatch(&admin, &ctx.profile, &eff) {
                return Err(OpError::new(ErrorCode::Internal).with_detail(d));
            }
            ctx.facts.sshd_effective = Some(eff);
            Ok(applied)
        })
    }

    fn paths(&self, _p: &Resolved) -> Vec<String> {
        vec![SSHD_CONFIG.into(), FLEET_CONF.into(), OLD_FLEET_CONF.into()]
    }

    fn reload(&self, _p: &Resolved) -> Vec<Cmd> {
        reload_cmds()
    }
}
