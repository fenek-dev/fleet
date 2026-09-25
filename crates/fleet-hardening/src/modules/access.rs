//! Phase 1 (design §9.1, §5.9): the admin user, its shell files, sudo;
//! plus locking unused system accounts and (Strict) password quality.

use crate::exec::is_root_owned;
use crate::module::{
    Action, Change, Cmd, Ctx, Module, Phase, Status, file_change, read_text, remove_change,
    run_change, status_of,
};
use crate::modules::install_change;
use crate::profile::Resolved;
use fleet_ops::handler::OpError;
use fleet_ops::users::{self, authorized_keys, parse};
use fleet_proto::alert::Severity;

pub const USERADD: &str = users::USERADD;
pub const USERMOD: &str = users::USERMOD;
pub const CHPASSWD: &str = "/usr/sbin/chpasswd";
pub const VISUDO: &str = "/usr/sbin/visudo";
pub const SUDOERS_FLEET: &str = "/etc/sudoers.d/10-fleet";
/// cloud-init's passwordless sudo grant for the default user.
pub const SUDOERS_CLOUD_INIT: &str = "/etc/sudoers.d/90-cloud-init-users";
pub const PWQUALITY: &str = "/etc/security/pwquality.conf.d/10-fleet.conf";

/// The shadow hash field of `user` (empty if absent).
fn shadow_hash(shadow: &str, user: &str) -> String {
    shadow
        .lines()
        .find_map(|l| {
            let mut f = l.split(':');
            (f.next() == Some(user)).then(|| f.next().unwrap_or("").to_owned())
        })
        .unwrap_or_default()
}

fn no_admin() -> Status {
    Status::NotApplicable(
        "no admin user: name one in [admin] or install the agent with --admin-user".into(),
    )
}

// ---- admin.user ----

/// The admin user (design §9.4): exists, in `sudo`, sudo password set from
/// the hash the Mac computed (never plaintext), roster keys present.
pub struct AdminUser;

impl Module for AdminUser {
    fn id(&self) -> &'static str {
        "admin.user"
    }
    fn title(&self) -> &'static str {
        "Admin user with sudo and Fleet-managed SSH keys"
    }
    fn phase(&self) -> Phase {
        Phase::Access
    }
    fn weight(&self) -> u8 {
        8
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn check(&self, ctx: &Ctx) -> Result<Status, OpError> {
        let Some(admin) = &ctx.profile.admin else {
            return Ok(no_admin());
        };
        let plan = self.plan(ctx)?;
        if !plan.is_empty() {
            return Ok(status_of(&plan));
        }
        if !authorized_keys::has_roster_section(&ctx.sys, &admin.name).unwrap_or(false) {
            return Ok(Status::Drifted(format!(
                "no Fleet roster keys in {}/{} (exec writes them on the next roster push)",
                authorized_keys::DIR,
                admin.name
            )));
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
        let name = admin.name.as_str();
        let mut plan = Vec::new();
        let pw = users::passwd(&ctx.sys)?;
        match parse::lookup(&pw, name) {
            None => plan.push(run_change(
                self.id(),
                format!("create admin user {name} (groups: sudo)"),
                vec![Cmd::new(
                    USERADD,
                    [
                        "--create-home",
                        "--user-group",
                        "--groups",
                        "sudo",
                        "--shell",
                        "/bin/bash",
                        "--comment",
                        "Fleet admin",
                        "--",
                        name,
                    ],
                )],
            )),
            Some(_) => {
                let in_sudo = users::groups(&ctx.sys)?
                    .iter()
                    .any(|g| g.name == "sudo" && g.members.iter().any(|m| m == name));
                if !in_sudo {
                    plan.push(run_change(
                        self.id(),
                        format!("add {name} to group sudo"),
                        vec![Cmd::new(
                            USERMOD,
                            ["--append", "--groups", "sudo", "--", name],
                        )],
                    ));
                }
            }
        }
        if let Some(hash) = &admin.password_hash
            && shadow_hash(&read_text(&ctx.sys, "/etc/shadow")?, name) != *hash
        {
            plan.push(Change {
                module: self.id(),
                description: format!("set the sudo password of {name} (hash from the Mac)"),
                diff: "~ password hash (redacted)\n".into(),
                actions: vec![Action::Run(
                    Cmd::new(CHPASSWD, ["--encrypted"])
                        .stdin(format!("{name}:{hash}\n").into_bytes()),
                )],
            });
        }
        Ok(plan)
    }
}

// ---- admin.shell ----

/// Startup files of the admin that become root-owned and read-only
/// (design §5.9).
pub const SHELL_FILES: &[&str] = &[
    ".profile",
    ".bashrc",
    ".bash_profile",
    ".bash_logout",
    ".inputrc",
    ".tmux.conf",
];

/// `.profile` with a fixed PATH of root-owned directories only.
pub const PROFILE: &str = "# Managed by Fleet (design §5.9): root-owned, read-only.\n\
# PATH holds no user-writable directories.\n\
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n\
export PATH\n\
if [ -n \"$BASH_VERSION\" ] && [ -f \"$HOME/.bashrc\" ]; then\n\
    . \"$HOME/.bashrc\"\n\
fi\n";

/// bash reads `.bash_profile` instead of `.profile` when it exists.
pub const BASH_PROFILE: &str = "# Managed by Fleet (design §5.9): root-owned, read-only.\n\
if [ -f \"$HOME/.profile\" ]; then\n\
    . \"$HOME/.profile\"\n\
fi\n";

fn shell_content(name: &str) -> Option<&'static str> {
    match name {
        ".profile" => Some(PROFILE),
        ".bash_profile" => Some(BASH_PROFILE),
        _ => None,
    }
}

pub struct AdminShell;

impl Module for AdminShell {
    fn id(&self) -> &'static str {
        "admin.shell"
    }
    fn title(&self) -> &'static str {
        "Admin shell startup files root-owned, safe PATH"
    }
    fn phase(&self) -> Phase {
        Phase::Access
    }
    fn weight(&self) -> u8 {
        4
    }

    fn check(&self, ctx: &Ctx) -> Result<Status, OpError> {
        if ctx.profile.admin.is_none() {
            return Ok(no_admin());
        }
        Ok(status_of(&self.plan(ctx)?))
    }

    fn fixable(&self, ctx: &Ctx) -> bool {
        ctx.profile.admin.is_some()
    }

    fn plan(&self, ctx: &Ctx) -> Result<Vec<Change>, OpError> {
        let Some(admin) = &ctx.profile.admin else {
            return Ok(Vec::new());
        };
        let pw = users::passwd(&ctx.sys)?;
        let home = parse::lookup(&pw, &admin.name)
            .map_or_else(|| format!("/home/{}", admin.name), |e| e.home.clone());
        let mut plan = Vec::new();
        for name in SHELL_FILES {
            let content = shell_content(name);
            if is_root_owned(&ctx.sys, &home, name, content.map(str::as_bytes)) {
                continue;
            }
            let what = if content.is_some() {
                "replace with Fleet's version, root-owned 0644"
            } else {
                "root-owned 0644 (created empty if missing)"
            };
            plan.push(Change {
                module: self.id(),
                description: format!("{home}/{name}: {what}"),
                diff: content
                    .map(|c| crate::module::line_diff("", c))
                    .unwrap_or_default(),
                actions: vec![Action::RootOwn {
                    user: admin.name.clone(),
                    name: (*name).to_owned(),
                    content: content.map(|c| c.as_bytes().to_vec()),
                }],
            });
        }
        Ok(plan)
    }
}

// ---- sudo.policy ----

pub fn sudoers(p: &Resolved) -> String {
    let mut s = String::from(
        "# Managed by Fleet (design §5.9, §9.4). Changes are overwritten.\n\
         Defaults use_pty\n\
         Defaults logfile=\"/var/log/sudo.log\"\n\
         Defaults timestamp_timeout=5\n",
    );
    if p.settings.sudo_log_io {
        s.push_str(
            "Defaults log_input, log_output\nDefaults iolog_dir=\"/var/log/sudo-io/%{user}\"\n",
        );
    }
    s
}

/// sudo drop-in (use_pty, logging; Strict: I/O logging), checked with
/// `visudo -c`. cloud-init's passwordless grant is removed once the admin
/// has a sudo password.
pub struct SudoPolicy;

impl Module for SudoPolicy {
    fn id(&self) -> &'static str {
        "sudo.policy"
    }
    fn title(&self) -> &'static str {
        "sudo requires a password and logs with use_pty"
    }
    fn phase(&self) -> Phase {
        Phase::Access
    }

    fn plan(&self, ctx: &Ctx) -> Result<Vec<Change>, OpError> {
        let mut plan: Vec<Change> = file_change(
            &ctx.sys,
            self.id(),
            SUDOERS_FLEET,
            &sudoers(&ctx.profile),
            0o440,
        )?
        .into_iter()
        .collect();
        let has_password = ctx
            .profile
            .admin
            .as_ref()
            .is_some_and(|a| a.password_hash.is_some());
        if has_password && let Some(c) = remove_change(&ctx.sys, self.id(), SUDOERS_CLOUD_INIT)? {
            plan.push(c);
        }
        crate::module::then_run(
            &mut plan,
            [Action::Validate(Cmd::new(VISUDO, ["-c", "-q"]))],
        );
        Ok(plan)
    }

    fn paths(&self, _p: &Resolved) -> Vec<String> {
        vec![SUDOERS_FLEET.into(), SUDOERS_CLOUD_INIT.into()]
    }
}

// ---- sudo.pwquality (Strict) ----

pub const PWQUALITY_CONF: &str = "# Managed by Fleet (design §9.5).\n\
minlen = 16\n\
minclass = 3\n\
maxrepeat = 3\n\
dictcheck = 1\n\
enforce_for_root\n";

pub struct PwQuality;

impl Module for PwQuality {
    fn id(&self) -> &'static str {
        "sudo.pwquality"
    }
    fn title(&self) -> &'static str {
        "Password quality policy (pam_pwquality)"
    }
    fn weight(&self) -> u8 {
        3
    }

    fn plan(&self, ctx: &Ctx) -> Result<Vec<Change>, OpError> {
        let mut plan: Vec<Change> =
            install_change(ctx, self.id(), &["libpam-pwquality".to_owned()])
                .into_iter()
                .collect();
        plan.extend(file_change(
            &ctx.sys,
            self.id(),
            PWQUALITY,
            PWQUALITY_CONF,
            0o644,
        )?);
        Ok(plan)
    }

    fn paths(&self, _p: &Resolved) -> Vec<String> {
        vec![PWQUALITY.into()]
    }
}

// ---- accounts.lock ----

/// System accounts that keep their shell (they only run a fixed command).
const KEEP_SHELL: &[&str] = &["sync", "shutdown", "halt"];

/// System accounts (uid 1..UID_MIN) get `nologin` and a locked password.
pub struct AccountsLock;

impl Module for AccountsLock {
    fn id(&self) -> &'static str {
        "accounts.lock"
    }
    fn title(&self) -> &'static str {
        "Unused system accounts locked"
    }

    fn plan(&self, ctx: &Ctx) -> Result<Vec<Change>, OpError> {
        let (uid_min, _) = users::uid_range(&ctx.sys)?;
        let shadow = read_text(&ctx.sys, "/etc/shadow")?;
        let mut plan = Vec::new();
        for e in users::passwd(&ctx.sys)? {
            if e.uid == 0 || e.uid >= uid_min || KEEP_SHELL.contains(&e.name.as_str()) {
                continue;
            }
            // Names come from /etc/passwd; `--` keeps a hostile one from
            // being read as an option.
            if !parse::NOLOGIN_SHELLS.contains(&e.shell.as_str()) && !e.shell.is_empty() {
                plan.push(run_change(
                    self.id(),
                    format!("set the shell of system account {} to nologin", e.name),
                    vec![Cmd::new(
                        USERMOD,
                        ["--shell", "/usr/sbin/nologin", "--", e.name.as_str()],
                    )],
                ));
            }
            if shadow_hash(&shadow, &e.name).starts_with('$') {
                plan.push(run_change(
                    self.id(),
                    format!("lock the password of system account {}", e.name),
                    vec![Cmd::new(USERMOD, ["--lock", "--", e.name.as_str()])],
                ));
            }
        }
        Ok(plan)
    }
}
