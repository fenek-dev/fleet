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

/// Whether `shell` is a real login shell: not `nologin`/`false`, absolute,
/// and listed in `/etc/shells` when that file exists.
fn valid_login_shell(ctx: &Ctx, e: &parse::PasswdEntry) -> Result<bool, OpError> {
    if !e.can_login() || !e.shell.starts_with('/') {
        return Ok(false);
    }
    let shells = read_text(&ctx.sys, "/etc/shells")?;
    if shells.trim().is_empty() {
        return Ok(true);
    }
    Ok(shells.lines().any(|l| l.trim() == e.shell))
}

/// Why `name` can't be the admin (design §9.4), or `Ok(None)` when it
/// doesn't exist yet (`useradd` then picks a uid ≥ `UID_MIN`). An existing
/// admin must be a regular account (uid ≥ `UID_MIN`, never 0), not a
/// `fleet*` account, and have a valid login shell: making a system or
/// service account the sudo admin (or locking SSH to it) would be wrong
/// either way.
pub fn admin_problem(ctx: &Ctx, name: &str) -> Result<Option<String>, OpError> {
    if name == "root" || name.starts_with("fleet") {
        return Ok(Some(format!("{name} can't be the admin")));
    }
    let pw = users::passwd(&ctx.sys)?;
    let Some(e) = parse::lookup(&pw, name) else {
        return Ok(None);
    };
    let (uid_min, _) = users::uid_range(&ctx.sys)?;
    if e.uid == 0 || e.uid < uid_min {
        return Ok(Some(format!(
            "admin {name} has uid {} (needs a regular account, uid ≥ {uid_min})",
            e.uid
        )));
    }
    if !valid_login_shell(ctx, e)? {
        return Ok(Some(format!(
            "admin {name} has no valid login shell ({:?})",
            e.shell
        )));
    }
    Ok(None)
}

fn admin_denied(detail: String) -> OpError {
    OpError::new(fleet_proto::ErrorCode::PolicyDenied).with_detail(detail)
}

/// `admin_problem` as an error (`PolicyDenied`), for plan/apply paths.
pub fn ensure_admin_ok(ctx: &Ctx, name: &str) -> Result<(), OpError> {
    match admin_problem(ctx, name)? {
        Some(p) => Err(admin_denied(p)),
        None => Ok(()),
    }
}

/// Users with a Fleet roster section under `/etc/fleet/authorized_keys`
/// (the admin, and any other account exec writes roster keys for).
pub fn roster_users(ctx: &Ctx) -> Vec<String> {
    crate::profile::roster_users(&ctx.sys)
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
        Phase::Accounts
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
        if let Some(p) = admin_problem(ctx, &admin.name)? {
            return Ok(Status::Drifted(p));
        }
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
        ensure_admin_ok(ctx, name)?;
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
            && shadow_hash(&read_text(&ctx.sys, "/etc/shadow")?, name) != hash.expose()
        {
            plan.push(Change {
                module: self.id(),
                description: format!("set the sudo password of {name} (hash from the Mac)"),
                diff: "~ password hash (redacted)\n".into(),
                actions: vec![Action::Run(
                    Cmd::new(CHPASSWD, ["--encrypted"])
                        .stdin(format!("{name}:{}\n", hash.expose()).into_bytes()),
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
        Phase::Accounts
    }
    fn weight(&self) -> u8 {
        4
    }

    fn check(&self, ctx: &Ctx) -> Result<Status, OpError> {
        let Some(admin) = &ctx.profile.admin else {
            return Ok(no_admin());
        };
        if let Some(p) = admin_problem(ctx, &admin.name)? {
            return Ok(Status::Drifted(p));
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
        ensure_admin_ok(ctx, &admin.name)?;
        let pw = users::passwd(&ctx.sys)?;
        let home = parse::lookup(&pw, &admin.name)
            .map_or_else(|| format!("/home/{}", admin.name), |e| e.home.clone());
        let immutable = ctx.profile.settings.admin_shell_immutable;
        let mut plan = Vec::new();
        for name in SHELL_FILES {
            let content = shell_content(name);
            if is_root_owned(&ctx.sys, &home, name, content.map(str::as_bytes))
                && (!immutable || crate::exec::home_file_immutable(&ctx.sys, &home, name))
            {
                continue;
            }
            let what = match (content.is_some(), immutable) {
                (true, false) => "replace with Fleet's version, root-owned 0644",
                (true, true) => "replace with Fleet's version, root-owned 0644, immutable",
                (false, false) => "root-owned 0644 (created empty if missing)",
                (false, true) => "root-owned 0644, immutable (created empty if missing)",
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
                    immutable,
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

/// Cloud provider sudoers drop-ins Fleet knows and may remove once the
/// admin has a sudo password: cloud-init's default-user grant, Azure's
/// `waagent` and Google's guest agent.
pub const CLOUD_SUDOERS: &[&str] = &[
    SUDOERS_CLOUD_INIT,
    "/etc/sudoers.d/waagent",
    "/etc/sudoers.d/google_sudoers",
];
pub const SUDOERS_D: &str = "/etc/sudoers.d";

/// Files in `/etc/sudoers.d` (as sudo reads them: no `.` in the name, no
/// trailing `~`; Fleet's own excluded) that let the admin run commands
/// without a password (`NOPASSWD`, `!authenticate`), in name order.
pub fn nopasswd_files(ctx: &Ctx, admin: &str) -> Result<Vec<String>, OpError> {
    let pw = users::passwd(&ctx.sys)?;
    let Some(e) = parse::lookup(&pw, admin) else {
        return Ok(Vec::new());
    };
    let gr = users::groups(&ctx.sys)?;
    let groups: Vec<(String, u32)> = e.groups_in(&gr).map(|g| (g.name.clone(), g.gid)).collect();
    let Some(dir) = ctx.sys.path(SUDOERS_D) else {
        return Ok(Vec::new());
    };
    let mut names: Vec<String> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .flatten()
            .take(256)
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| !n.contains('.') && !n.ends_with('~'))
            .collect(),
        Err(_) => return Ok(Vec::new()),
    };
    names.sort();
    let mut out = Vec::new();
    for n in names {
        let path = format!("{SUDOERS_D}/{n}");
        if path == SUDOERS_FLEET {
            continue;
        }
        let text = read_text(&ctx.sys, &path)?;
        if fleet_ops::escalation::nopasswd_grants(&text).covers(admin, e.uid, &groups) {
            out.push(path);
        }
    }
    Ok(out)
}

/// sudo drop-in (use_pty, logging; Strict: I/O logging), checked with
/// `visudo -c`. Passwordless grants for the admin in `/etc/sudoers.d` are
/// drift: once the admin has a sudo password, the cloud provider files
/// Fleet knows ([`CLOUD_SUDOERS`]) are removed; any other one is only
/// reported (it may be the operator's own).
pub struct SudoPolicy;

impl Module for SudoPolicy {
    fn id(&self) -> &'static str {
        "sudo.policy"
    }
    fn title(&self) -> &'static str {
        "sudo requires a password and logs with use_pty"
    }
    fn phase(&self) -> Phase {
        Phase::Accounts
    }

    fn check(&self, ctx: &Ctx) -> Result<Status, OpError> {
        let plan = self.plan(ctx)?;
        if !plan.is_empty() {
            return Ok(status_of(&plan));
        }
        if let Some(admin) = &ctx.profile.admin {
            let files = nopasswd_files(ctx, &admin.name)?;
            if !files.is_empty() {
                return Ok(Status::Drifted(format!(
                    "passwordless sudo for {} in {} (not removed automatically)",
                    admin.name,
                    files.join(", ")
                )));
            }
        }
        Ok(Status::Compliant)
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
        // Only once the admin has a password: removing the grant earlier
        // would leave it without working sudo.
        if let Some(admin) = &ctx.profile.admin
            && admin.password_hash.is_some()
        {
            for f in nopasswd_files(ctx, &admin.name)? {
                if CLOUD_SUDOERS.contains(&f.as_str())
                    && let Some(c) = remove_change(&ctx.sys, self.id(), &f)?
                {
                    plan.push(c);
                }
            }
        }
        crate::module::then_run(
            &mut plan,
            [Action::Validate(Cmd::new(VISUDO, ["-c", "-q"]))],
        );
        Ok(plan)
    }

    fn paths(&self, _p: &Resolved) -> Vec<String> {
        let mut v = vec![SUDOERS_FLEET.to_owned()];
        v.extend(CLOUD_SUDOERS.iter().map(|s| (*s).to_owned()));
        v
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
/// The admin and every account with a roster section in its authorized
/// keys file are never touched (locking them would lock the operator out).
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
        let mut keep = roster_users(ctx);
        if let Some(a) = &ctx.profile.admin {
            keep.push(a.name.clone());
        }
        for e in users::passwd(&ctx.sys)? {
            if e.uid == 0
                || e.uid >= uid_min
                || KEEP_SHELL.contains(&e.name.as_str())
                || keep.contains(&e.name)
            {
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
