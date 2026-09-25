//! Profiles (design §9.2): the built-in Baseline/Strict files and role
//! manifests under `profiles/` (compiled in, reviewed with the release)
//! and operator TOML with a strict schema that can only extend a built-in,
//! pick roles, name the admin, restrict SSH sources, set the reboot
//! window, skip modules or items, and declare exceptions. Nothing in an
//! operator profile adds commands, files or settings of its own.

use fleet_ops::SysCtx;
use fleet_ops::handler::OpError;
use fleet_ops::users::authorized_keys;
use fleet_proto::ErrorCode;
use fleet_proto::args::{
    Cidr, FirewallRule, FwAction, FwChain, FwComment, Port, PortRange, Protocol, RateLimit,
    SudoPasswordHash, UserName,
};
use fleet_proto::op::{ProfileLevel, ProfileRole, ProfileSource, ProfileSpec};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

pub const BASELINE_TOML: &str = include_str!("../../../profiles/baseline.toml");
pub const STRICT_TOML: &str = include_str!("../../../profiles/strict.toml");
pub const DOCKER_TOML: &str = include_str!("../../../profiles/roles/docker.toml");
pub const WEB_TOML: &str = include_str!("../../../profiles/roles/web.toml");
pub const GAME_TOML: &str = include_str!("../../../profiles/roles/game.toml");

/// At most this many `ssh.allow_from` ranges (one firewall rule each).
pub const MAX_ALLOW_FROM: usize = 16;
pub const MAX_SKIP: usize = 128;
pub const MAX_EXCEPTIONS: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileError(pub String);

impl std::error::Error for ProfileError {}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<ProfileError> for OpError {
    fn from(e: ProfileError) -> Self {
        OpError::new(ErrorCode::InvalidArgument).with_detail(format!("profile: {}", e.0))
    }
}

fn err<T>(s: impl Into<String>) -> Result<T, ProfileError> {
    Err(ProfileError(s.into()))
}

// ---- built-in file schema ----

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuiltinFile {
    profile: BuiltinHeader,
    #[serde(default)]
    ssh: SshSettings,
    #[serde(default)]
    sudo: SudoSettings,
    #[serde(default)]
    auditd: AuditdSettings,
    #[serde(default)]
    admin_shell: AdminShellSettings,
    #[serde(default)]
    journald: JournaldSettings,
    #[serde(default)]
    packages: PackageSettings,
    #[serde(default)]
    kernel: KernelSettings,
    #[serde(default)]
    services: ServiceSettings,
    #[serde(default)]
    sysctl: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuiltinHeader {
    name: String,
    #[serde(default)]
    extends: Option<String>,
    modules: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SshSettings {
    max_sessions: Option<u8>,
    rate_per_minute: Option<u32>,
    rate_burst: Option<u16>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SudoSettings {
    log_io: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditdSettings {
    immutable: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminShellSettings {
    /// `chattr +i` on the admin's shell startup files.
    immutable: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournaldSettings {
    system_max_use: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageSettings {
    #[serde(default)]
    install: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelSettings {
    #[serde(default)]
    blacklist: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceSettings {
    #[serde(default)]
    disable: Vec<String>,
}

// ---- role manifest schema ----

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleFile {
    role: RoleHeader,
    #[serde(default)]
    settings: BTreeMap<String, String>,
    #[serde(default)]
    apt_repo: Option<AptRepo>,
    #[serde(default)]
    sysctl: BTreeMap<String, String>,
    #[serde(default)]
    kernel: RoleKernel,
    #[serde(default)]
    exceptions: BTreeMap<String, String>,
    #[serde(default)]
    firewall: Vec<RoleFirewall>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleHeader {
    id: String,
    description: String,
    modules: Vec<String>,
    packages: Vec<String>,
    tracked_paths: Vec<String>,
    health_checks: Vec<String>,
}

/// A third-party apt repository whose key must match a pinned fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AptRepo {
    pub name: String,
    /// `{os}` → `/etc/os-release` ID.
    pub key_url: String,
    /// Uppercase hex, 40 characters.
    pub fingerprint: String,
    pub uri: String,
    /// Fixed suite; `None` uses the OS codename.
    #[serde(default)]
    pub suite: Option<String>,
    pub components: Vec<String>,
    #[serde(default)]
    pub pin_packages: Vec<String>,
    #[serde(default)]
    pub pin_version: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleKernel {
    #[serde(default)]
    load: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleFirewall {
    #[serde(default)]
    chain: Option<String>,
    proto: String,
    ports: Vec<u16>,
    #[serde(default)]
    rate_per_minute: Option<u32>,
    #[serde(default)]
    rate_burst: Option<u16>,
    comment: String,
}

/// A parsed role manifest (design §9.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleManifest {
    pub role: ProfileRole,
    pub id: String,
    pub description: String,
    pub modules: Vec<String>,
    pub packages: Vec<String>,
    pub tracked_paths: Vec<String>,
    pub health_checks: Vec<String>,
    pub settings: BTreeMap<String, String>,
    pub apt_repo: Option<AptRepo>,
    pub firewall: Vec<FirewallRule>,
}

// ---- operator profile schema (design §9.2) ----

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CustomFile {
    profile: CustomHeader,
    #[serde(default)]
    admin: Option<AdminSection>,
    #[serde(default)]
    ssh: Option<SshSection>,
    #[serde(default)]
    updates: Option<UpdatesSection>,
    #[serde(default)]
    skip: Option<SkipSection>,
    #[serde(default)]
    exceptions: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CustomHeader {
    #[serde(default)]
    name: Option<String>,
    extends: String,
    #[serde(default)]
    roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminSection {
    /// No `password_hash` here: the sudo password hash comes only in
    /// `profile.apply`'s own field, which makes the op Elevated and is
    /// redacted in the audit log (a hash in the TOML would be stored in
    /// the clear in the audit args).
    user: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SshSection {
    #[serde(default)]
    allow_from: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdatesSection {
    #[serde(default)]
    reboot_window: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SkipSection {
    #[serde(default)]
    modules: Vec<String>,
}

// ---- resolved ----

#[derive(Clone, PartialEq, Eq)]
pub struct Admin {
    pub name: String,
    pub password_hash: Option<SudoPasswordHash>,
}

impl std::fmt::Debug for Admin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Admin")
            .field("name", &self.name)
            .field(
                "password_hash",
                &self.password_hash.as_ref().map(|_| "(redacted)"),
            )
            .finish()
    }
}

/// `Sun 04:00-05:00 UTC` / `daily 03:00-04:00 UTC`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebootWindow {
    /// systemd weekday (`Mon`…`Sun`); `None` every day.
    pub day: Option<String>,
    pub start_min: u32,
    pub len_min: u32,
}

impl RebootWindow {
    pub fn parse(s: &str) -> Result<Self, ProfileError> {
        let bad = || {
            ProfileError(format!(
                "reboot window {s:?}: want e.g. \"Sun 04:00-05:00 UTC\""
            ))
        };
        let parts: Vec<&str> = s.split_whitespace().collect();
        let [day, range, "UTC"] = parts.as_slice() else {
            return Err(bad());
        };
        let day = match *day {
            "daily" | "Daily" => None,
            d if ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].contains(&d) => {
                Some(d.to_owned())
            }
            _ => return Err(bad()),
        };
        let (a, b) = range.split_once('-').ok_or_else(bad)?;
        let hm = |t: &str| -> Option<u32> {
            let (h, m) = t.split_once(':')?;
            if h.len() != 2 || m.len() != 2 {
                return None;
            }
            let (h, m): (u32, u32) = (h.parse().ok()?, m.parse().ok()?);
            (h < 24 && m < 60).then_some(h * 60 + m)
        };
        let (start, end) = (hm(a).ok_or_else(bad)?, hm(b).ok_or_else(bad)?);
        let len = if end > start {
            end - start
        } else {
            end + 1440 - start
        };
        if !(10..=720).contains(&len) {
            return Err(bad());
        }
        Ok(Self {
            day,
            start_min: start,
            len_min: len,
        })
    }

    /// systemd `OnCalendar=` value.
    pub fn on_calendar(&self) -> String {
        let day = self
            .day
            .as_deref()
            .map(|d| format!("{d} "))
            .unwrap_or_default();
        format!(
            "{day}*-*-* {:02}:{:02}:00 UTC",
            self.start_min / 60,
            self.start_min % 60
        )
    }
}

/// Settings the built-in profiles and roles fix; operators only skip.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Settings {
    pub ssh_max_sessions: u8,
    pub ssh_rate: (u32, u16),
    pub sudo_log_io: bool,
    pub auditd_immutable: bool,
    /// Strict: the admin's shell startup files are also `chattr +i`.
    pub admin_shell_immutable: bool,
    pub journald_max_use: String,
    pub packages: Vec<String>,
    pub blacklist: BTreeSet<String>,
    pub disable: Vec<String>,
    pub sysctl: BTreeMap<String, String>,
    pub modules_load: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub name: String,
    pub level: ProfileLevel,
    pub roles: Vec<ProfileRole>,
    /// Every module of the profile, in apply order (phase sorting is the
    /// engine's).
    pub modules: Vec<String>,
    /// `ProfileSpec::only`; empty = all.
    pub only: Vec<String>,
    pub admin: Option<Admin>,
    pub allow_from: Vec<Cidr>,
    pub reboot_window: Option<RebootWindow>,
    pub skip: BTreeSet<String>,
    /// Accepted exceptions (roles' and the operator's): id → reason.
    pub exceptions: BTreeMap<String, String>,
    pub settings: Settings,
    pub role_manifests: Vec<RoleManifest>,
}

impl Resolved {
    /// Turned off by `[skip]` or an exception.
    pub fn is_skipped(&self, id: &str) -> bool {
        self.skip.contains(id) || self.exceptions.contains_key(id)
    }

    /// In scope of this request (`only`).
    pub fn in_scope(&self, id: &str) -> bool {
        self.only.is_empty() || self.only.iter().any(|o| o == id)
    }

    /// Sets the admin's sudo password hash from `profile.apply`
    /// (`admin.user` then runs `chpasswd --encrypted`). Refused without an
    /// admin and for the redacted audit form. The op field is the only
    /// source of the hash (profile TOML has no `password_hash`).
    pub fn set_password(&mut self, h: &SudoPasswordHash) -> Result<(), ProfileError> {
        if h.is_redacted() {
            return err("password_hash: a crypt(3) hash, not the audit form");
        }
        let Some(admin) = self.admin.as_mut() else {
            return err("password_hash needs an admin user");
        };
        admin.password_hash = Some(h.clone());
        Ok(())
    }

    pub fn role(&self, r: ProfileRole) -> Option<&RoleManifest> {
        self.role_manifests.iter().find(|m| m.role == r)
    }
}

fn parse_builtin(text: &str) -> BuiltinFile {
    // Compiled-in files; the unit tests parse every one.
    toml::from_str(text).unwrap_or_else(|e| panic!("built-in profile: {e}"))
}

fn role_text(r: ProfileRole) -> &'static str {
    match r {
        ProfileRole::Docker => DOCKER_TOML,
        ProfileRole::Web => WEB_TOML,
        ProfileRole::Game => GAME_TOML,
    }
}

fn role_of(s: &str) -> Result<ProfileRole, ProfileError> {
    Ok(match s {
        "docker" => ProfileRole::Docker,
        "web" => ProfileRole::Web,
        "game" => ProfileRole::Game,
        _ => return err(format!("unknown role {s:?}")),
    })
}

pub fn role_manifest(r: ProfileRole) -> Result<RoleManifest, ProfileError> {
    let f: RoleFile = toml::from_str(role_text(r)).map_err(|e| ProfileError(e.to_string()))?;
    let firewall = f.role.firewall_rules(&f.firewall)?;
    if role_of(&f.role.id)? != r {
        return err("role id mismatch");
    }
    if let Some(repo) = &f.apt_repo {
        check_repo(repo)?;
    }
    Ok(RoleManifest {
        role: r,
        id: f.role.id,
        description: f.role.description,
        modules: f.role.modules,
        packages: f.role.packages,
        tracked_paths: f.role.tracked_paths,
        health_checks: f.role.health_checks,
        settings: f.settings,
        apt_repo: f.apt_repo,
        firewall,
    })
}

impl RoleHeader {
    fn firewall_rules(&self, rules: &[RoleFirewall]) -> Result<Vec<FirewallRule>, ProfileError> {
        rules
            .iter()
            .map(|r| {
                let chain = match r.chain.as_deref() {
                    None | Some("input") => FwChain::Input,
                    Some("forward") => FwChain::Forward,
                    Some(c) => return err(format!("firewall chain {c:?}")),
                };
                let proto = match r.proto.as_str() {
                    "tcp" => Protocol::Tcp,
                    "udp" => Protocol::Udp,
                    p => return err(format!("firewall proto {p:?}")),
                };
                let ports = r
                    .ports
                    .iter()
                    .map(|p| Port::new(*p).map(PortRange::single))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| ProfileError("firewall port".into()))?;
                let rate_limit = r.rate_per_minute.map(|per_minute| RateLimit {
                    per_minute,
                    burst: r.rate_burst.unwrap_or(10),
                });
                let comment = FwComment::new(format!("profile:{}:{}", self.id, r.comment))
                    .map_err(|_| ProfileError("firewall comment".into()))?;
                let rule = FirewallRule {
                    chain,
                    action: FwAction::Accept,
                    proto,
                    ports,
                    source: None,
                    rate_limit,
                    comment,
                };
                rule.validate()
                    .map_err(|e| ProfileError(format!("firewall rule: {e:?}")))?;
                Ok(rule)
            })
            .collect()
    }
}

fn check_repo(r: &AptRepo) -> Result<(), ProfileError> {
    let fp_ok = r.fingerprint.len() == 40
        && r.fingerprint
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b));
    if !fp_ok {
        return err("apt repo fingerprint");
    }
    if !r.key_url.starts_with("https://") || !r.uri.starts_with("https://") {
        return err("apt repo must use https");
    }
    let safe = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._:/{}*+~".contains(&b))
    };
    let all = [r.name.as_str(), &r.key_url, &r.uri]
        .into_iter()
        .chain(r.components.iter().map(String::as_str))
        .chain(r.suite.as_deref())
        .chain(r.pin_version.as_deref())
        .chain(r.pin_packages.iter().map(String::as_str));
    for s in all {
        if !safe(s) {
            return err(format!("apt repo field {s:?}"));
        }
    }
    Ok(())
}

fn level_files(level: ProfileLevel) -> Vec<BuiltinFile> {
    let base = parse_builtin(BASELINE_TOML);
    match level {
        ProfileLevel::Baseline => vec![base],
        ProfileLevel::Strict => vec![base, parse_builtin(STRICT_TOML)],
    }
}

/// A built-in profile with roles (no admin; see [`resolve`]).
pub fn builtin(level: ProfileLevel, roles: &[ProfileRole]) -> Result<Resolved, ProfileError> {
    let files = level_files(level);
    let mut s = Settings::default();
    let mut modules: Vec<String> = Vec::new();
    for (i, f) in files.iter().enumerate() {
        let want = (i > 0).then_some("baseline");
        if f.profile.extends.as_deref() != want {
            return err(format!(
                "built-in {} extends {:?}",
                f.profile.name, f.profile.extends
            ));
        }
        modules.extend(f.profile.modules.iter().cloned());
        if let Some(v) = f.ssh.max_sessions {
            s.ssh_max_sessions = v;
        }
        if let Some(v) = f.ssh.rate_per_minute {
            s.ssh_rate.0 = v;
        }
        if let Some(v) = f.ssh.rate_burst {
            s.ssh_rate.1 = v;
        }
        if let Some(v) = f.sudo.log_io {
            s.sudo_log_io = v;
        }
        if let Some(v) = f.auditd.immutable {
            s.auditd_immutable = v;
        }
        if let Some(v) = f.admin_shell.immutable {
            s.admin_shell_immutable = v;
        }
        if let Some(v) = &f.journald.system_max_use {
            s.journald_max_use.clone_from(v);
        }
        s.packages.extend(f.packages.install.iter().cloned());
        s.blacklist.extend(f.kernel.blacklist.iter().cloned());
        s.disable.extend(f.services.disable.iter().cloned());
        s.sysctl.extend(f.sysctl.clone());
    }
    let name = files
        .last()
        .map(|f| f.profile.name.clone())
        .unwrap_or_default();
    let mut roles = roles.to_vec();
    roles.sort();
    roles.dedup();
    let mut exceptions = BTreeMap::new();
    let mut manifests = Vec::new();
    for r in &roles {
        let text = role_text(*r);
        let f: RoleFile = toml::from_str(text).map_err(|e| ProfileError(e.to_string()))?;
        let m = role_manifest(*r)?;
        modules.extend(m.modules.iter().cloned());
        s.sysctl.extend(f.sysctl);
        for k in f.kernel.load {
            s.blacklist.remove(&k);
            s.modules_load.insert(k);
        }
        exceptions.extend(f.exceptions);
        manifests.push(m);
    }
    Ok(Resolved {
        name,
        level,
        roles,
        modules,
        only: Vec::new(),
        admin: None,
        allow_from: Vec::new(),
        reboot_window: None,
        skip: BTreeSet::new(),
        exceptions,
        settings: s,
        role_manifests: manifests,
    })
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// crypt(3) hash as `chpasswd -e` takes it: `$y$` or `$6$`, nothing that
/// could end the `user:hash` line (`SudoPasswordHash::crypt`, the same
/// rule `profile.apply`'s `password_hash` is held to).
pub fn valid_hash(h: &str) -> bool {
    SudoPasswordHash::crypt(h).is_ok()
}

/// Ids an operator may skip or except: module ids, and single items of
/// the item-level modules.
fn known_item(p: &Resolved, id: &str) -> bool {
    p.modules.iter().any(|m| m == id)
        || id
            .strip_prefix("sysctl.")
            .is_some_and(|k| p.settings.sysctl.contains_key(k))
        || id.strip_prefix("kernel.modules.").is_some_and(|k| {
            p.settings.blacklist.contains(k) || p.settings.modules_load.contains(k)
        })
        || id
            .strip_prefix("services.")
            .is_some_and(|u| p.settings.disable.iter().any(|d| d == u))
}

/// Drops excepted/skipped items from the item-level settings.
fn apply_item_skips(p: &mut Resolved) {
    let off: Vec<String> = p.skip.iter().chain(p.exceptions.keys()).cloned().collect();
    for id in off {
        if let Some(k) = id.strip_prefix("sysctl.") {
            // A role's value (e.g. ip_forward=1) stays; only an operator's
            // skip of a baseline key drops it.
            if p.skip.contains(&id) {
                p.settings.sysctl.remove(k);
            }
        } else if let Some(k) = id.strip_prefix("kernel.modules.") {
            p.settings.blacklist.remove(k);
        } else if let Some(u) = id.strip_prefix("services.") {
            p.settings.disable.retain(|d| d != u);
        }
    }
}

/// Parses and validates an operator profile.
pub fn parse_custom(text: &str) -> Result<Resolved, ProfileError> {
    let f: CustomFile = toml::from_str(text).map_err(|e| ProfileError(e.message().to_owned()))?;
    let level = match f.profile.extends.as_str() {
        "baseline" => ProfileLevel::Baseline,
        "strict" => ProfileLevel::Strict,
        e => return err(format!("extends {e:?}: only \"baseline\" or \"strict\"")),
    };
    let roles = f
        .profile
        .roles
        .iter()
        .map(|r| role_of(r))
        .collect::<Result<Vec<_>, _>>()?;
    let mut uniq = roles.clone();
    uniq.sort();
    uniq.dedup();
    if uniq.len() != roles.len() {
        return err("duplicate role");
    }
    let mut p = builtin(level, &roles)?;
    if let Some(n) = f.profile.name {
        if !valid_name(&n) {
            return err("profile name");
        }
        p.name = n;
    }
    if let Some(a) = f.admin {
        let user = UserName::new(a.user.as_str()).map_err(|_| ProfileError("admin user".into()))?;
        if user.is_root() || user.is_fleet() {
            return err("admin user can't be root or a fleet* account");
        }
        p.admin = Some(Admin {
            name: user.as_str().to_owned(),
            password_hash: None,
        });
    }
    if let Some(ssh) = f.ssh {
        if ssh.allow_from.len() > MAX_ALLOW_FROM {
            return err("too many ssh.allow_from ranges");
        }
        for c in &ssh.allow_from {
            p.allow_from.push(
                c.parse::<Cidr>()
                    .map_err(|_| ProfileError(format!("cidr {c:?}")))?,
            );
        }
    }
    if let Some(w) = f.updates.and_then(|u| u.reboot_window) {
        p.reboot_window = Some(RebootWindow::parse(&w)?);
    }
    let skip = f.skip.map(|s| s.modules).unwrap_or_default();
    if skip.len() > MAX_SKIP || f.exceptions.len() > MAX_EXCEPTIONS {
        return err("too many skips or exceptions");
    }
    for id in &skip {
        if !known_item(&p, id) {
            return err(format!("skip: unknown module or item {id:?}"));
        }
        p.skip.insert(id.clone());
    }
    for (id, reason) in f.exceptions {
        if !known_item(&p, &id) {
            return err(format!("exception: unknown module or item {id:?}"));
        }
        if reason.is_empty() || reason.len() > 200 || reason.chars().any(char::is_control) {
            return err("exception reason: 1-200 characters");
        }
        p.exceptions.insert(id, reason);
    }
    apply_item_skips(&mut p);
    Ok(p)
}

/// The admin user exec keeps roster keys for: the only file under
/// `/etc/fleet/authorized_keys/` with a managed roster section.
pub fn detect_admin(sys: &SysCtx) -> Option<String> {
    let mut found = roster_users(sys);
    (found.len() == 1).then(|| found.remove(0))
}

/// Every user whose file under `/etc/fleet/authorized_keys/` has a managed
/// roster section (at most 256 entries are looked at).
pub fn roster_users(sys: &SysCtx) -> Vec<String> {
    let Some(dir) = sys.path(authorized_keys::DIR) else {
        return Vec::new();
    };
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for e in rd.flatten().take(256) {
        let Some(name) = e.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if UserName::new(name.as_str()).is_ok()
            && authorized_keys::has_roster_section(sys, &name).unwrap_or(false)
        {
            found.push(name);
        }
    }
    found.sort();
    found
}

/// `ProfileSpec` → resolved profile, `only` checked against its modules.
pub fn resolve(spec: &ProfileSpec, sys: &SysCtx) -> Result<Resolved, OpError> {
    let mut p = match &spec.source {
        ProfileSource::Builtin { level, roles } => builtin(*level, roles)?,
        ProfileSource::Custom(t) => parse_custom(t.as_str())?,
    };
    for o in &spec.only {
        if !p.modules.iter().any(|m| m == o.as_str()) {
            return Err(
                ProfileError(format!("only: {} is not in this profile", o.as_str())).into(),
            );
        }
        p.only.push(o.as_str().to_owned());
    }
    if p.admin.is_none() {
        p.admin = detect_admin(sys).map(|name| Admin {
            name,
            password_hash: None,
        });
    }
    Ok(p)
}
