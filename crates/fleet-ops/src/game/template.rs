//! Game templates (design §9.6): TOML manifests under `profiles/games/`,
//! embedded at build time, and the hardened systemd unit rendered from
//! one.
//!
//! Every value that reaches the unit file or an argument vector is checked
//! against a narrow charset by [`Template::validate`] (no whitespace, no
//! quotes, no `\`, `;` or `%`), so templates can't smuggle unit directives
//! or systemd specifiers. Placeholders `{name}`, `{dir}`, `{server}` are
//! expanded from the typed [`GameName`]; `${VAR}` is left for systemd to
//! expand from the instance's root-only environment file.

use fleet_proto::args::{GameName, GameTemplateId};
use serde::Deserialize;
use std::fmt::Write;

/// The templates shipped with this agent.
pub const BUILTIN: &[&str] = &[
    include_str!("../../../../profiles/games/minecraft-paper.toml"),
    include_str!("../../../../profiles/games/valheim.toml"),
];

pub const GAMES_DIR: &str = "/srv/games";
pub const STATE_DIR: &str = "/var/lib/fleet/games";
pub const UNIT_DIR: &str = "/etc/systemd/system";
pub const DOCKER: &str = "/usr/bin/docker";
/// Generated per instance, in the environment file.
pub const GAME_PASSWORD_ENV: &str = "FLEET_GAME_PASSWORD";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Template {
    pub id: String,
    pub name: String,
    pub install: Install,
    #[serde(default)]
    pub ports: Vec<PortSpec>,
    pub limits: Limits,
    #[serde(default)]
    pub rcon: Option<Rcon>,
    pub backup: Backup,
    #[serde(default)]
    pub schedule: Option<Schedule>,
    #[serde(default)]
    pub health: Option<Health>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "method", rename_all = "lowercase", deny_unknown_fields)]
pub enum Install {
    Steamcmd {
        app_id: u32,
        /// Relative to `{server}`.
        exec: String,
        #[serde(default)]
        args: Vec<String>,
        /// `NAME=value` unit `Environment=` entries.
        #[serde(default)]
        env: Vec<String>,
    },
    Container {
        image: String,
        data_dir: String,
        /// `NAME=value`, or `NAME` to pass through from the environment.
        #[serde(default)]
        env: Vec<String>,
        #[serde(default)]
        args: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortSpec {
    pub proto: Proto,
    pub port: u16,
    #[serde(default)]
    pub end: Option<u16>,
}

impl PortSpec {
    pub fn text(&self) -> String {
        match self.end {
            Some(e) if e != self.port => format!("{}-{e}", self.port),
            _ => self.port.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// systemd/Docker size, e.g. `4G`.
    pub memory_max: String,
    pub tasks_max: u32,
    /// e.g. `300%`.
    #[serde(default)]
    pub cpu_quota: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rcon {
    /// Loopback port.
    pub port: u16,
    /// Variable in the instance environment file holding the password.
    pub password_env: String,
    #[serde(default)]
    pub players_command: Option<String>,
    /// The player count is the number right after this text.
    #[serde(default)]
    pub players_prefix: Option<String>,
    #[serde(default)]
    pub save_command: Option<String>,
    /// `<say_command> <text>` broadcasts restart warnings.
    #[serde(default)]
    pub say_command: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backup {
    /// Relative to `{dir}`.
    pub paths: Vec<String>,
    /// Backups kept (1..=100).
    pub keep: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    /// `HH:MM` UTC daily restart.
    pub restart_utc: String,
    /// Seconds before the restart to warn over RCON.
    #[serde(default)]
    pub warnings_s: Vec<u32>,
}

impl Schedule {
    /// Minutes after midnight UTC.
    pub fn minute_of_day(&self) -> Option<u32> {
        let (h, m) = self.restart_utc.split_once(':')?;
        if h.len() != 2 || m.len() != 2 {
            return None;
        }
        let (h, m): (u32, u32) = (h.parse().ok()?, m.parse().ok()?);
        (h < 24 && m < 60).then_some(h * 60 + m)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    /// A local TCP port the Mac can turn into a health check.
    #[serde(default)]
    pub tcp_port: Option<u16>,
}

/// Characters allowed in any template token that reaches a unit file or
/// an argument vector.
fn token_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'.' | b'_'
                        | b'/'
                        | b':'
                        | b'@'
                        | b'='
                        | b'+'
                        | b','
                        | b'-'
                        | b'{'
                        | b'}'
                        | b'$'
                )
        })
}

fn env_name_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

fn env_ok(s: &str, pass_through: bool) -> bool {
    match s.split_once('=') {
        Some((n, v)) => env_name_ok(n) && (v.is_empty() || token_ok(v)),
        None => pass_through && env_name_ok(s),
    }
}

/// Relative, no `..`, no leading `/`.
fn rel_ok(s: &str) -> bool {
    token_ok(s)
        && !s.starts_with('/')
        && s.split('/').all(|c| !c.is_empty() && c != "." && c != "..")
        && !s.contains('$')
        && !s.contains('{')
}

fn size_ok(s: &str) -> bool {
    let (n, u) = s.split_at(s.len().saturating_sub(1));
    !n.is_empty()
        && n.len() <= 6
        && n.bytes().all(|b| b.is_ascii_digit())
        && matches!(u, "K" | "M" | "G")
}

fn percent_ok(s: &str) -> bool {
    s.strip_suffix('%')
        .is_some_and(|n| !n.is_empty() && n.len() <= 5 && n.bytes().all(|b| b.is_ascii_digit()))
}

/// `${VAR}` references only (no bare `$`).
fn dollars_ok(s: &str) -> bool {
    let mut rest = s;
    while let Some(i) = rest.find('$') {
        let after = &rest[i + 1..];
        let Some(body) = after.strip_prefix('{') else {
            return false;
        };
        let Some(end) = body.find('}') else {
            return false;
        };
        if !env_name_ok(&body[..end]) {
            return false;
        }
        rest = &body[end + 1..];
    }
    true
}

impl Template {
    pub fn parse(text: &str) -> Result<Template, String> {
        let t: Template = toml::from_str(text).map_err(|e| e.message().to_owned())?;
        t.validate()?;
        Ok(t)
    }

    pub fn validate(&self) -> Result<(), String> {
        let bad = |what: &str| Err(format!("template {}: {what}", self.id));
        if GameTemplateId::new(self.id.clone()).is_err() {
            return bad("id");
        }
        if self.name.is_empty() || self.name.len() > 64 || self.name.chars().any(char::is_control) {
            return bad("name");
        }
        let args_ok = |a: &[String]| a.iter().all(|x| token_ok(x) && dollars_ok(x));
        match &self.install {
            Install::Steamcmd {
                app_id,
                exec,
                args,
                env,
            } => {
                if *app_id == 0 || !rel_ok(exec) || !args_ok(args) {
                    return bad("steamcmd install");
                }
                if !env.iter().all(|e| env_ok(e, false) && !e.contains('$')) {
                    return bad("env");
                }
            }
            Install::Container {
                image,
                data_dir,
                env,
                args,
            } => {
                if !token_ok(image) || image.contains(['$', '{']) || image.starts_with('-') {
                    return bad("image");
                }
                if !data_dir.starts_with('/')
                    || !token_ok(data_dir)
                    || data_dir.contains(['$', '{'])
                {
                    return bad("data dir");
                }
                if !env.iter().all(|e| env_ok(e, true) && !e.contains('$')) {
                    return bad("env");
                }
                if !args_ok(args) || args.iter().any(|a| a.contains('$')) {
                    return bad("container args");
                }
            }
        }
        if self.ports.len() > 16
            || self
                .ports
                .iter()
                .any(|p| p.port == 0 || p.end.is_some_and(|e| e < p.port))
        {
            return bad("ports");
        }
        if !size_ok(&self.limits.memory_max)
            || !(16..=65_536).contains(&self.limits.tasks_max)
            || self
                .limits
                .cpu_quota
                .as_deref()
                .is_some_and(|c| !percent_ok(c))
        {
            return bad("limits");
        }
        if let Some(r) = &self.rcon {
            let line = |s: &Option<String>| {
                s.as_deref().is_none_or(|s| {
                    !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control)
                })
            };
            if r.port == 0
                || !env_name_ok(&r.password_env)
                || r.password_env == GAME_PASSWORD_ENV
                || !line(&r.players_command)
                || !line(&r.players_prefix)
                || !line(&r.save_command)
                || !line(&r.say_command)
            {
                return bad("rcon");
            }
        }
        if self.backup.paths.is_empty()
            || self.backup.paths.len() > 16
            || !self.backup.paths.iter().all(|p| rel_ok(p))
            || !(1..=100).contains(&self.backup.keep)
        {
            return bad("backup");
        }
        if let Some(s) = &self.schedule
            && (s.minute_of_day().is_none()
                || s.warnings_s.len() > 8
                || s.warnings_s.iter().any(|w| *w == 0 || *w > 3600))
        {
            return bad("schedule");
        }
        Ok(())
    }

    pub fn is_container(&self) -> bool {
        matches!(self.install, Install::Container { .. })
    }
}

/// Every built-in template (a broken one is a build defect: tests parse
/// them all).
pub fn builtin() -> Vec<Template> {
    BUILTIN
        .iter()
        .filter_map(|t| Template::parse(t).ok())
        .collect()
}

pub fn dir(name: &GameName) -> String {
    format!("{GAMES_DIR}/{}", name.as_str())
}

pub fn user(name: &GameName) -> String {
    format!("game-{}", name.as_str())
}

pub fn unit(name: &GameName) -> String {
    format!("game-{}.service", name.as_str())
}

pub fn unit_path(name: &GameName) -> String {
    format!("{UNIT_DIR}/{}", unit(name))
}

pub fn env_path(name: &GameName) -> String {
    format!("{STATE_DIR}/{}.env", name.as_str())
}

pub fn instance_path(name: &GameName) -> String {
    format!("{STATE_DIR}/{}.toml", name.as_str())
}

/// `{name}`, `{dir}`, `{server}` → values; `${VAR}` untouched.
pub fn expand(s: &str, name: &GameName) -> String {
    let d = dir(name);
    s.replace("{server}", &format!("{d}/server"))
        .replace("{dir}", &d)
        .replace("{name}", name.as_str())
}

/// The hardened unit (design §9.6). SteamCMD games run as `game-<name>`;
/// container games run the Docker CLI as root and the container as
/// `<uid>:<gid>` without capabilities.
pub fn render_unit(t: &Template, name: &GameName, uid: u32, gid: u32) -> String {
    let d = dir(name);
    let mut s = String::new();
    let _ = write!(
        s,
        "# Managed by Fleet (game.install). Changes are overwritten.\n\
         [Unit]\n\
         Description=Fleet game server {n} ({id})\n\
         Wants=network-online.target\n\
         After=network-online.target{after}\n",
        n = name.as_str(),
        id = t.id,
        after = if t.is_container() {
            " docker.service"
        } else {
            ""
        },
    );
    if t.is_container() {
        s.push_str("Requires=docker.service\n");
    }
    s.push_str("\n[Service]\nType=simple\n");
    match &t.install {
        Install::Steamcmd {
            exec, args, env, ..
        } => {
            let u = user(name);
            let _ = write!(
                s,
                "User={u}\nGroup={u}\nWorkingDirectory={d}/server\nEnvironmentFile={}\n",
                env_path(name)
            );
            for e in env {
                let _ = writeln!(s, "Environment={}", expand(e, name));
            }
            let mut line = format!("{d}/server/{exec}");
            for a in args {
                line.push(' ');
                line.push_str(&expand(a, name));
            }
            let _ = writeln!(s, "ExecStart={line}");
        }
        Install::Container {
            image,
            data_dir,
            env,
            args,
        } => {
            let _ = writeln!(
                s,
                "WorkingDirectory={d}\nEnvironmentFile={}",
                env_path(name)
            );
            let mut line = format!(
                "{DOCKER} run --rm --name {c} --user {uid}:{gid} --cap-drop ALL \
                 --security-opt no-new-privileges --memory {mem} --pids-limit {tasks}",
                c = user(name),
                mem = t.limits.memory_max,
                tasks = t.limits.tasks_max,
            );
            for p in &t.ports {
                let r = p.text();
                let _ = write!(line, " -p {r}:{r}/{}", p.proto.as_str());
            }
            if let Some(r) = &t.rcon {
                let _ = write!(line, " -p 127.0.0.1:{p}:{p}/tcp", p = r.port);
            }
            let _ = write!(line, " -v {d}/data:{data_dir}");
            for e in env {
                let _ = write!(line, " -e {e}");
            }
            if let Some(r) = &t.rcon {
                // Name only: the value comes from the environment file,
                // never from the command line.
                let _ = write!(line, " -e {}", r.password_env);
            }
            let _ = write!(line, " {image}");
            for a in args {
                let _ = write!(line, " {}", expand(a, name));
            }
            let _ = writeln!(s, "ExecStart={line}");
            let _ = writeln!(s, "ExecStop={DOCKER} stop --time 30 {}", user(name));
        }
    }
    let _ = write!(
        s,
        "Restart=on-failure\n\
         RestartSec=10\n\
         TimeoutStopSec=90\n\
         NoNewPrivileges=yes\n\
         PrivateTmp=yes\n\
         ProtectSystem=strict\n\
         ProtectHome=yes\n\
         ReadWritePaths={d}\n\
         ProtectKernelTunables=yes\n\
         ProtectKernelModules=yes\n\
         ProtectControlGroups=yes\n\
         RestrictSUIDSGID=yes\n\
         LockPersonality=yes\n\
         MemoryMax={}\n\
         TasksMax={}\n",
        t.limits.memory_max, t.limits.tasks_max
    );
    if let Some(c) = &t.limits.cpu_quota {
        let _ = writeln!(s, "CPUQuota={c}");
    }
    s.push_str("\n[Install]\nWantedBy=multi-user.target\n");
    s
}
