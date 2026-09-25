//! Game servers (design §9.6): `game.*` operations and the background
//! scheduler (player counts, daily restarts with RCON warnings).
//!
//! Layout per instance `<name>`:
//!
//! - system user `game-<name>` (system account, no login shell, home
//!   `/srv/games/<name>`);
//! - `/srv/games/<name>/` (0750, owned by the game user): `server/`
//!   (SteamCMD install dir), `data/` (container volume), the game's saves;
//! - `/etc/systemd/system/game-<name>.service`: the hardened unit from
//!   [`template::render_unit`];
//! - `/var/lib/fleet/games/<name>.toml` (instance record) and
//!   `<name>.env` (generated secrets: join password, RCON password), both
//!   0600 root, outside config history;
//! - `/var/backups/fleet-games/<name>/<id>.tar.zst` (0750/0640
//!   `root:game-<name>`).
//!
//! Everything that reads or writes the game's own files runs **as the game
//! user** (`setpriv`, in the op's scope): SteamCMD, `tar` creating a backup
//! into its own directory, `tar` extracting a restore. Root only copies the
//! finished archive out, opened `O_NOFOLLOW` under `/srv/games` with
//! [`open_allowed`], so a game process can't redirect root through a
//! symlink. Backups are zstd (`tar --zstd`, needs the `zstd` package).
//!
//! Ports: the template's public ports are the ones the operator opens in
//! Fleet's firewall (`firewall.apply` from the Mac, with per-source rate
//! limits); RCON is published on loopback only. The CPU governor and UDP
//! buffer sysctls are the game role's provisioning modules, not ops.

pub mod rcon;
pub mod sched;
pub mod template;

use crate::allowed::open_allowed;
use crate::ctx::SysCtx;
use crate::fswrite;
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, Registry};
use crate::runner::{CommandOutput, CommandSpec, RunError, SYSTEMCTL};
use crate::telemetry::GaugeSink;
use crate::users::parse::lookup;
use fleet_proto::args::{AbsPath, GameName, UserName};
use fleet_proto::op::tag;
use fleet_proto::payload::{GameBackup, GameBackups, GameInfo, Games, MetricUnit};
use fleet_proto::{ErrorCode, Op, Payload};
use serde::{Deserialize, Serialize};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::Duration;
use template::{Install, Template};

pub const USERADD: &str = crate::users::USERADD;
pub const STEAMCMD: &str = "/usr/games/steamcmd";
pub const TAR: &str = "/usr/bin/tar";
pub const RM: &str = "/usr/bin/rm";
pub const NOLOGIN: &str = "/usr/sbin/nologin";
pub const BACKUP_DIR: &str = "/var/backups/fleet-games";
/// Staged archive, written by the game user in its own directory.
pub const STAGE: &str = ".fleet-backup.tar.zst";
const INSTALL_TIMEOUT: Duration = Duration::from_secs(3600);
const BACKUP_TIMEOUT: Duration = Duration::from_secs(3600);
const UNIT_TIMEOUT: Duration = Duration::from_secs(120);
const PLAYERS_EVERY_MS: u64 = 60_000;
/// Scheduler resolution.
pub const TICK: Duration = Duration::from_secs(15);
const SECRET_LEN: usize = 24;

fn log(what: &str, e: impl std::fmt::Display) {
    eprintln!("fleet-exec: game: {what}: {e}");
}

/// `/var/lib/fleet/games/<name>.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Instance {
    pub template: String,
    pub uid: u32,
    pub gid: u32,
    pub installed_ms: u64,
}

fn internal(what: &str, out: &CommandOutput) -> OpError {
    OpError::internal(format!("{what} failed: {:?}", out.code))
}

fn ok(out: Result<CommandOutput, RunError>, what: &str) -> Result<(), OpError> {
    let out = out?;
    if out.success() {
        Ok(())
    } else {
        Err(internal(what, &out))
    }
}

fn not_found(d: &'static str) -> OpError {
    OpError::new(ErrorCode::NotFound).with_detail(d)
}

fn invalid(d: &'static str) -> OpError {
    OpError::new(ErrorCode::InvalidArgument).with_detail(d)
}

pub fn systemctl(args: &[&str]) -> CommandSpec {
    CommandSpec::new(SYSTEMCTL)
        .args(args)
        .timeout(UNIT_TIMEOUT)
        .output_cap(8192)
}

/// `useradd --system --user-group --home-dir /srv/games/<n>
/// --no-create-home --shell /usr/sbin/nologin -- game-<n>`.
pub fn useradd_spec(name: &GameName) -> CommandSpec {
    CommandSpec::new(USERADD).args([
        "--system".to_owned(),
        "--user-group".to_owned(),
        "--home-dir".to_owned(),
        template::dir(name),
        "--no-create-home".to_owned(),
        "--shell".to_owned(),
        NOLOGIN.to_owned(),
        "--".to_owned(),
        template::user(name),
    ])
}

/// `program args…` as the game user, in the op's scope.
pub fn as_user(
    op_id: u64,
    inst: &Instance,
    program: &'static str,
    args: Vec<String>,
    timeout: Duration,
) -> CommandSpec {
    let inner = CommandSpec::new(crate::shell::SETPRIV)
        .arg(format!("--reuid={}", inst.uid))
        .arg(format!("--regid={}", inst.gid))
        .args(["--init-groups", "--reset-env", "--", program])
        .args(args)
        .timeout(timeout)
        .output_cap(64 * 1024);
    crate::scope::scoped(op_id, inner)
}

/// SteamCMD `app_update` as the game user, or `docker pull` (root).
pub fn install_spec(op_id: u64, t: &Template, name: &GameName, inst: &Instance) -> CommandSpec {
    match &t.install {
        Install::Steamcmd { app_id, .. } => as_user(
            op_id,
            inst,
            STEAMCMD,
            vec![
                "+force_install_dir".into(),
                format!("{}/server", template::dir(name)),
                "+login".into(),
                "anonymous".into(),
                "+app_update".into(),
                app_id.to_string(),
                "validate".into(),
                "+quit".into(),
            ],
            INSTALL_TIMEOUT,
        ),
        Install::Container { image, .. } => crate::scope::scoped(
            op_id,
            CommandSpec::new(template::DOCKER)
                .args(["pull", "--", image.as_str()])
                .env("HOME", "/root")
                .timeout(INSTALL_TIMEOUT)
                .output_cap(64 * 1024),
        ),
    }
}

/// `tar --zstd --ignore-failed-read -cf <dir>/.fleet-backup.tar.zst -C
/// <dir> -- <paths>` as the game user.
pub fn backup_spec(op_id: u64, t: &Template, name: &GameName, inst: &Instance) -> CommandSpec {
    let d = template::dir(name);
    let mut args = vec![
        "--zstd".to_owned(),
        "--ignore-failed-read".to_owned(),
        "-cf".to_owned(),
        format!("{d}/{STAGE}"),
        "-C".to_owned(),
        d,
        "--".to_owned(),
    ];
    args.extend(t.backup.paths.iter().cloned());
    as_user(op_id, inst, TAR, args, BACKUP_TIMEOUT)
}

pub fn backup_path(name: &GameName, id: u64) -> String {
    format!("{BACKUP_DIR}/{}/{id}.tar.zst", name.as_str())
}

/// `tar --zstd -xf <backup> -C <dir>` as the game user.
pub fn restore_spec(op_id: u64, name: &GameName, inst: &Instance, id: u64) -> CommandSpec {
    as_user(
        op_id,
        inst,
        TAR,
        vec![
            "--zstd".into(),
            "-xf".into(),
            backup_path(name, id),
            "-C".into(),
            template::dir(name),
        ],
        BACKUP_TIMEOUT,
    )
}

/// Alphanumeric secret from the kernel CSPRNG.
pub fn random_secret() -> Result<String, OpError> {
    use std::io::Read;
    const ALPHA: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut f = std::fs::File::open("/dev/urandom").map_err(OpError::internal)?;
    let mut out = String::with_capacity(SECRET_LEN);
    let mut buf = [0u8; 64];
    while out.len() < SECRET_LEN {
        f.read_exact(&mut buf).map_err(OpError::internal)?;
        let limit = 256 - 256 % ALPHA.len();
        for b in buf {
            if (b as usize) < limit && out.len() < SECRET_LEN {
                out.push(ALPHA[b as usize % ALPHA.len()] as char);
            }
        }
    }
    Ok(out)
}

fn euid_is_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// chown (root only; tests run unprivileged) + chmod.
fn own(ctx: &SysCtx, abs: &str, uid: u32, gid: u32, mode: u32) -> Result<(), OpError> {
    use std::os::unix::fs::PermissionsExt;
    let p = ctx.path(abs).ok_or_else(|| OpError::internal("bad path"))?;
    if euid_is_root() {
        std::os::unix::fs::lchown(&p, Some(uid), Some(gid)).map_err(OpError::internal)?;
    }
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).map_err(OpError::internal)
}

fn remove_file(ctx: &SysCtx, abs: &str) -> Result<(), OpError> {
    let p = ctx.path(abs).ok_or_else(|| OpError::internal("bad path"))?;
    match std::fs::remove_file(p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(OpError::internal(format!("remove {abs}: {e}"))),
    }
}

fn exists(ctx: &SysCtx, abs: &str) -> bool {
    ctx.path(abs)
        .is_some_and(|p| std::fs::symlink_metadata(p).is_ok())
}

pub struct GameService {
    templates: Vec<Template>,
    gauges: Rc<dyn GaugeSink>,
    players: RefCell<BTreeMap<String, u32>>,
    last_tick: Cell<Option<u64>>,
    last_players: Cell<u64>,
}

impl GameService {
    pub fn new(templates: Vec<Template>, gauges: Rc<dyn GaugeSink>) -> Rc<Self> {
        Rc::new(Self {
            templates,
            gauges,
            players: RefCell::default(),
            last_tick: Cell::new(None),
            last_players: Cell::new(0),
        })
    }

    /// The built-in templates.
    pub fn builtin(gauges: Rc<dyn GaugeSink>) -> Rc<Self> {
        Self::new(template::builtin(), gauges)
    }

    pub fn template(&self, id: &str) -> Option<&Template> {
        self.templates.iter().find(|t| t.id == id)
    }

    pub fn load(&self, ctx: &SysCtx, name: &GameName) -> Result<Option<Instance>, OpError> {
        let Some(b) = fswrite::read_regular(ctx, &template::instance_path(name), 4096)? else {
            return Ok(None);
        };
        let text = String::from_utf8(b).map_err(|_| OpError::internal("instance: not UTF-8"))?;
        toml::from_str(&text)
            .map(Some)
            .map_err(|e| OpError::internal(format!("instance: {}", e.message())))
    }

    /// The instance and its template (`NotFound` if either is missing).
    fn get(&self, ctx: &SysCtx, name: &GameName) -> Result<(Instance, &Template), OpError> {
        let inst = self.load(ctx, name)?.ok_or(not_found("no such game"))?;
        let t = self
            .template(&inst.template)
            .ok_or(not_found("template no longer shipped"))?;
        Ok((inst, t))
    }

    /// Every installed instance, by name.
    pub fn instances(&self, ctx: &SysCtx) -> Vec<(GameName, Instance)> {
        let Some(dir) = ctx.path(template::STATE_DIR) else {
            return Vec::new();
        };
        let Ok(rd) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut v: Vec<(GameName, Instance)> = rd
            .filter_map(Result::ok)
            .filter_map(|e| {
                let f = e.file_name().into_string().ok()?;
                let n = GameName::new(f.strip_suffix(".toml")?).ok()?;
                Some((n.clone(), self.load(ctx, &n).ok()??))
            })
            .take(256)
            .collect();
        v.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
        v
    }

    /// A variable from the instance environment file.
    pub fn env_value(
        &self,
        ctx: &SysCtx,
        name: &GameName,
        var: &str,
    ) -> Result<Option<String>, OpError> {
        let Some(b) = fswrite::read_regular(ctx, &template::env_path(name), 16 * 1024)? else {
            return Ok(None);
        };
        Ok(String::from_utf8_lossy(&b)
            .lines()
            .find_map(|l| l.strip_prefix(var)?.strip_prefix('=').map(str::to_owned)))
    }

    pub fn backups(&self, ctx: &SysCtx, name: &GameName) -> Vec<GameBackup> {
        let Some(dir) = ctx.path(&format!("{BACKUP_DIR}/{}", name.as_str())) else {
            return Vec::new();
        };
        let Ok(rd) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut v: Vec<GameBackup> = rd
            .filter_map(Result::ok)
            .filter_map(|e| {
                let f = e.file_name().into_string().ok()?;
                let id: u64 = f.strip_suffix(".tar.zst")?.parse().ok()?;
                let m = e.metadata().ok().filter(std::fs::Metadata::is_file)?;
                Some(GameBackup {
                    id,
                    time_ms: id,
                    size_bytes: m.len(),
                })
            })
            .collect();
        v.sort_by_key(|b| b.id);
        v
    }

    async fn is_active(&self, ctx: &SysCtx, name: &GameName) -> bool {
        ctx.runner
            .run(systemctl(&["is-active", "--quiet", &template::unit(name)]))
            .await
            .is_ok_and(|o| o.success())
    }

    async fn info(&self, ctx: &SysCtx, name: &GameName, inst: &Instance) -> GameInfo {
        GameInfo {
            name: name.as_str().to_owned(),
            template: inst.template.clone(),
            running: self.is_active(ctx, name).await,
            players: self.players.borrow().get(name.as_str()).copied(),
            version: None,
            last_backup_ms: self.backups(ctx, name).last().map(|b| b.time_ms),
        }
    }

    /// Runs one RCON command (password from the environment file).
    pub async fn rcon(
        &self,
        ctx: &SysCtx,
        name: &GameName,
        t: &Template,
        cmd: &str,
    ) -> Result<String, OpError> {
        let r = t
            .rcon
            .as_ref()
            .ok_or(OpError::new(ErrorCode::Unsupported).with_detail("no rcon"))?;
        let pw = self
            .env_value(ctx, name, &r.password_env)?
            .ok_or(not_found("rcon password"))?;
        rcon::run(r.port, &pw, cmd, rcon::TIMEOUT)
            .await
            .map_err(|e| match e {
                rcon::RconError::Timeout => OpError::new(ErrorCode::Timeout),
                e => OpError::internal(format!("rcon: {e}")),
            })
    }

    // -- install / remove --

    fn check_install(
        &self,
        ctx: &SysCtx,
        name: &GameName,
        tid: &str,
    ) -> Result<&Template, OpError> {
        let t = self.template(tid).ok_or(invalid("unknown template"))?;
        let user = template::user(name);
        let pw = crate::users::passwd(ctx)?;
        if self.load(ctx, name)?.is_some()
            || lookup(&pw, &user).is_some()
            || exists(ctx, &template::dir(name))
            || exists(ctx, &template::unit_path(name))
        {
            return Err(OpError::new(ErrorCode::Busy).with_detail("game already exists"));
        }
        let tool = if t.is_container() {
            template::DOCKER
        } else {
            STEAMCMD
        };
        if !exists(ctx, tool) {
            return Err(not_found("installer not present (game role)"));
        }
        Ok(t)
    }

    async fn install(
        &self,
        ctx: &SysCtx,
        name: &GameName,
        t: &Template,
        op_id: u64,
        now: u64,
    ) -> Result<GameInfo, OpError> {
        ok(ctx.runner.run(useradd_spec(name)).await, "useradd")?;
        let user = template::user(name);
        let entry = lookup(&crate::users::passwd(ctx)?, &user)
            .cloned()
            .ok_or_else(|| OpError::internal("game user missing after useradd"))?;
        let inst = Instance {
            template: t.id.clone(),
            uid: entry.uid,
            gid: entry.gid,
            installed_ms: now,
        };
        // Directories: created by root under the root-owned /srv/games, then
        // handed to the (new, process-less) game user.
        let d = template::dir(name);
        fswrite::ensure_dir(ctx, template::GAMES_DIR, 0o755)?;
        let subs = [format!("{d}/server"), format!("{d}/data")];
        for s in &subs {
            fswrite::ensure_dir(ctx, s, 0o750)?;
        }
        for s in subs.iter().chain([&d]) {
            own(ctx, s, inst.uid, inst.gid, 0o750)?;
        }
        // Instance record and secrets (root only).
        fswrite::ensure_dir(ctx, template::STATE_DIR, 0o700)?;
        let mut env = format!("{}={}\n", template::GAME_PASSWORD_ENV, random_secret()?);
        if let Some(r) = &t.rcon {
            env.push_str(&format!("{}={}\n", r.password_env, random_secret()?));
        }
        fswrite::write_atomic(ctx, &template::env_path(name), env.as_bytes(), 0o600)?;
        let rec = toml::to_string(&inst).map_err(OpError::internal)?;
        fswrite::write_atomic(ctx, &template::instance_path(name), rec.as_bytes(), 0o600)?;
        // Unit.
        let unit = template::render_unit(t, name, inst.uid, inst.gid);
        fswrite::write_atomic(ctx, &template::unit_path(name), unit.as_bytes(), 0o644)?;
        ok(
            ctx.runner.run(systemctl(&["daemon-reload"])).await,
            "daemon-reload",
        )?;
        ok(
            ctx.runner.run(install_spec(op_id, t, name, &inst)).await,
            "install",
        )?;
        ok(
            ctx.runner
                .run(systemctl(&["enable", "--now", &template::unit(name)]))
                .await,
            "enable",
        )?;
        Ok(self.info(ctx, name, &inst).await)
    }

    async fn remove(&self, ctx: &SysCtx, name: &GameName, keep_data: bool) -> Result<(), OpError> {
        let unit = template::unit(name);
        ok(
            ctx.runner
                .run(systemctl(&["disable", "--now", &unit]))
                .await,
            "disable",
        )?;
        remove_file(ctx, &template::unit_path(name))?;
        ok(
            ctx.runner.run(systemctl(&["daemon-reload"])).await,
            "daemon-reload",
        )?;
        remove_file(ctx, &template::env_path(name))?;
        remove_file(ctx, &template::instance_path(name))?;
        self.players.borrow_mut().remove(name.as_str());
        self.gauges.clear_gauge(&players_gauge(name));
        if !keep_data {
            let user =
                UserName::new(template::user(name)).map_err(|_| OpError::internal("user name"))?;
            ok(
                ctx.runner
                    .run(crate::users::userdel_cmd(&user, false))
                    .await,
                "userdel",
            )?;
            for dir in [
                template::dir(name),
                format!("{BACKUP_DIR}/{}", name.as_str()),
            ] {
                ok(
                    ctx.runner
                        .run(
                            CommandSpec::new(RM)
                                .args(["-rf", "--one-file-system", "--", dir.as_str()])
                                .timeout(BACKUP_TIMEOUT),
                        )
                        .await,
                    "rm",
                )?;
            }
        }
        Ok(())
    }

    // -- backups --

    async fn backup(
        &self,
        ctx: &SysCtx,
        name: &GameName,
        inst: &Instance,
        t: &Template,
        op_id: u64,
        now: u64,
    ) -> Result<Vec<GameBackup>, OpError> {
        if let Some(save) = t.rcon.as_ref().and_then(|r| r.save_command.clone())
            && self.is_active(ctx, name).await
            && let Err(e) = self.rcon(ctx, name, t, &save).await
        {
            // Best effort: a stopped or busy server still gets its files.
            log("save before backup", e);
        }
        let stage = format!("{}/{STAGE}", template::dir(name));
        remove_file(ctx, &stage)?;
        ok(
            ctx.runner.run(backup_spec(op_id, t, name, inst)).await,
            "tar",
        )?;
        // Copy out as root, never following a link the game user planted.
        let dir = format!("{BACKUP_DIR}/{}", name.as_str());
        fswrite::ensure_dir(ctx, BACKUP_DIR, 0o755)?;
        fswrite::ensure_dir(ctx, &dir, 0o750)?;
        own(ctx, &dir, 0, inst.gid, 0o750)?;
        let mut id = now;
        while exists(ctx, &backup_path(name, id)) {
            id += 1;
        }
        let src_path = AbsPath::new(stage.clone()).map_err(|_| OpError::internal("stage path"))?;
        let root = AbsPath::new(template::GAMES_DIR).map_err(|_| OpError::internal("root"))?;
        let (_, src) = open_allowed(ctx, &src_path, [&root])?;
        let dest_abs = backup_path(name, id);
        let tmp_abs = format!("{dest_abs}.tmp");
        remove_file(ctx, &tmp_abs)?;
        let tmp = ctx
            .path(&tmp_abs)
            .ok_or_else(|| OpError::internal("bad path"))?;
        let dst = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(libc::O_NOFOLLOW)
                .mode(0o640)
                .open(&tmp)
                .map_err(OpError::internal)?
        };
        let mut s = tokio::fs::File::from_std(src);
        let mut d = tokio::fs::File::from_std(dst);
        tokio::io::copy(&mut s, &mut d)
            .await
            .map_err(OpError::internal)?;
        d.sync_all().await.map_err(OpError::internal)?;
        drop(d);
        own(ctx, &tmp_abs, 0, inst.gid, 0o640)?;
        let dest = ctx
            .path(&dest_abs)
            .ok_or_else(|| OpError::internal("bad path"))?;
        std::fs::rename(&tmp, &dest).map_err(OpError::internal)?;
        remove_file(ctx, &stage)?;
        // Retention: newest `keep`.
        let all = self.backups(ctx, name);
        let excess = all.len().saturating_sub(t.backup.keep as usize);
        for b in &all[..excess] {
            remove_file(ctx, &backup_path(name, b.id))?;
        }
        Ok(self.backups(ctx, name))
    }

    async fn restore(
        &self,
        ctx: &SysCtx,
        name: &GameName,
        inst: &Instance,
        id: u64,
        op_id: u64,
    ) -> Result<(), OpError> {
        let unit = template::unit(name);
        ok(ctx.runner.run(systemctl(&["stop", &unit])).await, "stop")?;
        ok(
            ctx.runner.run(restore_spec(op_id, name, inst, id)).await,
            "tar",
        )?;
        ok(ctx.runner.run(systemctl(&["start", &unit])).await, "start")
    }

    // -- background --

    /// Players (every minute) and scheduled restarts. Call every [`TICK`].
    pub async fn tick(&self, ctx: &SysCtx) {
        let now = ctx.clock.now_ms();
        let prev = self.last_tick.replace(Some(now));
        let poll_players = now.saturating_sub(self.last_players.get()) >= PLAYERS_EVERY_MS;
        if poll_players {
            self.last_players.set(now);
        }
        for (name, inst) in self.instances(ctx) {
            let Some(t) = self.template(&inst.template) else {
                continue;
            };
            if let (Some(prev), Some(s)) = (prev, &t.schedule)
                && let Some(minute) = s.minute_of_day()
            {
                for (_, d) in sched::due(prev, now, minute, &s.warnings_s) {
                    self.scheduled(ctx, &name, t, d).await;
                }
            }
            if poll_players {
                self.poll_players(ctx, &name, t).await;
            }
        }
    }

    async fn scheduled(&self, ctx: &SysCtx, name: &GameName, t: &Template, d: sched::Due) {
        match d {
            sched::Due::Warn(secs) => {
                let Some(say) = t.rcon.as_ref().and_then(|r| r.say_command.as_deref()) else {
                    return;
                };
                let msg = format!("{say} Server restarting in {}", human(secs));
                if let Err(e) = self.rcon(ctx, name, t, &msg).await {
                    log("restart warning", e);
                }
            }
            sched::Due::Restart => {
                if !self.is_active(ctx, name).await {
                    return; // stopped on purpose: leave it
                }
                let r = ctx
                    .runner
                    .run(systemctl(&["restart", &template::unit(name)]))
                    .await;
                if let Err(e) = ok(r, "scheduled restart") {
                    log(name.as_str(), e);
                }
            }
        }
    }

    async fn poll_players(&self, ctx: &SysCtx, name: &GameName, t: &Template) {
        let Some((cmd, prefix)) = t
            .rcon
            .as_ref()
            .and_then(|r| Some((r.players_command.as_deref()?, r.players_prefix.as_deref()?)))
        else {
            return;
        };
        let n = match self.rcon(ctx, name, t, cmd).await {
            Ok(text) => rcon::player_count(&text, prefix),
            Err(_) => None,
        };
        match n {
            Some(n) => {
                self.players
                    .borrow_mut()
                    .insert(name.as_str().to_owned(), n);
                self.gauges
                    .set_gauge(&players_gauge(name), MetricUnit::Count, n as f32);
            }
            None => {
                self.players.borrow_mut().remove(name.as_str());
                self.gauges.clear_gauge(&players_gauge(name));
            }
        }
    }

    /// Forever, every [`TICK`]. Spawn on exec's LocalSet.
    pub async fn run(self: Rc<Self>, ctx: SysCtx) {
        let mut t = tokio::time::interval(TICK);
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            t.tick().await;
            self.tick(&ctx).await;
        }
    }
}

pub fn players_gauge(name: &GameName) -> String {
    format!("game.players:{}", name.as_str())
}

fn human(secs: u32) -> String {
    if secs >= 60 && secs.is_multiple_of(60) {
        let m = secs / 60;
        format!("{m} minute{}", if m == 1 { "" } else { "s" })
    } else {
        format!("{secs} second{}", if secs == 1 { "" } else { "s" })
    }
}

/// Every `game.*` op.
pub struct GameOps(pub Rc<GameService>);

impl OpHandler for GameOps {
    fn validate(&self, ctx: &SysCtx, op: &Op, _: &OpMeta) -> Result<(), OpError> {
        let s = &self.0;
        match op {
            Op::GameStatus { name } => {
                if let Some(n) = name {
                    s.get(ctx, n)?;
                }
                Ok(())
            }
            Op::GameInstall { name, template } => {
                s.check_install(ctx, name, template.as_str()).map(|_| ())
            }
            Op::GameUpdate { name } | Op::GameBackup { name } | Op::GameBackupsList { name } => {
                s.get(ctx, name).map(|_| ())
            }
            // Also when its template is no longer shipped.
            Op::GameRemove { name, .. } => s
                .load(ctx, name)?
                .map(|_| ())
                .ok_or(not_found("no such game")),
            Op::GameRestore { name, backup_id } => {
                s.get(ctx, name)?;
                if !s.backups(ctx, name).iter().any(|b| b.id == *backup_id) {
                    return Err(not_found("no such backup"));
                }
                Ok(())
            }
            Op::GameRcon { name, .. } => {
                let (_, t) = s.get(ctx, name)?;
                if t.rcon.is_none() {
                    return Err(ErrorCode::Unsupported.into());
                }
                Ok(())
            }
            _ => Err(ErrorCode::Unsupported.into()),
        }
    }

    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        op: &'a Op,
        meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            let s = &self.0;
            let op_id = || {
                meta.op_id()
                    .ok_or_else(|| OpError::internal("no audit seq"))
            };
            let p = match op {
                Op::GameStatus { name } => {
                    let mut games = Vec::new();
                    for (n, inst) in s.instances(ctx) {
                        if name.as_ref().is_none_or(|x| *x == n) {
                            games.push(s.info(ctx, &n, &inst).await);
                        }
                    }
                    Payload::Games(Games { games })
                }
                Op::GameInstall { name, template } => {
                    let t = s.check_install(ctx, name, template.as_str())?;
                    let info = s.install(ctx, name, t, op_id()?, meta.now_ms).await?;
                    Payload::Games(Games { games: vec![info] })
                }
                Op::GameUpdate { name } => {
                    let (inst, t) = s.get(ctx, name)?;
                    let unit = template::unit(name);
                    let was = s.is_active(ctx, name).await;
                    ok(ctx.runner.run(systemctl(&["stop", &unit])).await, "stop")?;
                    ok(
                        ctx.runner.run(install_spec(op_id()?, t, name, &inst)).await,
                        "update",
                    )?;
                    if was {
                        ok(ctx.runner.run(systemctl(&["start", &unit])).await, "start")?;
                    }
                    Payload::Empty
                }
                Op::GameBackup { name } => {
                    let (inst, t) = s.get(ctx, name)?;
                    let backups = s.backup(ctx, name, &inst, t, op_id()?, meta.now_ms).await?;
                    Payload::GameBackups(GameBackups { backups })
                }
                Op::GameBackupsList { name } => {
                    s.get(ctx, name)?;
                    Payload::GameBackups(GameBackups {
                        backups: s.backups(ctx, name),
                    })
                }
                Op::GameRestore { name, backup_id } => {
                    let (inst, _) = s.get(ctx, name)?;
                    if !s.backups(ctx, name).iter().any(|b| b.id == *backup_id) {
                        return Err(not_found("no such backup"));
                    }
                    s.restore(ctx, name, &inst, *backup_id, op_id()?).await?;
                    Payload::Empty
                }
                Op::GameRcon { name, command } => {
                    let (_, t) = s.get(ctx, name)?;
                    let text = s.rcon(ctx, name, t, command.as_str()).await?;
                    Payload::RconOutput { text }
                }
                Op::GameRemove { name, keep_data } => {
                    s.load(ctx, name)?.ok_or(not_found("no such game"))?;
                    s.remove(ctx, name, *keep_data).await?;
                    Payload::Empty
                }
                _ => return Err(ErrorCode::Unsupported.into()),
            };
            Ok(OpOutput::Payload(p))
        })
    }
}

pub fn register(r: &mut Registry, svc: Rc<GameService>) {
    let h: Rc<dyn OpHandler> = Rc::new(GameOps(svc));
    for t in [
        tag::GAME_STATUS,
        tag::GAME_INSTALL,
        tag::GAME_UPDATE,
        tag::GAME_BACKUP,
        tag::GAME_RESTORE,
        tag::GAME_RCON,
        tag::GAME_BACKUPS_LIST,
        tag::GAME_REMOVE,
    ] {
        r.register(t, h.clone());
    }
}

#[cfg(test)]
mod tests;
