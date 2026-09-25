//! Compose projects in `/srv/<project>/` (design §4.2 "Deploy handler
//! obligations", §9.6).
//!
//! Every command is `/usr/bin/docker compose -f /srv/<p>/compose.yaml
//! --project-directory /srv/<p> -p <p> …` with the runner's cleared
//! environment plus `HOME=/root` (registry credentials in
//! `/root/.docker`). No `COMPOSE_*`/`DOCKER_*` variable is ever passed, and
//! the explicit `-f` means no `compose.override.yaml` or `COMPOSE_FILE` is
//! merged in. Compose still reads `/srv/<p>/.env` for interpolation, so a
//! `.env` that sets any `COMPOSE_*`, `DOCKER_*`, `BUILDX_*` or `BUILDKIT_*`
//! key (profiles, path separator, host, builder…; `KEY=`, `KEY:` and
//! `export KEY=` forms, BOM stripped) or is a symlink is refused
//! (`PolicyDenied`).
//!
//! `compose.deploy`:
//! 1. `validate`: [`compose::validate`](crate::compose::validate) errors →
//!    `InvalidArgument`; `requires_elevated` → deny-listed features.
//! 2. `/srv` and `/srv/<p>` must be real, root-owned directories (created
//!    0755 / 0750 when missing); every in-project host path the file uses
//!    (bind sources, env files, build contexts) is walked and refused if a
//!    component is a symlink (a container could plant `data -> /etc`).
//! 3. `expected_version`, when given, must equal the BLAKE3 version of the
//!    current `compose.yaml` ("" when absent).
//! 4. `compose.yaml` is written atomically (0640, root).
//! 5. `pull` (when asked) then `up -d --remove-orphans`, each in a
//!    `fleet-op-<id>` scope.
//!
//! `compose.pull` pulls only (update = `compose.deploy{pull: true}` with the
//! same file, or pull then deploy); `compose.restart` restarts containers;
//! `compose.down` stops and removes them (`--volumes` on request) and keeps
//! the directory. Results are the project's `ComposeStatus`
//! (`docker compose ps --all --format json`).
//!
//! Residual race: a running container could create a symlink between the
//! walk and `up`; the Compose deny-list plus root-owned `/srv/<p>` keep
//! that to paths already writable by the project's own containers.

use crate::compose;
use crate::ctx::SysCtx;
use crate::escalation;
use crate::fswrite;
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, Registry};
use crate::runner::{CommandOutput, CommandSpec};
use crate::scope;
use fleet_proto::args::ComposeProject;
use fleet_proto::op::tag;
use fleet_proto::payload::{ComposeProjects, ComposeService, ComposeStatus};
use fleet_proto::{ErrorCode, Hash32, Op, Payload};
use std::rc::Rc;
use std::time::Duration;

pub const DOCKER: &str = "/usr/bin/docker";
pub const SRV: &str = "/srv";
pub const FILE_NAME: &str = "compose.yaml";
const MAX_FILE: u64 = 256 * 1024;
const MAX_PROJECTS: usize = 64;
const T_UP: Duration = Duration::from_secs(15 * 60);
const T_PULL: Duration = Duration::from_secs(30 * 60);
const T_DOWN: Duration = Duration::from_secs(10 * 60);
const T_PS: Duration = Duration::from_secs(60);

pub fn dir(p: &ComposeProject) -> String {
    format!("{SRV}/{}", p.as_str())
}

pub fn file(p: &ComposeProject) -> String {
    format!("{SRV}/{}/{FILE_NAME}", p.as_str())
}

/// `docker compose` with the fixed file, directory and project name.
pub fn compose_cmd<I, S>(p: &ComposeProject, args: I) -> CommandSpec
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString>,
{
    CommandSpec::new(DOCKER)
        .args(["compose", "-f"])
        .arg(file(p))
        .arg("--project-directory")
        .arg(dir(p))
        .arg("-p")
        .arg(p.as_str())
        .args(args)
        .env("HOME", "/root")
}

fn op_id(meta: &OpMeta) -> Result<u64, OpError> {
    meta.op_id()
        .ok_or_else(|| OpError::internal("mutating compose op without audit seq"))
}

fn failure(what: &str, out: &CommandOutput) -> OpError {
    let err = String::from_utf8_lossy(&out.stderr);
    let tail: String = err
        .chars()
        .rev()
        .take(400)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    OpError::new(ErrorCode::Internal).with_detail(format!("{what} exit {:?}: {tail}", out.code))
}

async fn run_ok(ctx: &SysCtx, what: &str, spec: CommandSpec) -> Result<CommandOutput, OpError> {
    let out = ctx.runner.run(spec).await?;
    if out.success() {
        Ok(out)
    } else {
        Err(failure(what, &out))
    }
}

/// Key prefixes (case-insensitive) that change what Compose, the Docker CLI
/// or BuildKit does rather than interpolate.
pub const ENV_REFUSED_PREFIXES: &[&str] = &["COMPOSE_", "DOCKER_", "BUILDX_", "BUILDKIT_"];

/// The key of one `.env` line: `KEY=…`, `KEY: …` or `export<ws>KEY=…`
/// (first `=` or `:` ends the key). `None` for blanks and comments.
fn env_key(line: &str) -> Option<&str> {
    let l = line.trim_start_matches('\u{feff}').trim();
    if l.is_empty() || l.starts_with('#') {
        return None;
    }
    let l = match l.strip_prefix("export") {
        Some(rest) if rest.starts_with(char::is_whitespace) => rest.trim_start(),
        _ => l,
    };
    let end = l.find(['=', ':'])?;
    Some(l[..end].trim())
}

/// `.env` keys that change what Compose does rather than interpolate.
pub fn env_file_refused(text: &str) -> Option<String> {
    text.lines()
        .filter_map(env_key)
        .map(str::to_owned)
        .find(|k| {
            let k = k.to_ascii_uppercase();
            ENV_REFUSED_PREFIXES.iter().any(|p| k.starts_with(p))
        })
}

/// Project directory safety: real root-owned dirs, safe `.env`.
fn check_dir(ctx: &SysCtx, p: &ComposeProject, create: bool) -> Result<bool, OpError> {
    let exists = if create {
        fswrite::ensure_dir(ctx, SRV, 0o755)?;
        fswrite::ensure_dir(ctx, &dir(p), 0o750)?;
        true
    } else {
        fswrite::walk(ctx, &dir(p))?.exists
    };
    if !exists {
        return Ok(false);
    }
    let env = format!("{}/.env", dir(p));
    if let Some(bytes) = fswrite::read_regular(ctx, &env, MAX_FILE)?
        && let Some(k) = env_file_refused(&String::from_utf8_lossy(&bytes))
    {
        return Err(OpError::new(ErrorCode::PolicyDenied).with_detail(format!(".env sets {k}")));
    }
    Ok(true)
}

fn current_file(ctx: &SysCtx, p: &ComposeProject) -> Result<Option<Vec<u8>>, OpError> {
    fswrite::read_regular(ctx, &file(p), MAX_FILE)
}

/// Existing project for pull/restart/down/status: `NotFound` otherwise.
fn require_project(ctx: &SysCtx, p: &ComposeProject) -> Result<Vec<u8>, OpError> {
    if !check_dir(ctx, p, false)? {
        return Err(OpError::new(ErrorCode::NotFound).with_detail("no such project"));
    }
    current_file(ctx, p)?
        .ok_or_else(|| OpError::new(ErrorCode::NotFound).with_detail("no compose.yaml"))
}

/// `docker compose ps --format json`: a JSON array (older Compose) or one
/// object per line (Compose ≥ 2.21).
pub fn parse_ps(out: &[u8]) -> Vec<ComposeService> {
    let text = String::from_utf8_lossy(out);
    let items: Vec<serde_json::Value> = match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(serde_json::Value::Array(a)) => a,
        Ok(v @ serde_json::Value::Object(_)) => vec![v],
        _ => text
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect(),
    };
    let s = |v: &serde_json::Value, k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .map(|x| super::clip(x, 256))
    };
    items
        .iter()
        .take(512)
        .map(|v| ComposeService {
            name: s(v, "Service").unwrap_or_default(),
            container: s(v, "Name"),
            state: super::container_state(&s(v, "State").unwrap_or_default()),
            image: s(v, "Image").unwrap_or_default(),
            update_available: None,
        })
        .collect()
}

fn hash32(bytes: &[u8]) -> Hash32 {
    *blake3::hash(bytes).as_bytes()
}

async fn status_of(
    ctx: &SysCtx,
    p: &ComposeProject,
    bytes: &[u8],
) -> Result<ComposeStatus, OpError> {
    let out = run_ok(
        ctx,
        "compose ps",
        compose_cmd(p, ["ps", "--all", "--format", "json"]).timeout(T_PS),
    )
    .await?;
    Ok(ComposeStatus {
        project: p.as_str().to_owned(),
        path: dir(p),
        file_hash: Some(hash32(bytes)),
        services: parse_ps(&out.stdout),
    })
}

async fn projects(ctx: &SysCtx, p: &ComposeProject, bytes: &[u8]) -> Result<Payload, OpError> {
    Ok(Payload::ComposeProjects(ComposeProjects {
        projects: vec![status_of(ctx, p, bytes).await?],
    }))
}

/// `compose.list`: every `/srv/<name>/compose.yaml` whose name is a valid
/// project.
async fn list(ctx: &SysCtx) -> Result<Payload, OpError> {
    let w = fswrite::walk(ctx, SRV)?;
    let mut names: Vec<ComposeProject> = if w.exists {
        std::fs::read_dir(&w.path)
            .map_err(OpError::internal)?
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter_map(|e| e.file_name().into_string().ok())
            .filter_map(|n| ComposeProject::new(n).ok())
            .collect()
    } else {
        Vec::new()
    };
    names.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    let mut out = Vec::new();
    for p in names {
        if out.len() >= MAX_PROJECTS {
            break;
        }
        // A project that can't be read safely is skipped, not fatal.
        let Ok(Some(bytes)) = check_dir(ctx, &p, false).and_then(|_| current_file(ctx, &p)) else {
            continue;
        };
        out.push(status_of(ctx, &p, &bytes).await?);
    }
    Ok(Payload::ComposeProjects(ComposeProjects { projects: out }))
}

async fn deploy(
    ctx: &SysCtx,
    meta: &OpMeta,
    p: &ComposeProject,
    yaml: &str,
    pull: bool,
) -> Result<Payload, OpError> {
    let id = op_id(meta)?;
    let verdict = compose::validate(p, yaml);
    if !verdict.ok {
        return Err(OpError::new(ErrorCode::InvalidArgument)
            .with_detail(format!("compose file: {:?}", verdict.errors)));
    }
    check_dir(ctx, p, true)?;
    let current = fswrite::version_of(&current_file(ctx, p)?.unwrap_or_default());
    if let Some(v) = meta.command.body.expected_version
        && v != current
    {
        return Err(ErrorCode::VersionConflict { current }.into());
    }
    for hp in &verdict.host_paths {
        fswrite::walk(ctx, hp)?;
    }
    fswrite::write_atomic(ctx, &file(p), yaml.as_bytes(), 0o640)?;
    if pull {
        run_ok(
            ctx,
            "compose pull",
            scope::scoped(id, compose_cmd(p, ["pull"]).timeout(T_PULL)),
        )
        .await?;
    }
    run_ok(
        ctx,
        "compose up",
        scope::scoped(
            id,
            compose_cmd(p, ["up", "-d", "--remove-orphans"]).timeout(T_UP),
        ),
    )
    .await?;
    projects(ctx, p, yaml.as_bytes()).await
}

/// `compose.*` (runner-based; no Engine API needed).
pub struct ComposeHandler;

impl ComposeHandler {
    async fn run(ctx: &SysCtx, op: &Op, meta: &OpMeta) -> Result<Payload, OpError> {
        match op {
            Op::ComposeList => list(ctx).await,
            Op::ComposeStatus { project } => {
                let bytes = require_project(ctx, project)?;
                projects(ctx, project, &bytes).await
            }
            Op::ComposeDeploy {
                project,
                file,
                pull,
            } => deploy(ctx, meta, project, file.as_str(), *pull).await,
            Op::ComposePull { project } => {
                let bytes = require_project(ctx, project)?;
                let spec = compose_cmd(project, ["pull"]).timeout(T_PULL);
                run_ok(ctx, "compose pull", scope::scoped(op_id(meta)?, spec)).await?;
                projects(ctx, project, &bytes).await
            }
            Op::ComposeRestart { project } => {
                let bytes = require_project(ctx, project)?;
                let spec = compose_cmd(project, ["restart"]).timeout(T_UP);
                run_ok(ctx, "compose restart", scope::scoped(op_id(meta)?, spec)).await?;
                projects(ctx, project, &bytes).await
            }
            Op::ComposeDown {
                project,
                remove_volumes,
            } => {
                let bytes = require_project(ctx, project)?;
                let mut args = vec!["down", "--remove-orphans"];
                if *remove_volumes {
                    args.push("--volumes");
                }
                let spec = compose_cmd(project, args).timeout(T_DOWN);
                run_ok(ctx, "compose down", scope::scoped(op_id(meta)?, spec)).await?;
                projects(ctx, project, &bytes).await
            }
            _ => Err(ErrorCode::Unsupported.into()),
        }
    }
}

impl OpHandler for ComposeHandler {
    fn validate(&self, _ctx: &SysCtx, op: &Op, _meta: &OpMeta) -> Result<(), OpError> {
        escalation::compose_deploy(op).map(|_| ())
    }

    fn requires_elevated(&self, _ctx: &SysCtx, op: &Op, _meta: &OpMeta) -> Result<bool, OpError> {
        escalation::compose_deploy(op)
    }

    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        op: &'a Op,
        meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move { Self::run(ctx, op, meta).await.map(OpOutput::Payload) })
    }
}

pub fn register(r: &mut Registry) {
    let h: Rc<dyn OpHandler> = Rc::new(ComposeHandler);
    for t in [
        tag::COMPOSE_LIST,
        tag::COMPOSE_STATUS,
        tag::COMPOSE_DEPLOY,
        tag::COMPOSE_PULL,
        tag::COMPOSE_RESTART,
        tag::COMPOSE_DOWN,
    ] {
        r.register(t, h.clone());
    }
}
