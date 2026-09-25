//! `cron` group (design §2.5, §4.2): crontabs and systemd timers.
//!
//! - `cron.list` parses `/var/spool/cron/crontabs/<user>` (one user, or
//!   every file there), plus `/etc/crontab` and `/etc/cron.d/*` when no
//!   user is given. Files are read without following symlinks, at most
//!   256 KiB each and 256 files.
//! - `cron.set` replaces a user's crontab through
//!   `/usr/bin/crontab -u <user> -` with the rendered text on stdin (the
//!   setgid `crontab` keeps spool ownership and signals cron). The version
//!   is BLAKE3 of the spool file (`fswrite::version_of`; "" when absent), so
//!   an edit made with `crontab -e` is a conflict. Elevated for root from
//!   the arguments; exec escalates for privileged users through
//!   [`escalation::cron_set`](crate::escalation::cron_set).
//! - `timers.list`: see [`timers`].

pub mod parse;
#[cfg(test)]
mod tests;
pub mod timers;

use crate::ctx::SysCtx;
use crate::escalation;
use crate::fswrite;
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, Registry};
use crate::runner::CommandSpec;
use fleet_proto::args::UserName;
use fleet_proto::op::{CronEntry, tag};
use fleet_proto::payload::{CronTab, CronTabs};
use fleet_proto::{ErrorCode, Op, Payload};
use std::rc::Rc;

pub const CRONTAB: &str = "/usr/bin/crontab";
pub const SPOOL: &str = "/var/spool/cron/crontabs";
const MAX_FILE: u64 = 256 * 1024;
const MAX_FILES: usize = 256;

pub fn crontab_cmd(user: &UserName, text: &str) -> CommandSpec {
    CommandSpec::new(CRONTAB)
        .args(["-u", user.as_str(), "-"])
        .stdin(text.as_bytes())
}

fn read(ctx: &SysCtx, abs: &str) -> Result<Option<Vec<u8>>, OpError> {
    fswrite::read_regular(ctx, abs, MAX_FILE)
}

fn tab(user: Option<&str>, source: &str, bytes: Option<&[u8]>, system: bool) -> CronTab {
    let bytes = bytes.unwrap_or_default();
    CronTab {
        user: user.map(str::to_owned),
        source: source.to_owned(),
        version: fswrite::version_of(bytes),
        entries: parse::parse_crontab(&String::from_utf8_lossy(bytes), system),
    }
}

fn user_tab(ctx: &SysCtx, user: &str) -> Result<CronTab, OpError> {
    let abs = format!("{SPOOL}/{user}");
    let bytes = read(ctx, &abs)?;
    Ok(tab(Some(user), &abs, bytes.as_deref(), false))
}

/// Regular file names in `abs`, sorted, skipping dotfiles and package
/// leftovers (`*~`, `*.dpkg-*`) like cron does.
fn dir_names(ctx: &SysCtx, abs: &str) -> Result<Vec<String>, OpError> {
    let w = fswrite::walk(ctx, abs)?;
    if !w.exists {
        return Ok(Vec::new());
    }
    let mut names: Vec<String> = std::fs::read_dir(&w.path)
        .map_err(|e| OpError::internal(format!("{abs}: {e}")))?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !n.starts_with('.') && !n.ends_with('~') && !n.contains(".dpkg-"))
        .collect();
    names.sort();
    names.truncate(MAX_FILES);
    Ok(names)
}

/// `cron.list`.
pub fn list(ctx: &SysCtx, user: Option<&UserName>) -> Result<CronTabs, OpError> {
    if let Some(u) = user {
        return Ok(CronTabs {
            tabs: vec![user_tab(ctx, u.as_str())?],
        });
    }
    let mut tabs = Vec::new();
    for n in dir_names(ctx, SPOOL)? {
        if UserName::new(n.clone()).is_ok() {
            tabs.push(user_tab(ctx, &n)?);
        }
    }
    if let Some(b) = read(ctx, "/etc/crontab")? {
        tabs.push(tab(None, "/etc/crontab", Some(&b), true));
    }
    for n in dir_names(ctx, "/etc/cron.d")? {
        let abs = format!("/etc/cron.d/{n}");
        if let Some(b) = read(ctx, &abs)? {
            tabs.push(tab(None, &abs, Some(&b), true));
        }
    }
    Ok(CronTabs { tabs })
}

fn check(ctx: &SysCtx, op: &Op) -> Result<(), OpError> {
    match op {
        Op::CronSet { user, entries } => {
            if entries.len() > 256 {
                return Err(OpError::new(ErrorCode::InvalidArgument).with_detail("entries"));
            }
            if !crate::users::passwd(ctx)?
                .iter()
                .any(|p| p.name == user.as_str())
            {
                return Err(OpError::new(ErrorCode::NotFound).with_detail("no such user"));
            }
            Ok(())
        }
        Op::CronList { .. } | Op::TimersList => Ok(()),
        _ => Err(ErrorCode::Unsupported.into()),
    }
}

async fn set(
    ctx: &SysCtx,
    meta: &OpMeta,
    user: &UserName,
    entries: &[CronEntry],
) -> Result<CronTabs, OpError> {
    let current = user_tab(ctx, user.as_str())?.version;
    if let Some(v) = meta.command.body.expected_version
        && v != current
    {
        return Err(ErrorCode::VersionConflict { current }.into());
    }
    let out = ctx
        .runner
        .run(crontab_cmd(user, &parse::render(entries)))
        .await?;
    if !out.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let code = if err.contains("not allowed") {
            ErrorCode::PolicyDenied // cron.allow / cron.deny
        } else {
            ErrorCode::Internal
        };
        return Err(OpError::new(code).with_detail(format!(
            "crontab exit {:?}: {}",
            out.code,
            err.chars().take(300).collect::<String>()
        )));
    }
    list(ctx, Some(user))
}

/// `cron.list`, `cron.set`, `timers.list`.
pub struct CronHandler;

impl OpHandler for CronHandler {
    fn validate(&self, ctx: &SysCtx, op: &Op, _meta: &OpMeta) -> Result<(), OpError> {
        check(ctx, op)
    }

    fn requires_elevated(&self, ctx: &SysCtx, op: &Op, _meta: &OpMeta) -> Result<bool, OpError> {
        escalation::cron_set(ctx, op)
    }

    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        op: &'a Op,
        meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            check(ctx, op)?;
            let p = match op {
                Op::CronList { user } => Payload::CronTabs(list(ctx, user.as_ref())?),
                Op::CronSet { user, entries } => {
                    Payload::CronTabs(set(ctx, meta, user, entries).await?)
                }
                Op::TimersList => Payload::Timers(timers::list(ctx).await?),
                _ => return Err(ErrorCode::Unsupported.into()),
            };
            Ok(OpOutput::Payload(p))
        })
    }
}

pub fn register(r: &mut Registry) {
    let h: Rc<dyn OpHandler> = Rc::new(CronHandler);
    for t in [tag::CRON_LIST, tag::CRON_SET, tag::TIMERS_LIST] {
        r.register(t, h.clone());
    }
}
