//! `shell.exec` (design §4.2): the one operation that runs a shell.
//!
//! **Security rule 4 exception, limited to this module.** Every other op
//! calls fixed binaries with typed argument vectors. `shell.exec` exists so
//! the operator can run ad-hoc commands (bulk snippets) where the policy
//! explicitly allows it, so here the operator's text *is* handed to
//! `/bin/sh -c`. What keeps it contained:
//!
//! - off by default: the policy's `shell_exec` gates the whole `shell`
//!   group in exec, and [`ShellPolicy::may_run_as`] requires the target user
//!   in `shell_exec_users` (`PolicyDenied` before the nonce is consumed);
//! - always Elevated in the catalog (`Op::tier`): every command carries a
//!   root-key approval (Touch ID);
//! - the text is operator-provided, never built by the agent from other
//!   data, and the full command goes into the audit log (the intent's
//!   `OpSummary::args` is the op's wire payload, command text included);
//! - it runs as the named user through `setpriv` (uid, gid, the user's
//!   supplementary groups, environment reset); `root` only when the policy
//!   lists `root` explicitly; never a `fleet*` account;
//! - in the op's transient scope (`fleet-op-<id>.scope`) with the op's
//!   timeout (the scope is killed with it) and output cap.
//!
//! No other module may call [`SH`].

use crate::ctx::SysCtx;
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, Registry};
use crate::runner::{CommandSpec, RunError};
use crate::users::parse::{PasswdEntry, lookup};
use fleet_proto::op::ShellExec;
use fleet_proto::payload::ShellResult;
use fleet_proto::{ErrorCode, Op, Payload};
use std::rc::Rc;
use std::time::Duration;

pub const SETPRIV: &str = "/usr/bin/setpriv";
/// `env -C <dir>`: the working directory without a `cd` in the shell text.
pub const ENV: &str = "/usr/bin/env";
/// The shell. Only [`exec_spec`] uses it.
pub const SH: &str = "/bin/sh";

/// Who may be the target of `shell.exec` (exec answers from its policy).
pub trait ShellPolicy {
    /// `capabilities.shell_exec` and `user` in `shell_exec_users`.
    fn may_run_as(&self, user: &str) -> bool;
}

/// Refuses everyone (the generic registry; exec re-registers with its
/// policy).
pub struct DenyAll;

impl ShellPolicy for DenyAll {
    fn may_run_as(&self, _: &str) -> bool {
        false
    }
}

fn denied(d: &'static str) -> OpError {
    OpError::new(ErrorCode::PolicyDenied).with_detail(d)
}

/// Policy and account checks (no side effects).
pub fn check(
    ctx: &SysCtx,
    policy: &dyn ShellPolicy,
    req: &ShellExec,
) -> Result<PasswdEntry, OpError> {
    req.validate()
        .map_err(|_| OpError::new(ErrorCode::InvalidArgument))?;
    let user = &req.user;
    if user.is_fleet() {
        return Err(denied("fleet account"));
    }
    if !policy.may_run_as(user.as_str()) {
        return Err(denied("user not in shell_exec_users"));
    }
    let entry = lookup(&crate::users::passwd(ctx)?, user.as_str())
        .cloned()
        .ok_or_else(|| OpError::new(ErrorCode::NotFound).with_detail("no such user"))?;
    // uid 0 under another name is root too: only as `root`, listed as such.
    if entry.uid == 0 && !user.is_root() {
        return Err(denied("uid 0 alias"));
    }
    Ok(entry)
}

/// `systemd-run --scope … -- setpriv --reuid=U --regid=G --init-groups
/// --reset-env -- env -C <dir> /bin/sh -c <command>`. `<dir>` is `cwd`
/// or the user's home.
pub fn exec_spec(op_id: u64, entry: &PasswdEntry, req: &ShellExec) -> CommandSpec {
    let dir = req
        .cwd
        .as_ref()
        .map_or(entry.home.as_str(), |c| c.as_str())
        .to_owned();
    let inner = CommandSpec::new(SETPRIV)
        .arg(format!("--reuid={}", entry.uid))
        .arg(format!("--regid={}", entry.gid))
        .arg("--init-groups")
        .arg("--reset-env")
        .arg("--")
        .arg(ENV)
        .arg("-C")
        .arg(dir)
        .arg(SH)
        .arg("-c")
        .arg(req.command.as_str())
        .timeout(Duration::from_secs(u64::from(req.timeout_s)))
        .output_cap(req.output_cap as usize);
    crate::scope::scoped(op_id, inner)
}

/// Combined cap: stdout first, stderr gets what is left.
fn cap_combined(mut out: Vec<u8>, mut err: Vec<u8>, cap: usize, truncated: bool) -> ShellResult {
    let mut cut = truncated;
    if out.len() > cap {
        out.truncate(cap);
        cut = true;
    }
    let room = cap - out.len();
    if err.len() > room {
        err.truncate(room);
        cut = true;
    }
    ShellResult {
        exit_code: None,
        stdout: out,
        stderr: err,
        truncated: cut,
        timed_out: false,
    }
}

pub struct ShellHandler {
    policy: Rc<dyn ShellPolicy>,
}

impl ShellHandler {
    pub fn new(policy: Rc<dyn ShellPolicy>) -> Self {
        Self { policy }
    }
}

impl OpHandler for ShellHandler {
    fn validate(&self, ctx: &SysCtx, op: &Op, _: &OpMeta) -> Result<(), OpError> {
        match op {
            Op::ShellExec(req) => check(ctx, &*self.policy, req).map(|_| ()),
            _ => Err(ErrorCode::Unsupported.into()),
        }
    }

    /// Already Elevated in the catalog (every `shell.exec`); kept true so
    /// a caller asking gets the same answer.
    fn requires_elevated(&self, _: &SysCtx, _: &Op, _: &OpMeta) -> Result<bool, OpError> {
        Ok(true)
    }

    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        op: &'a Op,
        meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            let Op::ShellExec(req) = op else {
                return Err(ErrorCode::Unsupported.into());
            };
            let entry = check(ctx, &*self.policy, req)?;
            let id = meta
                .op_id()
                .ok_or_else(|| OpError::internal("shell.exec without an audit seq"))?;
            let r = match ctx.runner.run(exec_spec(id, &entry, req)).await {
                Ok(o) => {
                    let mut r =
                        cap_combined(o.stdout, o.stderr, req.output_cap as usize, o.truncated);
                    r.exit_code = o.code;
                    r
                }
                Err(RunError::Timeout) => ShellResult {
                    exit_code: None,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    truncated: false,
                    timed_out: true,
                },
                Err(e) => return Err(e.into()),
            };
            Ok(OpOutput::Payload(Payload::ShellResult(r)))
        })
    }
}

pub fn register(r: &mut Registry, policy: Rc<dyn ShellPolicy>) {
    r.register(
        fleet_proto::op::tag::SHELL_EXEC,
        Rc::new(ShellHandler::new(policy)),
    );
}

#[cfg(test)]
mod tests;
