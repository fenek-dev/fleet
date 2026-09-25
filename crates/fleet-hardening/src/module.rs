//! The module contract (design §9.3) and the building blocks every module
//! plans with.

use crate::facts::Facts;
use crate::profile::Resolved;
use fleet_ops::handler::{LocalBoxFuture, OpError};
use fleet_ops::{SysCtx, fswrite};
use fleet_proto::alert::Severity;
use fleet_proto::args::FirewallRuleSet;
use serde::Serialize;
use std::fmt;

/// Largest managed file read for a comparison or a snapshot.
pub const MAX_FILE: u64 = 1 << 20;
/// Cap of one change's human-readable diff.
pub const MAX_DIFF: usize = 4096;

/// Result of `check`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Compliant,
    /// What differs, human-readable.
    Drifted(String),
    /// Why the module doesn't apply here (not installed, no admin, …).
    NotApplicable(String),
    /// Configured, but only takes effect after a reboot (Strict's
    /// immutable audit rules, `/tmp` mounts).
    PendingReboot(String),
}

/// Provisioning phase (design §9.1): phase 2 (sshd and firewall) runs only
/// after the Mac has proven admin login over a second connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Phase {
    Access = 1,
    Remote = 2,
    System = 3,
}

/// One command: a fixed absolute program and its argv. `stdin` may carry a
/// secret (`chpasswd`), so `Debug` never prints it.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct Cmd {
    pub program: &'static str,
    pub args: Vec<String>,
    pub stdin: Option<Vec<u8>>,
}

impl Cmd {
    pub fn new<I, S>(program: &'static str, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            program,
            args: args.into_iter().map(Into::into).collect(),
            stdin: None,
        }
    }

    pub fn stdin(mut self, bytes: Vec<u8>) -> Self {
        self.stdin = Some(bytes);
        self
    }

    /// `program arg…` for plans and logs (stdin never shown).
    pub fn display(&self) -> String {
        let mut s = self.program.to_owned();
        for a in &self.args {
            s.push(' ');
            s.push_str(a);
        }
        if self.stdin.is_some() {
            s.push_str(" < (redacted)");
        }
        s
    }
}

impl fmt::Debug for Cmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display())
    }
}

/// One step of a change. Executed in order by [`crate::exec`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Action {
    /// Replace `path` atomically (missing parents created 0755).
    Write {
        path: String,
        content: Vec<u8>,
        mode: u32,
    },
    /// Remove `path` if present.
    Remove { path: String },
    /// A file in `user`'s home: made `root:root` 0644 (read-only for the
    /// user), created when missing; `content` replaces it when set. Home
    /// and uid are looked up when it runs (the user may be created by an
    /// earlier change of the same apply).
    RootOwn {
        user: String,
        name: String,
        content: Option<Vec<u8>>,
    },
    /// Run a command; failure fails the module.
    Run(Cmd),
    /// `apt-get purge <names>` in the op's scope.
    Purge(Vec<String>),
    /// Download an apt signing key over HTTPS, check its primary
    /// fingerprint with `gpg --show-keys`, then write it to `dest` (0644).
    FetchKey {
        url: String,
        fingerprint: String,
        dest: String,
    },
    /// Run a validation command (`sshd -t`, `visudo -c`); failure puts
    /// back every file this module wrote and fails the module.
    Validate(Cmd),
    /// `apt-get install --no-install-recommends <names>` in the op's scope.
    Install(Vec<String>),
    /// `apt-get update` in the op's scope.
    AptUpdate,
    /// Replace `table inet fleet` with this model (lockout checks first).
    Firewall(FirewallRuleSet),
}

/// One planned change: what the operator reviews (design §9.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Change {
    pub module: &'static str,
    pub description: String,
    /// Human-readable diff (no secrets).
    pub diff: String,
    pub actions: Vec<Action>,
}

/// A file as it was before a module wrote it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct FileSnap {
    pub path: String,
    /// `None`: it didn't exist.
    pub prior: Option<(Vec<u8>, u32)>,
}

/// What `apply` did, enough for `revert`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Applied {
    pub module: &'static str,
    pub files: Vec<FileSnap>,
    /// Actions run (all of them unless the module failed).
    pub actions: usize,
    /// Notes for the result (e.g. "takes effect after reboot").
    pub notes: Vec<String>,
}

/// What a module runs against.
pub struct Ctx {
    pub sys: SysCtx,
    pub profile: Resolved,
    pub facts: Facts,
    /// Scope id for long-running children (`systemd-run --scope`).
    pub op_id: u64,
    /// `apt-get update` already ran in this apply (run once).
    pub apt_updated: bool,
}

/// The module contract (design §9.3). `check` defaults to "compliant iff
/// the plan is empty"; `apply` and `revert` default to the generic
/// executor.
pub trait Module {
    fn id(&self) -> &'static str;
    fn title(&self) -> &'static str;
    fn phase(&self) -> Phase {
        Phase::System
    }
    /// Share of the audit score.
    fn weight(&self) -> u8 {
        5
    }
    fn severity(&self) -> Severity {
        Severity::Warning
    }

    fn check(&self, ctx: &Ctx) -> Result<Status, OpError> {
        Ok(status_of(&self.plan(ctx)?))
    }

    /// Empty when compliant.
    fn plan(&self, ctx: &Ctx) -> Result<Vec<Change>, OpError>;

    /// Whether a `profile.apply` of this module can fix a drift (false for
    /// e.g. AppArmor disabled on the kernel command line).
    fn fixable(&self, _ctx: &Ctx) -> bool {
        true
    }

    /// Every file `apply` may write (the auto-revert snapshot). Files in
    /// users' homes aren't listed.
    fn paths(&self, _p: &Resolved) -> Vec<String> {
        Vec::new()
    }

    /// Commands that make restored files take effect (after `revert`).
    /// Programs must be in [`crate::revert::RELOAD_PROGRAMS`].
    fn reload(&self, _p: &Resolved) -> Vec<Cmd> {
        Vec::new()
    }

    fn apply<'a>(
        &'a self,
        ctx: &'a mut Ctx,
        plan: &'a [Change],
    ) -> LocalBoxFuture<'a, Result<Applied, OpError>> {
        Box::pin(crate::exec::execute(ctx, self.id(), plan))
    }

    fn revert<'a>(
        &'a self,
        ctx: &'a mut Ctx,
        applied: &'a Applied,
    ) -> LocalBoxFuture<'a, Result<(), OpError>> {
        Box::pin(async move {
            crate::exec::restore_files(&ctx.sys, &applied.files)?;
            for c in self.reload(&ctx.profile) {
                crate::exec::run_checked(&ctx.sys, &c).await?;
            }
            Ok(())
        })
    }
}

/// Compliant iff nothing is planned; otherwise the change descriptions.
pub fn status_of(plan: &[Change]) -> Status {
    if plan.is_empty() {
        Status::Compliant
    } else {
        Status::Drifted(
            plan.iter()
                .map(|c| c.description.as_str())
                .collect::<Vec<_>>()
                .join("; "),
        )
    }
}

/// Current content and mode of a regular file; `None` if missing.
pub fn read_file(sys: &SysCtx, path: &str) -> Result<Option<(Vec<u8>, u32)>, OpError> {
    let Some(bytes) = fswrite::read_regular(sys, path, MAX_FILE)? else {
        return Ok(None);
    };
    let mode = fleet_ops::files::walk::stat_path(sys, path)
        .map_err(|e| OpError::internal(format!("stat {path}: {e}")))?
        .mode;
    Ok(Some((bytes, mode)))
}

/// Text of a file, empty when missing (unreadable is an error).
pub fn read_text(sys: &SysCtx, path: &str) -> Result<String, OpError> {
    Ok(read_file(sys, path)?
        .map(|(b, _)| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default())
}

/// A change writing `content` to `path` unless it already has exactly that
/// content and mode.
pub fn file_change(
    sys: &SysCtx,
    module: &'static str,
    path: &str,
    content: &str,
    mode: u32,
) -> Result<Option<Change>, OpError> {
    let current = read_file(sys, path)?;
    let (description, diff) = match &current {
        Some((b, m)) if b == content.as_bytes() && *m == mode => return Ok(None),
        Some((b, m)) if b == content.as_bytes() => (
            format!("chmod {mode:04o} {path}"),
            format!("mode {m:04o} -> {mode:04o}"),
        ),
        Some((b, _)) => (
            format!("update {path}"),
            line_diff(&String::from_utf8_lossy(b), content),
        ),
        None => (format!("create {path}"), line_diff("", content)),
    };
    Ok(Some(Change {
        module,
        description,
        diff,
        actions: vec![Action::Write {
            path: path.to_owned(),
            content: content.as_bytes().to_vec(),
            mode,
        }],
    }))
}

/// A change removing `path` if it exists.
pub fn remove_change(
    sys: &SysCtx,
    module: &'static str,
    path: &str,
) -> Result<Option<Change>, OpError> {
    Ok(read_file(sys, path)?.map(|(b, _)| Change {
        module,
        description: format!("remove {path}"),
        diff: line_diff(&String::from_utf8_lossy(&b), ""),
        actions: vec![Action::Remove {
            path: path.to_owned(),
        }],
    }))
}

/// A simple line diff: `-` lines only in `old`, `+` lines only in `new`
/// (order of appearance), capped at [`MAX_DIFF`]. Control characters of
/// server content are replaced.
pub fn line_diff(old: &str, new: &str) -> String {
    let olds: Vec<&str> = old.lines().collect();
    let news: Vec<&str> = new.lines().collect();
    let mut out = String::new();
    for l in olds.iter().filter(|l| !news.contains(l)) {
        push_line(&mut out, '-', l);
    }
    for l in news.iter().filter(|l| !olds.contains(l)) {
        push_line(&mut out, '+', l);
    }
    if out.len() > MAX_DIFF {
        let mut end = MAX_DIFF;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
        out.push_str("\n(truncated)\n");
    }
    out
}

fn push_line(out: &mut String, sign: char, l: &str) {
    out.push(sign);
    out.push(' ');
    out.extend(l.chars().map(|c| if c.is_control() { '?' } else { c }));
    out.push('\n');
}

/// A change that only runs commands.
pub fn run_change(module: &'static str, description: impl Into<String>, cmds: Vec<Cmd>) -> Change {
    Change {
        module,
        description: description.into(),
        diff: cmds
            .iter()
            .map(|c| format!("$ {}\n", c.display()))
            .collect(),
        actions: cmds.into_iter().map(Action::Run).collect(),
    }
}

/// Appends `extra` actions to the last change of `plan` (reloads after
/// writes), or does nothing when the plan is empty.
pub fn then_run(plan: &mut [Change], extra: impl IntoIterator<Item = Action>) {
    if let Some(last) = plan.last_mut() {
        for a in extra {
            if let Action::Run(c) | Action::Validate(c) = &a {
                last.diff.push_str(&format!("$ {}\n", c.display()));
            }
            last.actions.push(a);
        }
    }
}
