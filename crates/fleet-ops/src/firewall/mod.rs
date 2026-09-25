//! `firewall` group (design §4.8): Fleet's own `table inet fleet`.
//!
//! - [`render`]: the typed model → one `nft -f -` transaction (pure).
//! - [`parse`]: `nft -j list table inet fleet` → model + version; other
//!   tables and `ufw status verbose` summarised read-only.
//! - [`FirewallHandler`]: `firewall.get`, `firewall.apply`.
//! - [`FirewallRevert`]: the auto-revert module for
//!   [`ChangeKind::Firewall`] (design §4.10).
//!
//! Ban sets survive applies: their declarations are re-added idempotently
//! and never deleted, only the chains and meters are replaced (see
//! [`render`]). Nothing outside `inet fleet` is ever touched.

pub mod model;
pub mod parse;
pub mod render;

#[cfg(test)]
mod tests;

use crate::ctx::SysCtx;
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, Registry};
use crate::revertible::Revertible;
use crate::runner::{CommandOutput, CommandSpec, RunError};
use fleet_proto::args::{FirewallMode, FirewallRuleSet};
use fleet_proto::op::tag;
use fleet_proto::payload::{ChangeKind, FirewallState, PendingChange};
use fleet_proto::{ErrorCode, Op, Payload};
use parse::{Parsed, UfwStatus};
use serde::{Deserialize, Serialize};
use std::rc::Rc;
use std::time::Duration;

pub const NFT: &str = "/usr/sbin/nft";
pub const UFW: &str = "/usr/sbin/ufw";
const NFT_TIMEOUT: Duration = Duration::from_secs(20);
/// `list table inet fleet` with a large ban list is still well under this.
const TABLE_CAP: usize = 16 << 20;
const RULESET_CAP: usize = 8 << 20;
/// Cap of `FirewallState::foreign_ruleset`.
pub const FOREIGN_TEXT_CAP: usize = 32 << 10;

pub fn list_table_spec() -> CommandSpec {
    CommandSpec::new(NFT)
        .args(["-j", "list", "table", "inet", "fleet"])
        .timeout(NFT_TIMEOUT)
        .output_cap(TABLE_CAP)
}

pub fn list_table_text_spec() -> CommandSpec {
    CommandSpec::new(NFT)
        .args(["list", "table", "inet", "fleet"])
        .timeout(NFT_TIMEOUT)
        .output_cap(TABLE_CAP)
}

pub fn list_ruleset_spec() -> CommandSpec {
    CommandSpec::new(NFT)
        .args(["-j", "list", "ruleset"])
        .timeout(NFT_TIMEOUT)
        .output_cap(RULESET_CAP)
}

/// `nft -f -` with the script on stdin: one atomic transaction.
pub fn apply_spec(script: String) -> CommandSpec {
    CommandSpec::new(NFT)
        .args(["-f", "-"])
        .stdin(script.into_bytes())
        .timeout(NFT_TIMEOUT)
}

pub fn ufw_status_spec() -> CommandSpec {
    CommandSpec::new(UFW)
        .args(["status", "verbose"])
        .timeout(Duration::from_secs(10))
        .output_cap(256 << 10)
}

/// State of `table inet fleet`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Table {
    Absent,
    Present(Parsed),
}

impl Table {
    pub fn version(&self) -> u64 {
        match self {
            Table::Absent => model::ABSENT_VERSION,
            Table::Present(p) => p.version,
        }
    }
}

fn nft_error(out: &CommandOutput) -> OpError {
    let err: String = String::from_utf8_lossy(&out.stderr)
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(512)
        .collect();
    OpError::internal(format!("nft: {err}"))
}

/// nft reports a missing table as ENOENT.
fn is_absent(out: &CommandOutput) -> bool {
    !out.success() && String::from_utf8_lossy(&out.stderr).contains("No such file or directory")
}

pub fn table_from(out: Result<CommandOutput, RunError>) -> Result<Table, OpError> {
    let out = out?;
    if is_absent(&out) {
        return Ok(Table::Absent);
    }
    if !out.success() {
        return Err(nft_error(&out));
    }
    if out.truncated {
        return Err(OpError::internal("nft: table listing over the size cap"));
    }
    parse::parse_table(&out.stdout)
        .map(Table::Present)
        .map_err(|e| OpError::internal(format!("nft: {e}")))
}

fn applied(out: Result<CommandOutput, RunError>) -> Result<(), OpError> {
    let out = out?;
    if out.success() {
        Ok(())
    } else {
        Err(nft_error(&out))
    }
}

fn ufw_from(out: Result<CommandOutput, RunError>) -> Option<UfwStatus> {
    // Not installed, not root, or failing: no adopted firewall to show.
    let out = out.ok().filter(CommandOutput::success)?;
    Some(parse::parse_ufw(&String::from_utf8_lossy(&out.stdout)))
}

/// Text cap on a char boundary.
fn cap_text(mut s: String, cap: usize) -> String {
    if s.len() > cap {
        let mut end = cap;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
        s.push_str("\n(truncated)\n");
    }
    s
}

/// Reads everything `firewall.get` answers.
pub async fn read_state(ctx: &SysCtx) -> Result<FirewallState, OpError> {
    let table = table_from(ctx.runner.run(list_table_spec()).await)?;
    let ruleset = ctx.runner.run(list_ruleset_spec()).await;
    let tables = match &ruleset {
        Ok(o) if o.success() && !o.truncated => {
            parse::summarize_ruleset(&o.stdout).map_err(|_| "unparseable listing")
        }
        Ok(o) if o.truncated => Err("listing over the size cap"),
        _ => Err("nft failed"),
    };
    let ufw = ufw_from(ctx.runner.run(ufw_status_spec()).await);
    let (mode, rules, banned, unrecognized) = match &table {
        // Nothing enforced yet: effectively bans-only (with no bans).
        Table::Absent => (FirewallMode::BansOnly, Vec::new(), 0, None),
        Table::Present(p) => (
            p.mode,
            p.model
                .as_ref()
                .map(|m| m.rules.clone())
                .unwrap_or_default(),
            p.banned,
            p.unrecognized,
        ),
    };
    let text = parse::foreign_text(
        tables.as_deref().map_err(|e| *e),
        ufw.as_ref(),
        unrecognized,
    );
    Ok(FirewallState {
        mode,
        version: table.version(),
        rules,
        banned,
        foreign_ruleset: cap_text(text, FOREIGN_TEXT_CAP),
    })
}

/// Lockout checks against where sshd listens now (`InvalidArgument`,
/// also when sshd's config can't be read in full).
fn check_set(ctx: &SysCtx, set: &FirewallRuleSet) -> Result<model::SshInfo, OpError> {
    let invalid = |d| OpError::new(ErrorCode::InvalidArgument).with_detail(d);
    let ssh = model::ssh_info(ctx).map_err(invalid)?;
    model::check(set, &ssh).map_err(invalid)?;
    Ok(ssh)
}

/// `firewall.get` and `firewall.apply`.
#[derive(Default)]
pub struct FirewallHandler;

impl FirewallHandler {
    async fn apply(
        &self,
        ctx: &SysCtx,
        set: &FirewallRuleSet,
        meta: &OpMeta,
    ) -> Result<OpOutput, OpError> {
        let set = model::canonical(set);
        let ssh = check_set(ctx, &set)?;
        // Ban updates must not interleave with the replacement.
        let _table = crate::nftlock::lock().await;
        // Versioned state (design §2.6): re-read right before applying.
        let table = table_from(ctx.runner.run(list_table_spec()).await)?;
        let current = table.version();
        if meta.command.body.expected_version != Some(current) {
            return Err(ErrorCode::VersionConflict { current }.into());
        }
        let mut script = render::render(&set, &ssh.ports);
        if let Table::Present(p) = &table
            && p.model.is_none()
        {
            // Unrecognized: drop its foreign chains/sets first, keep the
            // ban/exempt sets (re-adding elements of any recreated one).
            let c = p.cleanup.as_ref().map_err(|d| {
                OpError::new(ErrorCode::InvalidArgument)
                    .with_detail(format!("inet fleet can't be replaced: {d}"))
            })?;
            script = format!("{}{script}{}", c.pre, c.post);
        }
        applied(ctx.runner.run(apply_spec(script)).await)?;
        // Exec fills in id, deadline and origin; only `new_version` is read.
        Ok(OpOutput::Payload(Payload::ChangePending {
            change: PendingChange {
                change_id: [0; 16],
                kind: ChangeKind::Firewall,
                op_tag: tag::FIREWALL_APPLY,
                created_ms: 0,
                deadline_ms: 0,
                new_version: Some(model::version(&set)),
            },
            inner: None,
        }))
    }
}

impl OpHandler for FirewallHandler {
    fn validate(&self, ctx: &SysCtx, op: &Op, _meta: &OpMeta) -> Result<(), OpError> {
        match op {
            Op::FirewallGet => Ok(()),
            Op::FirewallApply(set) => check_set(ctx, &model::canonical(set)).map(|_| ()),
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
            match op {
                Op::FirewallGet => Ok(OpOutput::Payload(Payload::Firewall(read_state(ctx).await?))),
                Op::FirewallApply(set) => self.apply(ctx, set, meta).await,
                _ => Err(ErrorCode::Unsupported.into()),
            }
        })
    }
}

pub fn register(r: &mut Registry) {
    let h = Rc::new(FirewallHandler);
    r.register(tag::FIREWALL_GET, h.clone());
    r.register(tag::FIREWALL_APPLY, h);
}

/// What `pending/<id>.bin` holds for a firewall change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Snapshot {
    /// No `inet fleet` before: restoring deletes the table.
    Absent,
    /// The table was in rendered form: restoring re-renders it (bans kept,
    /// SSH ports as configured at restore time).
    Model(FirewallRuleSet),
    /// Not in rendered form: `nft list table inet fleet` text, restored as
    /// delete + recreate (set elements as listed then).
    Raw(String),
}

const SNAPSHOT_V1: u8 = 1;

impl Snapshot {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = vec![SNAPSHOT_V1];
        v.extend(fleet_proto::encode(self));
        v
    }

    pub fn decode(b: &[u8]) -> Result<Self, OpError> {
        match b.split_first() {
            Some((&SNAPSHOT_V1, rest)) => fleet_proto::decode(rest)
                .map_err(|_| OpError::internal("firewall snapshot: undecodable")),
            _ => Err(OpError::internal("firewall snapshot: unknown version")),
        }
    }

    /// The `nft -f -` script that puts this snapshot back. A raw snapshot
    /// must be exactly one `table inet fleet { … }` block.
    pub fn script(&self, ssh_ports: &[u16]) -> Result<String, OpError> {
        Ok(match self {
            Snapshot::Absent => render::delete_table_script(),
            Snapshot::Model(m) => render::render(m, ssh_ports),
            Snapshot::Raw(text) => {
                check_raw(text)
                    .map_err(|e| OpError::internal(format!("firewall snapshot: {e}")))?;
                let mut s = render::delete_table_script();
                s.push_str(text);
                s
            }
        })
    }
}

/// `text` is a single `table inet fleet { … }` block: nothing before or
/// after it, no `include`/`define`/variables, no nested `table`, no `#`
/// comments (which could hide braces). Quoted strings are skipped.
pub fn check_raw(text: &str) -> Result<(), &'static str> {
    let body = text
        .trim_start()
        .strip_prefix("table inet fleet {")
        .ok_or("not a table inet fleet block")?;
    let mut depth = 1usize;
    let mut word = String::new();
    let mut chars = body.char_indices();
    let mut end = None;
    while let Some((i, c)) = chars.next() {
        if c.is_ascii_alphanumeric() || c == '_' {
            word.push(c);
            continue;
        }
        if matches!(word.as_str(), "include" | "define" | "table") {
            return Err("forbidden statement");
        }
        word.clear();
        match c {
            '"' => loop {
                match chars.next() {
                    Some((_, '"')) => break,
                    Some((_, '\n')) | None => return Err("unterminated string"),
                    Some(_) => {}
                }
            },
            '#' | '$' | '\\' => return Err("forbidden character"),
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(i + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    let end = end.ok_or("unbalanced braces")?;
    if !body[end..].trim().is_empty() {
        return Err("content after the table");
    }
    Ok(())
}

/// Auto-revert module for [`ChangeKind::Firewall`]. Synchronous (the
/// `Revertible` contract), so it uses `CommandRunner::run_blocking`.
#[derive(Default)]
pub struct FirewallRevert;

impl FirewallRevert {
    pub fn take_snapshot(ctx: &SysCtx) -> Result<Snapshot, OpError> {
        Ok(
            match table_from(ctx.runner.run_blocking(list_table_spec()))? {
                Table::Absent => Snapshot::Absent,
                Table::Present(Parsed { model: Some(m), .. }) => Snapshot::Model(m),
                Table::Present(_) => {
                    let out = ctx.runner.run_blocking(list_table_text_spec())?;
                    if !out.success() || out.truncated {
                        return Err(nft_error(&out));
                    }
                    let text = String::from_utf8(out.stdout)
                        .map_err(|_| OpError::internal("nft: listing not UTF-8"))?;
                    // Refuse the op now rather than hold a snapshot that
                    // can't be restored.
                    check_raw(&text).map_err(|e| OpError::internal(format!("nft listing: {e}")))?;
                    Snapshot::Raw(text)
                }
            },
        )
    }
}

impl Revertible for FirewallRevert {
    fn snapshot(&self, ctx: &SysCtx, _op: &Op) -> Result<Vec<u8>, OpError> {
        Ok(Self::take_snapshot(ctx)?.encode())
    }

    fn restore(&self, ctx: &SysCtx, snapshot: &[u8]) -> Result<(), OpError> {
        let snap = Snapshot::decode(snapshot)?;
        let script = snap.script(&model::ssh_ports_lenient(ctx))?;
        // Synchronous: take the table lock when free. When an async writer
        // in this process holds it, waiting would deadlock the
        // single-threaded runtime, and a revert must not be skipped, so
        // it proceeds (the `fleet-agent revert` process never contends).
        let _table = crate::nftlock::try_lock();
        applied(ctx.runner.run_blocking(apply_spec(script)))
    }
}
