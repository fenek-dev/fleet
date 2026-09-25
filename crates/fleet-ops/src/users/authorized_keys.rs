//! `/etc/fleet/authorized_keys/<user>` (design §5.9): file format shared
//! with exec's roster writer, `authorized_keys.get/set`, and the
//! auto-revert module for [`ChangeKind::AuthorizedKeys`].
//!
//! The file has managed roster blocks (`BEGIN`…`END`, rewritten by exec from
//! the roster; read-only here) and the extra section (every other line).
//! `authorized_keys.set` replaces the extra section only: every managed
//! block is written back byte for byte. Extra entries are plain
//! `algo base64 [comment]` lines ([`SshPublicKey::to_line`]): no options.

use crate::ctx::SysCtx;
use crate::fswrite;
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput};
use crate::revertible::Revertible;
use crate::security::EventSink;
use fleet_proto::args::{SshPublicKey, UserName};
use fleet_proto::payload::{AuthorizedKeys, ChangeKind, ChangeSource, PendingChange, RosterKey};
use fleet_proto::{DeviceId, ErrorCode, Event, Op, Payload};
use std::collections::HashSet;
use std::rc::Rc;

pub const BEGIN: &str = "# BEGIN fleet roster (managed by fleet-exec; edits are overwritten)";
pub const END: &str = "# END fleet roster";
pub const DIR: &str = "/etc/fleet/authorized_keys";
/// Largest file read (64 extra keys plus the roster are a few KiB).
pub const MAX_FILE: u64 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MergeError {
    /// A `BEGIN` marker without its `END`: where the managed block stops is
    /// unknown, so the file is left alone rather than risk dropping (or
    /// keeping stale) keys.
    #[error("unterminated managed block (BEGIN without END)")]
    Unterminated,
}

/// A file split into its sections.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Sections {
    /// Every managed block, markers included, verbatim and in order.
    pub blocks: String,
    /// Key lines inside the blocks (blank and comment lines dropped).
    pub roster: Vec<String>,
    /// Lines outside the blocks, verbatim (stray `END` markers dropped).
    pub extra: Vec<String>,
}

impl Sections {
    /// Non-blank extra lines: what `authorized_keys.get` shows and what the
    /// version covers.
    pub fn extra_lines(&self) -> Vec<String> {
        self.extra
            .iter()
            .filter(|l| !l.trim().is_empty())
            .cloned()
            .collect()
    }

    /// `expected_version` of `authorized_keys.set`: the extra section only,
    /// so a roster rewrite doesn't invalidate the operator's view.
    pub fn version(&self) -> u64 {
        fswrite::version_of(join(&self.extra_lines()).as_bytes())
    }
}

fn join(lines: &[String]) -> String {
    lines.iter().map(|l| format!("{l}\n")).collect()
}

pub fn split(existing: &str) -> Result<Sections, MergeError> {
    let mut s = Sections::default();
    let mut inside = false;
    for line in existing.lines() {
        match (inside, line) {
            (_, BEGIN) => {
                inside = true;
                s.blocks.push_str(line);
                s.blocks.push('\n');
            }
            (true, END) => {
                inside = false;
                s.blocks.push_str(line);
                s.blocks.push('\n');
            }
            (false, END) => {}
            (true, _) => {
                s.blocks.push_str(line);
                s.blocks.push('\n');
                let t = line.trim();
                if !t.is_empty() && !t.starts_with('#') {
                    s.roster.push(line.to_owned());
                }
            }
            (false, _) => s.extra.push(line.to_owned()),
        }
    }
    if inside {
        return Err(MergeError::Unterminated);
    }
    Ok(s)
}

/// Exec's roster rewrite: removes every managed block from `existing`
/// (including duplicates left by hand edits) and prepends `section`. Lines
/// outside blocks are kept in order; stray `END` markers are dropped.
pub fn merge(existing: &str, section: &str) -> Result<String, MergeError> {
    let s = split(existing)?;
    Ok(format!("{section}{}", join(&s.extra)))
}

/// `authorized_keys.set`: managed blocks verbatim, then `extra` lines.
pub fn with_extra(existing: &str, extra: &[String]) -> Result<String, MergeError> {
    let s = split(existing)?;
    Ok(format!("{}{}", s.blocks, join(extra)))
}

fn file_abs(user: &str) -> String {
    format!("{DIR}/{user}")
}

fn unterminated(_: MergeError) -> OpError {
    // Same rule as exec's roster writer: never guess where a block ends.
    OpError::new(ErrorCode::Internal).with_detail("unterminated managed block")
}

/// Current file text ("" if absent). Refuses symlinks on the way.
pub fn read_file(ctx: &SysCtx, user: &str) -> Result<String, OpError> {
    let bytes = fswrite::read_regular(ctx, &file_abs(user), MAX_FILE)?.unwrap_or_default();
    String::from_utf8(bytes)
        .map_err(|_| OpError::new(ErrorCode::Internal).with_detail("authorized_keys not UTF-8"))
}

/// The user has roster keys: it's the admin user the Macs log in as.
pub fn has_roster_section(ctx: &SysCtx, user: &str) -> Result<bool, OpError> {
    let text = read_file(ctx, user)?;
    Ok(split(&text).map_err(unterminated)?.blocks.contains(BEGIN))
}

fn roster_key(line: &str) -> RosterKey {
    let device_id = line
        .split_whitespace()
        .last()
        .and_then(|c| c.strip_prefix("fleet-device-"))
        .and_then(|id| id.parse::<DeviceId>().ok());
    RosterKey {
        device_id,
        line: clip(line),
    }
}

fn clip(s: &str) -> String {
    s.chars().take(4096).collect()
}

/// `authorized_keys.get`.
pub fn get(ctx: &SysCtx, user: &str) -> Result<AuthorizedKeys, OpError> {
    let s = split(&read_file(ctx, user)?).map_err(unterminated)?;
    Ok(AuthorizedKeys {
        user: user.to_owned(),
        version: s.version(),
        roster_section: s.roster.iter().map(|l| roster_key(l)).collect(),
        extra: s.extra_lines().iter().map(|l| clip(l)).collect(),
    })
}

/// Writes `extra` below the unchanged roster blocks; returns the new
/// extra-section version.
fn write_extra(ctx: &SysCtx, user: &str, extra: &[String]) -> Result<u64, OpError> {
    let existing = read_file(ctx, user)?;
    let new = with_extra(&existing, extra).map_err(unterminated)?;
    fswrite::ensure_dir(ctx, "/etc/fleet", 0o755)?;
    fswrite::ensure_dir(ctx, DIR, 0o755)?;
    fswrite::write_atomic(ctx, &file_abs(user), new.as_bytes(), 0o644)?;
    Ok(split(&new).map_err(unterminated)?.version())
}

/// Bounds, then the target account ([`super::check_login_target`]).
fn check_set(ctx: &SysCtx, user: &UserName, keys: &[SshPublicKey]) -> Result<(), OpError> {
    if keys.len() > 64 {
        return Err(OpError::new(ErrorCode::InvalidArgument).with_detail("more than 64 keys"));
    }
    let mut seen = HashSet::new();
    if !keys
        .iter()
        .all(|k| seen.insert((k.algo(), k.blob().to_vec())))
    {
        return Err(OpError::new(ErrorCode::InvalidArgument).with_detail("duplicate key"));
    }
    super::check_login_target(ctx, user).map(|_| ())
}

/// `authorized_keys.get/set`. `set` is Elevated and auto-reverted: exec
/// snapshots through [`AuthorizedKeysReverter`] before calling `handle`.
pub struct AuthorizedKeysHandler {
    pub sink: Rc<dyn EventSink>,
}

impl AuthorizedKeysHandler {
    fn set(
        &self,
        ctx: &SysCtx,
        meta: &OpMeta,
        user: &UserName,
        keys: &[SshPublicKey],
    ) -> Result<Payload, OpError> {
        check_set(ctx, user, keys)?;
        let user = user.as_str();
        let current = split(&read_file(ctx, user)?)
            .map_err(unterminated)?
            .version();
        // Required: a blind overwrite could drop keys added since the
        // operator's last read.
        if meta.command.body.expected_version != Some(current) {
            return Err(ErrorCode::VersionConflict { current }.into());
        }
        let lines: Vec<String> = keys.iter().map(SshPublicKey::to_line).collect();
        let new_version = write_extra(ctx, user, &lines)?;
        self.sink.emit(Event::AuthorizedKeysChanged {
            user: user.to_owned(),
            source: ChangeSource::Fleet {
                op_tag: fleet_proto::op::tag::AUTHORIZED_KEYS_SET,
                audit_seq: meta.audit_seq.unwrap_or(0),
            },
        });
        // Exec fills in id, deadline and tag (revertible.rs contract).
        Ok(Payload::ChangePending(PendingChange {
            change_id: [0; 16],
            kind: ChangeKind::AuthorizedKeys,
            op_tag: fleet_proto::op::tag::AUTHORIZED_KEYS_SET,
            created_ms: meta.now_ms,
            deadline_ms: 0,
            new_version: Some(new_version),
        }))
    }
}

impl OpHandler for AuthorizedKeysHandler {
    fn validate(&self, ctx: &SysCtx, op: &Op, _meta: &OpMeta) -> Result<(), OpError> {
        match op {
            Op::AuthorizedKeysSet { user, keys } => check_set(ctx, user, keys),
            Op::AuthorizedKeysGet { .. } => Ok(()),
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
            let p = match op {
                Op::AuthorizedKeysGet { user } => Payload::AuthorizedKeys(get(ctx, user.as_str())?),
                Op::AuthorizedKeysSet { user, keys } => self.set(ctx, meta, user, keys)?,
                _ => return Err(ErrorCode::Unsupported.into()),
            };
            Ok(OpOutput::Payload(p))
        })
    }
}

/// Snapshot = `[len(user)] user extra-section`; restore puts the extra
/// section back under the *current* roster blocks (a roster update inside
/// the confirm window is not undone). Idempotent.
pub struct AuthorizedKeysReverter;

impl Revertible for AuthorizedKeysReverter {
    fn snapshot(&self, ctx: &SysCtx, op: &Op) -> Result<Vec<u8>, OpError> {
        let Op::AuthorizedKeysSet { user, .. } = op else {
            return Err(ErrorCode::Unsupported.into());
        };
        let s = split(&read_file(ctx, user.as_str())?).map_err(unterminated)?;
        let u = user.as_str().as_bytes();
        let mut out = vec![u8::try_from(u.len()).map_err(OpError::internal)?];
        out.extend_from_slice(u);
        out.extend_from_slice(join(&s.extra).as_bytes());
        Ok(out)
    }

    fn restore(&self, ctx: &SysCtx, snapshot: &[u8]) -> Result<(), OpError> {
        let bad = || OpError::internal("bad authorized_keys snapshot");
        let (&n, rest) = snapshot.split_first().ok_or_else(bad)?;
        let n = usize::from(n);
        let user = rest.get(..n).ok_or_else(bad)?;
        let user = fleet_proto::args::UserName::new(
            std::str::from_utf8(user).map_err(|_| bad())?.to_owned(),
        )
        .map_err(|_| bad())?;
        let extra = std::str::from_utf8(&rest[n..]).map_err(|_| bad())?;
        let lines: Vec<String> = extra.lines().map(str::to_owned).collect();
        write_extra(ctx, user.as_str(), &lines).map(|_| ())
    }
}
