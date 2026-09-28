//! `users` group (design §2.5, §4.2): accounts, groups and the extra
//! section of `/etc/fleet/authorized_keys/<user>`.
//!
//! - `users.list` reads `/etc/passwd`, `/etc/group` and `/etc/shadow`; only
//!   lock/expiry state leaves the shadow parser, never a hash.
//! - Mutations call `/usr/sbin/{useradd,usermod,userdel,groupadd}` with
//!   argument vectors (`--` before the name). Accounts are created without
//!   a password; login is by key only (`authorized_keys.set`).
//! - `users.lock` locks both password and key login: `--lock` plus
//!   `--expiredate 1` (sshd and PAM refuse expired accounts). Unlock clears
//!   the expiry and unlocks a locked hash.
//! - Refused with `PolicyDenied` in `validate` (before the nonce is
//!   consumed): any change to `root`/uid 0, to system accounts (outside
//!   `UID_MIN..=UID_MAX`), to `fleet*` accounts or groups, and lock, delete
//!   or group change of a user with a roster section in its authorized keys
//!   file (the admin the Macs log in as: lockout).
//! - Privileged groups (`sudo`, `docker`, …) make `users.create` and
//!   `users.groups.set` Elevated from their arguments (catalog tier); exec
//!   escalates further through [`escalation::users_create`] and
//!   [`escalation::users_groups_set`] (sudoers-granted groups, users that
//!   are privileged already).
//! - [`passwd`], [`groups`], [`uid_range`] and [`parse`] are the only
//!   `/etc/passwd`, `/etc/group` and `login.defs` readers in this crate.

pub mod authorized_keys;
pub mod parse;
/// `search.users`.
pub mod search;
#[cfg(test)]
mod tests;

use crate::ctx::SysCtx;
use crate::escalation;
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, Registry};
use crate::runner::{CommandOutput, CommandSpec};
use crate::security::EventSink;
use fleet_proto::args::{GroupName, UserName};
use fleet_proto::event::UserChangeKind;
use fleet_proto::op::tag;
use fleet_proto::payload::{GroupInfo, UserInfo, Users};
use fleet_proto::{ErrorCode, Event, Op, Payload};
use parse::{GroupEntry, PasswdEntry};
use std::rc::Rc;

pub const USERADD: &str = "/usr/sbin/useradd";
pub const USERMOD: &str = "/usr/sbin/usermod";
pub const USERDEL: &str = "/usr/sbin/userdel";
pub const GROUPADD: &str = "/usr/sbin/groupadd";

const MAX_ETC: u64 = 16 << 20;

pub(crate) fn read_etc(ctx: &SysCtx, abs: &str) -> Result<String, OpError> {
    let b = crate::fswrite::read_regular(ctx, abs, MAX_ETC)?.unwrap_or_default();
    Ok(String::from_utf8_lossy(&b).into_owned())
}

/// `/etc/passwd` entries (empty if absent). The one passwd reader.
pub fn passwd(ctx: &SysCtx) -> Result<Vec<PasswdEntry>, OpError> {
    Ok(parse::parse_passwd(&read_etc(ctx, "/etc/passwd")?))
}

/// `/etc/group` entries (empty if absent). The one group reader.
pub fn groups(ctx: &SysCtx) -> Result<Vec<GroupEntry>, OpError> {
    Ok(parse::parse_group(&read_etc(ctx, "/etc/group")?))
}

/// `(UID_MIN, UID_MAX)` of this host.
pub fn uid_range(ctx: &SysCtx) -> Result<(u32, u32), OpError> {
    Ok(parse::uid_range(&read_etc(ctx, "/etc/login.defs")?))
}

fn denied(detail: &'static str) -> OpError {
    OpError::new(ErrorCode::PolicyDenied).with_detail(detail)
}

/// Account whose crontab (`cron.set`) or extra keys (`authorized_keys.set`)
/// may be replaced: exists, not `fleet*`, a login shell, and a regular
/// account (`UID_MIN..=UID_MAX`) or `root` itself (Elevated by the catalog).
/// Refused with `PolicyDenied` (unknown: `NotFound`).
pub fn check_login_target(ctx: &SysCtx, user: &UserName) -> Result<PasswdEntry, OpError> {
    if user.is_fleet() {
        return Err(denied("fleet account"));
    }
    let entry = parse::lookup(&passwd(ctx)?, user.as_str())
        .cloned()
        .ok_or_else(|| OpError::new(ErrorCode::NotFound).with_detail("no such user"))?;
    let (uid_min, uid_max) = uid_range(ctx)?;
    if !(user.is_root() && entry.uid == 0) && !(uid_min..=uid_max).contains(&entry.uid) {
        return Err(denied("system account"));
    }
    if !entry.can_login() {
        return Err(denied("account has no login shell"));
    }
    Ok(entry)
}

/// `users.list`.
pub fn list(ctx: &SysCtx, now_ms: u64) -> Result<Users, OpError> {
    let pv = escalation::Privileges::load(ctx)?;
    let shadow = parse::parse_shadow(&read_etc(ctx, "/etc/shadow")?);
    let (uid_min, uid_max) = uid_range(ctx)?;
    let today = now_ms / 86_400_000;
    let mut users: Vec<UserInfo> = pv
        .passwd
        .iter()
        .map(|p| {
            let mut names: Vec<String> = p.groups_in(&pv.groups).map(|g| g.name.clone()).collect();
            names.dedup();
            let privileged = pv.entry_privileged(p);
            UserInfo {
                name: p.name.clone(),
                uid: p.uid,
                gid: p.gid,
                home: p.home.clone(),
                shell: p.shell.clone(),
                groups: names,
                locked: shadow.get(&p.name).is_some_and(|s| s.locked(today)),
                privileged,
                system: p.uid < uid_min || p.uid > uid_max,
                last_login_ms: None,
            }
        })
        .collect();
    users.sort_by_key(|u| u.uid);
    let mut groups: Vec<GroupInfo> = pv
        .groups
        .into_iter()
        .map(|g| GroupInfo {
            name: g.name,
            gid: g.gid,
            members: g.members,
        })
        .collect();
    groups.sort_by_key(|g| g.gid);
    Ok(Users { users, groups })
}

/// Lock, delete and group changes: only ordinary, non-admin accounts.
fn check_modifiable(ctx: &SysCtx, name: &UserName) -> Result<PasswdEntry, OpError> {
    if name.is_root() || name.is_fleet() {
        return Err(denied("protected account"));
    }
    let entry = parse::lookup(&passwd(ctx)?, name.as_str())
        .cloned()
        .ok_or_else(|| OpError::new(ErrorCode::NotFound).with_detail("no such user"))?;
    let (uid_min, uid_max) = uid_range(ctx)?;
    if entry.uid == 0 {
        return Err(denied("uid 0"));
    }
    if entry.uid < uid_min || entry.uid > uid_max {
        return Err(denied("system account"));
    }
    if authorized_keys::has_roster_section(ctx, name.as_str())? {
        return Err(denied("fleet admin user (roster keys)"));
    }
    Ok(entry)
}

fn check_groups(groups: &[GroupName]) -> Result<(), OpError> {
    if groups.len() > 32 {
        return Err(OpError::new(ErrorCode::InvalidArgument).with_detail("too many groups"));
    }
    if groups.iter().any(GroupName::is_fleet) {
        return Err(denied("fleet group"));
    }
    Ok(())
}

pub(crate) fn check(ctx: &SysCtx, op: &Op) -> Result<(), OpError> {
    match op {
        Op::UsersList => Ok(()),
        Op::UsersCreate {
            name,
            groups,
            comment,
            ..
        } => {
            if name.is_fleet() || name.is_root() {
                return Err(denied("reserved name"));
            }
            // `:` would split the passwd line (useradd refuses it too).
            if comment.as_str().contains(':') {
                return Err(OpError::new(ErrorCode::InvalidArgument).with_detail("':' in comment"));
            }
            check_groups(groups)
        }
        Op::UsersLock { name, .. } | Op::UsersDelete { name, .. } => {
            check_modifiable(ctx, name).map(|_| ())
        }
        Op::UsersGroupsSet { name, groups } => {
            check_groups(groups)?;
            check_modifiable(ctx, name).map(|_| ())
        }
        Op::GroupsCreate { name } => {
            if name.is_fleet() {
                return Err(denied("reserved name"));
            }
            Ok(())
        }
        _ => Err(ErrorCode::Unsupported.into()),
    }
}

fn joined(groups: &[GroupName]) -> String {
    groups
        .iter()
        .map(GroupName::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

pub fn useradd_cmd(
    name: &UserName,
    groups: &[GroupName],
    shell: &str,
    comment: &str,
) -> CommandSpec {
    let mut c = CommandSpec::new(USERADD).args([
        "--create-home",
        "--user-group",
        "--shell",
        shell,
        "--comment",
        comment,
    ]);
    if !groups.is_empty() {
        c = c.args(["--groups".to_owned(), joined(groups)]);
    }
    c.args(["--", name.as_str()])
}

pub fn lock_cmd(name: &UserName, locked: bool, hash_locked: bool) -> CommandSpec {
    let c = CommandSpec::new(USERMOD);
    let c = if locked {
        c.args(["--lock", "--expiredate", "1"])
    } else if hash_locked {
        c.args(["--unlock", "--expiredate", ""])
    } else {
        // No hash to unlock (key-only account): `--unlock` would refuse to
        // create a passwordless account.
        c.args(["--expiredate", ""])
    };
    c.args(["--", name.as_str()])
}

pub fn userdel_cmd(name: &UserName, remove_home: bool) -> CommandSpec {
    let c = CommandSpec::new(USERDEL);
    let c = if remove_home { c.arg("--remove") } else { c };
    c.args(["--", name.as_str()])
}

pub fn groups_set_cmd(name: &UserName, groups: &[GroupName]) -> CommandSpec {
    CommandSpec::new(USERMOD).args([
        "--groups".to_owned(),
        joined(groups),
        "--".to_owned(),
        name.as_str().to_owned(),
    ])
}

pub fn groupadd_cmd(name: &GroupName) -> CommandSpec {
    CommandSpec::new(GROUPADD).args(["--", name.as_str()])
}

/// shadow-utils exit codes → protocol codes.
fn exit_error(out: &CommandOutput) -> OpError {
    let code = match out.code {
        Some(6) => ErrorCode::NotFound,        // group or user doesn't exist
        Some(9) => ErrorCode::InvalidArgument, // name already in use
        Some(8) => ErrorCode::Busy,            // userdel: user logged in
        Some(10) => ErrorCode::Busy,           // can't update group file (lock)
        _ => ErrorCode::Internal,
    };
    let err = String::from_utf8_lossy(&out.stderr);
    let tail: String = err
        .chars()
        .rev()
        .take(300)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    OpError::new(code).with_detail(format!("exit {:?}: {tail}", out.code))
}

async fn run(ctx: &SysCtx, spec: CommandSpec) -> Result<(), OpError> {
    let out = ctx.runner.run(spec).await?;
    if out.success() {
        Ok(())
    } else {
        Err(exit_error(&out))
    }
}

fn sudo_in(groups: &[GroupName]) -> bool {
    groups.iter().any(|g| g.as_str() == "sudo")
}

/// Every `users` op except `authorized_keys.*`.
pub struct UsersHandler {
    pub sink: Rc<dyn EventSink>,
}

impl UsersHandler {
    fn emit(&self, kind: UserChangeKind, name: &str) {
        self.sink.emit(Event::UserChanged {
            kind,
            name: name.to_owned(),
        });
    }

    async fn run(&self, ctx: &SysCtx, op: &Op, meta: &OpMeta) -> Result<Payload, OpError> {
        check(ctx, op)?;
        match op {
            Op::UsersList => {}
            Op::UsersCreate {
                name,
                groups,
                shell,
                comment,
            } => {
                run(
                    ctx,
                    useradd_cmd(name, groups, shell.path(), comment.as_str()),
                )
                .await?;
                self.emit(UserChangeKind::UserAdded, name.as_str());
                if sudo_in(groups) {
                    self.emit(UserChangeKind::SudoerAdded, name.as_str());
                }
            }
            Op::UsersLock { name, locked } => {
                let hash_locked = parse::parse_shadow(&read_etc(ctx, "/etc/shadow")?)
                    .get(name.as_str())
                    .is_some_and(|s| s.password_locked);
                run(ctx, lock_cmd(name, *locked, hash_locked)).await?;
                let kind = if *locked {
                    UserChangeKind::UserLocked
                } else {
                    UserChangeKind::UserUnlocked
                };
                self.emit(kind, name.as_str());
            }
            Op::UsersDelete { name, remove_home } => {
                run(ctx, userdel_cmd(name, *remove_home)).await?;
                // Its key file (no roster section: checked above) goes too.
                let abs = format!("{}/{}", authorized_keys::DIR, name.as_str());
                let w = crate::fswrite::walk(ctx, &abs)?;
                if w.exists {
                    std::fs::remove_file(&w.path).map_err(OpError::internal)?;
                }
                self.emit(UserChangeKind::UserRemoved, name.as_str());
            }
            Op::UsersGroupsSet { name, groups: new } => {
                let was_sudo = groups(ctx)?
                    .iter()
                    .any(|g| g.name == "sudo" && g.members.iter().any(|m| m == name.as_str()));
                run(ctx, groups_set_cmd(name, new)).await?;
                self.emit(UserChangeKind::MembershipChanged, name.as_str());
                match (was_sudo, sudo_in(new)) {
                    (false, true) => self.emit(UserChangeKind::SudoerAdded, name.as_str()),
                    (true, false) => self.emit(UserChangeKind::SudoerRemoved, name.as_str()),
                    _ => {}
                }
            }
            Op::GroupsCreate { name } => {
                run(ctx, groupadd_cmd(name)).await?;
                self.emit(UserChangeKind::GroupAdded, name.as_str());
            }
            _ => return Err(ErrorCode::Unsupported.into()),
        }
        Ok(Payload::Users(list(ctx, meta.now_ms)?))
    }
}

impl OpHandler for UsersHandler {
    fn validate(&self, ctx: &SysCtx, op: &Op, _meta: &OpMeta) -> Result<(), OpError> {
        check(ctx, op)
    }

    /// Joining a group that is privileged or granted by sudoers (design
    /// §4.2), or changing an already privileged user. Exec asks only when
    /// `Op::may_escalate` holds.
    fn requires_elevated(&self, ctx: &SysCtx, op: &Op, _meta: &OpMeta) -> Result<bool, OpError> {
        match op {
            Op::UsersCreate { .. } => escalation::users_create(ctx, op),
            Op::UsersGroupsSet { .. } => escalation::users_groups_set(ctx, op),
            _ => Ok(false),
        }
    }

    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        op: &'a Op,
        meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move { self.run(ctx, op, meta).await.map(OpOutput::Payload) })
    }
}

/// Registers the `users` group (accounts and authorized keys). Exec passes
/// its event log as `sink`; [`Registry::with_generic`] uses a null sink.
pub fn register(r: &mut Registry, sink: Rc<dyn EventSink>) {
    let users: Rc<dyn OpHandler> = Rc::new(UsersHandler { sink: sink.clone() });
    for t in [
        tag::USERS_LIST,
        tag::USERS_CREATE,
        tag::USERS_LOCK,
        tag::USERS_DELETE,
        tag::USERS_GROUPS_SET,
        tag::GROUPS_CREATE,
    ] {
        r.register(t, users.clone());
    }
    let keys: Rc<dyn OpHandler> = Rc::new(authorized_keys::AuthorizedKeysHandler { sink });
    for t in [tag::AUTHORIZED_KEYS_GET, tag::AUTHORIZED_KEYS_SET] {
        r.register(t, keys.clone());
    }
    r.register(tag::SEARCH_USERS, Rc::new(search::SearchUsersHandler));
}
