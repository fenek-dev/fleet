//! Helpers for [`OpHandler::requires_elevated`](crate::OpHandler::requires_elevated)
//! (conditional Elevated, design §4.2). Handlers of ops with
//! `Op::may_escalate()` call these; exec answers `ApprovalRequired` when one
//! says yes and the command carries no valid root approval.
//!
//! A user is privileged (root-equivalent) when it has uid 0, is in a
//! [`PRIVILEGED_GROUPS`] group or a gid-0 group (primary or supplementary),
//! or sudoers grants it anything, directly or through one of its groups.
//! Sudoers parsing is conservative: whatever it can't follow (unreadable or
//! oversized files, too many includes, netgroups) makes every user count
//! as privileged, which only costs a Touch ID prompt.

use crate::compose;
use crate::ctx::SysCtx;
use crate::fswrite;
use crate::handler::OpError;
use crate::users::parse::{GroupEntry, PasswdEntry, lookup};
use fleet_proto::args::PRIVILEGED_GROUPS;
use fleet_proto::{ErrorCode, Op};
use std::collections::BTreeSet;

/// `compose.deploy`: `true` if the file uses a deny-listed feature;
/// `InvalidArgument` if it doesn't parse or has the wrong shape (see
/// [`compose::validate`]). `false` for every other op.
pub fn compose_deploy(op: &Op) -> Result<bool, OpError> {
    let Op::ComposeDeploy { project, file, .. } = op else {
        return Ok(false);
    };
    let v = compose::validate(project, file.as_str());
    if !v.ok {
        return Err(OpError::new(ErrorCode::InvalidArgument)
            .with_detail(format!("compose file: {:?}", v.errors)));
    }
    Ok(v.escalates())
}

/// `cron.set`: `true` for a privileged user ([`user_is_privileged`]).
/// `root` itself is already Elevated from the arguments.
pub fn cron_set(ctx: &SysCtx, op: &Op) -> Result<bool, OpError> {
    match op {
        Op::CronSet { user, .. } => user_is_privileged(ctx, user.as_str()),
        _ => Ok(false),
    }
}

/// `users.create`: `true` when the new account would be privileged: a
/// listed group (or its own `--user-group` group) is privileged or granted
/// by sudoers, or sudoers already names the user.
pub fn users_create(ctx: &SysCtx, op: &Op) -> Result<bool, OpError> {
    let Op::UsersCreate { name, groups, .. } = op else {
        return Ok(false);
    };
    let pv = Privileges::load(ctx)?;
    Ok(pv.sudo.everyone
        || pv.sudo.users.contains(name.as_str())
        || pv.user(name.as_str())
        || pv.group_name_privileged(name.as_str())
        || groups.iter().any(|g| pv.group_name_privileged(g.as_str())))
}

/// `users.groups.set`: `true` when the user is privileged already or any
/// of the new groups is.
pub fn users_groups_set(ctx: &SysCtx, op: &Op) -> Result<bool, OpError> {
    let Op::UsersGroupsSet { name, groups } = op else {
        return Ok(false);
    };
    let pv = Privileges::load(ctx)?;
    Ok(pv.user(name.as_str()) || groups.iter().any(|g| pv.group_name_privileged(g.as_str())))
}

/// From `/etc/passwd`, `/etc/group` and sudoers (under the context root).
/// An unknown user is not privileged (the op itself then fails).
pub fn user_is_privileged(ctx: &SysCtx, user: &str) -> Result<bool, OpError> {
    Ok(Privileges::load(ctx)?.user(user))
}

/// Accounts, groups and sudoers grants, read once.
#[derive(Debug, Clone, Default)]
pub struct Privileges {
    pub passwd: Vec<PasswdEntry>,
    pub groups: Vec<GroupEntry>,
    pub sudo: SudoersGrants,
}

impl Privileges {
    pub fn load(ctx: &SysCtx) -> Result<Self, OpError> {
        Ok(Self {
            passwd: crate::users::passwd(ctx)?,
            groups: crate::users::groups(ctx)?,
            sudo: sudoers(ctx),
        })
    }

    fn gid_privileged(&self, gid: u32) -> bool {
        gid == 0 || self.sudo.gids.contains(&gid)
    }

    pub fn group_privileged(&self, g: &GroupEntry) -> bool {
        self.gid_privileged(g.gid)
            || PRIVILEGED_GROUPS.contains(&g.name.as_str())
            || self.sudo.groups.contains(&g.name)
    }

    /// By name, for groups that may not exist yet.
    pub fn group_name_privileged(&self, name: &str) -> bool {
        PRIVILEGED_GROUPS.contains(&name)
            || self.sudo.groups.contains(name)
            || self
                .groups
                .iter()
                .any(|g| g.name == name && self.group_privileged(g))
    }

    pub fn entry_privileged(&self, p: &PasswdEntry) -> bool {
        p.uid == 0
            || self.sudo.everyone
            || self.sudo.users.contains(&p.name)
            || self.sudo.uids.contains(&p.uid)
            || self.gid_privileged(p.gid)
            || p.groups_in(&self.groups).any(|g| self.group_privileged(g))
    }

    pub fn user(&self, name: &str) -> bool {
        lookup(&self.passwd, name).is_some_and(|p| self.entry_privileged(p))
    }
}

// ---- sudoers ----

pub const SUDOERS: &str = "/etc/sudoers";
/// Files read in total (the main file and every include).
const MAX_FILES: usize = 128;
const MAX_FILE: u64 = 256 * 1024;
/// Nested include depth (sudo's own limit is 128; real configs use 1).
const MAX_DEPTH: usize = 8;

/// Who sudoers grants anything to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SudoersGrants {
    pub users: BTreeSet<String>,
    pub uids: BTreeSet<u32>,
    pub groups: BTreeSet<String>,
    pub gids: BTreeSet<u32>,
    /// `ALL` or a netgroup in a user list, or a file/include that couldn't
    /// be followed: every user counts as privileged.
    pub everyone: bool,
}

/// An `@include`/`@includedir` (or `#…`) directive, path as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Include {
    File(String),
    Dir(String),
}

/// Reads `/etc/sudoers` and its includes. Never fails: see
/// [`SudoersGrants::everyone`]. A missing `/etc/sudoers` grants nothing.
pub fn sudoers(ctx: &SysCtx) -> SudoersGrants {
    let mut l = Loader {
        ctx,
        g: SudoersGrants::default(),
        files: 0,
    };
    l.file(SUDOERS, 0);
    l.g
}

struct Loader<'a> {
    ctx: &'a SysCtx,
    g: SudoersGrants,
    files: usize,
}

impl Loader<'_> {
    fn file(&mut self, abs: &str, depth: usize) {
        if depth > MAX_DEPTH || self.files >= MAX_FILES || abs.contains('%') {
            self.g.everyone = true;
            return;
        }
        self.files += 1;
        let text = match fswrite::read_regular(self.ctx, abs, MAX_FILE) {
            Ok(Some(b)) => String::from_utf8_lossy(&b).into_owned(),
            Ok(None) => return,
            Err(_) => {
                self.g.everyone = true;
                return;
            }
        };
        for inc in parse_sudoers(&text, &mut self.g) {
            match inc {
                Include::File(p) => self.file(&resolve(abs, &p), depth + 1),
                Include::Dir(p) => self.dir(&resolve(abs, &p), depth + 1),
            }
        }
    }

    /// sudo reads every file in the directory in lexical order, skipping
    /// names that contain `.` or end in `~`.
    fn dir(&mut self, abs: &str, depth: usize) {
        let names = match list_dir(self.ctx, abs) {
            Ok(n) => n,
            Err(()) => {
                self.g.everyone = true;
                return;
            }
        };
        for n in names {
            if !n.contains('.') && !n.ends_with('~') {
                self.file(&format!("{}/{n}", abs.trim_end_matches('/')), depth);
            }
        }
    }
}

fn list_dir(ctx: &SysCtx, abs: &str) -> Result<Vec<String>, ()> {
    let w = fswrite::walk(ctx, abs).map_err(|_| ())?;
    if !w.exists {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for e in std::fs::read_dir(&w.path).map_err(|_| ())? {
        let e = e.map_err(|_| ())?;
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        names.push(e.file_name().into_string().map_err(|_| ())?);
        if names.len() > MAX_FILES {
            return Err(());
        }
    }
    names.sort();
    Ok(names)
}

/// Relative include paths are relative to the including file's directory.
fn resolve(including: &str, p: &str) -> String {
    if p.starts_with('/') {
        return p.to_owned();
    }
    let dir = including.rsplit_once('/').map_or("", |(d, _)| d);
    format!("{dir}/{p}")
}

/// Logical lines: `\` at end of line continues onto the next.
fn logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for l in text.lines() {
        match l.strip_suffix('\\') {
            Some(head) => {
                cur.push_str(head);
                cur.push(' ');
            }
            None => {
                cur.push_str(l);
                out.push(std::mem::take(&mut cur));
            }
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// `#` starts a comment unless a digit follows (`#1000` is a uid).
fn strip_comment(l: &str) -> &str {
    let b = l.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        if c == b'#' && !b.get(i + 1).is_some_and(u8::is_ascii_digit) {
            return &l[..i];
        }
    }
    l
}

fn directive(l: &str) -> Option<Include> {
    let (kw, rest) = l.split_once(char::is_whitespace)?;
    let path = rest.trim().trim_matches('"').to_owned();
    match kw {
        "@include" | "#include" => Some(Include::File(path)),
        "@includedir" | "#includedir" => Some(Include::Dir(path)),
        _ => None,
    }
}

/// Adds one user-list item (`name`, `#uid`, `%group`, `%#gid`, `ALL`, …).
/// Negation is ignored (conservative); upper-case alias names are skipped
/// (their `User_Alias` line is counted on its own).
fn add_item(g: &mut SudoersGrants, item: &str) {
    let item = item.trim_start_matches('!').trim_matches('"');
    if item.is_empty() {
        return;
    }
    if item == "ALL" || item.starts_with('+') {
        g.everyone = true;
    } else if let Some(gr) = item.strip_prefix('%') {
        let gr = gr.trim_start_matches(':');
        match gr.strip_prefix('#') {
            Some(n) => match n.parse() {
                Ok(gid) => {
                    g.gids.insert(gid);
                }
                Err(_) => g.everyone = true,
            },
            None if !gr.is_empty() => {
                g.groups.insert(gr.to_owned());
            }
            None => {}
        }
    } else if let Some(n) = item.strip_prefix('#') {
        match n.parse() {
            Ok(uid) => {
                g.uids.insert(uid);
            }
            Err(_) => g.everyone = true,
        }
    } else if !item.starts_with(|c: char| c.is_ascii_uppercase()) {
        g.users.insert(item.to_owned());
    }
}

/// Every word of a line we don't fully understand counts as a user.
fn add_all_words(g: &mut SudoersGrants, l: &str) {
    for w in l.split(|c: char| c.is_whitespace() || ",=:()".contains(c)) {
        add_item(g, w);
    }
}

/// Who one sudoers file lets run commands **without a password**: rules
/// with a `NOPASSWD` tag, and `Defaults[:users] !authenticate` (a bare
/// `Defaults` counts as everyone). Same user-list rules as
/// [`parse_sudoers`]; includes are not followed.
pub fn nopasswd_grants(text: &str) -> SudoersGrants {
    let mut g = SudoersGrants::default();
    for raw in logical_lines(text) {
        let t = raw.trim();
        if directive(t).is_some() {
            continue;
        }
        let l = strip_comment(t).trim();
        let Some(first) = l.split_whitespace().next() else {
            continue;
        };
        if let Some(rest) = first.strip_prefix("Defaults") {
            if !l.contains("!authenticate") {
                continue;
            }
            match rest.strip_prefix(':') {
                Some(users) => users.split(',').for_each(|u| add_item(&mut g, u)),
                // `Defaults !authenticate`, or host/command/runas scoped
                // (`@`, `!`, `>`): conservatively everyone.
                None => g.everyone = true,
            }
            continue;
        }
        if l.contains("NOPASSWD") {
            parse_sudoers(l, &mut g);
        }
    }
    g
}

impl SudoersGrants {
    /// Whether these grants cover `user` (uid `uid`, groups `groups` by
    /// name and gid).
    pub fn covers(&self, user: &str, uid: u32, groups: &[(String, u32)]) -> bool {
        self.everyone
            || self.users.contains(user)
            || self.uids.contains(&uid)
            || groups
                .iter()
                .any(|(n, gid)| self.groups.contains(n) || self.gids.contains(gid))
    }
}

/// Parses one sudoers file into `g`; returns its include directives in
/// order. Rule lines are `users hosts = …`: only the user list matters
/// (any grant counts). `Defaults` and host/command/runas aliases are
/// ignored; `User_Alias` lines and lines that don't look like a rule add
/// every name in them.
pub fn parse_sudoers(text: &str, g: &mut SudoersGrants) -> Vec<Include> {
    let mut incs = Vec::new();
    for raw in logical_lines(text) {
        let t = raw.trim();
        if let Some(inc) = directive(t) {
            incs.push(inc);
            continue;
        }
        let l = strip_comment(t).trim();
        let Some(first) = l.split_whitespace().next() else {
            continue;
        };
        if first.starts_with("Defaults")
            || matches!(
                first,
                "Host_Alias" | "Cmnd_Alias" | "Cmd_Alias" | "Runas_Alias"
            )
        {
            continue;
        }
        if first == "User_Alias" {
            add_all_words(g, &l["User_Alias".len()..]);
            continue;
        }
        let lhs: Vec<String> = l
            .split_once('=')
            .map(|(lhs, _)| {
                // `a, b` → `a,b`: list items may have spaces after commas.
                lhs.split(',')
                    .map(str::trim)
                    .collect::<Vec<_>>()
                    .join(",")
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        match lhs.as_slice() {
            [users, _hosts] => users.split(',').for_each(|u| add_item(g, u)),
            _ => add_all_words(g, l),
        }
    }
    incs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FakeRunner;
    use crate::testutil::ctx;
    use fleet_proto::args::Label;
    use fleet_proto::args::{ComposeFile, ComposeProject, GroupName, UserName};
    use fleet_proto::op::LoginShell;
    use std::rc::Rc;

    fn root(sudoers: &str) -> (tempfile::TempDir, SysCtx) {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("etc/sudoers.d")).unwrap();
        std::fs::write(
            d.path().join("etc/passwd"),
            "root:x:0:0::/root:/bin/sh\nops:x:1000:1000::/home/ops:/bin/bash\n\
             web:x:1001:1001::/srv:/usr/sbin/nologin\ndock:x:1002:999::/:/bin/sh\n\
             toor:x:0:1003::/:/bin/sh\nann:x:1004:1004::/:/bin/sh\n\
             bob:x:1005:1005::/:/bin/sh\njo:x:1006:1006::/:/bin/sh\n",
        )
        .unwrap();
        std::fs::write(
            d.path().join("etc/group"),
            "root:x:0:\nsudo:x:27:ops\nops:x:1000:\nweb:x:1001:\ndocker:x:999:\n\
             ann:x:1004:\nbob:x:1005:\ndevs:x:2000:bob\nadm:x:4:jo\n",
        )
        .unwrap();
        std::fs::write(d.path().join("etc/sudoers"), sudoers).unwrap();
        let c = ctx(d.path(), Rc::new(FakeRunner::new()));
        (d, c)
    }

    #[test]
    fn privileged_users() {
        let (_d, c) = root("");
        for (u, want) in [
            ("ops", true),  // sudo member
            ("dock", true), // primary docker
            ("toor", true), // uid 0
            ("jo", true),   // adm
            ("web", false),
            ("ann", false),
            ("nobody", false),
        ] {
            assert_eq!(user_is_privileged(&c, u).unwrap(), want, "{u}");
        }
        let op = |u: &str| Op::CronSet {
            user: UserName::new(u).unwrap(),
            entries: Vec::new(),
        };
        assert!(cron_set(&c, &op("ops")).unwrap());
        assert!(!cron_set(&c, &op("web")).unwrap());
        assert!(!cron_set(&c, &Op::SystemInfo).unwrap());
    }

    fn grants(text: &str) -> (SudoersGrants, Vec<Include>) {
        let mut g = SudoersGrants::default();
        let i = parse_sudoers(text, &mut g);
        (g, i)
    }

    fn set(v: &[&str]) -> BTreeSet<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn sudoers_parse_table() {
        // (text, users, groups, everyone)
        let cases: &[(&str, &[&str], &[&str], bool)] = &[
            (
                "# comment\n\nDefaults env_reset\nDefaults:ann !lecture\n",
                &[],
                &[],
                false,
            ),
            ("ann ALL=(ALL:ALL) ALL\n", &["ann"], &[], false),
            (
                "%devs ALL = (root) /usr/bin/systemctl\n",
                &[],
                &["devs"],
                false,
            ),
            (
                "ann, bob ,  %ops  web1 = ALL\n",
                &["ann", "bob"],
                &["ops"],
                false,
            ),
            ("ann ALL=/bin/a, \\\n    /bin/b\n", &["ann"], &[], false),
            ("ann \\\n ALL=ALL\n", &["ann"], &[], false),
            ("ALL ALL=(ALL) NOPASSWD: /bin/true\n", &[], &[], true),
            ("+admins ALL=ALL\n", &[], &[], true),
            ("!bob ALL=ALL\n", &["bob"], &[], false),
            (
                "Host_Alias H = h1, h2\nCmnd_Alias C = /bin/x\nRunas_Alias R = ann\n",
                &[],
                &[],
                false,
            ),
            (
                "User_Alias ADM = ann, %devs : OPS = bob\nADM ALL=ALL\n",
                &["ann", "bob"],
                &["devs"],
                false,
            ),
            (
                "this is not a rule\n",
                &["this", "is", "not", "a", "rule"],
                &[],
                false,
            ),
            (
                "ann ALL=ALL # trailing\n#bob ALL=ALL\n",
                &["ann"],
                &[],
                false,
            ),
            ("%:dom ALL=ALL\n", &[], &["dom"], false),
        ];
        for (text, users, groups, everyone) in cases {
            let (g, i) = grants(text);
            assert!(i.is_empty(), "{text}");
            assert_eq!(g.users, set(users), "{text}");
            assert_eq!(g.groups, set(groups), "{text}");
            assert_eq!(g.everyone, *everyone, "{text}");
        }
        let (g, _) = grants("#1000 ALL=ALL\n%#2000 ALL=ALL\n");
        assert_eq!(g.uids, BTreeSet::from([1000]));
        assert_eq!(g.gids, BTreeSet::from([2000]));
        let (_, i) = grants(
            "@includedir /etc/sudoers.d\n#includedir /x\n@include extra\n#include \"/a b\"\n",
        );
        assert_eq!(
            i,
            [
                Include::Dir("/etc/sudoers.d".into()),
                Include::Dir("/x".into()),
                Include::File("extra".into()),
                Include::File("/a b".into()),
            ]
        );
    }

    #[test]
    fn sudoers_includes_and_privilege() {
        let (d, c) = root("root ALL=(ALL) ALL\n@includedir /etc/sudoers.d\n@include local\n");
        let sd = d.path().join("etc/sudoers.d");
        std::fs::write(sd.join("10-ann"), "ann ALL=ALL\n").unwrap();
        std::fs::write(sd.join("devs"), "%devs ALL=ALL\n").unwrap();
        // Skipped by includedir rules.
        std::fs::write(sd.join("web.bak"), "web ALL=ALL\n").unwrap();
        std::fs::write(sd.join("web~"), "web ALL=ALL\n").unwrap();
        std::fs::write(d.path().join("etc/local"), "#1001 ALL=ALL\n").unwrap();
        let g = sudoers(&c);
        assert_eq!(g.users, set(&["ann", "root"]));
        assert_eq!(g.groups, set(&["devs"]));
        assert_eq!(g.uids, BTreeSet::from([1001]));
        assert!(!g.everyone);
        for (u, want) in [("ann", true), ("bob", true), ("web", true), ("dock", true)] {
            assert_eq!(user_is_privileged(&c, u).unwrap(), want, "{u}");
        }

        // Unfollowable input → everyone.
        std::fs::remove_file(d.path().join("etc/local")).unwrap();
        assert!(!sudoers(&c).everyone, "missing include is fine");
        std::os::unix::fs::symlink("/etc/shadow", sd.join("evil")).unwrap();
        assert!(sudoers(&c).everyone, "symlinked include");
        std::fs::remove_file(sd.join("evil")).unwrap();
        std::fs::write(sd.join("loop"), "@include /etc/sudoers.d/loop\n").unwrap();
        assert!(sudoers(&c).everyone, "include depth");
        std::fs::remove_file(sd.join("loop")).unwrap();
        std::fs::write(sd.join("big"), vec![b'#'; MAX_FILE as usize + 1]).unwrap();
        assert!(sudoers(&c).everyone, "oversized");
        let (_d, c) = root("");
        std::fs::remove_file(_d.path().join("etc/sudoers")).unwrap();
        assert_eq!(sudoers(&c), SudoersGrants::default());
    }

    #[test]
    fn users_ops_escalation() {
        let (_d, c) = root("%devs ALL=ALL\nnewbie ALL=ALL\n");
        let create = |n: &str, g: &[&str]| Op::UsersCreate {
            name: UserName::new(n).unwrap(),
            groups: g.iter().map(|g| GroupName::new(*g).unwrap()).collect(),
            shell: LoginShell::Bash,
            comment: Label::new("").unwrap(),
        };
        let gset = |n: &str, g: &[&str]| Op::UsersGroupsSet {
            name: UserName::new(n).unwrap(),
            groups: g.iter().map(|g| GroupName::new(*g).unwrap()).collect(),
        };
        for (op, want) in [
            (create("x", &["web"]), false),
            (create("x", &["devs"]), true),  // sudoers group
            (create("x", &["wheel"]), true), // listed group
            (create("newbie", &[]), true),   // sudoers names the user
            (create("devs", &[]), true),     // own user-group is %devs
            (gset("ann", &["web"]), false),
            (gset("ann", &["devs"]), true),
            (gset("ops", &[]), true), // already privileged
            (Op::SystemInfo, false),
        ] {
            let got = users_create(&c, &op).unwrap() || users_groups_set(&c, &op).unwrap();
            assert_eq!(got, want, "{op:?}");
        }
    }

    #[test]
    fn compose_escalation() {
        let op = |y: &str| Op::ComposeDeploy {
            project: ComposeProject::new("app").unwrap(),
            file: ComposeFile::new(y).unwrap(),
            pull: false,
        };
        assert!(!compose_deploy(&op("services:\n  w:\n    image: x\n")).unwrap());
        assert!(compose_deploy(&op("services:\n  w:\n    privileged: true\n")).unwrap());
        assert_eq!(
            compose_deploy(&op("a: &x 1\n")).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn nopasswd_rules() {
        let groups = [("ops".to_owned(), 1000), ("sudo".to_owned(), 27)];
        let covers = |t: &str| nopasswd_grants(t).covers("ops", 1000, &groups);
        assert!(covers("ops ALL=(ALL) NOPASSWD:ALL\n"));
        assert!(covers("%sudo ALL=(ALL:ALL) NOPASSWD: ALL\n"));
        assert!(covers("#1000 ALL=(ALL) NOPASSWD:ALL\n"));
        assert!(covers("ALL ALL=NOPASSWD: /usr/bin/apt\n"));
        assert!(covers("Defaults:ops !authenticate\n"));
        assert!(covers("Defaults !authenticate\n"));
        assert!(covers("ops ALL=(ALL) \\\n  NOPASSWD:ALL\n"));
        // With a password, or for someone else: fine.
        assert!(!covers("ops ALL=(ALL) ALL\n"));
        assert!(!covers("%sudo ALL=(ALL:ALL) ALL\n"));
        assert!(!covers("web ALL=(ALL) NOPASSWD:ALL\n"));
        assert!(!covers("Defaults use_pty\n# ops ALL=NOPASSWD:ALL\n"));
    }
}
