//! Exec's [`AttributionContext`] for config history (design §4.9).
//!
//! inotify gives no writer pid, so exec can't tell who wrote a tracked
//! file. What it can tell: which of its own operations are running, and
//! which files those operations are about to write. Every admitted command
//! is registered here from its audit intent until it finishes
//! ([`ExecAttribution::begin`] → [`OpGuard`]); ops with fixed write
//! targets ([`expected_paths`]) announce them, and a pid-less watch event
//! on an announced path — while the op runs or within [`GRACE`] after
//! (watch batching) — is recorded as `Fleet { op, seq }`.
//!
//! Everything else stays `Unknown` (`busy` is always true): background
//! writes by exec itself (the `authorized_keys` roster section), and edits
//! by other processes, can't be told apart without a pid and aren't
//! guessed. Handlers that write a file themselves may still call
//! `ConfigTracker::note_write` (`config.rollback` does).

use fleet_ops::confighist::AttributionContext;
use fleet_proto::Op;
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;
use std::time::{Duration, Instant};

/// How long after an op ends its announced paths still match.
pub(super) const GRACE: Duration = Duration::from_secs(10);
/// Finished ops remembered for `op_tag` lookups (transient scopes).
const RECENT: usize = 256;

/// A write target: one file, or everything below a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Target {
    File(String),
    Below(String),
}

impl Target {
    fn matches(&self, path: &str) -> bool {
        match self {
            Target::File(f) => f == path,
            Target::Below(d) => path
                .strip_prefix(d.as_str())
                .is_some_and(|r| r.starts_with('/') && r.len() > 1),
        }
    }
}

const ACCOUNT_FILES: &[&str] = &[
    "/etc/passwd",
    "/etc/passwd-",
    "/etc/shadow",
    "/etc/shadow-",
    "/etc/group",
    "/etc/group-",
    "/etc/gshadow",
    "/etc/gshadow-",
    "/etc/subuid",
    "/etc/subgid",
];

/// The files `op`'s handler writes, when they are fixed by its arguments.
pub(super) fn expected_paths(op: &Op) -> Vec<Target> {
    let file = |s: &str| Target::File(s.to_owned());
    let below = |s: &str| Target::Below(s.to_owned());
    match op {
        Op::AuthorizedKeysSet { user, .. } => {
            vec![Target::File(format!("/etc/fleet/authorized_keys/{}", user.as_str()))]
        }
        // The roster section of the admin's file is rewritten on install.
        Op::RosterUpdate { .. } => vec![below("/etc/fleet/authorized_keys")],
        Op::UsersCreate { .. }
        | Op::UsersDelete { .. }
        | Op::UsersLock { .. }
        | Op::UsersGroupsSet { .. }
        | Op::GroupsCreate { .. } => ACCOUNT_FILES.iter().map(|f| file(f)).collect(),
        Op::MeshJoin(_) | Op::MeshLeave | Op::MeshPeersSet { .. } => {
            vec![below(fleet_ops::mesh::DIR)]
        }
        Op::ConfigRollback { path, .. } => vec![file(path.as_str())],
        Op::ComposeDeploy { project, .. } => {
            vec![Target::File(format!("/srv/{}/compose.yaml", project.as_str()))]
        }
        Op::UnitEnable { .. } | Op::UnitDisable { .. } => vec![below("/etc/systemd/system")],
        // dpkg writes conffiles while a Fleet package op runs (the same
        // rule integrity uses for re-baselining, design §4.5).
        Op::PkgInstall { .. } | Op::PkgUpgrade { .. } | Op::PkgRemove { .. } => {
            vec![below("/etc")]
        }
        _ => Vec::new(),
    }
}

struct Announced {
    target: Target,
    tag: u16,
    seq: u64,
    /// `None` while the op runs; then the end of its grace.
    until: Option<Instant>,
}

#[derive(Default)]
pub(super) struct ExecAttribution {
    running: RefCell<BTreeMap<u64, u16>>,
    recent: RefCell<VecDeque<(u64, u16)>>,
    announced: RefCell<Vec<Announced>>,
}

/// Registered op; ends it on drop.
pub(super) struct OpGuard {
    att: Rc<ExecAttribution>,
    seq: u64,
}

impl Drop for OpGuard {
    fn drop(&mut self) {
        self.att.end(self.seq);
    }
}

impl ExecAttribution {
    /// Registers `op` (audit intent `seq`) and its write targets.
    pub(super) fn begin(self: &Rc<Self>, op: &Op, seq: u64) -> OpGuard {
        let tag = op.tag();
        self.running.borrow_mut().insert(seq, tag);
        let mut a = self.announced.borrow_mut();
        let now = Instant::now();
        a.retain(|x| x.until.is_none_or(|u| u > now));
        a.extend(expected_paths(op).into_iter().map(|target| Announced {
            target,
            tag,
            seq,
            until: None,
        }));
        OpGuard {
            att: self.clone(),
            seq,
        }
    }

    fn end(&self, seq: u64) {
        let Some(tag) = self.running.borrow_mut().remove(&seq) else {
            return;
        };
        let mut r = self.recent.borrow_mut();
        r.push_back((seq, tag));
        while r.len() > RECENT {
            r.pop_front();
        }
        let until = Instant::now() + GRACE;
        for a in self.announced.borrow_mut().iter_mut().filter(|a| a.seq == seq) {
            a.until = Some(until);
        }
    }
}

impl AttributionContext for ExecAttribution {
    fn exec_pid(&self) -> u32 {
        std::process::id()
    }

    fn current_op(&self) -> Option<(u16, u64)> {
        let r = self.running.borrow();
        if r.len() == 1 {
            r.iter().next().map(|(s, t)| (*t, *s))
        } else {
            None
        }
    }

    /// Always: without a pid, a write outside an announced path can't be
    /// told from exec's own background writes, so it stays `Unknown`.
    fn busy(&self) -> bool {
        true
    }

    fn op_tag(&self, seq: u64) -> Option<u16> {
        self.running.borrow().get(&seq).copied().or_else(|| {
            self.recent
                .borrow()
                .iter()
                .find(|(s, _)| *s == seq)
                .map(|(_, t)| *t)
        })
    }

    fn expected_write(&self, path: &str) -> Option<(u16, u64)> {
        let now = Instant::now();
        let a = self.announced.borrow();
        // The newest op announcing the path wins.
        a.iter()
            .rev()
            .filter(|x| x.until.is_none_or(|u| u > now))
            .find(|x| x.target.matches(path))
            .map(|x| (x.tag, x.seq))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_proto::args::{GroupName, Label, UserName};
    use fleet_proto::op::LoginShell;

    #[test]
    fn announced_paths_while_running_then_grace() {
        let att = Rc::new(ExecAttribution::default());
        let op = Op::UsersCreate {
            name: UserName::new("eve").unwrap(),
            groups: vec![GroupName::new("adm").unwrap()],
            shell: LoginShell::Bash,
            comment: Label::new("").unwrap(),
        };
        assert_eq!(att.expected_write("/etc/passwd"), None);
        let g = att.begin(&op, 7);
        assert_eq!(att.current_op(), Some((op.tag(), 7)));
        assert_eq!(att.expected_write("/etc/passwd"), Some((op.tag(), 7)));
        assert_eq!(att.expected_write("/etc/hosts"), None);
        let other = att.begin(&Op::MeshLeave, 8);
        assert_eq!(att.current_op(), None, "two ops: no single current op");
        assert_eq!(
            att.expected_write("/etc/wireguard/fleet0.conf"),
            Some((Op::MeshLeave.tag(), 8))
        );
        assert_eq!(att.expected_write("/etc/wireguard"), None);
        drop(g);
        drop(other);
        // Within the grace window the late watch event still matches.
        assert_eq!(att.expected_write("/etc/shadow"), Some((op.tag(), 7)));
        assert_eq!(att.op_tag(7), Some(op.tag()));
        assert!(att.busy());
    }

    #[test]
    fn targets() {
        assert!(Target::Below("/etc".into()).matches("/etc/apt/sources.list"));
        assert!(!Target::Below("/etc".into()).matches("/etcetera"));
        assert!(!Target::Below("/etc".into()).matches("/etc/"));
        assert!(expected_paths(&Op::SystemInfo).is_empty());
    }
}
