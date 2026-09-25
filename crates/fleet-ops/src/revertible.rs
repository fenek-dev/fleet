//! Auto-revert snapshots (design §4.10).
//!
//! For every op with `Op::auto_revert()`, exec (not the handler) runs the
//! protocol: after the audit intent it asks the [`Revertible`] registered for
//! the op's [`ChangeKind`] for a snapshot, writes `pending/<id>.bin`, arms
//! the `fleet-revert-<id>` timer and only then calls the op's handler. The
//! independent `fleet-agent revert <id>` process looks the kind up in the
//! same [`Reverters`] and calls [`Revertible::restore`]. A kind without a
//! registered `Revertible` can't be applied (`Unsupported`, nothing burned)
//! and can't be restored (audited as a failed revert).
//!
//! Handler contract for auto-revert ops: `handle` applies the change and
//! returns `Payload::ChangePending` (only `new_version` is read; exec fills
//! in id, kind, tag and deadline) or `Payload::Empty`.

use crate::ctx::SysCtx;
use crate::handler::OpError;
use fleet_proto::Op;
use fleet_proto::payload::ChangeKind;
use std::collections::BTreeMap;
use std::rc::Rc;

/// Snapshot and restore of one kind of state (ruleset, `sshd_config.d`,
/// authorized keys, mesh config, …).
pub trait Revertible {
    /// Captures what `op` is about to change. Runs in exec after the audit
    /// intent, before the handler; an error aborts the op (nothing applied).
    /// The bytes are stored in `pending/<id>.bin` (0600, root only); they
    /// must not need exec's state to restore.
    fn snapshot(&self, ctx: &SysCtx, op: &Op) -> Result<Vec<u8>, OpError>;

    /// Puts the snapshot back and reloads the affected service. Runs in the
    /// `revert <id>` process (no redb, no exec state) or in exec at startup
    /// / maintenance, possibly after a reboot; must be idempotent.
    fn restore(&self, ctx: &SysCtx, snapshot: &[u8]) -> Result<(), OpError>;
}

/// The kind an auto-revert op snapshots; `None` for every other op.
pub fn change_kind(op: &Op) -> Option<ChangeKind> {
    Some(match op {
        Op::FirewallApply(_) => ChangeKind::Firewall,
        Op::AuthorizedKeysSet { .. } => ChangeKind::AuthorizedKeys,
        Op::MeshJoin(_) | Op::MeshLeave | Op::MeshPeersSet { .. } => ChangeKind::Mesh,
        Op::ProfileApply { .. } => ChangeKind::Profile,
        _ => return None,
    })
}

/// [`ChangeKind`] → [`Revertible`]. Built the same way in exec and in the
/// `revert` process ([`Reverters::with_generic`]).
#[derive(Default, Clone)]
pub struct Reverters {
    by_kind: BTreeMap<u8, Rc<dyn Revertible>>,
}

fn key(kind: ChangeKind) -> u8 {
    match kind {
        ChangeKind::Firewall => 0,
        ChangeKind::Ssh => 1,
        ChangeKind::Network => 2,
        ChangeKind::Mesh => 3,
        ChangeKind::Profile => 4,
        ChangeKind::AuthorizedKeys => 5,
        ChangeKind::AgentUpdate => 6,
    }
}

impl Reverters {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every restore module in this crate. Kinds without one are
    /// unavailable (a revert is audited as failed, never as restored).
    pub fn with_generic() -> Self {
        let mut r = Self::new();
        r.register(
            ChangeKind::AuthorizedKeys,
            Rc::new(crate::users::authorized_keys::AuthorizedKeysReverter),
        );
        r
    }

    /// Registers (or replaces) the module for `kind`.
    pub fn register(&mut self, kind: ChangeKind, r: Rc<dyn Revertible>) {
        self.by_kind.insert(key(kind), r);
    }

    pub fn get(&self, kind: ChangeKind) -> Option<Rc<dyn Revertible>> {
        self.by_kind.get(&key(kind)).cloned()
    }

    /// Restores `snapshot` with the module for `kind`; `Unsupported` if none.
    pub fn restore(&self, ctx: &SysCtx, kind: ChangeKind, snapshot: &[u8]) -> Result<(), OpError> {
        self.get(kind)
            .ok_or(OpError::new(fleet_proto::ErrorCode::Unsupported))?
            .restore(ctx, snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_proto::ErrorCode;
    use std::cell::RefCell;

    struct Mem(RefCell<Vec<u8>>);
    impl Revertible for Mem {
        fn snapshot(&self, _: &SysCtx, _: &Op) -> Result<Vec<u8>, OpError> {
            Ok(self.0.borrow().clone())
        }
        fn restore(&self, _: &SysCtx, s: &[u8]) -> Result<(), OpError> {
            *self.0.borrow_mut() = s.to_vec();
            Ok(())
        }
    }

    #[test]
    fn kinds_match_auto_revert() {
        use fleet_proto::args::{FirewallMode, FirewallRuleSet};
        let fw = Op::FirewallApply(FirewallRuleSet {
            mode: FirewallMode::Managed,
            rules: vec![],
        });
        for (op, kind) in [
            (fw, Some(ChangeKind::Firewall)),
            (Op::MeshLeave, Some(ChangeKind::Mesh)),
            (Op::MeshPeersSet { peers: vec![] }, Some(ChangeKind::Mesh)),
            (Op::SystemInfo, None),
            (Op::FirewallGet, None),
        ] {
            assert_eq!(op.auto_revert(), kind.is_some(), "{}", op.name());
            assert_eq!(change_kind(&op), kind, "{}", op.name());
        }
    }

    #[test]
    fn registry_restores_by_kind() {
        let ctx = SysCtx::system();
        let mut r = Reverters::with_generic();
        assert_eq!(
            r.restore(&ctx, ChangeKind::Firewall, b"x")
                .unwrap_err()
                .code(),
            ErrorCode::Unsupported
        );
        let m = Rc::new(Mem(RefCell::new(b"old".to_vec())));
        r.register(ChangeKind::Firewall, m.clone());
        let snap = r
            .get(ChangeKind::Firewall)
            .unwrap()
            .snapshot(&ctx, &Op::MeshLeave)
            .unwrap();
        *m.0.borrow_mut() = b"new".to_vec();
        r.restore(&ctx, ChangeKind::Firewall, &snap).unwrap();
        assert_eq!(*m.0.borrow(), b"old");
        assert!(r.get(ChangeKind::Mesh).is_none());
    }
}
