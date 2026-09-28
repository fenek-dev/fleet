//! Security and Firewall tab support: Mac-side ruleset history (with
//! roll back by re-applying an older ruleset) and accepted hardening
//! exceptions. Storage lives in `fleet_core::fw_history`; the agent keeps
//! neither. Nothing here talks to a server.

use crate::admin_ops::{firewall_diff, firewall_rules_to_args};
use crate::admin_rows::{DiffLineKind, DiffLineRow, FirewallRulesetArgs};
use crate::api::{FleetCore, lock};
use crate::rows::FirewallRow;
use crate::types::FleetError;
use crate::validate;
use fleet_core::fw_history::{self, FwHistoryEntry};
use fleet_proto::args::{FirewallMode, FirewallRuleSet};
use fleet_proto::payload::FirewallState;
use fleet_proto::{decode, encode};

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FwHistoryRow {
    /// Local sequence number (`v<n>` in the app).
    pub n: u32,
    pub time_ms: u64,
    /// The agent's version digest of this ruleset.
    pub version: u64,
    /// `This Mac`, `Outside this Mac`, … (never a name from the server).
    pub source: String,
    /// What changed relative to the entry before it.
    pub title: String,
}

fn corrupt() -> FleetError {
    FleetError::InvalidArgument {
        field: "history".into(),
    }
}

fn to_args(set: &FirewallRuleSet) -> FirewallRulesetArgs {
    let row = FirewallRow::from(FirewallState {
        mode: set.mode,
        version: 0,
        rules: set.rules.clone(),
        banned: 0,
        foreign_ruleset: String::new(),
    });
    FirewallRulesetArgs {
        managed: set.mode == FirewallMode::Managed,
        rules: firewall_rules_to_args(row.rules),
    }
}

/// `tcp 9100 from 10.8.0.0/24 limit …` -> `9100/tcp from 10.8.0.0/24`.
fn rule_label(line: &str) -> String {
    let body = line.split("  #").next().unwrap_or(line);
    let mut t = body.split_whitespace();
    let (_chain, _action, proto, ports) = (t.next(), t.next(), t.next(), t.next());
    let (Some(proto), Some(ports)) = (proto, ports) else {
        return body.to_string();
    };
    let source = match (t.next(), t.next()) {
        (Some("from"), Some(s)) if s != "any" => format!(" from {s}"),
        _ => String::new(),
    };
    format!("{ports}/{proto}{source}")
}

/// One line of words for a ruleset diff.
pub(crate) fn describe(lines: &[DiffLineRow]) -> String {
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut mode = None;
    for l in lines {
        if l.text.starts_with("mode ") {
            if l.kind == DiffLineKind::Added {
                mode = Some(if l.text.contains("managed") {
                    "Switched to managed mode (default drop)"
                } else {
                    "Switched to bans-only mode"
                });
            }
            continue;
        }
        match l.kind {
            DiffLineKind::Added => added.push(rule_label(&l.text)),
            DiffLineKind::Removed => removed.push(rule_label(&l.text)),
            DiffLineKind::Same => {}
        }
    }
    let rules = match (added.as_slice(), removed.as_slice()) {
        ([], []) => None,
        ([a], []) => Some(format!("Added {a}")),
        ([], [r]) => Some(format!("Removed {r}")),
        ([a], [r]) if a == r => Some(format!("Changed {a}")),
        ([a], [r]) => Some(format!("Replaced {r} with {a}")),
        (a, []) => Some(format!("Added {} rules", a.len())),
        ([], r) => Some(format!("Removed {} rules", r.len())),
        (a, r) => Some(format!("{} rules added, {} removed", a.len(), r.len())),
    };
    match (mode, rules) {
        (Some(m), Some(r)) => format!("{m}; {}", r.to_lowercase_first()),
        (Some(m), None) => m.to_string(),
        (None, Some(r)) => r,
        (None, None) => "No rule changes".to_string(),
    }
}

trait LowerFirst {
    fn to_lowercase_first(&self) -> String;
}

impl LowerFirst for String {
    fn to_lowercase_first(&self) -> String {
        let mut c = self.chars();
        c.next()
            .map(|f| f.to_lowercase().collect::<String>() + c.as_str())
            .unwrap_or_default()
    }
}

/// One line of words for the change from `current` to `proposed`
/// ("Added 9100/tcp from 10.8.0.0/24").
#[uniffi::export]
pub fn firewall_describe_change(
    current: FirewallRulesetArgs,
    proposed: FirewallRulesetArgs,
) -> Result<String, FleetError> {
    Ok(describe(&firewall_diff(current, proposed)?))
}

#[uniffi::export]
impl FleetCore {
    /// Rulesets this Mac has seen on the server, newest first.
    pub fn fw_history_list(&self, server_id: String) -> Result<Vec<FwHistoryRow>, FleetError> {
        let id = validate::server_id(&server_id)?;
        Ok(fw_history::history(&lock(&self.cache), &id)?
            .into_iter()
            .map(|e| FwHistoryRow {
                n: e.n,
                time_ms: e.time_ms,
                version: e.version,
                source: e.source,
                title: e.title,
            })
            .collect())
    }

    /// Remembers the ruleset `firewall_get` just reported (`version`) unless
    /// it is already the newest entry. The title describes the change from
    /// the previous entry unless `title` is given (roll back). Returns
    /// whether an entry was added.
    pub fn fw_history_observe(
        &self,
        server_id: String,
        current: FirewallRulesetArgs,
        version: u64,
        source: String,
        title: Option<String>,
    ) -> Result<bool, FleetError> {
        let id = validate::server_id(&server_id)?;
        let set = crate::admin_ops::fw_ruleset(&current)?;
        let cache = lock(&self.cache);
        let previous = fw_history::history(&cache, &id)?
            .into_iter()
            .next()
            .and_then(|e| decode::<FirewallRuleSet>(&e.ruleset).ok());
        let title = match (title, previous) {
            (Some(t), _) => t,
            (None, Some(prev)) => describe(&firewall_diff(to_args(&prev), to_args(&set))?),
            (None, None) => "First ruleset seen by this Mac".into(),
        };
        Ok(fw_history::observe(
            &cache,
            &id,
            FwHistoryEntry {
                n: 0,
                time_ms: fleet_core::now_ms(),
                version,
                source,
                title,
                ruleset: encode(&set),
            },
        )?)
    }

    /// The ruleset of history entry `n`, ready for `firewall_apply`.
    pub fn fw_history_ruleset(
        &self,
        server_id: String,
        n: u32,
    ) -> Result<FirewallRulesetArgs, FleetError> {
        let id = validate::server_id(&server_id)?;
        let entry = fw_history::history(&lock(&self.cache), &id)?
            .into_iter()
            .find(|e| e.n == n)
            .ok_or_else(corrupt)?;
        let set = decode::<FirewallRuleSet>(&entry.ruleset).map_err(|_| corrupt())?;
        Ok(to_args(&set))
    }

    /// Hardening modules the operator accepted as exceptions (local to this
    /// Mac), sorted.
    pub fn audit_exceptions(&self, server_id: String) -> Result<Vec<String>, FleetError> {
        let id = validate::server_id(&server_id)?;
        Ok(fw_history::exceptions(&lock(&self.cache), &id)?)
    }

    pub fn audit_exception_set(
        &self,
        server_id: String,
        module: String,
        accepted: bool,
    ) -> Result<(), FleetError> {
        let id = validate::server_id(&server_id)?;
        if module.is_empty()
            || module.len() > 64
            || !module
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
        {
            return Err(FleetError::InvalidArgument {
                field: "module".into(),
            });
        }
        Ok(fw_history::set_exception(
            &lock(&self.cache),
            &id,
            &module,
            accepted,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin_rows::{FirewallRuleArgs, FwActionArg, FwChainArg, FwProtoArg};

    fn rule(port: &str, source: Option<&str>) -> FirewallRuleArgs {
        FirewallRuleArgs {
            chain: FwChainArg::Input,
            action: FwActionArg::Accept,
            proto: FwProtoArg::Tcp,
            ports: vec![port.into()],
            source: source.map(Into::into),
            rate_per_minute: None,
            rate_burst: 10,
            comment: "x".into(),
        }
    }

    fn set(managed: bool, rules: Vec<FirewallRuleArgs>) -> FirewallRulesetArgs {
        FirewallRulesetArgs { managed, rules }
    }

    fn words(old: FirewallRulesetArgs, new: FirewallRulesetArgs) -> String {
        describe(&firewall_diff(old, new).unwrap())
    }

    #[test]
    fn describes_single_rule_changes() {
        let base = set(true, vec![rule("22", None)]);
        let plus = set(
            true,
            vec![rule("22", None), rule("9100", Some("10.8.0.0/24"))],
        );
        assert_eq!(words(base.clone(), plus.clone()), "Added 9100/tcp from 10.8.0.0/24");
        assert_eq!(words(plus.clone(), base.clone()), "Removed 9100/tcp from 10.8.0.0/24");
        let narrowed = set(true, vec![rule("22", Some("10.0.0.1"))]);
        assert_eq!(words(base, narrowed), "Replaced 22/tcp with 22/tcp from 10.0.0.1/32");
    }

    #[test]
    fn describes_mode_and_bulk_changes() {
        let a = set(true, vec![rule("22", None), rule("80", None)]);
        let b = set(false, vec![]);
        assert_eq!(
            words(a.clone(), b.clone()),
            "Switched to bans-only mode; removed 2 rules"
        );
        assert_eq!(
            words(b, a),
            "Switched to managed mode (default drop); added 2 rules"
        );
    }

    #[test]
    fn reorder_reads_as_changed_and_identical_as_none() {
        let a = set(true, vec![rule("22", None), rule("80", None)]);
        let b = set(true, vec![rule("80", None), rule("22", None)]);
        assert_eq!(words(a.clone(), b), "Changed 80/tcp");
        assert_eq!(words(a.clone(), a), "No rule changes");
    }

    #[test]
    fn ruleset_round_trips_through_history_encoding() {
        let s = set(true, vec![rule("22", Some("10.0.0.0/8")), rule("8000-8100", None)]);
        let proto = crate::admin_ops::fw_ruleset(&s).unwrap();
        let back = to_args(&decode::<FirewallRuleSet>(&encode(&proto)).unwrap());
        assert_eq!(crate::admin_ops::fw_ruleset(&back).unwrap(), proto);
    }
}
