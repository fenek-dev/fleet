//! `firewall.baseline` (design §4.8, §9.4): `table inet fleet` in Managed
//! mode with rate-limited SSH and the roles' ports (`ssh.allow_from` is
//! enforced by sshd, see `profile_rules`). Rules the operator added (any comment not starting
//! with `profile:`) are kept, so re-applying the profile never drops
//! them. Phase 2: auto-revert.

use crate::module::{Action, Change, Ctx, Module, Phase};
use fleet_ops::firewall::{Table, model};
use fleet_ops::handler::OpError;
use fleet_proto::ErrorCode;
use fleet_proto::alert::Severity;
use fleet_proto::args::{
    FirewallMode, FirewallRule, FirewallRuleSet, FwAction, FwChain, FwComment, Port, PortRange,
    Protocol, RateLimit,
};

pub const PROFILE_PREFIX: &str = "profile:";

fn is_profile_rule(r: &FirewallRule) -> bool {
    r.comment.as_str().starts_with(PROFILE_PREFIX)
}

/// The profile's own rules for these sshd ports.
pub fn profile_rules(ctx: &Ctx, ssh_ports: &[u16]) -> Result<Vec<FirewallRule>, OpError> {
    let s = &ctx.profile.settings;
    let bad = |_| OpError::internal("firewall rule");
    let ports = ssh_ports
        .iter()
        .map(|p| Port::new(*p).map(PortRange::single))
        .collect::<Result<Vec<_>, _>>()
        .map_err(bad)?;
    let rate = RateLimit {
        per_minute: s.ssh_rate.0.max(1),
        burst: s.ssh_rate.1.max(1),
    };
    // From anywhere: `firewall::model::check` refuses a Managed table
    // without an unrestricted SSH accept (lockout safety). `ssh.allow_from`
    // is enforced by sshd instead (`AllowUsers <admin>@<cidr>`).
    let mut out = vec![FirewallRule {
        chain: FwChain::Input,
        action: FwAction::Accept,
        proto: Protocol::Tcp,
        ports,
        source: None,
        rate_limit: Some(rate),
        comment: FwComment::new(format!("{PROFILE_PREFIX}ssh")).map_err(bad)?,
    }];
    for m in &ctx.profile.role_manifests {
        out.extend(m.firewall.iter().cloned());
    }
    Ok(out)
}

fn describe(r: &FirewallRule) -> String {
    let ports: Vec<String> = r
        .ports
        .iter()
        .map(|p| {
            if p.start() == p.end() {
                p.start().get().to_string()
            } else {
                format!("{}-{}", p.start().get(), p.end().get())
            }
        })
        .collect();
    let proto = match r.proto {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    };
    let from = r.source.map_or_else(|| "any".to_owned(), |c| c.to_string());
    format!(
        "{:?} accept {proto}/{} from {from} [{}]",
        r.chain,
        ports.join(","),
        r.comment.as_str()
    )
}

pub struct FirewallBaseline;

impl FirewallBaseline {
    /// Current model (absent = bans-only, no rules) and the desired one.
    fn models(ctx: &Ctx) -> Result<(FirewallRuleSet, FirewallRuleSet), OpError> {
        let fail = |d: String| OpError::new(ErrorCode::InvalidArgument).with_detail(d);
        let current = match &ctx.facts.firewall {
            None => return Err(OpError::internal("firewall state not read")),
            Some(Err(e)) => return Err(fail(format!("nft: {e}"))),
            Some(Ok(Table::Absent)) => FirewallRuleSet {
                mode: FirewallMode::BansOnly,
                rules: Vec::new(),
            },
            Some(Ok(Table::Present(p))) => p.model.clone().ok_or_else(|| {
                fail("inet fleet is not in rendered form; replace it with firewall.apply".into())
            })?,
        };
        let ssh = model::ssh_info(&ctx.sys).map_err(|e| fail(e.to_owned()))?;
        let ports = if ssh.ports.is_empty() {
            vec![model::DEFAULT_SSH_PORT]
        } else {
            ssh.ports
        };
        let mut rules: Vec<FirewallRule> = current
            .rules
            .iter()
            .filter(|r| !is_profile_rule(r))
            .cloned()
            .collect();
        rules.extend(profile_rules(ctx, &ports)?);
        let desired = model::canonical(&FirewallRuleSet {
            mode: FirewallMode::Managed,
            rules,
        });
        Ok((model::canonical(&current), desired))
    }
}

impl Module for FirewallBaseline {
    fn id(&self) -> &'static str {
        "firewall.baseline"
    }
    fn title(&self) -> &'static str {
        "Firewall: drop inbound by default, rate-limited SSH"
    }
    fn phase(&self) -> Phase {
        Phase::Remote
    }
    fn weight(&self) -> u8 {
        15
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn plan(&self, ctx: &Ctx) -> Result<Vec<Change>, OpError> {
        let (current, desired) = Self::models(ctx)?;
        if current == desired {
            return Ok(Vec::new());
        }
        let mut diff = String::new();
        if current.mode != desired.mode {
            diff.push_str(&format!(
                "~ mode {:?} -> {:?}\n",
                current.mode, desired.mode
            ));
        }
        for r in current.rules.iter().filter(|r| !desired.rules.contains(r)) {
            diff.push_str(&format!("- {}\n", describe(r)));
        }
        for r in desired.rules.iter().filter(|r| !current.rules.contains(r)) {
            diff.push_str(&format!("+ {}\n", describe(r)));
        }
        Ok(vec![Change {
            module: self.id(),
            description: "replace table inet fleet (Managed, profile rules)".into(),
            diff,
            actions: vec![Action::Firewall(desired)],
        }])
    }
}
