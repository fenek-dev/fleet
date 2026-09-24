//! Canonical form, version and lockout-safety checks of a
//! [`FirewallRuleSet`].

use crate::ctx::SysCtx;
use fleet_proto::args::{
    FirewallMode, FirewallRule, FirewallRuleSet, FwAction, FwChain, Port, PortRange, Protocol,
};

/// Version reported for a server without `table inet fleet`.
pub const ABSENT_VERSION: u64 = 0;
/// Rules with a per-source rate limit (each owns a meter set per family).
pub const MAX_METERED: usize = 16;
/// sshd `Port` values honoured by the lockout check and the exempt rule.
pub const MAX_SSH_PORTS: usize = 8;
pub const DEFAULT_SSH_PORT: u16 = 22;

/// Sorted, merged (overlapping or adjacent ranges joined) port ranges.
/// nftables refuses overlapping intervals in one anonymous set and lists
/// them sorted, so this is the only form that renders and parses back to
/// the same model.
pub fn canonical_ports(ports: &[PortRange]) -> Vec<PortRange> {
    let mut v: Vec<(u16, u16)> = ports
        .iter()
        .map(|r| (r.start().get(), r.end().get()))
        .collect();
    v.sort_unstable();
    let mut out: Vec<(u16, u16)> = Vec::with_capacity(v.len());
    for (s, e) in v {
        match out.last_mut() {
            Some(last) if u32::from(s) <= u32::from(last.1) + 1 => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out.into_iter()
        .filter_map(|(s, e)| {
            let (s, e) = (Port::new(s).ok()?, Port::new(e).ok()?);
            PortRange::new(s, e).ok()
        })
        .collect()
}

/// The form that is rendered, parsed back and hashed.
pub fn canonical(set: &FirewallRuleSet) -> FirewallRuleSet {
    FirewallRuleSet {
        mode: set.mode,
        rules: set
            .rules
            .iter()
            .map(|r| FirewallRule {
                ports: canonical_ports(&r.ports),
                ..r.clone()
            })
            .collect(),
    }
}

/// BLAKE3 (derive-key mode) of the postcard encoding of the canonical
/// model, first 8 bytes little-endian. Never [`ABSENT_VERSION`].
pub fn version(set: &FirewallRuleSet) -> u64 {
    digest_version(&fleet_proto::encode(&canonical(set)))
}

pub(crate) fn digest_version(bytes: &[u8]) -> u64 {
    let mut h = blake3::Hasher::new_derive_key("fleet firewall model v1");
    h.update(bytes);
    let d = h.finalize();
    let mut b = [0u8; 8];
    b.copy_from_slice(&d.as_bytes()[..8]);
    match u64::from_le_bytes(b) {
        ABSENT_VERSION => 1,
        v => v,
    }
}

fn covers(r: &FirewallRule, port: u16) -> bool {
    r.ports
        .iter()
        .any(|p| (p.start().get()..=p.end().get()).contains(&port))
}

/// Why a model is refused before anything is touched (`InvalidArgument`
/// detail).
pub fn check(set: &FirewallRuleSet, ssh_ports: &[u16]) -> Result<(), &'static str> {
    set.validate().map_err(|_| "invalid rule set")?;
    if set
        .rules
        .iter()
        .any(|r| r.rate_limit.is_some() && r.action != FwAction::Accept)
    {
        return Err("rate limits apply to accept rules only");
    }
    if set.rules.iter().filter(|r| r.rate_limit.is_some()).count() > MAX_METERED {
        return Err("too many rate-limited rules");
    }
    if set.mode == FirewallMode::BansOnly {
        return Ok(());
    }
    let ssh_rule = |r: &&FirewallRule| {
        r.chain == FwChain::Input
            && r.proto == Protocol::Tcp
            && ssh_ports.iter().any(|&p| covers(r, p))
    };
    // Managed drops by default: SSH must stay reachable. Enrolled Macs
    // (the exempt sets) always are, via the fixed rule before operator
    // rules; this keeps it reachable for everything else the operator
    // declared, and auto-revert covers the rest.
    if !set
        .rules
        .iter()
        .filter(ssh_rule)
        .any(|r| r.action == FwAction::Accept)
    {
        return Err("managed mode needs an input accept rule for the SSH port");
    }
    if set
        .rules
        .iter()
        .filter(ssh_rule)
        .any(|r| r.action != FwAction::Accept && r.source.is_none())
    {
        return Err("refusing a rule that blocks the SSH port from everywhere");
    }
    Ok(())
}

/// `Port` values from `/etc/ssh/sshd_config` and
/// `/etc/ssh/sshd_config.d/*.conf` (sshd accumulates every `Port`
/// line); [`DEFAULT_SSH_PORT`] if none. Sorted, deduplicated, capped.
pub fn ssh_ports(ctx: &SysCtx) -> Vec<u16> {
    let mut files = Vec::new();
    if let Some(p) = ctx.path("/etc/ssh/sshd_config") {
        files.push(p);
    }
    if let Some(dir) = ctx.path("/etc/ssh/sshd_config.d")
        && let Ok(rd) = std::fs::read_dir(&dir)
    {
        let mut conf: Vec<_> = rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "conf"))
            .collect();
        conf.sort();
        conf.truncate(64);
        files.extend(conf);
    }
    let mut ports = Vec::new();
    for f in files {
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        ports.extend(parse_sshd_ports(&text));
    }
    ports.sort_unstable();
    ports.dedup();
    ports.truncate(MAX_SSH_PORTS);
    if ports.is_empty() {
        ports.push(DEFAULT_SSH_PORT);
    }
    ports
}

/// `Port N` lines before the first `Match` block.
pub fn parse_sshd_ports(text: &str) -> Vec<u16> {
    let mut out = Vec::new();
    for line in text.lines().take(10_000) {
        let mut it = line
            .split(|c: char| c.is_ascii_whitespace() || c == '=')
            .filter(|s| !s.is_empty());
        let Some(key) = it.next() else { continue };
        if key.starts_with('#') {
            continue;
        }
        if key.eq_ignore_ascii_case("match") {
            break;
        }
        if key.eq_ignore_ascii_case("port")
            && let Some(Ok(p)) = it.next().map(str::parse::<u16>)
            && p != 0
        {
            out.push(p);
        }
    }
    out
}
