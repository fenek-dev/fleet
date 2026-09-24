//! Pure rendering of `table inet fleet` as one `nft -f -` transaction.
//!
//! Shape (see the golden files in `testdata/`):
//!
//! 1. `add table`, `add set` for the four ban/exempt sets (idempotent:
//!    same declaration every time, so their elements — live bans and
//!    learned Mac addresses — survive every apply), `add chain` + `delete
//!    chain` for `input`/`forward` (the idiom that doesn't fail when they
//!    don't exist yet) and `add set` + `delete set` for every meter slot
//!    (a meter's per-source state carries the rate of the rule that created
//!    it, so meters are always recreated).
//! 2. A `table inet fleet { … }` block with the meters in use and both
//!    chains.
//!
//! Nothing outside `inet fleet` is named; no `flush`. Every text token
//! comes from a typed value (`Port`, `Cidr`, `IpAddr` formatting, fixed
//! keywords) except comments, which are [`FwComment`]s (charset
//! `[A-Za-z0-9 ._:/-]`, no quote or backslash) inside double quotes.
//!
//! [`FwComment`]: fleet_proto::args::FwComment

use super::model::{MAX_METERED, canonical};
use fleet_proto::args::{
    Cidr, FirewallMode, FirewallRule, FirewallRuleSet, FwAction, FwChain, PortRange, Protocol,
    RateLimit,
};
use std::fmt::Write;

pub const TABLE: &str = "inet fleet";
/// Comment on every fixed (non-operator) rule.
pub const BASE_COMMENT: &str = "base";
/// Idle timeout of meter entries.
pub const METER_TIMEOUT: &str = "1m";
pub const METER_SIZE: u32 = 65_535;
pub const BAN_SETS: [(&str, &str); 4] = [
    ("banned4", "ipv4_addr"),
    ("banned6", "ipv6_addr"),
    ("exempt4", "ipv4_addr"),
    ("exempt6", "ipv6_addr"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    fn digit(self) -> u8 {
        match self {
            Family::V4 => 4,
            Family::V6 => 6,
        }
    }
    fn saddr(self) -> &'static str {
        match self {
            Family::V4 => "ip saddr",
            Family::V6 => "ip6 saddr",
        }
    }
    fn nfproto(self) -> &'static str {
        match self {
            Family::V4 => "ipv4",
            Family::V6 => "ipv6",
        }
    }
    fn addr_type(self) -> &'static str {
        match self {
            Family::V4 => "ipv4_addr",
            Family::V6 => "ipv6_addr",
        }
    }
}

pub fn meter_name(f: Family, slot: usize) -> String {
    format!("m{}_{slot}", f.digit())
}

fn meter_decl(f: Family) -> String {
    format!(
        "{{ type {}; size {METER_SIZE}; flags dynamic, timeout; timeout {METER_TIMEOUT}; }}",
        f.addr_type()
    )
}

/// Table deletion that doesn't fail when the table is absent.
pub fn delete_table_script() -> String {
    format!("add table {TABLE}\ndelete table {TABLE}\n")
}

fn ports(p: &[PortRange]) -> String {
    let one = |r: &PortRange| {
        if r.start() == r.end() {
            r.start().get().to_string()
        } else {
            format!("{}-{}", r.start().get(), r.end().get())
        }
    };
    match p {
        [r] => one(r),
        _ => format!("{{ {} }}", p.iter().map(one).collect::<Vec<_>>().join(", ")),
    }
}

fn source_family(c: &Cidr) -> Family {
    if c.addr().is_ipv4() {
        Family::V4
    } else {
        Family::V6
    }
}

/// `ip saddr 10.0.0.0/8` / `ip6 saddr 2001:db8::1`.
fn source(c: &Cidr) -> String {
    let f = source_family(c);
    let full = if f == Family::V4 { 32 } else { 128 };
    if c.prefix() == full {
        format!("{} {}", f.saddr(), c.addr())
    } else {
        format!("{} {c}", f.saddr())
    }
}

fn proto(p: Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

fn verdict(a: FwAction) -> &'static str {
    match a {
        FwAction::Accept => "accept",
        FwAction::Drop => "drop",
        FwAction::Reject => "reject",
    }
}

fn limit(r: RateLimit) -> String {
    if r.burst == 0 {
        format!("limit rate over {}/minute", r.per_minute)
    } else {
        format!(
            "limit rate over {}/minute burst {} packets",
            r.per_minute, r.burst
        )
    }
}

/// `r<i>` or `r<i> <comment>`; `FwComment` is ≤ 64 bytes, so this stays
/// under nftables' 128-byte comment limit.
pub fn rule_comment(i: usize, r: &FirewallRule) -> String {
    let c = r.comment.as_str();
    if c.is_empty() {
        format!("r{i}")
    } else {
        format!("r{i} {c}")
    }
}

/// The match part of one operator rule (without verdict).
fn rule_match(r: &FirewallRule) -> String {
    let mut m = match r.chain {
        FwChain::Input => format!("{} dport {}", proto(r.proto), ports(&r.ports)),
        FwChain::Forward => format!(
            "ct status dnat meta l4proto {} ct original proto-dst {}",
            proto(r.proto),
            ports(&r.ports)
        ),
    };
    if let Some(c) = &r.source {
        m.push(' ');
        m.push_str(&source(c));
    }
    m
}

/// nft lines (one statement each) for operator rule `i`; `slot` is its
/// meter slot if rate limited.
fn operator_rule(i: usize, r: &FirewallRule, slot: Option<usize>) -> Vec<String> {
    let m = rule_match(r);
    let comment = rule_comment(i, r);
    let mut out = Vec::new();
    if let (Some(rl), Some(slot)) = (r.rate_limit, slot) {
        let fams: &[Family] = match r.source.as_ref().map(source_family) {
            Some(Family::V4) => &[Family::V4],
            Some(Family::V6) => &[Family::V6],
            None => &[Family::V4, Family::V6],
        };
        for &f in fams {
            out.push(format!(
                "{m} ct state new meta nfproto {} update @{} {{ {} {} }} drop comment \"{comment}\"",
                f.nfproto(),
                meter_name(f, slot),
                f.saddr(),
                limit(rl)
            ));
        }
    }
    out.push(format!("{m} {} comment \"{comment}\"", verdict(r.action)));
    out
}

fn base(line: &str) -> String {
    format!("{line} comment \"{BASE_COMMENT}\"")
}

fn ban_rules() -> Vec<String> {
    [Family::V4, Family::V6]
        .iter()
        .map(|f| {
            let d = f.digit();
            let s = f.saddr();
            base(&format!("{s} != @exempt{d} {s} @banned{d} drop"))
        })
        .collect()
}

fn icmp_rules() -> Vec<String> {
    [
        "icmp type { destination-unreachable, time-exceeded, parameter-problem } limit rate 100/second burst 200 packets accept",
        "icmp type echo-request limit rate 10/second burst 20 packets accept",
        "icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } limit rate 100/second burst 200 packets accept",
        "icmpv6 type echo-request limit rate 10/second burst 20 packets accept",
        // Neighbour discovery is never rate limited (it would break the
        // link); hop limit 255 proves it's on-link.
        "icmpv6 type { nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept",
        "icmpv6 type { mld-listener-query, mld-listener-report, mld2-listener-report } ip6 saddr fe80::/10 accept",
        // DHCPv6 replies come from a link-local server to our port 546 and
        // aren't tracked as replies to the multicast solicit.
        "ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept",
    ]
    .iter()
    .map(|l| base(l))
    .collect()
}

/// The complete transaction for `set` (canonicalised first). `ssh_ports`
/// get a fixed accept for the exempt sets (enrolled Macs, configured
/// ranges) ahead of operator rules, so Fleet itself can't be locked out by
/// a source-restricted SSH rule.
pub fn render(set: &FirewallRuleSet, ssh_ports: &[u16]) -> String {
    let set = canonical(set);
    let managed = set.mode == FirewallMode::Managed;
    let mut s = String::new();
    let w = &mut s;
    // 1. Preamble.
    let _ = writeln!(w, "add table {TABLE}");
    for (name, ty) in BAN_SETS {
        let _ = writeln!(
            w,
            "add set {TABLE} {name} {{ type {ty}; flags interval, timeout; }}"
        );
    }
    for chain in ["input", "forward"] {
        let _ = writeln!(
            w,
            "add chain {TABLE} {chain} {{ type filter hook {chain} priority filter; policy accept; }}"
        );
    }
    for chain in ["input", "forward"] {
        let _ = writeln!(w, "delete chain {TABLE} {chain}");
    }
    for slot in 0..MAX_METERED {
        for f in [Family::V4, Family::V6] {
            let n = meter_name(f, slot);
            let _ = writeln!(w, "add set {TABLE} {n} {}", meter_decl(f));
            let _ = writeln!(w, "delete set {TABLE} {n}");
        }
    }

    // 2. Definition.
    let mut slots = Vec::with_capacity(set.rules.len());
    let mut next = 0usize;
    for r in &set.rules {
        if r.rate_limit.is_some() && next < MAX_METERED {
            slots.push(Some(next));
            next += 1;
        } else {
            slots.push(None);
        }
    }
    let _ = writeln!(w, "table {TABLE} {{");
    for (r, slot) in set.rules.iter().zip(&slots) {
        let Some(slot) = *slot else { continue };
        let fams: &[Family] = match r.source.as_ref().map(source_family) {
            Some(Family::V4) => &[Family::V4],
            Some(Family::V6) => &[Family::V6],
            None => &[Family::V4, Family::V6],
        };
        for &f in fams {
            let _ = writeln!(w, "\tset {} {}", meter_name(f, slot), meter_decl(f));
        }
    }

    let policy = if managed { "drop" } else { "accept" };
    let mut input = Vec::new();
    if managed {
        input.push(base("iif \"lo\" accept"));
    }
    input.extend(ban_rules());
    if managed {
        input.push(base("ct state established,related accept"));
        input.push(base("ct state invalid drop"));
        input.extend(icmp_rules());
        let ssh = ssh_ports.iter().filter_map(|&p| {
            fleet_proto::args::Port::new(p)
                .ok()
                .map(fleet_proto::args::PortRange::single)
        });
        let ssh = super::model::canonical_ports(&ssh.collect::<Vec<_>>());
        if !ssh.is_empty() {
            for f in [Family::V4, Family::V6] {
                let (s, d) = (f.saddr(), f.digit());
                input.push(base(&format!(
                    "tcp dport {} {s} @exempt{d} accept",
                    ports(&ssh)
                )));
            }
        }
    }
    let mut forward = ban_rules();
    if managed {
        forward.push(base("ct state established,related accept"));
    }
    for (i, (r, slot)) in set.rules.iter().zip(&slots).enumerate() {
        let lines = operator_rule(i, r, *slot);
        match r.chain {
            FwChain::Input => input.extend(lines),
            FwChain::Forward => forward.extend(lines),
        }
    }
    if managed {
        // Only DNAT'd traffic (published container ports) is filtered;
        // other forwarding is left alone.
        forward.push(base("ct status dnat drop"));
    }
    // Forward always accepts by default: non-DNAT forwarding isn't ours.
    for (chain, policy, rules) in [("input", policy, input), ("forward", "accept", forward)] {
        let _ = writeln!(w, "\tchain {chain} {{");
        let _ = writeln!(
            w,
            "\t\ttype filter hook {chain} priority filter; policy {policy};"
        );
        for r in rules {
            let _ = writeln!(w, "\t\t{r}");
        }
        let _ = writeln!(w, "\t}}");
    }
    let _ = writeln!(w, "}}");
    s
}
