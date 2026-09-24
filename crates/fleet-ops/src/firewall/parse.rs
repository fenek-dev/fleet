//! Reading the live state: `nft -j list table inet fleet` back into the
//! model, `nft -j list ruleset` summarised (other tables, read-only) and
//! `ufw status verbose`. All of it is untrusted server output: sizes are
//! capped and nothing here is ever fed back into a script except through
//! the typed model.

use super::model::{canonical, digest_version};
use super::render::{BAN_SETS, BASE_COMMENT};
use fleet_proto::args::{
    Cidr, FirewallMode, FirewallRule, FirewallRuleSet, FwAction, FwChain, FwComment, Port,
    PortRange, Protocol, RateLimit,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::net::IpAddr;

/// `table inet fleet` as found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// From the input chain's policy (`drop` = Managed).
    pub mode: FirewallMode,
    /// `None` if the table holds anything the renderer wouldn't produce
    /// (hand edits, a newer agent's rules); see `unrecognized`.
    pub model: Option<FirewallRuleSet>,
    pub unrecognized: Option<&'static str>,
    /// Elements in `banned4` + `banned6`.
    pub banned: u32,
    /// `model::version` of the model, or a digest of the chains, rules and
    /// set declarations (handles and set elements excluded, so bans don't
    /// change it) when unrecognized.
    pub version: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("not nft JSON")]
    Json,
}

fn items(v: &Value) -> impl Iterator<Item = (&str, &Value)> {
    v.get("nftables")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|o| o.as_object()?.iter().next().map(|(k, v)| (k.as_str(), v)))
}

fn str_of<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

#[derive(Debug, Clone, Default)]
struct Part {
    idx: usize,
    comment: String,
    chain: Option<FwChain>,
    dnat: bool,
    meter: Option<RateLimit>,
    action: Option<FwAction>,
    proto: Option<Protocol>,
    ports: Vec<PortRange>,
    source: Option<Cidr>,
}

type R<T> = Result<T, &'static str>;

fn port(v: &Value) -> R<Port> {
    let n = v.as_u64().ok_or("port")?;
    Port::new(u16::try_from(n).map_err(|_| "port")?).map_err(|_| "port")
}

fn port_range(v: &Value) -> R<PortRange> {
    if let Some(r) = v.get("range").and_then(Value::as_array) {
        let [a, b] = r.as_slice() else {
            return Err("port range");
        };
        return PortRange::new(port(a)?, port(b)?).map_err(|_| "port range");
    }
    Ok(PortRange::single(port(v)?))
}

fn ports(v: &Value) -> R<Vec<PortRange>> {
    match v.get("set").and_then(Value::as_array) {
        Some(s) => s.iter().take(64).map(port_range).collect(),
        None => Ok(vec![port_range(v)?]),
    }
}

fn cidr(v: &Value, family: &str) -> R<Cidr> {
    let (addr, len) = match v {
        Value::String(s) => {
            let a: IpAddr = s.parse().map_err(|_| "address")?;
            (a, if a.is_ipv4() { 32 } else { 128 })
        }
        _ => {
            let p = v.get("prefix").ok_or("address")?;
            let a: IpAddr = str_of(p, "addr")
                .ok_or("address")?
                .parse()
                .map_err(|_| "address")?;
            let len = p.get("len").and_then(Value::as_u64).ok_or("prefix")?;
            (a, u8::try_from(len).map_err(|_| "prefix")?)
        }
    };
    if addr.is_ipv4() != (family == "ip") {
        return Err("address family");
    }
    Cidr::new(addr, len).map_err(|_| "cidr")
}

fn proto_name(v: &Value) -> R<Protocol> {
    match v {
        Value::String(s) if s == "tcp" => Ok(Protocol::Tcp),
        Value::String(s) if s == "udp" => Ok(Protocol::Udp),
        Value::Number(n) if n.as_u64() == Some(6) => Ok(Protocol::Tcp),
        Value::Number(n) if n.as_u64() == Some(17) => Ok(Protocol::Udp),
        _ => Err("protocol"),
    }
}

/// `"x"` or `["x"]`.
fn is_flag(v: &Value, flag: &str) -> bool {
    match v {
        Value::String(s) => s == flag,
        Value::Array(a) => a.len() == 1 && a[0].as_str() == Some(flag),
        _ => false,
    }
}

fn set_proto(p: &mut Part, proto: Protocol) -> R<()> {
    match p.proto {
        Some(q) if q != proto => Err("protocol"),
        _ => {
            p.proto = Some(proto);
            Ok(())
        }
    }
}

fn parse_match(p: &mut Part, m: &Value) -> R<()> {
    let op = str_of(m, "op").unwrap_or("==");
    if op != "==" && op != "in" {
        return Err("match operator");
    }
    let left = m.get("left").ok_or("match")?;
    let right = m.get("right").ok_or("match")?;
    if let Some(pl) = left.get("payload") {
        let proto = str_of(pl, "protocol").ok_or("payload")?;
        match (proto, str_of(pl, "field")) {
            ("tcp" | "udp", Some("dport")) => {
                set_proto(p, proto_name(&Value::String(proto.into()))?)?;
                p.ports = ports(right)?;
            }
            ("ip" | "ip6", Some("saddr")) => p.source = Some(cidr(right, proto)?),
            _ => return Err("payload"),
        }
        return Ok(());
    }
    if let Some(ct) = left.get("ct") {
        match (str_of(ct, "key"), str_of(ct, "dir")) {
            (Some("proto-dst"), Some("original")) => p.ports = ports(right)?,
            (Some("status"), None) if is_flag(right, "dnat") => p.dnat = true,
            (Some("state"), None) if is_flag(right, "new") => {}
            _ => return Err("ct match"),
        }
        return Ok(());
    }
    if let Some(meta) = left.get("meta") {
        match str_of(meta, "key") {
            Some("l4proto") => set_proto(p, proto_name(right)?)?,
            Some("nfproto") => {}
            _ => return Err("meta match"),
        }
        return Ok(());
    }
    Err("match")
}

fn parse_limit(v: &Value) -> R<RateLimit> {
    let l = v.get("limit").ok_or("meter statement")?;
    if str_of(l, "per") != Some("minute")
        || l.get("inv").and_then(Value::as_bool) != Some(true)
        || l.get("rate_unit").is_some_and(|u| u != "packets")
    {
        return Err("limit");
    }
    let per_minute = l
        .get("rate")
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or("limit")?;
    let burst = match l.get("burst") {
        None => 0,
        Some(b) => b
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .ok_or("limit")?,
    };
    Ok(RateLimit { per_minute, burst })
}

/// The limit inside `update @m4_0 { ip saddr limit … }`, listed as a set
/// statement (`{"set": {"op", "elem", "set", "stmt": [...]}}`) or, by
/// older nft, as a meter (`{"meter": {"key", "stmt", "name"}}`).
fn parse_meter(v: &Value, name_key: &str) -> R<RateLimit> {
    let name = str_of(v, name_key).ok_or("meter")?;
    let name = name.strip_prefix('@').unwrap_or(name);
    let ok_name = name
        .strip_prefix("m4_")
        .or_else(|| name.strip_prefix("m6_"))
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()));
    if !ok_name {
        return Err("meter name");
    }
    match v.get("stmt") {
        Some(Value::Array(a)) if a.len() == 1 => parse_limit(&a[0]),
        Some(o @ Value::Object(_)) => parse_limit(o),
        _ => Err("meter statement"),
    }
}

/// `rN` / `rN <comment>`.
pub(crate) fn parse_comment(c: &str) -> Option<(usize, &str)> {
    let rest = c.strip_prefix('r')?;
    let (n, text) = rest.split_once(' ').unwrap_or((rest, ""));
    if n.is_empty() || n.len() > 4 || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((n.parse().ok()?, text))
}

fn parse_rule(chain: FwChain, rule: &Value) -> R<Option<Part>> {
    let comment = str_of(rule, "comment").ok_or("rule without comment")?;
    if comment == BASE_COMMENT {
        return Ok(None);
    }
    let (idx, text) = parse_comment(comment).ok_or("rule comment")?;
    let mut p = Part {
        idx,
        comment: text.to_owned(),
        chain: Some(chain),
        ..Part::default()
    };
    let exprs = rule.get("expr").and_then(Value::as_array).ok_or("rule")?;
    for e in exprs.iter().take(64) {
        let (k, v) = e.as_object().and_then(|o| o.iter().next()).ok_or("expr")?;
        match k.as_str() {
            "match" => parse_match(&mut p, v)?,
            "set" => p.meter = Some(parse_meter(v, "set")?),
            "meter" => p.meter = Some(parse_meter(v, "name")?),
            "counter" => {}
            "accept" | "drop" | "reject" => {
                if p.action.is_some() {
                    return Err("verdict");
                }
                p.action = Some(match k.as_str() {
                    "accept" => FwAction::Accept,
                    "drop" => FwAction::Drop,
                    _ => FwAction::Reject,
                });
            }
            _ => return Err("statement"),
        }
    }
    if (chain == FwChain::Forward) != p.dnat {
        return Err("forward rule without ct status dnat");
    }
    if p.ports.is_empty() || p.proto.is_none() || p.action.is_none() {
        return Err("incomplete rule");
    }
    Ok(Some(p))
}

fn build_rules(parts: Vec<Part>) -> R<Vec<FirewallRule>> {
    let mut groups: BTreeMap<usize, Vec<Part>> = BTreeMap::new();
    for p in parts {
        groups.entry(p.idx).or_default().push(p);
    }
    let mut rules = Vec::with_capacity(groups.len());
    for (want, (idx, parts)) in groups.into_iter().enumerate() {
        if idx != want {
            return Err("rule numbering");
        }
        let (meters, mains): (Vec<_>, Vec<_>) = parts.into_iter().partition(|p| p.meter.is_some());
        let [main] = mains.as_slice() else {
            return Err("rule parts");
        };
        let same = |m: &Part| {
            m.chain == main.chain
                && m.proto == main.proto
                && m.ports == main.ports
                && m.source == main.source
                && m.comment == main.comment
                && m.action == Some(FwAction::Drop)
        };
        if meters.len() > 2 || !meters.iter().all(same) {
            return Err("meter parts");
        }
        let rate_limit = meters.first().and_then(|m| m.meter);
        if meters.iter().any(|m| m.meter != rate_limit) {
            return Err("meter parts");
        }
        rules.push(FirewallRule {
            chain: main.chain.ok_or("chain")?,
            action: main.action.ok_or("verdict")?,
            proto: main.proto.ok_or("protocol")?,
            ports: main.ports.clone(),
            source: main.source,
            rate_limit,
            comment: FwComment::new(main.comment.clone()).map_err(|_| "comment")?,
        });
    }
    Ok(rules)
}

/// Parses `nft -j list table inet fleet`.
pub fn parse_table(json: &[u8]) -> Result<Parsed, ParseError> {
    let v: Value = serde_json::from_slice(json).map_err(|_| ParseError::Json)?;
    let mut policy = None;
    let mut chains = 0usize;
    let mut banned = 0u32;
    let mut parts = Vec::new();
    let mut err: Option<&'static str> = None;
    // Digest input for the unrecognized case.
    let mut digest = Vec::new();
    fn note(err: &mut Option<&'static str>, e: &'static str) {
        err.get_or_insert(e);
    }
    for (kind, obj) in items(&v) {
        if kind == "metainfo" {
            continue;
        }
        if str_of(obj, if kind == "table" { "name" } else { "table" }) != Some("fleet")
            || str_of(obj, "family") != Some("inet")
        {
            note(&mut err, "object outside inet fleet");
            continue;
        }
        let mut stable = obj.clone();
        if let Some(o) = stable.as_object_mut() {
            o.remove("handle");
            o.remove("elem");
        }
        digest.extend_from_slice(kind.as_bytes());
        digest.extend_from_slice(stable.to_string().as_bytes());
        digest.push(b'\n');
        match kind {
            "table" => {}
            "chain" => {
                chains += 1;
                match str_of(obj, "name") {
                    Some("input") => policy = str_of(obj, "policy").map(str::to_owned),
                    Some("forward") => {}
                    _ => note(&mut err, "unknown chain"),
                }
            }
            "set" => {
                let name = str_of(obj, "name").unwrap_or("");
                let elems = obj
                    .get("elem")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len);
                if name.starts_with("banned") {
                    banned = banned.saturating_add(u32::try_from(elems).unwrap_or(u32::MAX));
                }
                let meter = (name.starts_with("m4_") || name.starts_with("m6_"))
                    && name[3..].bytes().all(|c| c.is_ascii_digit());
                if !meter && !BAN_SETS.iter().any(|(n, _)| *n == name) {
                    note(&mut err, "unknown set");
                }
            }
            "rule" => {
                let chain = match str_of(obj, "chain") {
                    Some("input") => FwChain::Input,
                    Some("forward") => FwChain::Forward,
                    _ => {
                        note(&mut err, "rule in unknown chain");
                        continue;
                    }
                };
                match parse_rule(chain, obj) {
                    Ok(Some(p)) => parts.push(p),
                    Ok(None) => {}
                    Err(e) => note(&mut err, e),
                }
            }
            _ => note(&mut err, "unknown object"),
        }
    }
    let mode = match policy.as_deref() {
        Some("drop") => FirewallMode::Managed,
        Some("accept") => FirewallMode::BansOnly,
        _ => {
            note(&mut err, "input chain missing");
            FirewallMode::BansOnly
        }
    };
    if chains != 2 {
        note(&mut err, "chains");
    }
    let model = match err {
        Some(_) => None,
        None => match build_rules(parts) {
            Ok(rules) => {
                let set = canonical(&FirewallRuleSet { mode, rules });
                match set.validate() {
                    Ok(()) => Some(set),
                    Err(_) => {
                        note(&mut err, "rule set");
                        None
                    }
                }
            }
            Err(e) => {
                note(&mut err, e);
                None
            }
        },
    };
    let version = match &model {
        Some(m) => super::model::version(m),
        None => digest_version(&digest),
    };
    Ok(Parsed {
        mode,
        model,
        unrecognized: err,
        banned,
        version,
    })
}

/// One table in `nft list ruleset` other than Fleet's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignTable {
    pub family: String,
    pub name: String,
    pub chains: u32,
    pub rules: u32,
    /// Recognised owners: `ufw`, `docker`, `firewalld`, `fail2ban`,
    /// `tailscale`, `libvirt`.
    pub owners: Vec<&'static str>,
}

pub const MAX_FOREIGN_TABLES: usize = 64;

fn owner_of(name: &str) -> Option<&'static str> {
    let n = name.to_ascii_lowercase();
    [
        ("ufw", "ufw"),
        ("docker", "docker"),
        ("firewalld", "firewalld"),
        ("f2b", "fail2ban"),
        ("fail2ban", "fail2ban"),
        ("ts-", "tailscale"),
        ("tailscale", "tailscale"),
        ("libvirt", "libvirt"),
    ]
    .into_iter()
    .find(|(p, _)| n.starts_with(p))
    .map(|(_, o)| o)
}

/// Every table except `inet fleet`, from `nft -j list ruleset`; names are
/// reduced to `[A-Za-z0-9_.-]` and 64 bytes.
pub fn summarize_ruleset(json: &[u8]) -> Result<Vec<ForeignTable>, ParseError> {
    let v: Value = serde_json::from_slice(json).map_err(|_| ParseError::Json)?;
    let mut tables: Vec<ForeignTable> = Vec::new();
    let clean = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric() || "_.-".contains(*c))
            .take(64)
            .collect()
    };
    for (kind, obj) in items(&v) {
        let family = clean(str_of(obj, "family").unwrap_or(""));
        let table =
            clean(str_of(obj, if kind == "table" { "name" } else { "table" }).unwrap_or(""));
        if family == "inet" && table == "fleet" {
            continue;
        }
        let pos = tables
            .iter()
            .position(|t| t.family == family && t.name == table);
        let t = match (kind, pos) {
            ("table", None) if tables.len() < MAX_FOREIGN_TABLES => {
                let mut owners = Vec::new();
                owners.extend(owner_of(&table));
                tables.push(ForeignTable {
                    family,
                    name: table,
                    chains: 0,
                    rules: 0,
                    owners,
                });
                continue;
            }
            (_, Some(i)) => &mut tables[i],
            _ => continue,
        };
        match kind {
            "chain" => {
                t.chains = t.chains.saturating_add(1);
                if let Some(o) = str_of(obj, "name").and_then(owner_of)
                    && !t.owners.contains(&o)
                {
                    t.owners.push(o);
                }
            }
            "rule" => t.rules = t.rules.saturating_add(1),
            _ => {}
        }
    }
    Ok(tables)
}

/// `ufw status verbose`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UfwStatus {
    pub active: bool,
    /// The output, control characters removed; at most [`UFW_MAX_LINES`]
    /// lines of [`UFW_MAX_LINE`] bytes.
    pub lines: Vec<String>,
}

pub const UFW_MAX_LINES: usize = 300;
pub const UFW_MAX_LINE: usize = 200;

pub fn parse_ufw(text: &str) -> UfwStatus {
    let lines: Vec<String> = text
        .lines()
        .take(UFW_MAX_LINES)
        .map(|l| {
            l.chars()
                .filter(|c| !c.is_control())
                .take(UFW_MAX_LINE)
                .collect::<String>()
                .trim_end()
                .to_owned()
        })
        .collect();
    let active = lines
        .iter()
        .any(|l| l.trim().eq_ignore_ascii_case("status: active"));
    UfwStatus { active, lines }
}

/// Text for `FirewallState::foreign_ruleset`.
pub fn foreign_text(
    tables: Result<&[ForeignTable], &str>,
    ufw: Option<&UfwStatus>,
    unrecognized: Option<&str>,
) -> String {
    let mut s = String::new();
    if let Some(u) = unrecognized {
        s.push_str("inet fleet: not in the form Fleet renders (");
        s.push_str(u);
        s.push_str("); the next apply replaces it\n\n");
    }
    match tables {
        Ok([]) => s.push_str("other tables: none\n"),
        Ok(ts) => {
            s.push_str("other tables:\n");
            for t in ts {
                s.push_str(&format!(
                    "  {} {}: {} chains, {} rules",
                    t.family, t.name, t.chains, t.rules
                ));
                if !t.owners.is_empty() {
                    s.push_str(&format!(" ({})", t.owners.join(", ")));
                }
                s.push('\n');
            }
        }
        Err(e) => {
            s.push_str("other tables: unavailable (");
            s.push_str(e);
            s.push_str(")\n");
        }
    }
    if let Some(u) = ufw
        && !u.lines.is_empty()
    {
        s.push_str("\nufw status verbose:\n");
        for l in &u.lines {
            s.push_str(l);
            s.push('\n');
        }
    }
    s
}
