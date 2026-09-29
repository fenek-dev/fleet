//! Reading the live state: `nft -j list table inet fleet` back into the
//! model, `nft -j list ruleset` summarised (other tables, read-only) and
//! `ufw status verbose`. All of it is untrusted server output: sizes are
//! capped and nothing here is ever fed back into a script except through
//! the typed model.

use super::model::{MAX_METERED, canonical, digest_version};
use super::render::{BAN_SETS, BASE_COMMENT, Family, meter_name};
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
    /// For an unrecognized table: what to run around the rendered script
    /// so it replaces the table's foreign objects while keeping the
    /// ban/exempt sets and their elements; `Err` if that isn't possible
    /// safely (unexpected object kinds or names).
    pub cleanup: Result<Cleanup, &'static str>,
}

/// Script parts wrapped around [`super::render::render`] when the table
/// is unrecognized.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cleanup {
    /// Flushes and deletes every chain, deletes every set and map except
    /// ban/exempt sets declared exactly as rendered.
    pub pre: String,
    /// Re-adds the listed elements of ban/exempt sets `pre` had to delete
    /// (declared differently), with their remaining timeouts.
    pub post: String,
}

/// Most expressions any rendered rule has is well under this.
pub const MAX_RULE_EXPRS: usize = 64;

fn rule_exprs(rule: &Value) -> R<&Vec<Value>> {
    let exprs = rule.get("expr").and_then(Value::as_array).ok_or("rule")?;
    if exprs.len() > MAX_RULE_EXPRS {
        return Err("rule too long");
    }
    Ok(exprs)
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
    let exprs = rule_exprs(rule)?;
    for e in exprs {
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

/// Hit counters of the operator rules in `nft -j list table inet fleet`:
/// `(rule index, packets, bytes)` for every operator rule whose final
/// verdict rule carries an nft `counter` (rate-limit meter rules are
/// skipped), ordered by index. Anything unexpected in a rule is skipped:
/// counters are informational and never feed back into a script.
pub fn parse_counters(json: &[u8]) -> Result<Vec<(usize, u64, u64)>, ParseError> {
    let v: Value = serde_json::from_slice(json).map_err(|_| ParseError::Json)?;
    let mut by_idx: BTreeMap<usize, (u64, u64)> = BTreeMap::new();
    for (kind, obj) in items(&v) {
        if kind != "rule"
            || str_of(obj, "table") != Some("fleet")
            || str_of(obj, "family") != Some("inet")
            || !matches!(str_of(obj, "chain"), Some("input" | "forward"))
        {
            continue;
        }
        let Some((idx, _)) = str_of(obj, "comment").and_then(parse_comment) else {
            continue;
        };
        let Ok(exprs) = rule_exprs(obj) else { continue };
        let mut counter = None;
        let mut metered = false;
        for e in exprs {
            let Some((k, v)) = e.as_object().and_then(|o| o.iter().next()) else {
                continue;
            };
            match k.as_str() {
                "set" | "meter" => metered = true,
                "counter" => {
                    let n = |f: &str| v.get(f).and_then(Value::as_u64).unwrap_or(0);
                    counter = Some((n("packets"), n("bytes")));
                }
                _ => {}
            }
        }
        if let (false, Some((p, b))) = (metered, counter) {
            let e = by_idx.entry(idx).or_default();
            e.0 = e.0.saturating_add(p);
            e.1 = e.1.saturating_add(b);
        }
    }
    Ok(by_idx.into_iter().map(|(i, (p, b))| (i, p, b)).collect())
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
    // Listing order per chain: base rule text or operator rule index.
    let mut seq: [Vec<Entry>; 2] = [Vec::new(), Vec::new()];
    let mut clean = CleanupBuilder::default();
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
            clean.fail("object outside inet fleet");
            continue;
        }
        clean.object(kind, obj);
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
                let name = str_of(obj, "name");
                let base_ok = |hook: &str| {
                    str_of(obj, "type") == Some("filter")
                        && str_of(obj, "hook") == Some(hook)
                        && obj.get("prio").and_then(Value::as_i64) == Some(0)
                };
                match name {
                    Some("input") => {
                        policy = str_of(obj, "policy").map(str::to_owned);
                        if !base_ok("input") {
                            note(&mut err, "chain definition");
                        }
                    }
                    Some("forward") => {
                        if !base_ok("forward") || str_of(obj, "policy") != Some("accept") {
                            note(&mut err, "chain definition");
                        }
                    }
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
                let meter = (0..MAX_METERED).any(|i| {
                    name == meter_name(Family::V4, i) || name == meter_name(Family::V6, i)
                });
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
                let slot = &mut seq[usize::from(chain == FwChain::Forward)];
                if str_of(obj, "comment") == Some(BASE_COMMENT) {
                    match base_text(obj) {
                        Ok(t) => slot.push(Entry::Base(t)),
                        Err(e) => note(&mut err, e),
                    }
                    continue;
                }
                match parse_rule(chain, obj) {
                    Ok(Some(p)) => {
                        slot.push(Entry::Op(p.idx));
                        parts.push(p);
                    }
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
                if set.validate().is_err() {
                    note(&mut err, "rule set");
                    None
                } else if expected_entries(&set) != seq {
                    // Base rules, or the placement of operator rules, are
                    // not what `render` would write for this model.
                    note(&mut err, "base rules");
                    None
                } else {
                    Some(set)
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
    let cleanup = match model {
        Some(_) => Ok(Cleanup::default()),
        None => clean.finish(),
    };
    Ok(Parsed {
        mode,
        model,
        unrecognized: err,
        banned,
        version,
        cleanup,
    })
}

/// One rule of a chain listing, as far as the round-trip check cares.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    /// A fixed rule: its nft text (as `render` writes it, without the
    /// comment; sshd ports of the exempt rule masked).
    Base(String),
    /// A line of operator rule `i`.
    Op(usize),
}

/// The exempt rule's ports follow sshd's config at render time, which
/// the parser doesn't know: mask them.
fn mask_exempt(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("tcp dport ") {
        for suf in [" ip saddr @exempt4 accept", " ip6 saddr @exempt6 accept"] {
            if rest.ends_with(suf) {
                return format!("tcp dport *{suf}");
            }
        }
    }
    s.to_owned()
}

/// `[input, forward]` entries of `render(set)`.
fn expected_entries(set: &FirewallRuleSet) -> [Vec<Entry>; 2] {
    let text = super::render::render(set, &[super::model::DEFAULT_SSH_PORT]);
    let mut out: [Vec<Entry>; 2] = [Vec::new(), Vec::new()];
    let mut cur: Option<usize> = None;
    for line in text.lines() {
        match line {
            "\tchain input {" => cur = Some(0),
            "\tchain forward {" => cur = Some(1),
            "\t}" => cur = None,
            _ => {}
        }
        let (Some(c), Some(rule)) = (cur, line.strip_prefix("\t\t")) else {
            continue;
        };
        if rule.starts_with("type ") {
            continue;
        }
        let Some((body, comment)) = rule.rsplit_once(" comment \"") else {
            continue;
        };
        let comment = comment.strip_suffix('"').unwrap_or(comment);
        out[c].push(if comment == BASE_COMMENT {
            Entry::Base(mask_exempt(body))
        } else {
            Entry::Op(parse_comment(comment).map_or(usize::MAX, |(i, _)| i))
        });
    }
    out
}

fn left_text(v: &Value) -> R<String> {
    if let Some(p) = v.get("payload") {
        return Ok(format!(
            "{} {}",
            str_of(p, "protocol").ok_or("base rule")?,
            str_of(p, "field").ok_or("base rule")?
        ));
    }
    if let Some(m) = v.get("meta") {
        return Ok(match str_of(m, "key").ok_or("base rule")? {
            "iif" => "iif".to_owned(),
            k => format!("meta {k}"),
        });
    }
    if let Some(ct) = v.get("ct") {
        let key = str_of(ct, "key").ok_or("base rule")?;
        return Ok(match str_of(ct, "dir") {
            Some(d) => format!("ct {d} {key}"),
            None => format!("ct {key}"),
        });
    }
    Err("base rule")
}

fn value_text(v: &Value) -> R<String> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Array(a) => Ok(a.iter().map(value_text).collect::<R<Vec<_>>>()?.join(",")),
        Value::Object(_) => {
            if let Some(s) = v.get("set").and_then(Value::as_array) {
                let e = s.iter().map(value_text).collect::<R<Vec<_>>>()?;
                return Ok(format!("{{ {} }}", e.join(", ")));
            }
            if let Some(p) = v.get("prefix") {
                let a = str_of(p, "addr").ok_or("base rule")?;
                let l = p.get("len").and_then(Value::as_u64).ok_or("base rule")?;
                return Ok(format!("{a}/{l}"));
            }
            if let Some(Value::Array(r)) = v.get("range")
                && let [a, b] = r.as_slice()
            {
                return Ok(format!("{}-{}", value_text(a)?, value_text(b)?));
            }
            Err("base rule")
        }
        _ => Err("base rule"),
    }
}

fn expr_text(e: &Value) -> R<String> {
    let (k, v) = e
        .as_object()
        .and_then(|o| o.iter().next())
        .ok_or("base rule")?;
    match k.as_str() {
        "match" => {
            let left = v.get("left").ok_or("base rule")?;
            let right = v.get("right").ok_or("base rule")?;
            let lt = left_text(left)?;
            let rt = match (lt.as_str(), right) {
                ("iif", Value::String(s)) => format!("\"{s}\""),
                _ => value_text(right)?,
            };
            match str_of(v, "op").unwrap_or("==") {
                "==" | "in" => Ok(format!("{lt} {rt}")),
                "!=" => Ok(format!("{lt} != {rt}")),
                _ => Err("base rule"),
            }
        }
        "limit" => {
            if v.get("rate_unit").is_some_and(|u| u != "packets")
                || v.get("burst_unit").is_some_and(|u| u != "packets")
            {
                return Err("base rule");
            }
            let rate = v.get("rate").and_then(Value::as_u64).ok_or("base rule")?;
            let per = str_of(v, "per").ok_or("base rule")?;
            let over = if v.get("inv").and_then(Value::as_bool) == Some(true) {
                "over "
            } else {
                ""
            };
            let mut s = format!("limit rate {over}{rate}/{per}");
            match v.get("burst").map(|b| b.as_u64().ok_or("base rule")) {
                Some(Ok(0)) | None => {}
                Some(Ok(b)) => s.push_str(&format!(" burst {b} packets")),
                Some(Err(e)) => return Err(e),
            }
            Ok(s)
        }
        "accept" | "drop" | "reject" => Ok(k.clone()),
        _ => Err("base rule"),
    }
}

/// nft text of a fixed rule, as `render` writes it (exempt ports
/// masked). Only compared, never fed back to nft.
fn base_text(rule: &Value) -> R<String> {
    let t = rule_exprs(rule)?
        .iter()
        .map(expr_text)
        .collect::<R<Vec<_>>>()?
        .join(" ");
    Ok(mask_exempt(&t))
}

/// `[A-Za-z_][A-Za-z0-9_.-]{0,63}`: safe to name in an nft script.
fn safe_ident(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(c))
}

/// One ban/exempt set element as nft text, formatted from parsed values.
fn element_text(e: &Value, v4: bool) -> R<Option<String>> {
    let (val, timeout, expires) = match e.get("elem") {
        Some(inner) => (
            inner.get("val").ok_or("set element")?,
            inner.get("timeout").and_then(Value::as_u64),
            inner.get("expires").and_then(Value::as_u64),
        ),
        None => (e, None, None),
    };
    let fam = |a: IpAddr| {
        if a.is_ipv4() == v4 {
            Ok(a)
        } else {
            Err("set element")
        }
    };
    let ip = |v: &Value| -> R<IpAddr> {
        fam(v
            .as_str()
            .ok_or("set element")?
            .parse()
            .map_err(|_| "set element")?)
    };
    let text = if let Some(p) = val.get("prefix") {
        let a = fam(str_of(p, "addr")
            .ok_or("set element")?
            .parse()
            .map_err(|_| "set element")?)?;
        let l = p.get("len").and_then(Value::as_u64).ok_or("set element")?;
        let c =
            Cidr::new(a, u8::try_from(l).map_err(|_| "set element")?).map_err(|_| "set element")?;
        c.to_string()
    } else if let Some(Value::Array(r)) = val.get("range") {
        let [a, b] = r.as_slice() else {
            return Err("set element");
        };
        format!("{}-{}", ip(a)?, ip(b)?)
    } else {
        ip(val)?.to_string()
    };
    Ok(match (timeout, expires) {
        // About to expire: nothing to keep.
        (Some(_), Some(0)) => None,
        (Some(_), Some(left)) | (Some(left), None) => Some(format!("{text} timeout {left}s")),
        (None, _) => Some(text),
    })
}

/// Elements per `add element` line.
const ELEMENTS_PER_LINE: usize = 256;

#[derive(Debug, Default)]
struct CleanupBuilder {
    chains: Vec<String>,
    sets: Vec<(&'static str, String)>,
    post: String,
    err: Option<&'static str>,
}

impl CleanupBuilder {
    fn fail(&mut self, e: &'static str) {
        self.err.get_or_insert(e);
    }

    fn name(&mut self, obj: &Value) -> Option<String> {
        match str_of(obj, "name") {
            Some(n) if safe_ident(n) => Some(n.to_owned()),
            _ => {
                self.fail("inet fleet object name unsafe to script");
                None
            }
        }
    }

    fn object(&mut self, kind: &str, obj: &Value) {
        match kind {
            "table" | "rule" => {}
            "chain" => {
                if let Some(n) = self.name(obj) {
                    self.chains.push(n);
                }
            }
            "map" => {
                if let Some(n) = self.name(obj) {
                    self.sets.push(("map", n));
                }
            }
            "set" => {
                let Some(n) = self.name(obj) else { return };
                let ban = BAN_SETS.iter().find(|(b, _)| *b == n);
                let Some((_, ty)) = ban else {
                    self.sets.push(("set", n));
                    return;
                };
                if ban_decl_ok(obj, ty) {
                    return;
                }
                // Declared differently: delete and recreate (by render),
                // then put the listed elements back.
                let v4 = *ty == "ipv4_addr";
                let mut elems = Vec::new();
                for e in obj
                    .get("elem")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    match element_text(e, v4) {
                        Ok(Some(t)) => elems.push(t),
                        Ok(None) => {}
                        Err(e) => return self.fail(e),
                    }
                }
                for chunk in elems.chunks(ELEMENTS_PER_LINE) {
                    self.post.push_str(&format!(
                        "add element inet fleet {n} {{ {} }}\n",
                        chunk.join(", ")
                    ));
                }
                self.sets.push(("set", n));
            }
            _ => self.fail("unsupported object in inet fleet"),
        }
    }

    fn finish(self) -> Result<Cleanup, &'static str> {
        if let Some(e) = self.err {
            return Err(e);
        }
        let mut pre = String::new();
        for c in &self.chains {
            pre.push_str(&format!("flush chain inet fleet {c}\n"));
        }
        for c in &self.chains {
            pre.push_str(&format!("delete chain inet fleet {c}\n"));
        }
        for (kind, n) in &self.sets {
            pre.push_str(&format!("delete {kind} inet fleet {n}\n"));
        }
        Ok(Cleanup {
            pre,
            post: self.post,
        })
    }
}

/// Declared exactly as `render` declares it (type, `flags interval,
/// timeout`, nothing else).
fn ban_decl_ok(obj: &Value, ty: &str) -> bool {
    let Some(o) = obj.as_object() else {
        return false;
    };
    let mut flags: Vec<&str> = obj
        .get("flags")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    flags.sort_unstable();
    str_of(obj, "type") == Some(ty)
        && flags == ["interval", "timeout"]
        && o.keys().all(|k| {
            ["family", "name", "table", "type", "handle", "flags", "elem"].contains(&k.as_str())
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
