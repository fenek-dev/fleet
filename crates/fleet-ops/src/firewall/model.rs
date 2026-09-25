//! Canonical form, version and lockout-safety checks of a
//! [`FirewallRuleSet`], and where sshd listens.

use crate::ctx::SysCtx;
use fleet_proto::args::{
    FirewallMode, FirewallRule, FirewallRuleSet, FwAction, FwChain, Port, PortRange, Protocol,
};
use std::net::IpAddr;
use std::path::Path;

/// Version reported for a server without `table inet fleet`.
pub const ABSENT_VERSION: u64 = 0;
/// Rules with a per-source rate limit (each owns a meter set per family).
pub const MAX_METERED: usize = 16;
/// sshd ports honoured by the lockout check and the exempt rule; more is
/// an error, never a silent truncation.
pub const MAX_SSH_PORTS: usize = 8;
pub const DEFAULT_SSH_PORT: u16 = 22;
/// sshd config files read (main file + everything `Include`d).
pub const MAX_SSHD_FILES: usize = 64;
pub const MAX_SSHD_INCLUDE_DEPTH: usize = 8;
const MAX_SSHD_LINES: usize = 10_000;
const MAX_SSHD_FILE: u64 = 1 << 20;
/// A source prefix shorter than this counts as "from anywhere".
pub const ANY_PREFIX_V4: u8 = 8;
pub const ANY_PREFIX_V6: u8 = 16;

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

/// Whether `set` keeps new inbound connections to `proto`/`port` out
/// (`NewListeningPort::blocked`, design §4.8): the first input rule
/// matching the port decides (accept from any or some source → reachable;
/// drop/reject from any source → blocked; a source-limited drop doesn't
/// decide), otherwise the chain policy (Managed drops, bans-only accepts).
/// sshd's ports are always reachable (fixed base rule).
pub fn port_blocked(set: &FirewallRuleSet, ssh_ports: &[u16], proto: Protocol, port: u16) -> bool {
    if set.mode == FirewallMode::BansOnly || ssh_ports.contains(&port) && proto == Protocol::Tcp {
        return false;
    }
    for r in &set.rules {
        let hit = r.chain == FwChain::Input
            && r.proto == proto
            && r.ports
                .iter()
                .any(|p| (p.start().get()..=p.end().get()).contains(&port));
        if !hit {
            continue;
        }
        match (r.action, r.source) {
            (FwAction::Accept, _) => return false,
            (_, None) => return true,
            (_, Some(_)) => {}
        }
    }
    true
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

/// Where sshd accepts connections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshInfo {
    /// Every sshd port (config and live), sorted: the exempt rule and the
    /// "no earlier drop" check cover all of them.
    pub ports: Vec<u16>,
    /// Ports sshd is actually listening on (empty if unknown). An
    /// unrestricted accept must cover one of these, else one of `ports`.
    pub live: Vec<u16>,
    pub v4: bool,
    pub v6: bool,
}

impl SshInfo {
    /// Both families, nothing known live.
    pub fn ports(ports: &[u16]) -> Self {
        Self {
            ports: ports.to_vec(),
            live: Vec::new(),
            v4: true,
            v6: true,
        }
    }
}

fn covers(r: &FirewallRule, port: u16) -> bool {
    r.ports
        .iter()
        .any(|p| (p.start().get()..=p.end().get()).contains(&port))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fam {
    V4,
    V6,
}

/// Whether `r` can match traffic of family `f`.
fn applies_to(r: &FirewallRule, f: Fam) -> bool {
    r.source
        .is_none_or(|c| c.addr().is_ipv4() == (f == Fam::V4))
}

/// No source, or one so wide it is "anywhere".
fn from_anywhere(r: &FirewallRule) -> bool {
    r.source.is_none_or(|c| {
        let min = if c.addr().is_ipv4() {
            ANY_PREFIX_V4
        } else {
            ANY_PREFIX_V6
        };
        c.prefix() < min
    })
}

/// Why a model is refused before anything is touched (`InvalidArgument`
/// detail).
pub fn check(set: &FirewallRuleSet, ssh: &SshInfo) -> Result<(), &'static str> {
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
    // Managed drops by default: SSH must stay reachable from anywhere, per
    // address family sshd serves, and nothing may drop it first. Enrolled
    // Macs (the exempt sets) always reach it via the fixed rule before
    // operator rules; auto-revert covers the rest.
    let want: &[u16] = if ssh.live.is_empty() {
        &ssh.ports
    } else {
        &ssh.live
    };
    let fams = [(ssh.v4, Fam::V4), (ssh.v6, Fam::V6)];
    for f in fams.iter().filter(|(on, _)| *on).map(|(_, f)| *f) {
        let ssh_rule = |r: &FirewallRule, ports: &[u16]| {
            r.chain == FwChain::Input
                && r.proto == Protocol::Tcp
                && applies_to(r, f)
                && ports.iter().any(|&p| covers(r, p))
        };
        let Some(pos) = set
            .rules
            .iter()
            .position(|r| r.action == FwAction::Accept && from_anywhere(r) && ssh_rule(r, want))
        else {
            return Err(
                "managed mode needs an input accept rule for the SSH port from any source (each address family)",
            );
        };
        if set.rules[..pos]
            .iter()
            .any(|r| r.action != FwAction::Accept && ssh_rule(r, &ssh.ports))
        {
            return Err("a drop or reject rule ahead of the SSH accept rule covers the SSH port");
        }
    }
    Ok(())
}

/// sshd settings that decide where it listens.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshdConfig {
    pub ports: Vec<u16>,
    /// `ListenAddress` entries: `Some(port)` when the entry names one.
    pub listen: Vec<Option<u16>>,
    /// `AddressFamily`: `(v4, v6)`; `None` = any.
    pub family: Option<(bool, bool)>,
}

impl SshdConfig {
    /// The ports sshd binds: explicit `ListenAddress` ports, plus the
    /// `Port` values (default 22) for addresses without one.
    pub fn bound_ports(&self) -> Vec<u16> {
        let base = if self.ports.is_empty() {
            vec![DEFAULT_SSH_PORT]
        } else {
            self.ports.clone()
        };
        let mut out: Vec<u16> = self.listen.iter().flatten().copied().collect();
        if self.listen.is_empty() || self.listen.iter().any(Option::is_none) {
            out.extend(base);
        }
        out.sort_unstable();
        out.dedup();
        out
    }
}

/// Port of a `ListenAddress` value: `host:port`, `[v6]:port`; a bare
/// host or IPv6 address has none. `Err` for a malformed port.
fn listen_port(v: &str) -> Result<Option<u16>, &'static str> {
    let port = if let Some(rest) = v.strip_prefix('[') {
        match rest.split_once("]:") {
            Some((_, p)) => Some(p),
            None if rest.ends_with(']') => None,
            None => return Err("sshd ListenAddress"),
        }
    } else {
        match v.split_once(':') {
            Some((_, p)) if !p.contains(':') => Some(p),
            _ => None,
        }
    };
    match port {
        None => Ok(None),
        Some(p) => match p.parse::<u16>() {
            Ok(n) if n != 0 => Ok(Some(n)),
            _ => Err("sshd ListenAddress port"),
        },
    }
}

/// One file's lines until the first `Match`. `include` receives each
/// `Include` argument, in order.
pub fn parse_sshd_config(
    text: &str,
    cfg: &mut SshdConfig,
    include: &mut dyn FnMut(&str) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    if text.lines().nth(MAX_SSHD_LINES).is_some() {
        return Err("sshd config too long");
    }
    for line in text.lines() {
        let mut it = line
            .split(|c: char| c.is_ascii_whitespace() || c == '=')
            .filter(|s| !s.is_empty());
        let Some(key) = it.next() else { continue };
        if key.starts_with('#') {
            continue;
        }
        let key = key.to_ascii_lowercase();
        match key.as_str() {
            "match" => break,
            "port" => match it.next().map(str::parse::<u16>) {
                Some(Ok(p)) if p != 0 => cfg.ports.push(p),
                _ => return Err("sshd Port"),
            },
            "listenaddress" => {
                let v = it.next().ok_or("sshd ListenAddress")?;
                cfg.listen.push(listen_port(v)?);
            }
            "addressfamily" => {
                cfg.family = match it.next().map(str::to_ascii_lowercase).as_deref() {
                    Some("inet") => Some((true, false)),
                    Some("inet6") => Some((false, true)),
                    _ => None,
                };
            }
            "include" => {
                for arg in it {
                    include(arg)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// `Port` values of one file (tests, fuzzing).
pub fn parse_sshd_ports(text: &str) -> Vec<u16> {
    let mut cfg = SshdConfig::default();
    let _ = parse_sshd_config(text, &mut cfg, &mut |_| Ok(()));
    cfg.ports
}

/// `*`/`?` glob on one path component; a leading `.` is only matched
/// literally.
fn glob_match(pat: &[u8], name: &[u8]) -> bool {
    match (pat.first(), name.first()) {
        (None, None) => true,
        (Some(b'*'), _) => {
            glob_match(&pat[1..], name) || (!name.is_empty() && glob_match(pat, &name[1..]))
        }
        (Some(b'?'), Some(_)) => glob_match(&pat[1..], &name[1..]),
        (Some(a), Some(b)) if a == b => glob_match(&pat[1..], &name[1..]),
        _ => false,
    }
}

fn read_capped(p: &Path) -> Result<Option<String>, &'static str> {
    match std::fs::metadata(p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("sshd config unreadable"),
        Ok(m) if !m.is_file() => return Ok(None),
        Ok(m) if m.len() > MAX_SSHD_FILE => return Err("sshd config too large"),
        Ok(_) => {}
    }
    std::fs::read_to_string(p)
        .map(Some)
        .map_err(|_| "sshd config unreadable")
}

struct SshdReader<'a> {
    ctx: &'a SysCtx,
    files: usize,
    cfg: SshdConfig,
}

impl SshdReader<'_> {
    fn file(&mut self, abs: &str, depth: usize) -> Result<(), &'static str> {
        if depth > MAX_SSHD_INCLUDE_DEPTH {
            return Err("sshd Include nesting too deep");
        }
        self.files += 1;
        if self.files > MAX_SSHD_FILES {
            return Err("too many sshd config files");
        }
        let Some(p) = self.ctx.path(abs) else {
            return Err("sshd config path");
        };
        let Some(text) = read_capped(&p)? else {
            return Ok(());
        };
        let mut includes = Vec::new();
        let mut cfg = std::mem::take(&mut self.cfg);
        // Includes are expanded in place: collect them per file, then
        // recurse (sshd's order for Port/ListenAddress doesn't matter,
        // they accumulate).
        let r = parse_sshd_config(&text, &mut cfg, &mut |a| {
            includes.push(a.to_owned());
            Ok(())
        });
        self.cfg = cfg;
        r?;
        for inc in includes {
            self.include(&inc, depth + 1)?;
        }
        Ok(())
    }

    fn include(&mut self, arg: &str, depth: usize) -> Result<(), &'static str> {
        let abs = if arg.starts_with('/') {
            arg.to_owned()
        } else {
            format!("/etc/ssh/{arg}")
        };
        let (dir, pat) = abs.rsplit_once('/').ok_or("sshd Include")?;
        if dir.contains(['*', '?', '[']) || pat.contains('[') {
            return Err("sshd Include glob unsupported");
        }
        if !pat.contains(['*', '?']) {
            return self.file(&abs, depth);
        }
        let Some(d) = self.ctx.path(if dir.is_empty() { "/" } else { dir }) else {
            return Err("sshd Include");
        };
        let rd = match std::fs::read_dir(&d) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err("sshd Include unreadable"),
        };
        let mut names = Vec::new();
        for e in rd {
            let e = e.map_err(|_| "sshd Include unreadable")?;
            let Ok(n) = e.file_name().into_string() else {
                continue;
            };
            let hidden = n.starts_with('.') && !pat.starts_with('.');
            if !hidden && glob_match(pat.as_bytes(), n.as_bytes()) {
                if names.len() >= MAX_SSHD_FILES {
                    return Err("too many sshd config files");
                }
                names.push(n);
            }
        }
        names.sort();
        for n in names {
            self.file(&format!("{dir}/{n}"), depth)?;
        }
        Ok(())
    }
}

/// `/etc/ssh/sshd_config` and everything it `Include`s.
pub fn sshd_config(ctx: &SysCtx) -> Result<SshdConfig, &'static str> {
    let mut r = SshdReader {
        ctx,
        files: 0,
        cfg: SshdConfig::default(),
    };
    r.file("/etc/ssh/sshd_config", 0)?;
    Ok(r.cfg)
}

/// Config ports merged with the TCP ports processes named `sshd` listen
/// on. Hitting a bound is an error (the caller refuses), never a
/// truncated list.
pub fn ssh_info(ctx: &SysCtx) -> Result<SshInfo, &'static str> {
    let cfg = sshd_config(ctx)?;
    let mut live = Vec::new();
    let (mut v4, mut v6) = cfg.family.unwrap_or((true, true));
    for p in crate::security::ports::collect(ctx).ports {
        if p.proto != Protocol::Tcp || p.process.as_deref() != Some("sshd") {
            continue;
        }
        live.push(p.port);
        match p.addr {
            IpAddr::V4(a) if !a.is_loopback() => v4 = true,
            IpAddr::V6(a) if !a.is_loopback() => v6 = true,
            _ => {}
        }
    }
    live.sort_unstable();
    live.dedup();
    let mut ports = cfg.bound_ports();
    ports.extend(&live);
    ports.sort_unstable();
    ports.dedup();
    if ports.len() > MAX_SSH_PORTS {
        return Err("too many sshd ports");
    }
    Ok(SshInfo {
        ports,
        live,
        v4,
        v6,
    })
}

/// [`ssh_info`] for restores, which must not fail on sshd config: its
/// ports only widen the exempt rule. Falls back to the default port.
pub fn ssh_ports_lenient(ctx: &SysCtx) -> Vec<u16> {
    ssh_info(ctx).map_or_else(|_| vec![DEFAULT_SSH_PORT], |i| i.ports)
}
