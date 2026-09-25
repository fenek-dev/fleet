//! Parsers for dpkg/apt output and logs. Input is untrusted server data:
//! nothing here panics on any input (proptested), malformed lines are
//! skipped, and every collection is capped.

use fleet_proto::payload::{PackageChange, PackageHistoryEntry, PkgAction};
use std::cmp::Ordering;
use std::collections::HashSet;

/// `dpkg-query -W -f=` format: one tab-separated line per package.
pub const DPKG_QUERY_FORMAT: &str =
    "${Package}\\t${Architecture}\\t${Version}\\t${db:Status-Want}\\t${db:Status-Status}\\n";

/// Most packages parsed from one listing (a frame is at most 1 MiB).
pub const MAX_PACKAGES: usize = 8000;
/// Most entries parsed from one log.
pub const MAX_LOG_ENTRIES: usize = 50_000;
const MAX_FIELD: usize = 256;

fn clip(s: &str) -> String {
    s.chars().take(MAX_FIELD).collect()
}

/// An installed package from `dpkg-query`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub name: String,
    pub arch: String,
    pub version: String,
    /// Selection state `hold`.
    pub held: bool,
}

/// Rows of [`DPKG_QUERY_FORMAT`] whose status is `installed` (not
/// `config-files`, `half-installed`, …).
pub fn parse_dpkg_query(out: &str) -> Vec<Installed> {
    out.lines()
        .filter_map(|l| {
            let mut f = l.split('\t');
            let (name, arch, version, want, status) =
                (f.next()?, f.next()?, f.next()?, f.next()?, f.next()?);
            if f.next().is_some() || name.is_empty() || status != "installed" {
                return None;
            }
            Some(Installed {
                name: clip(name),
                arch: clip(arch),
                version: clip(version),
                held: want == "hold",
            })
        })
        .take(MAX_PACKAGES)
        .collect()
}

/// `(name, arch)` of packages apt marked automatically installed
/// (`/var/lib/apt/extended_states`, deb822 stanzas).
pub fn parse_extended_states(text: &str) -> HashSet<(String, String)> {
    let mut out = HashSet::new();
    for stanza in text.split("\n\n") {
        let (mut name, mut arch, mut auto) = (None, None, false);
        for l in stanza.lines() {
            if let Some(v) = l.strip_prefix("Package:") {
                name = Some(v.trim());
            } else if let Some(v) = l.strip_prefix("Architecture:") {
                arch = Some(v.trim());
            } else if let Some(v) = l.strip_prefix("Auto-Installed:") {
                auto = v.trim() == "1";
            }
        }
        if let (Some(n), true) = (name, auto) {
            out.insert((clip(n), clip(arch.unwrap_or(""))));
            if out.len() >= MAX_PACKAGES {
                break;
            }
        }
    }
    out
}

/// An `Inst` line of `apt-get -s`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimInst {
    /// As apt prints it; may carry `:arch`.
    pub name: String,
    /// `None` for a new install.
    pub current: Option<String>,
    pub candidate: String,
    /// Comma-separated origins, e.g. `Debian-Security:12/stable-security`.
    pub origins: String,
    pub security: bool,
}

/// Parsed `apt-get -s` output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sim {
    pub inst: Vec<SimInst>,
    /// Packages the transaction would remove (`Remv`/`Purg`), arch stripped.
    pub remove: Vec<String>,
}

fn parse_inst(rest: &str) -> Option<SimInst> {
    let (name, rest) = rest.split_once(' ')?;
    let mut rest = rest.trim_start();
    let current = if let Some(r) = rest.strip_prefix('[') {
        let (old, r) = r.split_once(']')?;
        rest = r.trim_start();
        Some(clip(old))
    } else {
        None
    };
    let inner = rest.strip_prefix('(')?;
    let inner = &inner[..inner.rfind(')')?];
    let (candidate, origins) = inner.split_once(' ').unwrap_or((inner, ""));
    // Drop the trailing ` [arch]`.
    let origins = match origins.rfind(" [") {
        Some(i) => &origins[..i],
        None if origins.starts_with('[') => "",
        None => origins,
    }
    .trim();
    if name.is_empty() || candidate.is_empty() {
        return None;
    }
    Some(SimInst {
        name: clip(name),
        current,
        candidate: clip(candidate),
        origins: clip(origins),
        security: origins.to_ascii_lowercase().contains("-security"),
    })
}

pub fn parse_apt_sim(out: &str) -> Sim {
    let mut sim = Sim::default();
    for l in out.lines() {
        if sim.inst.len() + sim.remove.len() >= MAX_PACKAGES {
            break;
        }
        if let Some(rest) = l.strip_prefix("Inst ") {
            if let Some(i) = parse_inst(rest) {
                sim.inst.push(i);
            }
        } else if let Some(rest) = l.strip_prefix("Remv ").or_else(|| l.strip_prefix("Purg "))
            && let Some(name) = rest.split(' ').next().filter(|n| !n.is_empty())
        {
            sim.remove.push(strip_arch(name).to_owned());
        }
    }
    sim
}

/// `libc6:amd64` → `libc6`.
pub fn strip_arch(name: &str) -> &str {
    name.split_once(':').map_or(name, |(n, _)| n)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `YYYY-MM-DD` + `HH:MM:SS` → Unix ms. Logs are local time; the baseline
/// profile sets the time zone to UTC (design §9.4), so they are read as UTC.
pub fn parse_datetime(date: &str, time: &str) -> Option<u64> {
    let mut d = date.split('-');
    let (y, mo, da) = (d.next()?, d.next()?, d.next()?);
    let mut t = time.split(':');
    let (h, mi, s) = (t.next()?, t.next()?, t.next()?);
    if d.next().is_some() || t.next().is_some() || y.len() != 4 {
        return None;
    }
    let y: i64 = y.parse().ok()?;
    let mo: u32 = mo.parse().ok()?;
    let da: u32 = da.parse().ok()?;
    let (h, mi, s): (u64, u64, u64) = (h.parse().ok()?, mi.parse().ok()?, s.parse().ok()?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&da) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let days = u64::try_from(days_from_civil(y, mo, da)).ok()?;
    Some(((days * 86_400) + h * 3600 + mi * 60 + s) * 1000)
}

fn change(name: &str, action: PkgAction, from: Option<&str>, to: Option<&str>) -> PackageChange {
    PackageChange {
        name: clip(strip_arch(name)),
        action,
        from: from.map(clip),
        to: to.map(clip),
    }
}

/// Upgrade or downgrade by version order.
fn up_or_down(from: &str, to: &str) -> PkgAction {
    if compare_versions(to, from) == Ordering::Less {
        PkgAction::Downgrade
    } else {
        PkgAction::Upgrade
    }
}

/// `/var/log/dpkg.log` lines `DATE TIME install|upgrade|remove|purge
/// PKG:ARCH FROM TO` (`<none>` for no version). Other lines are ignored.
pub fn parse_dpkg_log(text: &str) -> Vec<PackageHistoryEntry> {
    text.lines()
        .filter_map(parse_dpkg_log_line)
        .take(MAX_LOG_ENTRIES)
        .collect()
}

pub fn parse_dpkg_log_line(l: &str) -> Option<PackageHistoryEntry> {
    let mut f = l.split(' ');
    let (date, time, verb, pkg, from, to) = (
        f.next()?,
        f.next()?,
        f.next()?,
        f.next()?,
        f.next()?,
        f.next()?,
    );
    if f.next().is_some() || pkg.is_empty() {
        return None;
    }
    let opt = |v: &str| (v != "<none>" && !v.is_empty()).then(|| v.to_owned());
    let (from, to) = (opt(from), opt(to));
    let action = match (verb, &from, &to) {
        ("install", None, Some(_)) => PkgAction::Install,
        ("install" | "upgrade", Some(a), Some(b)) => up_or_down(a, b),
        ("remove", Some(_), _) => PkgAction::Remove,
        ("purge", _, _) => PkgAction::Purge,
        _ => return None,
    };
    Some(PackageHistoryEntry {
        time_ms: parse_datetime(date, time)?,
        change: change(pkg, action, from.as_deref(), to.as_deref()),
    })
}

/// Splits `a:amd64 (1.0), b:amd64 (1.0, 2.0)` into `(name, [versions])`,
/// dropping the `automatic` marker.
fn history_items(list: &str) -> Vec<(&str, Vec<&str>)> {
    list.split("), ")
        .filter_map(|item| {
            let (name, vers) = item.trim().split_once(" (")?;
            let vers = vers.trim_end_matches(')');
            let v: Vec<&str> = vers
                .split(", ")
                .filter(|v| *v != "automatic" && !v.is_empty())
                .collect();
            (!name.is_empty()).then_some((name, v))
        })
        .collect()
}

/// `/var/log/apt/history.log` transactions (stanzas starting with
/// `Start-Date:`); every change gets the transaction's start time.
pub fn parse_history_log(text: &str) -> Vec<PackageHistoryEntry> {
    let mut out = Vec::new();
    let mut time_ms = None;
    for l in text.lines() {
        if out.len() >= MAX_LOG_ENTRIES {
            break;
        }
        if let Some(v) = l.strip_prefix("Start-Date:") {
            let mut p = v.split_whitespace();
            time_ms = p
                .next()
                .zip(p.next())
                .and_then(|(d, t)| parse_datetime(d, t));
            continue;
        }
        let Some(t) = time_ms else { continue };
        let Some((key, list)) = l.split_once(": ") else {
            continue;
        };
        for (name, v) in history_items(list) {
            let c = match (key, v.as_slice()) {
                ("Install", [to, ..]) => change(name, PkgAction::Install, None, Some(to)),
                ("Reinstall", [v, ..]) => change(name, PkgAction::Install, Some(v), Some(v)),
                ("Upgrade", [a, b, ..]) => change(name, PkgAction::Upgrade, Some(a), Some(b)),
                ("Downgrade", [a, b, ..]) => change(name, PkgAction::Downgrade, Some(a), Some(b)),
                ("Remove", [a, ..]) => change(name, PkgAction::Remove, Some(a), None),
                ("Purge", [a, ..]) => change(name, PkgAction::Purge, Some(a), None),
                _ => continue,
            };
            out.push(PackageHistoryEntry {
                time_ms: t,
                change: c,
            });
        }
    }
    out
}

/// `history.log` entries plus the `dpkg.log` ones apt didn't log (plain
/// `dpkg -i`), matched on `(name, action, to)`; in `range`, oldest first,
/// the newest `limit`.
pub fn merge_history(
    apt: Vec<PackageHistoryEntry>,
    dpkg: Vec<PackageHistoryEntry>,
    since_ms: Option<u64>,
    until_ms: Option<u64>,
    limit: usize,
) -> Vec<PackageHistoryEntry> {
    let key = |e: &PackageHistoryEntry| {
        let a = match e.change.action {
            PkgAction::Remove | PkgAction::Purge => PkgAction::Remove,
            a => a,
        };
        (e.change.name.clone(), a, e.change.to.clone())
    };
    let seen: HashSet<_> = apt.iter().map(key).collect();
    let mut all: Vec<_> = apt
        .into_iter()
        .chain(dpkg.into_iter().filter(|e| !seen.contains(&key(e))))
        .filter(|e| since_ms.is_none_or(|s| e.time_ms >= s))
        .filter(|e| until_ms.is_none_or(|u| e.time_ms < u))
        .collect();
    all.sort_by_key(|e| e.time_ms);
    let skip = all.len().saturating_sub(limit);
    all.split_off(skip)
}

/// Debian version order (`dpkg --compare-versions`); shared with the Mac's
/// vulnerability matching (`fleet-debver`).
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    fleet_debver::compare(a, b)
}

/// Changes between two `dpkg-query` snapshots, sorted by name. Packages
/// that disappeared are `Purge` when `purged`, else `Remove`.
pub fn diff_installed(
    before: &[Installed],
    after: &[Installed],
    purged: bool,
) -> Vec<PackageChange> {
    use std::collections::BTreeMap;
    let index = |v: &[Installed]| -> BTreeMap<(String, String), (String, bool)> {
        v.iter()
            .map(|p| {
                (
                    (p.name.clone(), p.arch.clone()),
                    (p.version.clone(), p.held),
                )
            })
            .collect()
    };
    let (b, a) = (index(before), index(after));
    let mut out = Vec::new();
    for (key, (ver, held)) in &b {
        let name = &key.0;
        match a.get(key) {
            None => out.push(change(
                name,
                if purged {
                    PkgAction::Purge
                } else {
                    PkgAction::Remove
                },
                Some(ver),
                None,
            )),
            Some((nv, nheld)) => {
                if nv != ver {
                    out.push(change(name, up_or_down(ver, nv), Some(ver), Some(nv)));
                }
                if nheld != held {
                    let act = if *nheld {
                        PkgAction::Hold
                    } else {
                        PkgAction::Unhold
                    };
                    out.push(change(name, act, None, None));
                }
            }
        }
    }
    for (key, (ver, _)) in &a {
        if !b.contains_key(key) {
            out.push(change(&key.0, PkgAction::Install, None, Some(ver)));
        }
    }
    out.sort_by(|x, y| x.name.cmp(&y.name));
    out
}
