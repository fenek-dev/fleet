//! Installed packages × advisories → findings.
//!
//! Lookup key: on Debian the tracker is per **source** package, so the
//! key is the package's source name (`pkg.list` reports it as
//! `PackageInfo::source`), else the binary name (older agents). On Ubuntu
//! the USN rows are per binary package already.
//!
//! A package is affected by an advisory when the fixed version is newer
//! than the installed one (dpkg order; on Debian the installed **source**
//! version when known, since the tracker's fixed versions are source
//! versions), or when no fix exists yet.

use super::dpkgver::is_older;
use super::release::Target;
use super::{Advisory, Distro, Severity};
use std::collections::BTreeSet;

/// One installed package, as `pkg.list` reports it (untrusted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub name: String,
    pub version: String,
    /// Source package name, when known.
    pub source: Option<String>,
    /// Source version (`${source:Version}`), when known; differs from
    /// `version` for binNMUs and separately versioned binaries.
    pub source_version: Option<String>,
}

impl Installed {
    /// From `pkg.list` (`PackageInfo::source`/`source_version`).
    pub fn from_info(p: fleet_proto::payload::PackageInfo) -> Self {
        Self {
            name: p.name,
            version: p.version,
            source: p.source,
            source_version: p.source_version,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub package: String,
    pub installed: String,
    pub id: String,
    pub aliases: Vec<String>,
    /// `None`: no fix released yet.
    pub fixed: Option<String>,
    pub severity: Severity,
}

impl Finding {
    pub fn fixable(&self) -> bool {
        self.fixed.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {
    /// Most severe first, then package, then id.
    pub findings: Vec<Finding>,
    /// Packages with at least one finding that an upgrade fixes (the
    /// fleet table's "vulnerable packages").
    pub vulnerable_packages: u32,
    /// Packages whose only findings have no fix yet.
    pub unfixed_packages: u32,
    pub highest: Option<Severity>,
}

/// Most findings kept per server.
pub const MAX_FINDINGS: usize = 5_000;

fn key<'a>(target: &Target, p: &'a Installed) -> &'a str {
    match target.distro {
        Distro::Debian => p.source.as_deref().unwrap_or(&p.name),
        Distro::Ubuntu => &p.name,
    }
}

/// The version compared with the advisory's fixed version: Debian's are
/// source versions, so the source version when the inventory has one.
fn compared_version<'a>(target: &Target, p: &'a Installed) -> &'a str {
    match (target.distro, &p.source, &p.source_version) {
        (Distro::Debian, Some(_), Some(v)) => v,
        _ => &p.version,
    }
}

/// Matches `installed` against `lookup(package) -> advisories` for
/// `target`'s release.
pub fn match_packages<E>(
    target: &Target,
    installed: &[Installed],
    mut lookup: impl FnMut(&str) -> Result<Vec<Advisory>, E>,
) -> Result<Report, E> {
    let mut findings = Vec::new();
    for p in installed {
        for a in lookup(key(target, p))? {
            if a.release != target.codename || a.distro != target.distro {
                continue;
            }
            let affected = match &a.fixed {
                Some(f) => is_older(compared_version(target, p), f),
                None => true,
            };
            if affected && findings.len() < MAX_FINDINGS {
                findings.push(Finding {
                    package: p.name.clone(),
                    installed: p.version.clone(),
                    id: a.id,
                    aliases: a.aliases,
                    fixed: a.fixed,
                    severity: a.severity,
                });
            }
        }
    }
    Ok(summarize(findings))
}

pub fn summarize(mut findings: Vec<Finding>) -> Report {
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.package.cmp(&b.package))
            .then_with(|| a.id.cmp(&b.id))
    });
    let fixable: BTreeSet<&str> = findings
        .iter()
        .filter(|f| f.fixable())
        .map(|f| f.package.as_str())
        .collect();
    let unfixed: BTreeSet<&str> = findings
        .iter()
        .filter(|f| !f.fixable() && !fixable.contains(f.package.as_str()))
        .map(|f| f.package.as_str())
        .collect();
    let (v, u) = (fixable.len() as u32, unfixed.len() as u32);
    let highest = findings.iter().map(|f| f.severity).max();
    Report {
        findings,
        vulnerable_packages: v,
        unfixed_packages: u,
        highest,
    }
}
