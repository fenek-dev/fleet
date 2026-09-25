//! Debian Security Tracker JSON
//! (<https://security-tracker.debian.org/tracker/data/json>):
//!
//! ```json
//! { "<source package>": {
//!     "<CVE-… | TEMP-…>": {
//!       "description": "…", "scope": "…",
//!       "releases": {
//!         "<codename>": { "status": "resolved|open|undetermined",
//!                         "fixed_version": "…", "urgency": "…",
//!                         "repositories": { … } } } } } }
//! ```
//!
//! Kept per supported release: `resolved` with a real fixed version (`0`
//! means the release was never affected) and `open` (no fix yet) unless
//! the urgency is `unimportant`. `undetermined` is dropped.

use super::feed::{FeedError, Stats, for_each_entry};
use super::{Advisory, Distro, Severity, release, valid_package, valid_token, valid_version};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::Read;

#[derive(Deserialize)]
struct Issue {
    #[serde(default)]
    releases: BTreeMap<String, ReleaseStatus>,
}

#[derive(Deserialize)]
struct ReleaseStatus {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    fixed_version: Option<String>,
    #[serde(default)]
    urgency: Option<String>,
}

/// What one tracker cell means for matching.
fn row(r: &ReleaseStatus) -> Option<(Option<String>, Severity)> {
    let urgency = r.urgency.as_deref().unwrap_or("");
    let severity = Severity::from_urgency(urgency);
    match r.status.as_deref()? {
        "resolved" => {
            let v = r.fixed_version.as_deref()?.trim();
            (v != "0").then(|| (Some(v.to_string()), severity))
        }
        "open" if severity != Severity::Negligible => Some((None, severity)),
        _ => None,
    }
}

pub fn parse<R: Read>(
    reader: R,
    sink: &mut dyn FnMut(Advisory) -> Result<(), String>,
) -> Result<Stats, FeedError> {
    let mut stats = Stats::default();
    stats.entries = for_each_entry(
        reader,
        |package: String, issues: BTreeMap<String, Issue>| {
            if !valid_package(&package) {
                stats.invalid += 1;
                return Ok(());
            }
            for (id, issue) in issues {
                if !valid_token(&id, 64) {
                    stats.invalid += 1;
                    continue;
                }
                for (codename, r) in &issue.releases {
                    if !release::supported(Distro::Debian, codename) {
                        continue;
                    }
                    let Some((fixed, severity)) = row(r) else {
                        continue;
                    };
                    if fixed.as_deref().is_some_and(|v| !valid_version(v)) {
                        stats.invalid += 1;
                        continue;
                    }
                    sink(Advisory {
                        distro: Distro::Debian,
                        release: codename.clone(),
                        package: package.clone(),
                        id: id.clone(),
                        aliases: Vec::new(),
                        fixed,
                        severity,
                    })?;
                    stats.advisories += 1;
                }
            }
            Ok(())
        },
    )?;
    Ok(stats)
}
