//! Ubuntu Security Notices database
//! (<https://usn.ubuntu.com/usn-db/database.json.bz2>):
//!
//! ```json
//! { "<usn id, e.g. 6000-1>": {
//!     "id": "6000-1", "title": "…", "timestamp": 1680000000.0,
//!     "cves": ["CVE-…", "https://launchpad.net/bugs/…"],
//!     "releases": {
//!       "<codename>": {
//!         "sources":     { "<src>": { "version": "…" } },
//!         "binaries":    { "<bin>": { "version": "…", "pocket": "…" } },
//!         "allbinaries": { "<bin>": { "version": "…", "source": "…", "pocket": "…" } } } } } }
//! ```
//!
//! A USN is a fix: every listed binary package at a lower version is
//! vulnerable. Rows are keyed by binary package, so no source mapping is
//! needed on Ubuntu. USNs carry no priority (`Severity::Unknown`).

use super::feed::{FeedError, Stats, for_each_entry};
use super::{
    Advisory, Distro, MAX_ALIASES, Severity, release, valid_package, valid_token, valid_version,
};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::Read;

#[derive(Deserialize)]
struct Notice {
    #[serde(default)]
    cves: Vec<String>,
    #[serde(default)]
    releases: BTreeMap<String, NoticeRelease>,
}

#[derive(Deserialize)]
struct NoticeRelease {
    #[serde(default)]
    binaries: BTreeMap<String, Binary>,
    #[serde(default)]
    allbinaries: BTreeMap<String, Binary>,
}

#[derive(Deserialize)]
struct Binary {
    version: String,
}

pub fn parse<R: Read>(
    reader: R,
    sink: &mut dyn FnMut(Advisory) -> Result<(), String>,
) -> Result<Stats, FeedError> {
    let mut stats = Stats::default();
    stats.entries = for_each_entry(reader, |key: String, notice: Notice| {
        let id = format!("USN-{key}");
        if !valid_token(&id, 32) {
            stats.invalid += 1;
            return Ok(());
        }
        let aliases: Vec<String> = notice
            .cves
            .into_iter()
            .filter(|c| c.starts_with("CVE-") && valid_token(c, 32))
            .take(MAX_ALIASES)
            .collect();
        for (codename, rel) in notice.releases {
            if !release::supported(Distro::Ubuntu, &codename) {
                continue;
            }
            // `allbinaries` is the full list; older notices only have
            // `binaries`. Same package in both: one row.
            let mut bins = rel.binaries;
            bins.extend(rel.allbinaries);
            for (package, bin) in bins {
                if !valid_package(&package) || !valid_version(&bin.version) {
                    stats.invalid += 1;
                    continue;
                }
                sink(Advisory {
                    distro: Distro::Ubuntu,
                    release: codename.clone(),
                    package,
                    id: id.clone(),
                    aliases: aliases.clone(),
                    fixed: Some(bin.version),
                    severity: Severity::Unknown,
                })?;
                stats.advisories += 1;
            }
        }
        Ok(())
    })?;
    Ok(stats)
}
