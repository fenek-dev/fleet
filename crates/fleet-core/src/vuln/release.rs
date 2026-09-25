//! Which feed release a server runs, from `system.info` (`os-release`
//! `ID` and `VERSION_ID`, untrusted strings).
//!
//! Only supported releases are listed (design scope: Debian 12+, Ubuntu
//! 22.04+); feeds are filtered to these codenames at ingest, which keeps
//! the table small. A new release is one line here.

use super::Distro;

/// `(VERSION_ID, codename)`.
pub const DEBIAN: &[(&str, &str)] = &[("12", "bookworm"), ("13", "trixie"), ("14", "forky")];

pub const UBUNTU: &[(&str, &str)] = &[
    ("22.04", "jammy"),
    ("24.04", "noble"),
    ("24.10", "oracular"),
    ("25.04", "plucky"),
    ("25.10", "questing"),
    ("26.04", "resolute"),
];

/// A server's distribution and release codename.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    pub distro: Distro,
    pub codename: &'static str,
}

fn table(d: Distro) -> &'static [(&'static str, &'static str)] {
    match d {
        Distro::Debian => DEBIAN,
        Distro::Ubuntu => UBUNTU,
    }
}

/// `None` for other distributions and unsupported (or testing/unstable,
/// which have no `VERSION_ID`) releases.
pub fn target(os_id: &str, os_version: &str) -> Option<Target> {
    let distro = Distro::parse(os_id.trim())?;
    let v = os_version.trim().trim_matches('"');
    table(distro)
        .iter()
        .find(|(ver, _)| *ver == v)
        .map(|&(_, codename)| Target { distro, codename })
}

/// Codenames kept from a feed.
pub fn supported(distro: Distro, codename: &str) -> bool {
    table(distro).iter().any(|&(_, c)| c == codename)
}
