//! Web access-log bans (design §4.7).
//!
//! Trust boundary: the uid of the web server that writes the access log.
//! Whoever can write that file controls every field of every line, so a
//! compromised or misconfigured web server (or anything else with write
//! access to the log) can make the agent ban arbitrary addresses. Hence:
//!
//! - opt-in per log path ([`WebBanSource`]); lines from other paths never
//!   ban;
//! - each source caps the ban step ([`WebBanSource::max_step_s`]), so a
//!   forged flood can't produce week-long bans;
//! - private (RFC 1918), CGNAT, ULA, link-local and the host's own
//!   addresses ([`BanService::set_own_addrs`]) are never banned from a
//!   web log, so forged lines can't cut the host off its own network.

use super::{BanService, Decision, MAX_MANUAL_S, ban_key, canonical};
use crate::ctx::SysCtx;
use crate::handler::OpError;
use crate::security::webscan::{AccessHit, is_scanner_probe};
use fleet_proto::payload::BanReason;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Default cap on a web-origin ban: one day.
pub const DEFAULT_WEB_MAX_STEP_S: u32 = 86_400;

/// An access log whose scanner hits may ban.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebBanSource {
    pub path: PathBuf,
    /// Longest ban a hit from this log can cause (60 s ..= 30 days).
    pub max_step_s: u32,
}

impl WebBanSource {
    /// `max_step_s` is clamped to 60 s ..= 30 days.
    pub fn new(path: impl Into<PathBuf>, max_step_s: u32) -> Self {
        Self {
            path: path.into(),
            max_step_s: max_step_s.clamp(60, MAX_MANUAL_S),
        }
    }
}

/// Addresses a web log may never ban: RFC 1918, CGNAT `100.64/10`, ULA
/// `fc00::/7`, link-local (`169.254/16`, `fe80::/10`), plus everything
/// that is never bannable at all (loopback, unspecified, multicast).
pub fn is_internal(ip: IpAddr) -> bool {
    match canonical(ip) {
        IpAddr::V4(a) => {
            let [o0, o1, ..] = a.octets();
            a.is_private()
                || a.is_link_local()
                || (o0 == 100 && (o1 & 0xc0) == 64)
                || a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || a.is_broadcast()
        }
        IpAddr::V6(a) => {
            let s0 = a.segments()[0];
            (s0 & 0xfe00) == 0xfc00
                || (s0 & 0xffc0) == 0xfe80
                || a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
        }
    }
}

impl BanService {
    /// The access logs whose scanner hits may ban (replaces the list).
    pub fn set_web_sources(&self, sources: Vec<WebBanSource>) {
        *self.web_sources.borrow_mut() = sources;
    }

    /// The host's own addresses (replaces the set). Web logs never ban
    /// them, nor the IPv6 /64 they are in.
    pub fn set_own_addrs(&self, addrs: impl IntoIterator<Item = IpAddr>) {
        *self.own_addrs.borrow_mut() = addrs.into_iter().map(canonical).collect();
    }

    fn web_cap(&self, log: &Path) -> Option<u32> {
        self.web_sources
            .borrow()
            .iter()
            .find(|s| s.path == log)
            .map(|s| s.max_step_s)
    }

    fn web_bannable(&self, ip: IpAddr) -> bool {
        let key = ban_key(ip);
        !is_internal(ip) && !self.own_addrs.borrow().iter().any(|o| ban_key(*o) == key)
    }

    /// One request from the access log at `log`. Bans only when `log` is
    /// a configured [`WebBanSource`] (capped at its `max_step_s`) and the
    /// client may be banned from a web log at all.
    pub async fn observe_access_from(
        &self,
        ctx: &SysCtx,
        log: &Path,
        hit: &AccessHit,
        now_ms: u64,
    ) -> Result<Option<Decision>, OpError> {
        if !is_scanner_probe(hit) {
            return Ok(None);
        }
        let Some(cap) = self.web_cap(log) else {
            return Ok(None);
        };
        if !self.web_bannable(hit.ip) {
            return Ok(None);
        }
        let d = self.engine.borrow_mut().observe_capped(
            hit.ip,
            BanReason::WebScanner,
            now_ms,
            Some(cap),
        );
        self.apply_opt(ctx, d).await
    }

    /// A request from an unnamed log. Web bans are opt-in per log path,
    /// so this never bans; use [`BanService::observe_access_from`].
    pub async fn observe_access(
        &self,
        _ctx: &SysCtx,
        _hit: &AccessHit,
        _now_ms: u64,
    ) -> Result<Option<Decision>, OpError> {
        Ok(None)
    }
}
