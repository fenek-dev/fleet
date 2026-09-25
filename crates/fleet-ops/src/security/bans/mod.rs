//! Intrusion blocking (design §4.7).
//!
//! - [`BanEngine`] (`engine`): pure state machine. Failures per ban key
//!   (IPv4 address or IPv6 /64) inside a sliding window; reaching the
//!   threshold is an offence; the n-th offence within [`STRIKE_MEMORY_MS`]
//!   gets `ban_steps_s[n-1]` (last step repeats). Exempt: configured
//!   ranges, learned Mac addresses (7 days after their last Fleet login;
//!   an IPv6 Mac is learned as its /64, the same unit a ban covers),
//!   loopback/unspecified/multicast.
//! - [`BanService`] (`service`): the engine plus nftables. Bans are
//!   elements with timeouts in `inet fleet` sets; argv only, through the
//!   context's `CommandRunner`, never a shell. Every set update holds
//!   [`crate::nftlock::lock`]. Required set definitions (created by the
//!   firewall module):
//!
//!   ```text
//!   set banned4 { type ipv4_addr; flags interval, timeout; }
//!   set banned6 { type ipv6_addr; flags interval, timeout; }
//!   set exempt4 { type ipv4_addr; flags interval, timeout; }
//!   set exempt6 { type ipv6_addr; flags interval, timeout; }
//!   ```
//!
//!   Interval sets reject overlapping elements, so configured exempt
//!   ranges must not overlap each other, and a learned address inside a
//!   configured range has no element of its own (it is still remembered,
//!   and gets its element back when the range is removed).
//! - Web access-log bans (`web`): opt-in per log path ([`WebBanSource`]),
//!   with their own cap on the ban step. **Trust boundary:** the uid of
//!   the web server that writes the log. Anything that can write the log
//!   file can make the agent ban any public address, so web bans never
//!   touch private, CGNAT, ULA or link-local ranges or the host's own
//!   addresses, and their duration is capped per source.
//! - [`BansHandler`] (`handler`): `bans.list/add/remove`,
//!   `bans.config.get/set`.
//!
//! State is in memory; exec persists [`BanService::export`] whenever
//! [`BanService::revision`] moves and restores it at startup
//! ([`BanService::import`], then [`BanService::restore_kernel`] for sets
//! the kernel lost).

mod engine;
mod handler;
mod nft;
mod service;
mod web;

#[cfg(test)]
mod tests;

pub use engine::{BanEngine, BanState, Decision};
pub use handler::BansHandler;
pub use nft::{
    ban_args, exempt_args, learned_args, nft_add_args, nft_delete_args, nft_set_is_empty,
    unban_args,
};
pub use service::{BanService, LearnedMacIps};
pub use web::{DEFAULT_WEB_MAX_STEP_S, WebBanSource, is_internal};

use fleet_proto::args::Cidr;
use fleet_proto::op::BanConfig;
use std::net::{IpAddr, Ipv6Addr};

pub const NFT: &str = "/usr/sbin/nft";
pub const TABLE: [&str; 2] = ["inet", "fleet"];
const DAY_MS: u64 = 86_400_000;
/// Learned Mac addresses stay exempt this long after their last login.
pub const LEARNED_TTL_MS: u64 = 7 * DAY_MS;
/// Offences older than this no longer escalate.
pub const STRIKE_MEMORY_MS: u64 = 30 * DAY_MS;
/// Bound on tracked keys (failure windows, strikes, learned IPs).
pub const MAX_TRACKED: usize = 65_536;
pub const MAX_MANUAL_S: u32 = 30 * 86_400;

/// The design defaults: 5 failures in 10 minutes → 1 h, then 24 h, 7 days.
pub fn default_config() -> BanConfig {
    BanConfig {
        threshold: 5,
        window_s: 600,
        ban_steps_s: vec![3_600, 86_400, 7 * 86_400],
        exempt: Vec::new(),
        web_scanners: true,
    }
}

/// What a ban covers: one IPv4 address or an IPv6 /64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BanKey {
    pub addr: IpAddr,
    pub prefix: u8,
}

/// IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is the IPv4 address.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(a) => a.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

pub fn ban_key(ip: IpAddr) -> BanKey {
    match canonical(ip) {
        IpAddr::V4(a) => BanKey {
            addr: IpAddr::V4(a),
            prefix: 32,
        },
        IpAddr::V6(a) => BanKey {
            addr: IpAddr::V6(Ipv6Addr::from(u128::from(a) & !((1u128 << 64) - 1))),
            prefix: 64,
        },
    }
}

/// The unit a Mac address is learned as: the ban key (IPv4 address or
/// IPv6 /64), so a Mac whose IPv6 privacy address rotates stays exempt and
/// its /64 never collects failures.
pub fn learned_key(ip: IpAddr) -> BanKey {
    ban_key(ip)
}

fn never_bannable(ip: IpAddr) -> bool {
    ip.is_loopback() || ip.is_unspecified() || ip.is_multicast()
}

/// Whether two ranges share an address (same family only).
pub fn cidrs_overlap(a: &Cidr, b: &Cidr) -> bool {
    a.contains(b.addr()) || b.contains(a.addr())
}

/// Configured exempt ranges become elements of one interval set each
/// family, which rejects overlaps: duplicates or nested ranges are
/// invalid.
pub fn validate_exempt(exempt: &[Cidr]) -> Result<(), fleet_proto::ErrorCode> {
    let clash = exempt
        .iter()
        .enumerate()
        .any(|(i, a)| exempt[i + 1..].iter().any(|b| cidrs_overlap(a, b)));
    if clash {
        Err(fleet_proto::ErrorCode::InvalidArgument)
    } else {
        Ok(())
    }
}
