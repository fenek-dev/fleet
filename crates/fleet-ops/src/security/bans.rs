//! Intrusion blocking (design §4.7).
//!
//! - [`BanEngine`]: pure state machine. Failures per ban key (IPv4 address
//!   or IPv6 /64) inside a sliding window; reaching the threshold is an
//!   offence; the n-th offence within [`STRIKE_MEMORY_MS`] gets
//!   `ban_steps_s[n-1]` (last step repeats). Exempt: configured ranges,
//!   learned Mac addresses (7 days after their last Fleet login),
//!   loopback/unspecified/multicast.
//! - [`BanService`]: the engine plus nftables. Bans are elements with
//!   timeouts in `inet fleet` sets; argv only, through the context's
//!   `CommandRunner`, never a shell. Required set definitions (created by
//!   the firewall module):
//!
//!   ```text
//!   set banned4 { type ipv4_addr; flags interval, timeout; }
//!   set banned6 { type ipv6_addr; flags interval, timeout; }
//!   set exempt4 { type ipv4_addr; flags interval, timeout; }
//!   set exempt6 { type ipv6_addr; flags interval, timeout; }
//!   ```
//!
//! - [`BansHandler`]: `bans.list/add/remove`, `bans.config.get/set`.
//!
//! State is in memory; exec persists [`BanService::export`] whenever
//! [`BanService::revision`] moves and restores it at startup
//! ([`BanService::import`], then [`BanService::restore_kernel`] for sets
//! the kernel lost).

use super::EventSink;
use super::authlog::AuthEvent;
use super::webscan::{AccessHit, is_scanner_probe};
use crate::ctx::SysCtx;
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, Registry};
use crate::runner::CommandSpec;
use fleet_proto::args::Cidr;
use fleet_proto::op::{BanConfig, tag};
use fleet_proto::payload::{BanEntry, BanReason, Bans};
use fleet_proto::{ErrorCode, Event, Op, Payload};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr};
use std::rc::Rc;
use std::time::Duration;

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

fn never_bannable(ip: IpAddr) -> bool {
    ip.is_loopback() || ip.is_unspecified() || ip.is_multicast()
}

/// A ban to put into the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub key: BanKey,
    pub duration_s: u32,
    pub until_ms: u64,
    pub reason: BanReason,
    pub strikes: u16,
    /// The element is (still) in the set: replace it to reset the timeout.
    pub replace: bool,
}

pub struct BanEngine {
    config: BanConfig,
    failures: HashMap<BanKey, VecDeque<u64>>,
    /// Offence count and time of the last offence.
    strikes: HashMap<BanKey, (u16, u64)>,
    bans: BTreeMap<BanKey, BanEntry>,
    /// Learned Mac address → last successful Fleet login.
    learned: HashMap<IpAddr, u64>,
    /// Bumped by every change worth persisting ([`BanEngine::revision`]).
    rev: u64,
}

impl BanEngine {
    pub fn new(config: BanConfig) -> Self {
        Self {
            config,
            failures: HashMap::new(),
            strikes: HashMap::new(),
            bans: BTreeMap::new(),
            learned: HashMap::new(),
            rev: 0,
        }
    }

    /// Changes whenever bans, strikes, learned addresses or the config
    /// change (exec persists [`BanEngine::export`] when it moved).
    pub fn revision(&self) -> u64 {
        self.rev
    }

    pub fn config(&self) -> &BanConfig {
        &self.config
    }

    /// Replaces the config; returns the exempt ranges (removed, added).
    pub fn set_config(&mut self, config: BanConfig) -> (Vec<Cidr>, Vec<Cidr>) {
        let removed = self
            .config
            .exempt
            .iter()
            .filter(|c| !config.exempt.contains(c))
            .copied()
            .collect();
        let added = config
            .exempt
            .iter()
            .filter(|c| !self.config.exempt.contains(c))
            .copied()
            .collect();
        self.config = config;
        self.rev += 1;
        (removed, added)
    }

    fn in_configured(&self, ip: IpAddr) -> bool {
        self.config.exempt.iter().any(|c| c.contains(ip))
    }

    pub fn is_exempt(&self, ip: IpAddr, now_ms: u64) -> bool {
        let ip = canonical(ip);
        never_bannable(ip)
            || self.in_configured(ip)
            || self
                .learned
                .get(&ip)
                .is_some_and(|t| now_ms < t.saturating_add(LEARNED_TTL_MS))
    }

    /// Records a successful Fleet login from `ip`. Returns whether the
    /// address needs an exempt-set element (`Some(replace)`), or `None`
    /// when a configured range already covers it (an overlapping element
    /// would conflict in an interval set) or it is never bannable anyway.
    pub fn learn(&mut self, ip: IpAddr, now_ms: u64) -> Option<bool> {
        let ip = canonical(ip);
        if never_bannable(ip) || self.in_configured(ip) {
            return None;
        }
        if self.learned.len() >= MAX_TRACKED && !self.learned.contains_key(&ip) {
            self.learned
                .retain(|_, t| now_ms < t.saturating_add(LEARNED_TTL_MS));
            if self.learned.len() >= MAX_TRACKED {
                return None;
            }
        }
        let prev = self.learned.insert(ip, now_ms);
        self.rev += 1;
        Some(prev.is_some_and(|t| now_ms < t.saturating_add(LEARNED_TTL_MS)))
    }

    pub fn learned(&self, now_ms: u64) -> Vec<IpAddr> {
        let mut v: Vec<IpAddr> = self
            .learned
            .iter()
            .filter(|(_, t)| now_ms < t.saturating_add(LEARNED_TTL_MS))
            .map(|(ip, _)| *ip)
            .collect();
        v.sort();
        v
    }

    fn active(&self, key: &BanKey, now_ms: u64) -> bool {
        self.bans.get(key).is_some_and(|b| b.until_ms > now_ms)
    }

    fn step_s(&self, strikes: u16) -> u32 {
        let steps = &self.config.ban_steps_s;
        let i = usize::from(strikes.max(1) - 1).min(steps.len().saturating_sub(1));
        steps.get(i).copied().unwrap_or(3_600)
    }

    fn ban(
        &mut self,
        key: BanKey,
        duration_s: u32,
        reason: BanReason,
        strikes: u16,
        now_ms: u64,
    ) -> Decision {
        let replace = self.active(&key, now_ms);
        self.rev += 1;
        let until_ms = now_ms.saturating_add(u64::from(duration_s) * 1000);
        self.bans.insert(
            key,
            BanEntry {
                addr: key.addr,
                prefix: key.prefix,
                until_ms,
                reason,
                strikes,
            },
        );
        Decision {
            key,
            duration_s,
            until_ms,
            reason,
            strikes,
            replace,
        }
    }

    /// One failure from `ip`. Returns a ban when it completes an offence.
    pub fn observe(&mut self, ip: IpAddr, reason: BanReason, now_ms: u64) -> Option<Decision> {
        if reason == BanReason::WebScanner && !self.config.web_scanners {
            return None;
        }
        if self.is_exempt(ip, now_ms) {
            return None;
        }
        let key = ban_key(ip);
        if self.active(&key, now_ms) {
            return None;
        }
        let window_ms = u64::from(self.config.window_s) * 1000;
        self.bound_failures(now_ms, window_ms);
        let q = self.failures.entry(key).or_default();
        q.push_back(now_ms);
        while q
            .front()
            .is_some_and(|t| now_ms.saturating_sub(*t) > window_ms)
        {
            q.pop_front();
        }
        if q.len() < usize::from(self.config.threshold) {
            return None;
        }
        self.failures.remove(&key);
        self.bound_strikes(now_ms);
        let s = self.strikes.entry(key).or_insert((0, 0));
        if now_ms.saturating_sub(s.1) > STRIKE_MEMORY_MS {
            s.0 = 0;
        }
        s.0 = s.0.saturating_add(1);
        s.1 = now_ms;
        let strikes = s.0;
        let d = self.step_s(strikes);
        Some(self.ban(key, d, reason, strikes, now_ms))
    }

    fn bound_failures(&mut self, now_ms: u64, window_ms: u64) {
        if self.failures.len() >= MAX_TRACKED {
            self.failures.retain(|_, q| {
                q.back()
                    .is_some_and(|t| now_ms.saturating_sub(*t) <= window_ms)
            });
            if self.failures.len() >= MAX_TRACKED {
                self.failures.clear();
            }
        }
    }

    fn bound_strikes(&mut self, now_ms: u64) {
        if self.strikes.len() >= MAX_TRACKED {
            self.strikes
                .retain(|_, (_, t)| now_ms.saturating_sub(*t) <= STRIKE_MEMORY_MS);
            if self.strikes.len() >= MAX_TRACKED {
                self.strikes.clear();
            }
        }
    }

    /// `bans.add`.
    pub fn manual(
        &mut self,
        ip: IpAddr,
        duration_s: u32,
        now_ms: u64,
    ) -> Result<Decision, ErrorCode> {
        if !(60..=MAX_MANUAL_S).contains(&duration_s) || self.is_exempt(ip, now_ms) {
            return Err(ErrorCode::InvalidArgument);
        }
        let key = ban_key(ip);
        let strikes = self.bans.get(&key).map_or(0, |b| b.strikes);
        Ok(self.ban(key, duration_s, BanReason::Manual, strikes, now_ms))
    }

    /// `bans.remove`: forgets the ban, its failures and strikes.
    pub fn remove(&mut self, ip: IpAddr) -> Option<BanEntry> {
        let key = ban_key(ip);
        self.rev += 1;
        self.failures.remove(&key);
        self.strikes.remove(&key);
        self.bans.remove(&key)
    }

    /// Undo of a ban whose nft update failed.
    fn forget_ban(&mut self, key: &BanKey) {
        self.rev += 1;
        self.bans.remove(key);
    }

    pub fn expire(&mut self, now_ms: u64) {
        self.bans.retain(|_, b| b.until_ms > now_ms);
        self.learned
            .retain(|_, t| now_ms < t.saturating_add(LEARNED_TTL_MS));
    }

    pub fn snapshot(&self, now_ms: u64) -> Bans {
        Bans {
            bans: self
                .bans
                .values()
                .filter(|b| b.until_ms > now_ms)
                .cloned()
                .collect(),
            learned_exempt: self.learned(now_ms),
        }
    }

    /// What survives an exec restart: config, active bans, strikes still
    /// inside [`STRIKE_MEMORY_MS`], learned addresses still inside
    /// [`LEARNED_TTL_MS`]. Failure windows are not kept (minutes long).
    pub fn export(&self, now_ms: u64) -> BanState {
        let mut learned: Vec<(IpAddr, u64)> = self
            .learned
            .iter()
            .filter(|(_, t)| now_ms < t.saturating_add(LEARNED_TTL_MS))
            .map(|(ip, t)| (*ip, *t))
            .collect();
        learned.sort();
        let mut strikes: Vec<(IpAddr, u8, u16, u64)> = self
            .strikes
            .iter()
            .filter(|(_, (_, t))| now_ms.saturating_sub(*t) <= STRIKE_MEMORY_MS)
            .map(|(k, (n, t))| (k.addr, k.prefix, *n, *t))
            .collect();
        strikes.sort();
        BanState {
            config: self.config.clone(),
            bans: self.snapshot(now_ms).bans,
            strikes,
            learned,
        }
    }

    /// Restores [`BanEngine::export`]ed state. Entries are re-validated
    /// (the database is exec's, but nothing is trusted blindly): keys must
    /// be canonical ban keys, expired entries are dropped, sizes bounded;
    /// an invalid config falls back to the current one.
    pub fn import(&mut self, st: BanState, now_ms: u64) {
        if st.config.validate().is_ok() {
            self.config = st.config;
        }
        let valid = |addr: IpAddr, prefix: u8| {
            let k = ban_key(addr);
            k.addr == addr && k.prefix == prefix && !never_bannable(addr)
        };
        self.bans = st
            .bans
            .into_iter()
            .filter(|b| b.until_ms > now_ms && valid(b.addr, b.prefix))
            .take(MAX_TRACKED)
            .map(|b| {
                (
                    BanKey {
                        addr: b.addr,
                        prefix: b.prefix,
                    },
                    b,
                )
            })
            .collect();
        self.strikes = st
            .strikes
            .into_iter()
            .filter(|(a, p, n, t)| {
                *n > 0 && now_ms.saturating_sub(*t) <= STRIKE_MEMORY_MS && valid(*a, *p)
            })
            .take(MAX_TRACKED)
            .map(|(addr, prefix, n, t)| (BanKey { addr, prefix }, (n, t)))
            .collect();
        self.learned = st
            .learned
            .into_iter()
            .filter(|(ip, t)| {
                canonical(*ip) == *ip
                    && !never_bannable(*ip)
                    && now_ms < t.saturating_add(LEARNED_TTL_MS)
            })
            .take(MAX_TRACKED)
            .collect();
        self.failures.clear();
        self.rev += 1;
    }
}

/// Persisted form of a [`BanEngine`] (exec's redb, design §4.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BanState {
    pub config: BanConfig,
    pub bans: Vec<BanEntry>,
    /// `(addr, prefix, offences, last offence ms)`.
    pub strikes: Vec<(IpAddr, u8, u16, u64)>,
    /// `(address, last Fleet login ms)`.
    pub learned: Vec<(IpAddr, u64)>,
}

/// Whether `nft -j list set …` output shows a set without elements.
/// `None` if the output isn't a recognisable set listing.
pub fn nft_set_is_empty(json: &str) -> Option<bool> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let set = v
        .get("nftables")?
        .as_array()?
        .iter()
        .find_map(|o| o.get("set"))?;
    Some(
        set.get("elem")
            .and_then(serde_json::Value::as_array)
            .is_none_or(Vec::is_empty),
    )
}

// ---- nft argv ----

fn set_name(base: &str, addr: IpAddr) -> String {
    format!("{base}{}", if addr.is_ipv4() { 4 } else { 6 })
}

fn element(addr: IpAddr, prefix: u8) -> String {
    let full = if addr.is_ipv4() { 32 } else { 128 };
    if prefix == full {
        addr.to_string()
    } else {
        format!("{addr}/{prefix}")
    }
}

/// `[delete element inet fleet <set> { <e> } ;] add element inet fleet
/// <set> { <e> [timeout <n>s] }`. `elem` is always formatted from an
/// `IpAddr` (never text from the wire), so it can't carry nft syntax.
pub fn nft_add_args(set: &str, elem: &str, timeout_s: Option<u64>, replace: bool) -> Vec<String> {
    let mut a: Vec<String> = Vec::new();
    let head = |verb: &str| -> Vec<String> {
        [verb, "element", TABLE[0], TABLE[1], set, "{", elem]
            .into_iter()
            .map(str::to_owned)
            .collect()
    };
    if replace {
        a.extend(head("delete"));
        a.extend(["}".to_owned(), ";".to_owned()]);
    }
    a.extend(head("add"));
    if let Some(t) = timeout_s {
        a.extend(["timeout".to_owned(), format!("{t}s")]);
    }
    a.push("}".to_owned());
    a
}

pub fn nft_delete_args(set: &str, elem: &str) -> Vec<String> {
    ["delete", "element", TABLE[0], TABLE[1], set, "{", elem, "}"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

pub fn ban_args(d: &Decision) -> Vec<String> {
    nft_add_args(
        &set_name("banned", d.key.addr),
        &element(d.key.addr, d.key.prefix),
        Some(u64::from(d.duration_s)),
        d.replace,
    )
}

pub fn unban_args(key: &BanKey) -> Vec<String> {
    nft_delete_args(
        &set_name("banned", key.addr),
        &element(key.addr, key.prefix),
    )
}

pub fn exempt_args(c: &Cidr, add: bool) -> Vec<String> {
    let (set, e) = (set_name("exempt", c.addr()), element(c.addr(), c.prefix()));
    if add {
        nft_add_args(&set, &e, None, false)
    } else {
        nft_delete_args(&set, &e)
    }
}

pub fn learned_args(ip: IpAddr, replace: bool) -> Vec<String> {
    let ip = canonical(ip);
    let full = if ip.is_ipv4() { 32 } else { 128 };
    nft_add_args(
        &set_name("exempt", ip),
        &element(ip, full),
        Some(LEARNED_TTL_MS / 1000),
        replace,
    )
}

async fn run_nft(ctx: &SysCtx, args: Vec<String>) -> Result<(), OpError> {
    let out = ctx
        .runner
        .run(
            CommandSpec::new(NFT)
                .args(args)
                .timeout(Duration::from_secs(10)),
        )
        .await?;
    if out.success() {
        Ok(())
    } else {
        let err: String = String::from_utf8_lossy(&out.stderr)
            .chars()
            .take(512)
            .collect();
        Err(OpError::internal(format!("nft: {err}")))
    }
}

/// Fed by exec with the source address of every successful Fleet login
/// (the SSH connection a Mac's session arrived on).
pub trait LearnedMacIps {
    fn fleet_login<'a>(
        &'a self,
        ctx: &'a SysCtx,
        ip: IpAddr,
        now_ms: u64,
    ) -> LocalBoxFuture<'a, Result<(), OpError>>;
}

/// The engine plus nftables and event emission. Shared (`Rc`) between the
/// handlers and exec's detectors (auth-event and access-log followers).
pub struct BanService {
    engine: RefCell<BanEngine>,
    sink: Rc<dyn EventSink>,
}

impl BanService {
    pub fn new(config: BanConfig, sink: Rc<dyn EventSink>) -> Rc<Self> {
        Rc::new(Self {
            engine: RefCell::new(BanEngine::new(config)),
            sink,
        })
    }

    pub fn snapshot(&self, now_ms: u64) -> Bans {
        self.engine.borrow().snapshot(now_ms)
    }

    /// Registers `bans.*` handlers backed by this service.
    pub fn register(self: &Rc<Self>, r: &mut Registry) {
        let h = Rc::new(BansHandler(self.clone()));
        for t in [
            tag::BANS_LIST,
            tag::BANS_ADD,
            tag::BANS_REMOVE,
            tag::BANS_CONFIG_GET,
            tag::BANS_CONFIG_SET,
        ] {
            r.register(t, h.clone());
        }
    }

    async fn apply(&self, ctx: &SysCtx, d: Decision) -> Result<Decision, OpError> {
        if let Err(e) = run_nft(ctx, ban_args(&d)).await {
            self.engine.borrow_mut().forget_ban(&d.key);
            return Err(e);
        }
        self.sink.emit(Event::BanChanged {
            addr: d.key.addr,
            banned: true,
            until_ms: Some(d.until_ms),
            reason: d.reason,
        });
        Ok(d)
    }

    /// One parsed sshd event. Bans when it completes an offence.
    pub async fn observe_auth(
        &self,
        ctx: &SysCtx,
        ev: &AuthEvent,
        now_ms: u64,
    ) -> Result<Option<Decision>, OpError> {
        if !ev.is_failure() {
            return Ok(None);
        }
        let d = self
            .engine
            .borrow_mut()
            .observe(ev.addr, BanReason::SshBruteForce, now_ms);
        match d {
            Some(d) => self.apply(ctx, d).await.map(Some),
            None => Ok(None),
        }
    }

    /// One access-log request.
    pub async fn observe_access(
        &self,
        ctx: &SysCtx,
        hit: &AccessHit,
        now_ms: u64,
    ) -> Result<Option<Decision>, OpError> {
        if !is_scanner_probe(hit) {
            return Ok(None);
        }
        let d = self
            .engine
            .borrow_mut()
            .observe(hit.ip, BanReason::WebScanner, now_ms);
        match d {
            Some(d) => self.apply(ctx, d).await.map(Some),
            None => Ok(None),
        }
    }

    /// Drops expired entries (call periodically; nft expires its own).
    pub fn expire(&self, now_ms: u64) {
        self.engine.borrow_mut().expire(now_ms);
    }

    pub fn revision(&self) -> u64 {
        self.engine.borrow().revision()
    }

    pub fn export(&self, now_ms: u64) -> BanState {
        self.engine.borrow().export(now_ms)
    }

    pub fn import(&self, st: BanState, now_ms: u64) {
        self.engine.borrow_mut().import(st, now_ms);
    }

    /// After an exec restart: puts restored state back into the kernel,
    /// per set, **only if that set is empty** (the kernel keeps its
    /// elements across an exec restart; it loses them on reboot or a
    /// ruleset reload). Bans get their remaining time; exempt sets get the
    /// configured ranges and learned addresses. A set that can't be listed
    /// (firewall table not set up yet) is skipped. Returns elements added.
    pub async fn restore_kernel(&self, ctx: &SysCtx, now_ms: u64) -> usize {
        let (bans, exempt, learned) = {
            let e = self.engine.borrow();
            (
                e.snapshot(now_ms).bans,
                e.config().exempt.clone(),
                e.learned
                    .iter()
                    .filter(|(ip, t)| {
                        now_ms < t.saturating_add(LEARNED_TTL_MS) && !e.in_configured(**ip)
                    })
                    .map(|(ip, t)| (*ip, *t))
                    .collect::<Vec<_>>(),
            )
        };
        let mut added = 0;
        for v4 in [true, false] {
            let fam = |a: &IpAddr| a.is_ipv4() == v4;
            let n = if v4 { "4" } else { "6" };
            if set_empty(ctx, &format!("banned{n}")).await == Some(true) {
                for b in bans.iter().filter(|b| fam(&b.addr)) {
                    let left_s = b.until_ms.saturating_sub(now_ms).div_ceil(1000).max(1);
                    let args = nft_add_args(
                        &set_name("banned", b.addr),
                        &element(b.addr, b.prefix),
                        Some(left_s),
                        false,
                    );
                    added += usize::from(run_nft(ctx, args).await.is_ok());
                }
            }
            if set_empty(ctx, &format!("exempt{n}")).await == Some(true) {
                for c in exempt.iter().filter(|c| fam(&c.addr())) {
                    added += usize::from(run_nft(ctx, exempt_args(c, true)).await.is_ok());
                }
                for (ip, t) in learned.iter().filter(|(ip, _)| fam(ip)) {
                    let full = if ip.is_ipv4() { 32 } else { 128 };
                    let left_s = t
                        .saturating_add(LEARNED_TTL_MS)
                        .saturating_sub(now_ms)
                        .div_ceil(1000)
                        .max(1);
                    let args = nft_add_args(
                        &set_name("exempt", *ip),
                        &element(*ip, full),
                        Some(left_s),
                        false,
                    );
                    added += usize::from(run_nft(ctx, args).await.is_ok());
                }
            }
        }
        added
    }
}

/// `nft -j list set inet fleet <set>`: `Some(true)` if it has no elements,
/// `None` if it can't be listed.
async fn set_empty(ctx: &SysCtx, set: &str) -> Option<bool> {
    let args: Vec<String> = ["-j", "list", "set", TABLE[0], TABLE[1], set]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let out = ctx
        .runner
        .run(
            CommandSpec::new(NFT)
                .args(args)
                .timeout(Duration::from_secs(10)),
        )
        .await
        .ok()?;
    if !out.success() {
        return None;
    }
    nft_set_is_empty(&String::from_utf8_lossy(&out.stdout))
}

impl LearnedMacIps for BanService {
    fn fleet_login<'a>(
        &'a self,
        ctx: &'a SysCtx,
        ip: IpAddr,
        now_ms: u64,
    ) -> LocalBoxFuture<'a, Result<(), OpError>> {
        Box::pin(async move {
            let need = self.engine.borrow_mut().learn(ip, now_ms);
            match need {
                Some(replace) => run_nft(ctx, learned_args(ip, replace)).await,
                None => Ok(()),
            }
        })
    }
}

/// `bans.list`, `bans.add`, `bans.remove`, `bans.config.get/set`.
pub struct BansHandler(pub Rc<BanService>);

impl OpHandler for BansHandler {
    fn validate(&self, _ctx: &SysCtx, op: &Op, meta: &OpMeta) -> Result<(), OpError> {
        match op {
            Op::BansList | Op::BansConfigGet | Op::BansRemove { .. } => Ok(()),
            Op::BansAdd {
                addr, duration_s, ..
            } => {
                let e = self.0.engine.borrow();
                if !(60..=MAX_MANUAL_S).contains(duration_s) || e.is_exempt(*addr, meta.now_ms) {
                    return Err(ErrorCode::InvalidArgument.into());
                }
                Ok(())
            }
            Op::BansConfigSet(c) => c.validate().map_err(|e| ErrorCode::from(e).into()),
            _ => Err(ErrorCode::Unsupported.into()),
        }
    }

    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        op: &'a Op,
        meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            let now = meta.now_ms;
            let svc = &self.0;
            match op {
                Op::BansList => {}
                Op::BansAdd {
                    addr, duration_s, ..
                } => {
                    let d = svc.engine.borrow_mut().manual(*addr, *duration_s, now)?;
                    svc.apply(ctx, d).await?;
                }
                Op::BansRemove { addr } => {
                    let key = ban_key(*addr);
                    let known = svc.engine.borrow_mut().remove(*addr);
                    let nft = run_nft(ctx, unban_args(&key)).await;
                    if known.is_none() && nft.is_err() {
                        return Err(ErrorCode::NotFound.into());
                    }
                    svc.sink.emit(Event::BanChanged {
                        addr: key.addr,
                        banned: false,
                        until_ms: None,
                        reason: known.map_or(BanReason::Manual, |b| b.reason),
                    });
                }
                Op::BansConfigGet => {
                    return Ok(OpOutput::Payload(Payload::BanConfig(
                        svc.engine.borrow().config().clone(),
                    )));
                }
                Op::BansConfigSet(c) => {
                    let (removed, added) = svc.engine.borrow_mut().set_config(c.clone());
                    for r in &removed {
                        // Already absent is fine.
                        let _ = run_nft(ctx, exempt_args(r, false)).await;
                    }
                    for a in &added {
                        run_nft(ctx, exempt_args(a, true)).await?;
                    }
                    return Ok(OpOutput::Payload(Payload::BanConfig(c.clone())));
                }
                _ => return Err(ErrorCode::Unsupported.into()),
            }
            Ok(OpOutput::Payload(Payload::Bans(svc.snapshot(now))))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::VecSink;
    use crate::security::authlog::parse_sshd;
    use crate::testutil::{T0, block, ctx_at, meta_at};
    use crate::{CommandOutput, FakeRunner};
    use fleet_proto::args::Label;

    const MIN: u64 = 60_000;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn threshold_window_and_escalation() {
        let mut e = BanEngine::new(default_config());
        let a = ip("198.51.100.7");
        let mut t = 1_000_000_000;
        // 4 failures, then a gap longer than the window: no ban.
        for _ in 0..4 {
            assert!(e.observe(a, BanReason::SshBruteForce, t).is_none());
            t += MIN;
        }
        t += 11 * MIN;
        for i in 0..4 {
            assert!(e.observe(a, BanReason::SshBruteForce, t + i).is_none());
        }
        let d = e.observe(a, BanReason::SshBruteForce, t + 5).unwrap();
        assert_eq!((d.duration_s, d.strikes, d.replace), (3_600, 1, false));
        assert_eq!(
            d.key,
            BanKey {
                addr: a,
                prefix: 32
            }
        );
        // While banned, more failures change nothing.
        assert!(e.observe(a, BanReason::SshBruteForce, t + 6).is_none());
        let mut offence = |at: u64| {
            (0..5)
                .find_map(|i| e.observe(a, BanReason::SshBruteForce, at + i))
                .unwrap()
        };
        t += 2 * 3_600_000;
        assert_eq!(offence(t).duration_s, 86_400);
        t += 2 * DAY_MS;
        assert_eq!(offence(t).duration_s, 7 * 86_400);
        t += 8 * DAY_MS;
        assert_eq!(offence(t).duration_s, 7 * 86_400); // last step repeats
        t += 60 * DAY_MS;
        let d = offence(t);
        assert_eq!((d.duration_s, d.strikes), (3_600, 1)); // forgiven after 30 days
    }

    #[test]
    fn ipv6_slash64_and_exemptions() {
        let mut cfg = default_config();
        cfg.threshold = 2;
        cfg.exempt = vec![Cidr::new(ip("10.0.0.0"), 8).unwrap()];
        let mut e = BanEngine::new(cfg);
        let now = 5 * DAY_MS;
        // Two different hosts in one /64 add up.
        assert!(
            e.observe(ip("2001:db8:1:2::1"), BanReason::SshBruteForce, now)
                .is_none()
        );
        let d = e
            .observe(ip("2001:db8:1:2:ffff::9"), BanReason::SshBruteForce, now)
            .unwrap();
        assert_eq!(
            d.key,
            BanKey {
                addr: ip("2001:db8:1:2::"),
                prefix: 64
            }
        );
        assert_eq!(
            ban_args(&d),
            [
                "add",
                "element",
                "inet",
                "fleet",
                "banned6",
                "{",
                "2001:db8:1:2::/64",
                "timeout",
                "3600s",
                "}"
            ]
        );
        for x in ["10.1.2.3", "127.0.0.1", "::1", "::ffff:10.9.9.9"] {
            for _ in 0..5 {
                assert!(
                    e.observe(ip(x), BanReason::SshBruteForce, now).is_none(),
                    "{x}"
                );
            }
        }
        // Learned Mac: exempt for 7 days after the last login.
        let mac = ip("203.0.113.50");
        assert_eq!(e.learn(mac, now), Some(false));
        assert_eq!(e.learn(mac, now + 1), Some(true));
        assert_eq!(e.learn(ip("10.3.3.3"), now), None);
        assert!(e.is_exempt(mac, now + LEARNED_TTL_MS));
        assert!(!e.is_exempt(mac, now + 1 + LEARNED_TTL_MS));
        assert_eq!(e.snapshot(now).learned_exempt, [mac]);
        assert!(e.manual(mac, 3_600, now).is_err());
        assert!(e.manual(ip("192.0.2.1"), 59, now).is_err());
        // Web scanners can be turned off.
        let mut c = e.config().clone();
        c.web_scanners = false;
        e.set_config(c);
        for _ in 0..5 {
            assert!(
                e.observe(ip("192.0.2.9"), BanReason::WebScanner, now)
                    .is_none()
            );
        }
    }

    #[test]
    fn nft_argv_shapes() {
        let d = Decision {
            key: ban_key(ip("192.0.2.1")),
            duration_s: 60,
            until_ms: 0,
            reason: BanReason::Manual,
            strikes: 0,
            replace: true,
        };
        assert_eq!(
            ban_args(&d).join(" "),
            "delete element inet fleet banned4 { 192.0.2.1 } ; add element inet fleet banned4 { 192.0.2.1 timeout 60s }"
        );
        assert_eq!(
            unban_args(&d.key).join(" "),
            "delete element inet fleet banned4 { 192.0.2.1 }"
        );
        assert_eq!(
            exempt_args(&Cidr::new(ip("10.0.0.0"), 8).unwrap(), true).join(" "),
            "add element inet fleet exempt4 { 10.0.0.0/8 }"
        );
        assert_eq!(
            learned_args(ip("::ffff:203.0.113.5"), false).join(" "),
            "add element inet fleet exempt4 { 203.0.113.5 timeout 604800s }"
        );
    }

    fn argv(v: Vec<String>) -> Vec<&'static str> {
        v.into_iter()
            .map(|s| &*Box::leak(s.into_boxed_str()))
            .collect()
    }

    #[test]
    fn service_and_handlers() {
        let runner = Rc::new(FakeRunner::new());
        let sink = Rc::new(VecSink::default());
        let mut cfg = default_config();
        cfg.threshold = 2;
        let svc = BanService::new(cfg, sink.clone());
        let dir = tempfile::tempdir().unwrap();
        let c = ctx_at(dir.path(), runner.clone(), T0);
        let now = meta_at(Op::SystemInfo, Some(1), T0).now_ms;

        // Detector path: two failures → nft add → event.
        let ev = parse_sshd("Failed password for root from 198.51.100.7 port 1 ssh2").unwrap();
        let d0 = Decision {
            key: ban_key(ip("198.51.100.7")),
            duration_s: 3_600,
            until_ms: 0,
            reason: BanReason::SshBruteForce,
            strikes: 1,
            replace: false,
        };
        runner.expect(NFT, &argv(ban_args(&d0)), Ok(CommandOutput::ok("")));
        assert!(block(svc.observe_auth(&c, &ev, now)).unwrap().is_none());
        let d = block(svc.observe_auth(&c, &ev, now)).unwrap().unwrap();
        assert_eq!(d.until_ms, now + 3_600_000);
        assert_eq!(sink.take().len(), 1);

        // nft failure rolls the ban back.
        let ev2 = parse_sshd("Invalid user x from 198.51.100.8 port 1").unwrap();
        let d1 = Decision {
            key: ban_key(ip("198.51.100.8")),
            ..d0
        };
        runner.expect(NFT, &argv(ban_args(&d1)), Ok(CommandOutput::exit(1)));
        assert!(block(svc.observe_auth(&c, &ev2, now)).unwrap().is_none());
        assert!(block(svc.observe_auth(&c, &ev2, now)).is_err());
        assert_eq!(svc.snapshot(now).bans.len(), 1);
        assert!(sink.take().is_empty());

        // Learned Mac via the trait.
        runner.expect(
            NFT,
            &argv(learned_args(ip("203.0.113.50"), false)),
            Ok(CommandOutput::ok("")),
        );
        block(svc.fleet_login(&c, ip("203.0.113.50"), now)).unwrap();

        let h = BansHandler(svc.clone());
        let m = meta_at(Op::SystemInfo, Some(1), T0);
        let add = Op::BansAdd {
            addr: ip("203.0.113.50"),
            duration_s: 600,
            comment: Label::new("").unwrap(),
        };
        assert_eq!(
            h.validate(&c, &add, &m).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
        let add = Op::BansAdd {
            addr: ip("192.0.2.77"),
            duration_s: 600,
            comment: Label::new("by hand").unwrap(),
        };
        h.validate(&c, &add, &m).unwrap();
        let dm = Decision {
            key: ban_key(ip("192.0.2.77")),
            duration_s: 600,
            until_ms: 0,
            reason: BanReason::Manual,
            strikes: 0,
            replace: false,
        };
        runner.expect(NFT, &argv(ban_args(&dm)), Ok(CommandOutput::ok("")));
        let OpOutput::Payload(Payload::Bans(b)) = block(h.handle(&c, &add, &m)).unwrap() else {
            panic!()
        };
        assert_eq!(b.bans.len(), 2);
        assert_eq!(b.learned_exempt, [ip("203.0.113.50")]);

        let rm = Op::BansRemove {
            addr: ip("192.0.2.77"),
        };
        runner.expect(NFT, &argv(unban_args(&dm.key)), Ok(CommandOutput::ok("")));
        let OpOutput::Payload(Payload::Bans(b)) = block(h.handle(&c, &rm, &m)).unwrap() else {
            panic!()
        };
        assert_eq!(b.bans.len(), 1);
        // Unknown and not in the kernel either.
        runner.expect(NFT, &argv(unban_args(&dm.key)), Ok(CommandOutput::exit(1)));
        assert_eq!(
            block(h.handle(&c, &rm, &m)).unwrap_err().code(),
            ErrorCode::NotFound
        );

        // Config round trip with exempt-set sync.
        let mut cfg = default_config();
        cfg.exempt = vec![Cidr::new(ip("10.0.0.0"), 8).unwrap()];
        let set = Op::BansConfigSet(cfg.clone());
        h.validate(&c, &set, &m).unwrap();
        runner.expect(
            NFT,
            &argv(exempt_args(&cfg.exempt[0], true)),
            Ok(CommandOutput::ok("")),
        );
        block(h.handle(&c, &set, &m)).unwrap();
        let OpOutput::Payload(Payload::BanConfig(got)) =
            block(h.handle(&c, &Op::BansConfigGet, &m)).unwrap()
        else {
            panic!()
        };
        assert_eq!(got, cfg);
        let mut bad = cfg;
        bad.threshold = 0;
        assert!(h.validate(&c, &Op::BansConfigSet(bad), &m).is_err());
        assert_eq!(runner.pending(), 0);
        let mut r = Registry::new();
        svc.register(&mut r);
        assert_eq!(r.tags().count(), 5);
    }

    #[test]
    fn export_import_round_trip_and_revalidation() {
        let t = 1_000_000_000;
        let mut e = BanEngine::new(default_config());
        let a = ip("198.51.100.7");
        let r0 = e.revision();
        let d = (0..5)
            .find_map(|i| e.observe(a, BanReason::SshBruteForce, t + i))
            .unwrap();
        assert!(e.revision() > r0);
        e.learn(ip("203.0.113.9"), t).unwrap();
        let st = e.export(t + 10);
        assert_eq!(st.bans.len(), 1);
        assert_eq!(st.strikes, vec![(a, 32, 1, d.until_ms - 3_600_000)]);
        let back: BanState = fleet_proto::decode(&fleet_proto::encode(&st)).unwrap();

        let mut f = BanEngine::new(default_config());
        f.import(back.clone(), t + 10);
        assert_eq!(f.export(t + 10), st);
        // The strike survived: the next offence escalates to 24 h.
        let later = t + 2 * 3_600_000;
        let d2 = (0..5)
            .find_map(|i| f.observe(a, BanReason::SshBruteForce, later + i))
            .unwrap();
        assert_eq!(d2.duration_s, 86_400);
        assert!(f.is_exempt(ip("203.0.113.9"), later));

        // Expired and non-canonical entries are dropped on import.
        let mut bad = back;
        bad.bans[0].prefix = 24;
        bad.strikes.push((ip("127.0.0.1"), 32, 3, t));
        bad.learned.push((ip("::ffff:192.0.2.1"), t));
        bad.config.threshold = 0;
        let mut g = BanEngine::new(default_config());
        g.import(bad, t + 10);
        let st = g.export(t + 10);
        assert!(st.bans.is_empty());
        assert_eq!(st.strikes.len(), 1);
        assert_eq!(st.learned, vec![(ip("203.0.113.9"), t)]);
        assert_eq!(st.config, default_config());
        let mut h = BanEngine::new(default_config());
        h.import(f.export(t), t + 8 * 86_400_000);
        assert!(h.export(t + 8 * 86_400_000).learned.is_empty());
    }

    #[test]
    fn nft_set_listing() {
        let empty = r#"{"nftables":[{"metainfo":{"version":"1.0.6"}},{"set":{"family":"inet","name":"banned4","table":"fleet","type":"ipv4_addr","handle":3,"flags":["interval","timeout"]}}]}"#;
        let full = r#"{"nftables":[{"metainfo":{}},{"set":{"name":"banned4","elem":[{"elem":{"val":"198.51.100.7","timeout":3600,"expires":3500}}]}}]}"#;
        assert_eq!(nft_set_is_empty(empty), Some(true));
        assert_eq!(nft_set_is_empty(full), Some(false));
        assert_eq!(nft_set_is_empty("{}"), None);
        assert_eq!(nft_set_is_empty("garbage"), None);
    }

    #[test]
    fn restore_kernel_only_fills_empty_sets() {
        let runner = Rc::new(FakeRunner::new());
        let dir = tempfile::tempdir().unwrap();
        let c = ctx_at(dir.path(), runner.clone(), T0);
        let now = T0;
        let svc = BanService::new(default_config(), Rc::new(VecSink::default()));
        let mut st = svc.export(now);
        st.bans.push(BanEntry {
            addr: ip("198.51.100.7"),
            prefix: 32,
            until_ms: now + 1_800_000,
            reason: BanReason::SshBruteForce,
            strikes: 1,
        });
        st.learned.push((ip("203.0.113.9"), now));
        svc.import(st, now);
        let list = |set: &'static str| ["-j", "list", "set", "inet", "fleet", set];
        let empty = r#"{"nftables":[{"set":{"name":"x"}}]}"#;
        let full = r#"{"nftables":[{"set":{"name":"x","elem":[1]}}]}"#;
        runner.expect(NFT, &list("banned4"), Ok(CommandOutput::ok(empty)));
        runner.expect(
            NFT,
            &argv(nft_add_args("banned4", "198.51.100.7", Some(1_800), false)),
            Ok(CommandOutput::ok("")),
        );
        // The kernel kept its exemptions: nothing re-added there.
        runner.expect(NFT, &list("exempt4"), Ok(CommandOutput::ok(full)));
        runner.expect(NFT, &list("banned6"), Ok(CommandOutput::exit(1)));
        runner.expect(NFT, &list("exempt6"), Ok(CommandOutput::ok(empty)));
        assert_eq!(block(svc.restore_kernel(&c, now)), 1);
        assert_eq!(runner.pending(), 0);
    }
}
