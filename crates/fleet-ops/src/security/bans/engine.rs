//! [`BanEngine`]: the pure ban state machine and its persisted form.

use super::{
    BanKey, LEARNED_TTL_MS, MAX_MANUAL_S, MAX_TRACKED, STRIKE_MEMORY_MS, ban_key, canonical,
    learned_key, never_bannable,
};
use fleet_proto::ErrorCode;
use fleet_proto::args::Cidr;
use fleet_proto::op::BanConfig;
use fleet_proto::payload::{BanEntry, BanReason, Bans};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::IpAddr;

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

/// Kernel changes a new exempt config needs, in order: delete learned
/// elements the added ranges cover, delete removed ranges, add added
/// ranges, re-add learned elements the removed ranges covered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExemptPlan {
    /// Learned keys with their remaining timeout (seconds).
    pub unlearn: Vec<(BanKey, u64)>,
    pub removed: Vec<Cidr>,
    pub added: Vec<Cidr>,
    pub relearn: Vec<(BanKey, u64)>,
}

pub struct BanEngine {
    config: BanConfig,
    failures: HashMap<BanKey, VecDeque<u64>>,
    /// Offence count and time of the last offence.
    strikes: HashMap<BanKey, (u16, u64)>,
    bans: BTreeMap<BanKey, BanEntry>,
    /// Learned Mac key ([`learned_key`]) → last successful Fleet login.
    /// Kept even when a configured range covers it (see `learn`).
    learned: HashMap<IpAddr, u64>,
    /// Bumped by every change worth persisting ([`BanEngine::revision`]).
    rev: u64,
}

/// Whether `range` shares an address with the learned `key`.
fn overlaps(range: &Cidr, key: &BanKey) -> bool {
    range.contains(key.addr) || (range.prefix() >= key.prefix && ban_key(range.addr()) == *key)
}

fn key_of(addr: IpAddr) -> BanKey {
    learned_key(addr)
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
    /// Callers with a kernel apply [`BanEngine::plan_config`] first.
    pub fn set_config(&mut self, config: BanConfig) -> (Vec<Cidr>, Vec<Cidr>) {
        let (removed, added) = diff(&self.config.exempt, &config.exempt);
        self.config = config;
        self.rev += 1;
        (removed, added)
    }

    /// The kernel changes switching to `new` needs (nothing is changed).
    pub fn plan_config(&self, new: &BanConfig, now_ms: u64) -> ExemptPlan {
        let (removed, added) = diff(&self.config.exempt, &new.exempt);
        let mut plan = ExemptPlan {
            removed,
            added,
            ..ExemptPlan::default()
        };
        for (key, left_s) in self.learned_left(now_ms) {
            let old = self.config.exempt.iter().any(|c| overlaps(c, &key));
            let new = new.exempt.iter().any(|c| overlaps(c, &key));
            match (old, new) {
                (false, true) => plan.unlearn.push((key, left_s)),
                (true, false) => plan.relearn.push((key, left_s)),
                _ => {}
            }
        }
        plan
    }

    /// Active learned keys with their remaining time in seconds, sorted.
    fn learned_left(&self, now_ms: u64) -> Vec<(BanKey, u64)> {
        let mut v: Vec<(BanKey, u64)> = self
            .learned
            .iter()
            .filter(|(_, t)| now_ms < t.saturating_add(LEARNED_TTL_MS))
            .map(|(a, t)| {
                let left = t.saturating_add(LEARNED_TTL_MS).saturating_sub(now_ms);
                (key_of(*a), left.div_ceil(1000).max(1))
            })
            .collect();
        v.sort();
        v
    }

    /// Active learned keys that need their own exempt-set element (no
    /// configured range overlaps them), with the remaining seconds.
    pub fn learned_elements(&self, now_ms: u64) -> Vec<(BanKey, u64)> {
        let mut v = self.learned_left(now_ms);
        v.retain(|(k, _)| !self.covered(k));
        v
    }

    fn covered(&self, key: &BanKey) -> bool {
        self.config.exempt.iter().any(|c| overlaps(c, key))
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
                .get(&key_of(ip).addr)
                .is_some_and(|t| now_ms < t.saturating_add(LEARNED_TTL_MS))
    }

    /// Records a successful Fleet login from `ip` (learned as
    /// [`learned_key`]). Returns whether the key needs an exempt-set
    /// element (`Some(replace)`), or `None` when a configured range
    /// overlaps it (an overlapping element would conflict in an interval
    /// set; the address is remembered anyway) or it is never bannable.
    pub fn learn(&mut self, ip: IpAddr, now_ms: u64) -> Option<bool> {
        let ip = canonical(ip);
        if never_bannable(ip) {
            return None;
        }
        let key = key_of(ip);
        if self.learned.len() >= MAX_TRACKED && !self.learned.contains_key(&key.addr) {
            self.learned
                .retain(|_, t| now_ms < t.saturating_add(LEARNED_TTL_MS));
            if self.learned.len() >= MAX_TRACKED {
                return None;
            }
        }
        let prev = self.learned.insert(key.addr, now_ms);
        self.rev += 1;
        if self.covered(&key) {
            return None;
        }
        Some(prev.is_some_and(|t| now_ms < t.saturating_add(LEARNED_TTL_MS)))
    }

    /// Undo of a first `learn` whose nft update failed.
    pub(super) fn unlearn(&mut self, key: &BanKey) {
        self.rev += 1;
        self.learned.remove(&key.addr);
    }

    /// Active learned keys (IPv4 addresses, IPv6 /64 network addresses).
    pub fn learned(&self, now_ms: u64) -> Vec<IpAddr> {
        self.learned_left(now_ms)
            .into_iter()
            .map(|(k, _)| k.addr)
            .collect()
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
        self.observe_capped(ip, reason, now_ms, None)
    }

    /// [`BanEngine::observe`] with the ban step capped at `cap_s` (web
    /// sources, see [`super::WebBanSource`]).
    pub fn observe_capped(
        &mut self,
        ip: IpAddr,
        reason: BanReason,
        now_ms: u64,
        cap_s: Option<u32>,
    ) -> Option<Decision> {
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
        let d = cap_s.map_or(self.step_s(strikes), |c| self.step_s(strikes).min(c));
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
    pub(super) fn forget_ban(&mut self, key: &BanKey) {
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
    /// be canonical ban/learned keys, expired entries are dropped, sizes
    /// bounded; an invalid config (including overlapping exempt ranges)
    /// falls back to the current one.
    pub fn import(&mut self, st: BanState, now_ms: u64) {
        if st.config.validate().is_ok() && super::validate_exempt(&st.config.exempt).is_ok() {
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
                key_of(*ip).addr == *ip
                    && !never_bannable(*ip)
                    && now_ms < t.saturating_add(LEARNED_TTL_MS)
            })
            .take(MAX_TRACKED)
            .collect();
        self.failures.clear();
        self.rev += 1;
    }
}

fn diff(old: &[Cidr], new: &[Cidr]) -> (Vec<Cidr>, Vec<Cidr>) {
    let removed = old.iter().filter(|c| !new.contains(c)).copied().collect();
    let added = new.iter().filter(|c| !old.contains(c)).copied().collect();
    (removed, added)
}

/// Persisted form of a [`BanEngine`] (exec's redb, design §4.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BanState {
    pub config: BanConfig,
    pub bans: Vec<BanEntry>,
    /// `(addr, prefix, offences, last offence ms)`.
    pub strikes: Vec<(IpAddr, u8, u16, u64)>,
    /// `(learned key address, last Fleet login ms)`: an IPv4 address or
    /// the network address of an IPv6 /64.
    pub learned: Vec<(IpAddr, u64)>,
}
