//! [`BanService`]: the engine plus nftables and event emission.

use super::nft::{
    Step, element, learned_key_args, nft_add_args, run_nft, run_steps, set_empty, set_name,
    unlearn_args,
};
use super::{BanEngine, BanState, BansHandler, Decision, WebBanSource, ban_args, exempt_args};
use crate::ctx::SysCtx;
use crate::handler::{LocalBoxFuture, OpError, Registry};
use crate::nftlock;
use crate::security::EventSink;
use crate::security::authlog::AuthEvent;
use fleet_proto::op::{BanConfig, tag};
use fleet_proto::payload::{BanReason, Bans};
use fleet_proto::{ErrorCode, Event};
use std::cell::RefCell;
use std::collections::HashSet;
use std::net::IpAddr;
use std::rc::Rc;

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
    pub(super) engine: RefCell<BanEngine>,
    pub(super) sink: Rc<dyn EventSink>,
    /// Access logs whose scanner hits may ban (opt-in, see `web`).
    pub(super) web_sources: RefCell<Vec<WebBanSource>>,
    /// The host's own addresses: never banned from web logs.
    pub(super) own_addrs: RefCell<HashSet<IpAddr>>,
    /// Checked (design §5.4) immediately before every kernel write that
    /// decides, applies or restores a ban or a learned exemption — never
    /// before a read-only `nft list` — with no `.await` between the check
    /// and the write. Exec is single-threaded, so that makes the check
    /// atomic against a concurrent `policy.update` switching to
    /// Agent-only: callers (`ssh::learn`, `pollers::poll_web`,
    /// `sources::spawn`) also check earlier as a fast path to skip work,
    /// but this is the check that actually guards the write.
    gate: Rc<dyn Fn() -> bool>,
}

impl BanService {
    /// `gate` always allowed (tests, or any caller that doesn't need
    /// Agent-only gating).
    pub fn new(config: BanConfig, sink: Rc<dyn EventSink>) -> Rc<Self> {
        Self::with_gate(config, sink, Rc::new(|| true))
    }

    pub fn with_gate(
        config: BanConfig,
        sink: Rc<dyn EventSink>,
        gate: Rc<dyn Fn() -> bool>,
    ) -> Rc<Self> {
        Rc::new(Self {
            engine: RefCell::new(BanEngine::new(config)),
            sink,
            web_sources: RefCell::new(Vec::new()),
            own_addrs: RefCell::new(HashSet::new()),
            gate,
        })
    }

    fn may_write(&self) -> bool {
        (self.gate)()
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

    pub(super) async fn apply(&self, ctx: &SysCtx, d: Decision) -> Result<Decision, OpError> {
        let res = {
            let _table = nftlock::lock().await;
            // No `.await` between this check and the write it guards.
            if self.may_write() {
                run_nft(ctx, ban_args(&d)).await
            } else {
                Err(ErrorCode::PolicyDenied.into())
            }
        };
        if let Err(e) = res {
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

    pub(super) async fn apply_opt(
        &self,
        ctx: &SysCtx,
        d: Option<Decision>,
    ) -> Result<Option<Decision>, OpError> {
        match d {
            Some(d) => self.apply(ctx, d).await.map(Some),
            None => Ok(None),
        }
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
        self.apply_opt(ctx, d).await
    }

    /// `bans.config.set`: applies the exempt-set changes to the kernel,
    /// then commits the config. Order: delete learned elements the new
    /// ranges cover, delete removed ranges, add new ranges, re-add learned
    /// elements the removed ranges covered. When a step fails, the steps
    /// done are undone (best effort) and the config stays as it was.
    pub async fn set_config(
        &self,
        ctx: &SysCtx,
        config: BanConfig,
        now_ms: u64,
    ) -> Result<(), OpError> {
        config
            .validate()
            .map_err(|e| OpError::from(ErrorCode::from(e)))?;
        super::validate_exempt(&config.exempt)?;
        let _table = nftlock::lock().await;
        if !self.may_write() {
            return Err(ErrorCode::PolicyDenied.into());
        }
        let plan = self.engine.borrow().plan_config(&config, now_ms);
        let mut steps = Vec::new();
        for (k, left) in &plan.unlearn {
            steps.push(Step {
                run: unlearn_args(k),
                undo: learned_key_args(k, *left, false),
                required: false,
            });
        }
        for r in &plan.removed {
            steps.push(Step {
                run: exempt_args(r, false),
                undo: exempt_args(r, true),
                required: false,
            });
        }
        for a in &plan.added {
            steps.push(Step {
                run: exempt_args(a, true),
                undo: exempt_args(a, false),
                required: true,
            });
        }
        for (k, left) in &plan.relearn {
            steps.push(Step {
                run: learned_key_args(k, *left, false),
                undo: unlearn_args(k),
                required: true,
            });
        }
        run_steps(ctx, steps).await?;
        self.engine.borrow_mut().set_config(config);
        Ok(())
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
    /// configured ranges and learned keys no range overlaps. A set that
    /// can't be listed (firewall table not set up yet) is skipped. Returns
    /// elements added.
    pub async fn restore_kernel(&self, ctx: &SysCtx, now_ms: u64) -> usize {
        let _table = nftlock::lock().await;
        let (bans, exempt, learned) = {
            let e = self.engine.borrow();
            (
                e.snapshot(now_ms).bans,
                e.config().exempt.clone(),
                e.learned_elements(now_ms),
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
                    // `&&` short-circuits: `run_nft` is never even awaited
                    // once `may_write()` is false, so there's no `.await`
                    // between the check and the write it guards.
                    added += usize::from(self.may_write() && run_nft(ctx, args).await.is_ok());
                }
            }
            if set_empty(ctx, &format!("exempt{n}")).await == Some(true) {
                for c in exempt.iter().filter(|c| fam(&c.addr())) {
                    added +=
                        usize::from(self.may_write() && run_nft(ctx, exempt_args(c, true)).await.is_ok());
                }
                for (k, left_s) in learned.iter().filter(|(k, _)| fam(&k.addr)) {
                    let args = learned_key_args(k, *left_s, false);
                    added += usize::from(self.may_write() && run_nft(ctx, args).await.is_ok());
                }
            }
        }
        added
    }
}

impl LearnedMacIps for BanService {
    fn fleet_login<'a>(
        &'a self,
        ctx: &'a SysCtx,
        ip: IpAddr,
        now_ms: u64,
    ) -> LocalBoxFuture<'a, Result<(), OpError>> {
        Box::pin(async move {
            let _table = nftlock::lock().await;
            let need = self.engine.borrow_mut().learn(ip, now_ms);
            let Some(replace) = need else {
                return Ok(());
            };
            let key = super::learned_key(ip);
            let ttl_s = super::LEARNED_TTL_MS / 1000;
            // No `.await` between this check and the write it guards.
            let res = if self.may_write() {
                run_nft(ctx, learned_key_args(&key, ttl_s, replace)).await
            } else {
                Err(ErrorCode::PolicyDenied.into())
            };
            if res.is_err() && !replace {
                // Not in the kernel: forget it, so the next login adds it
                // afresh instead of replacing a missing element.
                self.engine.borrow_mut().unlearn(&key);
            }
            res
        })
    }
}
