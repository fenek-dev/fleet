//! nft argv for the ban and exempt sets, and running it.

use super::{BanKey, Decision, LEARNED_TTL_MS, NFT, TABLE, learned_key};
use crate::ctx::SysCtx;
use crate::handler::OpError;
use crate::runner::CommandSpec;
use fleet_proto::args::Cidr;
use std::net::IpAddr;
use std::time::Duration;

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

pub(super) fn set_name(base: &str, addr: IpAddr) -> String {
    format!("{base}{}", if addr.is_ipv4() { 4 } else { 6 })
}

pub(super) fn element(addr: IpAddr, prefix: u8) -> String {
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

/// A learned Mac element (IPv4 address or IPv6 /64) with a full TTL.
pub fn learned_args(ip: IpAddr, replace: bool) -> Vec<String> {
    learned_key_args(&learned_key(ip), LEARNED_TTL_MS / 1000, replace)
}

pub(super) fn learned_key_args(key: &BanKey, timeout_s: u64, replace: bool) -> Vec<String> {
    nft_add_args(
        &set_name("exempt", key.addr),
        &element(key.addr, key.prefix),
        Some(timeout_s),
        replace,
    )
}

pub(super) fn unlearn_args(key: &BanKey) -> Vec<String> {
    nft_delete_args(
        &set_name("exempt", key.addr),
        &element(key.addr, key.prefix),
    )
}

pub(super) async fn run_nft(ctx: &SysCtx, args: Vec<String>) -> Result<(), OpError> {
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

/// `nft -j list set inet fleet <set>`: `Some(true)` if it has no elements,
/// `None` if it can't be listed.
pub(super) async fn set_empty(ctx: &SysCtx, set: &str) -> Option<bool> {
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

/// One step of a multi-command set change: `run`, undone by `undo` when a
/// later step fails. `required: false` steps may fail (deleting an element
/// that is already gone); a failed step has nothing to undo.
pub(super) struct Step {
    pub run: Vec<String>,
    pub undo: Vec<String>,
    pub required: bool,
}

/// Runs `steps` in order. When a required step fails, undoes the steps
/// that succeeded (reverse order, best effort) and returns the error.
pub(super) async fn run_steps(ctx: &SysCtx, steps: Vec<Step>) -> Result<(), OpError> {
    let mut done: Vec<Vec<String>> = Vec::new();
    for s in steps {
        match run_nft(ctx, s.run).await {
            Ok(()) => done.push(s.undo),
            Err(_) if !s.required => {}
            Err(e) => {
                for u in done.into_iter().rev() {
                    let _ = run_nft(ctx, u).await;
                }
                return Err(e);
            }
        }
    }
    Ok(())
}
