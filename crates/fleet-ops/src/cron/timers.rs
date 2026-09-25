//! `timers.list` through `systemctl` (read-only):
//!
//! 1. `systemctl list-timers --all --output=json` for units and next/last
//!    trigger times (systemd ≥ 251, Debian 12). If that fails or doesn't
//!    parse (Ubuntu 22.04 has 249), names come from
//!    `systemctl list-units --type=timer --all --plain --no-legend` and
//!    times stay unknown.
//! 2. `systemctl show -p Id,Unit,TimersCalendar,TimersMonotonic -- <timers>`
//!    for the schedule and the activated unit.
//!
//! Unit names read back from systemd are checked (`*.timer`, unit-name
//! characters) before they go into an argument vector.

use crate::ctx::SysCtx;
use crate::handler::OpError;
use crate::runner::CommandSpec;
use fleet_proto::payload::{TimerInfo, Timers};
use std::collections::BTreeMap;

pub const SYSTEMCTL: &str = "/usr/bin/systemctl";
const MAX_TIMERS: usize = 512;

pub fn list_timers_cmd() -> CommandSpec {
    CommandSpec::new(SYSTEMCTL).args(["list-timers", "--all", "--no-pager", "--output=json"])
}

pub fn list_units_cmd() -> CommandSpec {
    CommandSpec::new(SYSTEMCTL).args([
        "list-units",
        "--type=timer",
        "--all",
        "--plain",
        "--no-legend",
        "--no-pager",
    ])
}

pub fn show_cmd(units: &[String]) -> CommandSpec {
    CommandSpec::new(SYSTEMCTL)
        .args([
            "show",
            "--no-pager",
            "--property=Id,Unit,TimersCalendar,TimersMonotonic",
            "--",
        ])
        .args(units.iter().cloned())
}

fn timer_name_ok(s: &str) -> bool {
    s.len() <= 256
        && s.ends_with(".timer")
        && !s.starts_with('-')
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"@._-:\\".contains(&c))
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Times {
    pub activates: Option<String>,
    pub next_ms: Option<u64>,
    pub last_ms: Option<u64>,
}

fn usec_ms(v: &serde_json::Value) -> Option<u64> {
    v.as_u64().filter(|&u| u > 0).map(|u| u / 1000)
}

/// `list-timers --output=json`: `[{"next":µs,"last":µs,"unit":…,"activates":…}]`.
pub fn parse_list_timers(json: &[u8]) -> Option<BTreeMap<String, Times>> {
    let v: serde_json::Value = serde_json::from_slice(json).ok()?;
    let mut out = BTreeMap::new();
    for t in v.as_array()? {
        let Some(unit) = t
            .get("unit")
            .and_then(|u| u.as_str())
            .filter(|u| timer_name_ok(u))
        else {
            continue;
        };
        out.insert(
            unit.to_owned(),
            Times {
                activates: t
                    .get("activates")
                    .and_then(|a| a.as_str())
                    .map(str::to_owned),
                next_ms: t.get("next").and_then(usec_ms),
                last_ms: t.get("last").and_then(usec_ms),
            },
        );
    }
    Some(out)
}

/// `list-units --plain --no-legend`: first column.
pub fn parse_list_units(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|u| timer_name_ok(u))
        .map(str::to_owned)
        .collect()
}

/// `{ OnCalendar=*-*-* 06:00:00 ; next_elapse=… }` → `OnCalendar=*-*-* 06:00:00`
/// (several entries joined with `; `).
fn schedule_of(prop: &str) -> Vec<String> {
    prop.split('{')
        .filter_map(|chunk| {
            let body = chunk.split('}').next()?.trim();
            let first = body.split(" ; ").next()?.trim();
            (!first.is_empty()).then(|| first.to_owned())
        })
        .collect()
}

/// `systemctl show` blocks (blank-line separated) → per-Id
/// `(unit, schedule)`.
pub fn parse_show(text: &str) -> BTreeMap<String, (Option<String>, String)> {
    let mut out = BTreeMap::new();
    for block in text.split("\n\n") {
        let mut id = None;
        let mut unit = None;
        let mut sched = Vec::new();
        for l in block.lines() {
            match l.split_once('=') {
                Some(("Id", v)) => id = Some(v.to_owned()),
                Some(("Unit", v)) if !v.is_empty() => unit = Some(v.to_owned()),
                Some(("TimersCalendar" | "TimersMonotonic", v)) => sched.extend(schedule_of(v)),
                _ => {}
            }
        }
        if let Some(id) = id {
            out.insert(id, (unit, sched.join("; ")));
        }
    }
    out
}

fn clip(s: &str) -> String {
    s.chars().take(512).collect()
}

/// `timers.list`.
pub async fn list(ctx: &SysCtx) -> Result<Timers, OpError> {
    let json = ctx.runner.run(list_timers_cmd()).await?;
    let mut times = if json.success() {
        parse_list_timers(&json.stdout)
    } else {
        None
    };
    if times.is_none() {
        let out = ctx.runner.run(list_units_cmd()).await?;
        if !out.success() {
            return Err(OpError::internal(format!("systemctl exit {:?}", out.code)));
        }
        times = Some(
            parse_list_units(&String::from_utf8_lossy(&out.stdout))
                .into_iter()
                .map(|u| (u, Times::default()))
                .collect(),
        );
    }
    let times = times.unwrap_or_default();
    let units: Vec<String> = times.keys().take(MAX_TIMERS).cloned().collect();
    let show = if units.is_empty() {
        BTreeMap::new()
    } else {
        let out = ctx.runner.run(show_cmd(&units)).await?;
        parse_show(&String::from_utf8_lossy(&out.stdout))
    };
    let timers = units
        .iter()
        .map(|u| {
            let t = &times[u];
            let (unit, schedule) = show.get(u).cloned().unwrap_or_default();
            TimerInfo {
                unit: clip(u),
                activates: clip(&t.activates.clone().or(unit).unwrap_or_default()),
                schedule: clip(&schedule),
                next_ms: t.next_ms,
                last_ms: t.last_ms,
            }
        })
        .collect();
    Ok(Timers { timers })
}
