//! Snapshot → named series, and the series catalog (design §4.3).
//!
//! **Cap:** at most [`MAX_LIVE`] series per tick. Budgets per family keep
//! the total under it: CPU cores beyond [`MAX_CORE_GROUPS`] are averaged in
//! contiguous groups (`cpu.busy:0-3`); the busiest [`MAX_DEVICES`] disks and
//! interfaces are kept individually and the rest summed into `…:other`;
//! filesystems and sensors are cut at fixed counts (largest first).
//!
//! **Ids:** a series keeps its id across restarts (the catalog is persisted
//! with the metrics), so stored history stays attributable. An id whose
//! series hasn't been seen for longer than the retention can be reused once
//! [`MAX_KNOWN`] names exist.

use super::collect::{CpuPct, IoRate, Snapshot};
use fleet_proto::payload::{MetricSeries, MetricUnit};
use std::collections::HashMap;

/// Series per tick (design §4.3).
pub const MAX_LIVE: usize = 256;
pub const MAX_CORE_GROUPS: usize = 32;
pub const MAX_DEVICES: usize = 12;
pub const MAX_FS: usize = 16;
pub const MAX_TEMPS: usize = 16;
/// Names remembered (live or with history).
pub const MAX_KNOWN: usize = 4096;
/// An id unseen this long has no data left and may be reused.
pub const REUSE_AFTER_MS: u64 = 7 * 86_400_000 + 3_600_000;

/// One value of one tick, before id assignment.
#[derive(Debug, Clone, PartialEq)]
pub struct NamedValue {
    pub name: String,
    pub unit: MetricUnit,
    pub value: f32,
}

fn push(out: &mut Vec<NamedValue>, name: impl Into<String>, unit: MetricUnit, value: f32) {
    if value.is_finite() {
        out.push(NamedValue {
            name: name.into(),
            unit,
            value,
        });
    }
}

fn cpu_groups(cores: &[CpuPct]) -> Vec<(String, CpuPct)> {
    let n = cores.len();
    if n <= MAX_CORE_GROUPS {
        return cores
            .iter()
            .enumerate()
            .map(|(i, c)| (i.to_string(), *c))
            .collect();
    }
    let size = n.div_ceil(MAX_CORE_GROUPS);
    cores
        .chunks(size)
        .enumerate()
        .map(|(g, chunk)| {
            let k = chunk.len() as f32;
            let mut avg = CpuPct::default();
            for c in chunk {
                avg.user += c.user / k;
                avg.system += c.system / k;
                avg.iowait += c.iowait / k;
                avg.steal += c.steal / k;
                avg.idle += c.idle / k;
            }
            let first = g * size;
            (format!("{first}-{}", first + chunk.len() - 1), avg)
        })
        .collect()
}

fn devices(out: &mut Vec<NamedValue>, prefix: [&str; 2], rates: &[IoRate]) {
    use MetricUnit::BytesPerSec;
    for r in rates.iter().take(MAX_DEVICES) {
        push(
            out,
            format!("{}:{}", prefix[0], r.name),
            BytesPerSec,
            r.rx_bps,
        );
        push(
            out,
            format!("{}:{}", prefix[1], r.name),
            BytesPerSec,
            r.tx_bps,
        );
    }
    if rates.len() > MAX_DEVICES {
        let rest = &rates[MAX_DEVICES..];
        let rx = rest.iter().map(|r| r.rx_bps).sum();
        let tx = rest.iter().map(|r| r.tx_bps).sum();
        push(out, format!("{}:other", prefix[0]), BytesPerSec, rx);
        push(out, format!("{}:other", prefix[1]), BytesPerSec, tx);
    }
}

/// Every series of `s`, in a fixed order (fixed series first, so the cap
/// never drops them).
pub fn named_values(s: &Snapshot) -> Vec<NamedValue> {
    use MetricUnit::{Bytes, Celsius, Percent, Ratio};
    let mut out = Vec::with_capacity(64 + s.cores.len() * 3);
    if let Some(c) = &s.cpu {
        push(&mut out, "cpu.busy", Percent, c.busy());
        push(&mut out, "cpu.user", Percent, c.user);
        push(&mut out, "cpu.system", Percent, c.system);
        push(&mut out, "cpu.iowait", Percent, c.iowait);
        push(&mut out, "cpu.steal", Percent, c.steal);
    }
    if let Some(l) = s.load {
        push(&mut out, "load.1", Ratio, l[0]);
        push(&mut out, "load.5", Ratio, l[1]);
        push(&mut out, "load.15", Ratio, l[2]);
    }
    if let Some(m) = &s.mem {
        push(&mut out, "mem.total", Bytes, m.total as f32);
        push(&mut out, "mem.used", Bytes, m.used() as f32);
        push(&mut out, "mem.available", Bytes, m.available as f32);
        push(&mut out, "mem.cached", Bytes, m.cached as f32);
        push(&mut out, "swap.total", Bytes, m.swap_total as f32);
        push(&mut out, "swap.used", Bytes, m.swap_used() as f32);
    }
    for f in s.fs.iter().take(MAX_FS) {
        let st = &f.stat;
        push(
            &mut out,
            format!("disk.used:{}", f.mount),
            Percent,
            f.used_permille() as f32 / 10.0,
        );
        push(
            &mut out,
            format!("disk.free:{}", f.mount),
            Bytes,
            st.avail_bytes as f32,
        );
        if st.files > 0 {
            push(
                &mut out,
                format!("disk.inodes:{}", f.mount),
                Percent,
                f.inode_permille() as f32 / 10.0,
            );
        }
    }
    devices(&mut out, ["disk.read", "disk.write"], &s.disks);
    devices(&mut out, ["net.rx", "net.tx"], &s.nets);
    for (g, c) in cpu_groups(&s.cores) {
        push(&mut out, format!("cpu.busy:{g}"), Percent, c.busy());
        push(&mut out, format!("cpu.iowait:{g}"), Percent, c.iowait);
        push(&mut out, format!("cpu.steal:{g}"), Percent, c.steal);
    }
    for (name, t) in s.temps.iter().take(MAX_TEMPS) {
        push(&mut out, format!("temp:{name}"), Celsius, *t);
    }
    out
}

/// A known series and when it was last live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeriesEntry {
    pub series: MetricSeries,
    pub last_seen_ms: u64,
}

/// Name → id for every known series, plus the live set.
#[derive(Debug, Default)]
pub struct Catalog {
    known: Vec<SeriesEntry>,
    by_name: HashMap<String, usize>,
    live: Vec<u16>,
    /// Bumped whenever the live set changes.
    version: u64,
    /// Known set changed since [`Catalog::take_dirty`].
    dirty: bool,
}

impl Catalog {
    pub fn new(known: Vec<SeriesEntry>) -> Self {
        let mut c = Self::default();
        for e in known {
            if c.by_name.contains_key(&e.series.name)
                || c.known.iter().any(|k| k.series.id == e.series.id)
            {
                continue; // corrupt duplicate: first wins
            }
            c.by_name.insert(e.series.name.clone(), c.known.len());
            c.known.push(e);
        }
        c
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    /// Live series, in id order.
    pub fn live(&self) -> Vec<MetricSeries> {
        self.live
            .iter()
            .filter_map(|id| self.get(*id).cloned())
            .collect()
    }

    pub fn live_ids(&self) -> &[u16] {
        &self.live
    }

    pub fn get(&self, id: u16) -> Option<&MetricSeries> {
        self.known
            .iter()
            .find(|e| e.series.id == id)
            .map(|e| &e.series)
    }

    pub fn known(&self) -> &[SeriesEntry] {
        &self.known
    }

    /// Returns the known set if it changed since the last call.
    pub fn take_dirty(&mut self) -> Option<&[SeriesEntry]> {
        std::mem::take(&mut self.dirty).then_some(&self.known[..])
    }

    /// Marks every live series seen now (persisted with the next dirty save).
    pub fn touch(&mut self, now_ms: u64) {
        for id in &self.live {
            if let Some(e) = self.known.iter_mut().find(|e| e.series.id == *id) {
                e.last_seen_ms = now_ms;
            }
        }
        self.dirty = true;
    }

    fn allocate(&mut self, v: &NamedValue, now_ms: u64) -> Option<u16> {
        let entry = |id| SeriesEntry {
            series: MetricSeries {
                id,
                name: v.name.clone(),
                unit: v.unit,
            },
            last_seen_ms: now_ms,
        };
        if self.known.len() < MAX_KNOWN {
            let id = self
                .known
                .iter()
                .map(|e| e.series.id)
                .max()
                .map_or(Some(0), |m| m.checked_add(1))?;
            self.by_name.insert(v.name.clone(), self.known.len());
            self.known.push(entry(id));
            return Some(id);
        }
        // Reuse the stalest expired id.
        let idx = self
            .known
            .iter()
            .enumerate()
            .filter(|(_, e)| now_ms.saturating_sub(e.last_seen_ms) > REUSE_AFTER_MS)
            .min_by_key(|(_, e)| e.last_seen_ms)
            .map(|(i, _)| i)?;
        let id = self.known[idx].series.id;
        self.by_name.remove(&self.known[idx].series.name);
        self.known[idx] = entry(id);
        self.by_name.insert(v.name.clone(), idx);
        Some(id)
    }

    /// Ids for this tick's values (sorted by id); values beyond the cap or
    /// without an id are dropped. A unit change keeps the id.
    pub fn resolve(&mut self, values: &[NamedValue], now_ms: u64) -> Vec<(u16, f32)> {
        let mut out = Vec::with_capacity(values.len().min(MAX_LIVE));
        for v in values {
            if out.len() >= MAX_LIVE {
                break;
            }
            let id = match self.by_name.get(&v.name) {
                Some(&i) => {
                    let e = &mut self.known[i];
                    if e.series.unit != v.unit {
                        e.series.unit = v.unit;
                        self.dirty = true;
                    }
                    Some(e.series.id)
                }
                None => {
                    let id = self.allocate(v, now_ms);
                    self.dirty |= id.is_some();
                    id
                }
            };
            if let Some(id) = id {
                out.push((id, v.value));
            }
        }
        out.sort_by_key(|(id, _)| *id);
        out.dedup_by_key(|(id, _)| *id);
        if out.len() != self.live.len() || out.iter().zip(&self.live).any(|((a, _), b)| a != b) {
            self.live = out.iter().map(|(id, _)| *id).collect();
            self.version += 1;
            // New live members must not look expired.
            for id in &self.live {
                if let Some(e) = self.known.iter_mut().find(|e| e.series.id == *id) {
                    e.last_seen_ms = e.last_seen_ms.max(now_ms);
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::collect::{FsStat, FsUsage};

    fn rate(name: &str, total: u64) -> IoRate {
        IoRate {
            name: name.into(),
            rx_bps: 1.0,
            tx_bps: 2.0,
            total,
        }
    }

    fn big_snapshot() -> Snapshot {
        let core = CpuPct {
            user: 10.0,
            system: 5.0,
            iowait: 1.0,
            steal: 0.5,
            idle: 83.5,
        };
        Snapshot {
            time_ms: 0,
            cpu: Some(core),
            cores: vec![core; 256],
            ncpu: 256,
            mem: Some(Default::default()),
            load: Some([1.0, 2.0, 3.0]),
            disks: (0..40).map(|i| rate(&format!("sd{i}"), 100 - i)).collect(),
            nets: (0..300)
                .map(|i| rate(&format!("veth{i}"), 1000 - i))
                .collect(),
            fs: (0..40)
                .map(|i| FsUsage {
                    mount: format!("/m{i}"),
                    stat: FsStat {
                        total_bytes: 10,
                        avail_bytes: 5,
                        used_bytes: 5,
                        files: 10,
                        files_free: 1,
                    },
                })
                .collect(),
            temps: (0..40).map(|i| (format!("t{i}"), 40.0)).collect(),
        }
    }

    #[test]
    fn cap_and_aggregation() {
        let v = named_values(&big_snapshot());
        assert!(v.len() <= MAX_LIVE, "{}", v.len());
        let has = |n: &str| v.iter().any(|x| x.name == n);
        assert!(has("cpu.steal") && has("load.5") && has("mem.used"));
        assert!(has("net.rx:other") && has("disk.write:other"));
        assert!(has("net.rx:veth0") && !has("net.rx:veth12"));
        assert!(has("cpu.busy:0-7") && has("cpu.steal:248-255"));
        assert!(!has("cpu.busy:0"));
        let other = v.iter().find(|x| x.name == "net.rx:other").unwrap();
        assert_eq!(other.value, 288.0);
        assert!(has("disk.used:/m15") && !has("disk.used:/m16"));
    }

    #[test]
    fn ids_stable_and_persisted() {
        let v = named_values(&big_snapshot());
        let mut c = Catalog::new(Vec::new());
        let ids = c.resolve(&v, 1);
        assert_eq!(c.version(), 1);
        let saved = c.take_dirty().unwrap().to_vec();
        assert!(c.take_dirty().is_none());
        // Same tick again: no change.
        assert_eq!(c.resolve(&v, 2), ids);
        assert_eq!(c.version(), 1);
        // Restart: same ids.
        let mut c2 = Catalog::new(saved);
        assert_eq!(c2.resolve(&v, 3), ids);
        assert!(c2.take_dirty().is_none());
        // A series disappears: live set changes, id stays reserved.
        let fewer: Vec<_> = v.iter().skip(1).cloned().collect();
        c2.resolve(&fewer, 4);
        assert_eq!(c2.version(), 2);
        assert_eq!(c2.live_ids().len(), ids.len() - 1);
        assert!(c2.get(ids[0].0).is_some());
    }

    #[test]
    fn full_catalog_reuses_expired_ids() {
        let known = (0..MAX_KNOWN as u16)
            .map(|i| SeriesEntry {
                series: MetricSeries {
                    id: i,
                    name: format!("s{i}"),
                    unit: MetricUnit::Count,
                },
                last_seen_ms: if i == 7 { 0 } else { REUSE_AFTER_MS * 2 },
            })
            .collect();
        let mut c = Catalog::new(known);
        let v = |n: &str| NamedValue {
            name: n.into(),
            unit: MetricUnit::Count,
            value: 1.0,
        };
        let now = REUSE_AFTER_MS * 2;
        assert_eq!(c.resolve(&[v("new")], now), [(7, 1.0)]);
        assert!(c.get(7).is_some_and(|s| s.name == "new"));
        // Nothing else expired: a further new name gets no id.
        assert_eq!(c.resolve(&[v("new"), v("newer")], now), [(7, 1.0)]);
    }
}
