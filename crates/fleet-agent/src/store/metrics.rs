//! Metrics tables (design §4.4) behind `fleet_ops::telemetry::MetricsStore`.
//!
//! | Table | Key | Value |
//! |---|---|---|
//! | `metrics_raw` | frame time (ms) | varint count, then (id delta varint, f32 LE) per value |
//! | `metrics_1m` | (hour index, series id) | one hour block: 60-bit minute bitmap, then min/avg/max per present minute as zigzag-varint deltas of `value × 100` |
//! | `top_procs` | minute start (ms) | `postcard(TopProcessMinute)` |
//! | `telemetry_meta` | `"series"` / `"alert_rules"` | postcard series catalog / `AlertRuleSet` |
//!
//! Writes come in one transaction per flush (once a minute): raw frames,
//! the minute's rollups merged into their hour blocks, top processes and
//! a changed catalog together. zstd isn't a dependency, so blocks use
//! plain delta + varint coding (~2–3 bytes per value for smooth series).
//!
//! **Disk bound** (256 series, worst case): raw 1 h at 1 s ≈ 3600 × 256 ×
//! 5 B ≈ 4.6 MB; rollups 168 h × 256 blocks × ≤ 1.1 KB ≈ 20–45 MB (typical
//! ≈ 15 MB, most series are flat); top processes 10 080 minutes × ≤ 1 KB ≈
//! 7 MB. Within the 64 MB budget before redb page overhead; free pages are
//! reused after hourly pruning (no compaction while exec runs).

use super::StoreError;
use fleet_ops::telemetry::series::SeriesEntry;
use fleet_ops::telemetry::store::{RAW_RETENTION_MS, ROLLUP_RETENTION_MS, RawVisitor};
use fleet_ops::telemetry::{Batch, MetricsStore, Rollup, StoreResult};
use fleet_proto::alert::AlertRuleSet;
use fleet_proto::payload::{MetricSeries, MetricUnit, TopProcessMinute};
use redb::{ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction};
use std::collections::BTreeMap;

const RAW: TableDefinition<u64, &[u8]> = TableDefinition::new("metrics_raw");
const MINUTES: TableDefinition<(u32, u16), &[u8]> = TableDefinition::new("metrics_1m");
const TOP: TableDefinition<u64, &[u8]> = TableDefinition::new("top_procs");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("telemetry_meta");

const HOUR_MS: u64 = 3_600_000;
const MINUTE_MS: u64 = 60_000;

pub(super) fn create_tables(tx: &WriteTransaction) -> super::Result<()> {
    tx.open_table(RAW)?;
    tx.open_table(MINUTES)?;
    tx.open_table(TOP)?;
    tx.open_table(META)?;
    Ok(())
}

fn err(e: impl Into<StoreError>) -> String {
    e.into().to_string()
}

// ---- varint coding ----------------------------------------------------

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn get_varint(b: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *b.get(*pos)?;
        *pos += 1;
        v |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

fn zigzag(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

fn unzigzag(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

/// Fixed-point with 0.01 resolution (finer than f32 keeps above 10⁵).
fn quantize(v: f32) -> i64 {
    const LIMIT: f64 = 9.0e16;
    (f64::from(v) * 100.0).round().clamp(-LIMIT, LIMIT) as i64
}

fn dequantize(q: i64) -> f32 {
    (q as f64 / 100.0) as f32
}

// ---- raw frames -------------------------------------------------------

pub(crate) fn encode_frame(values: &[(u16, f32)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + values.len() * 6);
    put_varint(&mut out, values.len() as u64);
    let mut prev = 0u16;
    for &(id, v) in values {
        put_varint(&mut out, u64::from(id.wrapping_sub(prev)));
        out.extend_from_slice(&v.to_le_bytes());
        prev = id;
    }
    out
}

pub(crate) fn decode_frame(b: &[u8], out: &mut Vec<(u16, f32)>) -> Option<()> {
    out.clear();
    let mut pos = 0;
    let n = get_varint(b, &mut pos)?;
    if n > 65_536 {
        return None;
    }
    let mut id = 0u16;
    for _ in 0..n {
        let d = u16::try_from(get_varint(b, &mut pos)?).ok()?;
        id = id.wrapping_add(d);
        let v = f32::from_le_bytes(b.get(pos..pos + 4)?.try_into().ok()?);
        pos += 4;
        out.push((id, v));
    }
    (pos == b.len()).then_some(())
}

// ---- hour blocks ------------------------------------------------------

/// One series' hour: `[min, avg, max]` per minute.
pub(crate) type Block = [Option<[f32; 3]>; 60];

pub(crate) fn encode_block(block: &Block) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 60 * 3 * 2);
    let mut bitmap = 0u64;
    for (i, m) in block.iter().enumerate() {
        if m.is_some() {
            bitmap |= 1 << i;
        }
    }
    put_varint(&mut out, bitmap);
    let mut prev = [0i64; 3];
    for m in block.iter().flatten() {
        for (k, v) in m.iter().enumerate() {
            let q = quantize(*v);
            put_varint(&mut out, zigzag(q.wrapping_sub(prev[k])));
            prev[k] = q;
        }
    }
    out
}

pub(crate) fn decode_block(b: &[u8]) -> Option<Block> {
    let mut pos = 0;
    let bitmap = get_varint(b, &mut pos)?;
    if bitmap >> 60 != 0 {
        return None;
    }
    let mut block: Block = [None; 60];
    let mut prev = [0i64; 3];
    for (i, slot) in block.iter_mut().enumerate() {
        if bitmap & (1 << i) == 0 {
            continue;
        }
        let mut m = [0f32; 3];
        for (k, v) in m.iter_mut().enumerate() {
            prev[k] = prev[k].wrapping_add(unzigzag(get_varint(b, &mut pos)?));
            *v = dequantize(prev[k]);
        }
        *slot = Some(m);
    }
    (pos == b.len()).then_some(block)
}

// ---- catalog ----------------------------------------------------------

type StoredSeries = Vec<(String, u16, MetricUnit, u64)>;

/// The metrics view of exec's database. Owns a handle, so the sampler task
/// keeps it without borrowing exec's state.
#[derive(Clone)]
pub struct MetricsDb {
    db: super::Db,
}

impl MetricsDb {
    pub(super) fn new(db: super::Db) -> Self {
        Self { db }
    }

    fn db(&self) -> super::DbRead<'_> {
        super::read(&self.db)
    }

    fn meta_get(&self, key: &str) -> StoreResult<Option<Vec<u8>>> {
        let tx = self.db().begin_read().map_err(err)?;
        let t = tx.open_table(META).map_err(err)?;
        Ok(t.get(key).map_err(err)?.map(|v| v.value().to_vec()))
    }
}

impl MetricsStore for MetricsDb {
    fn load_catalog(&self) -> StoreResult<Vec<SeriesEntry>> {
        let Some(b) = self.meta_get("series")? else {
            return Ok(Vec::new());
        };
        let v: StoredSeries = fleet_proto::decode(&b).map_err(|e| e.to_string())?;
        Ok(v.into_iter()
            .map(|(name, id, unit, last_seen_ms)| SeriesEntry {
                series: MetricSeries { id, name, unit },
                last_seen_ms,
            })
            .collect())
    }

    fn load_rules(&self) -> StoreResult<Option<AlertRuleSet>> {
        self.meta_get("alert_rules")?
            .map(|b| fleet_proto::decode(&b).map_err(|e| e.to_string()))
            .transpose()
    }

    fn save_rules(&self, rules: &AlertRuleSet) -> StoreResult<()> {
        let tx = self.db().begin_write().map_err(err)?;
        tx.open_table(META)
            .map_err(err)?
            .insert("alert_rules", &fleet_proto::encode(rules)[..])
            .map_err(err)?;
        tx.commit().map_err(err)
    }

    fn write(&self, b: &Batch<'_>) -> StoreResult<()> {
        let tx = self.db().begin_write().map_err(err)?;
        {
            let mut raw = tx.open_table(RAW).map_err(err)?;
            for f in b.raw {
                raw.insert(f.time_ms, &encode_frame(&f.values)[..])
                    .map_err(err)?;
            }
            // Group the rollups by hour block, merge each block once.
            let mut blocks: BTreeMap<(u32, u16), Vec<(usize, &Rollup)>> = BTreeMap::new();
            for (minute_ms, rs) in b.minutes {
                let hour = u32::try_from(minute_ms / HOUR_MS).unwrap_or(u32::MAX);
                let slot = ((minute_ms % HOUR_MS) / MINUTE_MS) as usize;
                for r in rs {
                    blocks.entry((hour, r.id)).or_default().push((slot, r));
                }
            }
            let mut minutes = tx.open_table(MINUTES).map_err(err)?;
            for (key, rs) in blocks {
                let mut block = minutes
                    .get(key)
                    .map_err(err)?
                    .and_then(|v| decode_block(v.value()))
                    .unwrap_or([None; 60]);
                for (slot, r) in rs {
                    block[slot] = Some([r.min, r.avg, r.max]);
                }
                minutes
                    .insert(key, &encode_block(&block)[..])
                    .map_err(err)?;
            }
            let mut top = tx.open_table(TOP).map_err(err)?;
            for m in b.top {
                top.insert(m.time_ms, &fleet_proto::encode(m)[..])
                    .map_err(err)?;
            }
            if let Some(c) = b.catalog {
                let v: StoredSeries = c
                    .iter()
                    .map(|e| {
                        (
                            e.series.name.clone(),
                            e.series.id,
                            e.series.unit,
                            e.last_seen_ms,
                        )
                    })
                    .collect();
                tx.open_table(META)
                    .map_err(err)?
                    .insert("series", &fleet_proto::encode(&v)[..])
                    .map_err(err)?;
            }
        }
        tx.commit().map_err(err)
    }

    fn raw(&self, since_ms: u64, until_ms: u64, f: &mut RawVisitor<'_>) -> StoreResult<()> {
        if since_ms >= until_ms {
            return Ok(());
        }
        let tx = self.db().begin_read().map_err(err)?;
        let t = tx.open_table(RAW).map_err(err)?;
        let mut values = Vec::new();
        for row in t.range(since_ms..until_ms).map_err(err)? {
            let (k, v) = row.map_err(err)?;
            // A corrupt frame is skipped, not fatal.
            if decode_frame(v.value(), &mut values).is_some() {
                f(k.value(), &values);
            }
        }
        Ok(())
    }

    fn minutes(
        &self,
        since_ms: u64,
        until_ms: u64,
        ids: &[u16],
        f: &mut dyn FnMut(u64, Rollup),
    ) -> StoreResult<()> {
        if since_ms >= until_ms || ids.is_empty() {
            return Ok(());
        }
        let tx = self.db().begin_read().map_err(err)?;
        let t = tx.open_table(MINUTES).map_err(err)?;
        let first = u32::try_from(since_ms / HOUR_MS).unwrap_or(u32::MAX);
        let last = u32::try_from((until_ms - 1) / HOUR_MS).unwrap_or(u32::MAX);
        for row in t.range((first, 0)..=(last, u16::MAX)).map_err(err)? {
            let (k, v) = row.map_err(err)?;
            let (hour, id) = k.value();
            if ids.binary_search(&id).is_err() {
                continue;
            }
            let Some(block) = decode_block(v.value()) else {
                continue;
            };
            let base = u64::from(hour) * HOUR_MS;
            for (i, m) in block.iter().enumerate() {
                let t = base + i as u64 * MINUTE_MS;
                if let Some([min, avg, max]) = m
                    && (since_ms..until_ms).contains(&t)
                {
                    f(
                        t,
                        Rollup {
                            id,
                            min: *min,
                            avg: *avg,
                            max: *max,
                        },
                    );
                }
            }
        }
        Ok(())
    }

    fn top_procs(
        &self,
        since_ms: u64,
        until_ms: u64,
        limit: usize,
    ) -> StoreResult<Vec<TopProcessMinute>> {
        if since_ms >= until_ms {
            return Ok(Vec::new());
        }
        let tx = self.db().begin_read().map_err(err)?;
        let t = tx.open_table(TOP).map_err(err)?;
        let mut out = Vec::new();
        for row in t.range(since_ms..until_ms).map_err(err)?.rev() {
            if out.len() >= limit {
                break;
            }
            let (_, v) = row.map_err(err)?;
            if let Ok(m) = fleet_proto::decode::<TopProcessMinute>(v.value()) {
                out.push(m);
            }
        }
        out.reverse();
        Ok(out)
    }

    fn prune(&self, now_ms: u64) -> StoreResult<()> {
        let raw_cut = now_ms.saturating_sub(RAW_RETENTION_MS);
        let cut = now_ms.saturating_sub(ROLLUP_RETENTION_MS);
        let cut_hour = u32::try_from(cut / HOUR_MS).unwrap_or(u32::MAX);
        let tx = self.db().begin_write().map_err(err)?;
        {
            tx.open_table(RAW)
                .map_err(err)?
                .retain_in(..raw_cut, |_, _| false)
                .map_err(err)?;
            tx.open_table(MINUTES)
                .map_err(err)?
                .retain_in(..(cut_hour, 0), |_, _| false)
                .map_err(err)?;
            tx.open_table(TOP)
                .map_err(err)?
                .retain_in(..cut, |_, _| false)
                .map_err(err)?;
        }
        tx.commit().map_err(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_ops::telemetry::Frame;
    use fleet_proto::F32;
    use fleet_proto::payload::TopProcess;
    use proptest::prelude::*;
    use std::rc::Rc;

    fn db() -> (tempfile::TempDir, MetricsDb) {
        let d = tempfile::tempdir().unwrap();
        let s = super::super::Store::open(d.path().join("state.redb")).unwrap();
        let m = s.metrics();
        (d, m)
    }

    proptest! {
        #[test]
        fn frame_roundtrip(mut v in proptest::collection::vec((any::<u16>(), any::<f32>()), 0..300)) {
            v.sort_by_key(|x| x.0);
            v.dedup_by_key(|x| x.0);
            let mut out = Vec::new();
            decode_frame(&encode_frame(&v), &mut out).unwrap();
            prop_assert_eq!(
                out.iter().map(|(i, f)| (*i, f.to_bits())).collect::<Vec<_>>(),
                v.iter().map(|(i, f)| (*i, f.to_bits())).collect::<Vec<_>>()
            );
        }

        #[test]
        fn block_roundtrip(vals in proptest::collection::vec(proptest::option::of((-1e6f32..1e12, -1e6f32..1e12, -1e6f32..1e12)), 60)) {
            let mut b: Block = [None; 60];
            for (i, v) in vals.iter().enumerate() {
                b[i] = v.map(|(a, c, d)| [a, c, d]);
            }
            let back = decode_block(&encode_block(&b)).unwrap();
            for (x, y) in b.iter().zip(back.iter()) {
                prop_assert_eq!(x.is_some(), y.is_some());
                if let (Some(x), Some(y)) = (x, y) {
                    for k in 0..3 {
                        let tol = (x[k].abs() * 1e-6).max(0.006);
                        prop_assert!((x[k] - y[k]).abs() <= tol, "{} {}", x[k], y[k]);
                    }
                }
            }
        }

        #[test]
        fn decoders_never_panic(b in proptest::collection::vec(any::<u8>(), 0..200)) {
            let _ = decode_block(&b);
            let _ = decode_frame(&b, &mut Vec::new());
        }
    }

    #[test]
    fn smooth_block_is_compact() {
        let mut b: Block = [None; 60];
        for (i, m) in b.iter_mut().enumerate() {
            let v = 40.0 + (i % 5) as f32 * 0.25;
            *m = Some([v - 1.0, v, v + 1.0]);
        }
        let n = encode_block(&b).len();
        assert!(n < 60 * 3 * 2 + 10, "{n}");
    }

    #[test]
    fn write_query_prune() {
        let (_d, m) = db();
        let t0 = 1_700_000_000_000 / HOUR_MS * HOUR_MS;
        let frames: Vec<Rc<Frame>> = (0..6)
            .map(|i| {
                Rc::new(Frame {
                    time_ms: t0 + i * 10_000,
                    values: vec![(0, i as f32), (5, 1.5)],
                    catalog_version: 1,
                })
            })
            .collect();
        let roll = |id, v| Rollup {
            id,
            min: v - 1.0,
            avg: v,
            max: v + 1.0,
        };
        let minutes = vec![(t0, vec![roll(0, 2.5), roll(5, 1.5)])];
        let top = vec![TopProcessMinute {
            time_ms: t0,
            by_cpu: vec![TopProcess {
                pid: 42,
                name: "nginx".into(),
                cpu_pct: F32(12.5),
                rss_bytes: 1 << 20,
            }],
            by_memory: vec![],
        }];
        let catalog = vec![SeriesEntry {
            series: MetricSeries {
                id: 0,
                name: "cpu.busy".into(),
                unit: MetricUnit::Percent,
            },
            last_seen_ms: t0,
        }];
        m.write(&Batch {
            raw: &frames,
            minutes: &minutes,
            top: &top,
            catalog: Some(&catalog),
        })
        .unwrap();
        // A second flush merges into the same hour block.
        m.write(&Batch {
            minutes: &[(t0 + MINUTE_MS, vec![roll(0, 7.0)])],
            ..Batch::default()
        })
        .unwrap();

        let mut seen = Vec::new();
        m.raw(t0 + 10_000, t0 + 30_000, &mut |t, v| {
            seen.push((t, v.to_vec()))
        })
        .unwrap();
        assert_eq!(
            seen,
            [
                (t0 + 10_000, vec![(0, 1.0), (5, 1.5)]),
                (t0 + 20_000, vec![(0, 2.0), (5, 1.5)])
            ]
        );
        let mut rolls = Vec::new();
        m.minutes(t0, t0 + HOUR_MS, &[0], &mut |t, r| rolls.push((t, r)))
            .unwrap();
        assert_eq!(rolls, [(t0, roll(0, 2.5)), (t0 + MINUTE_MS, roll(0, 7.0))]);
        assert_eq!(m.top_procs(t0, t0 + 1, 10).unwrap(), top);
        assert_eq!(m.load_catalog().unwrap(), catalog);

        let rules = AlertRuleSet {
            version: 4,
            rules: vec![],
        };
        assert_eq!(m.load_rules().unwrap(), None);
        m.save_rules(&rules).unwrap();
        assert_eq!(m.load_rules().unwrap(), Some(rules));

        // One hour later raw is gone; rollups stay 7 days.
        m.prune(t0 + HOUR_MS + 60_000).unwrap();
        let mut n = 0;
        m.raw(0, u64::MAX, &mut |_, _| n += 1).unwrap();
        assert_eq!(n, 0);
        let mut n = 0;
        m.minutes(0, u64::MAX, &[0, 5], &mut |_, _| n += 1).unwrap();
        assert_eq!(n, 3);
        m.prune(t0 + ROLLUP_RETENTION_MS + 2 * HOUR_MS).unwrap();
        let mut n = 0;
        m.minutes(0, u64::MAX, &[0, 5], &mut |_, _| n += 1).unwrap();
        assert_eq!(n, 0);
        assert!(m.top_procs(0, u64::MAX, 10).unwrap().is_empty());
    }
}
