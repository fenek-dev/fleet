//! Fleet overview data (docs/ui-design.md Screens 1): per-server facts
//! for the table and summary cards (versions, uptime, package updates,
//! CPU sparkline), the health note shown in the Status column and the
//! "While you were away" digest.
//!
//! Everything derived here is plain data plus pure functions (tested);
//! server-provided text is already escaped by the row conversions.

use crate::api::FleetCore;
use crate::rows::{MetricsHistoryRow, UpgradableListRow};
use crate::timeline::{TimelineCategory, TimelineItemRow};
use crate::types::{AlertSeverity, FleetError};
use std::collections::BTreeSet;

/// Points in the CPU sparkline.
pub const SPARK_POINTS: usize = 30;
const HOUR_MS: u64 = 3_600_000;

/// What the fleet table knows about one server beyond live metrics.
/// A field is `None` / empty when its request failed (`error` says why
/// for the first failure).
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct FleetFactsRow {
    pub server_id: String,
    pub agent_version: Option<String>,
    pub kernel: Option<String>,
    pub uptime_s: Option<u64>,
    /// Upgradable packages; `None` when the list could not be read.
    pub updates: Option<u32>,
    pub security_updates: Option<u32>,
    pub reboot_required: bool,
    /// CPU busy %, oldest first, at most [`SPARK_POINTS`] points.
    pub cpu_spark: Vec<f32>,
    pub error: Option<String>,
}

/// Downsamples the `cpu.busy` average series to at most `points` values,
/// oldest first. Gaps (NaN) are dropped; a history without the series
/// gives an empty vector.
pub fn cpu_spark(h: &MetricsHistoryRow, points: usize) -> Vec<f32> {
    let Some(id) = h.catalog.iter().find(|s| s.name == "cpu.busy").map(|s| s.id) else {
        return Vec::new();
    };
    let Some(series) = h.series.iter().find(|s| s.id == id) else {
        return Vec::new();
    };
    let vals: Vec<f32> = series
        .avg
        .iter()
        .copied()
        .filter(|v| v.is_finite())
        .map(|v| v.clamp(0.0, 100.0))
        .collect();
    if points == 0 || vals.len() <= points {
        return vals;
    }
    // Mean of equal buckets.
    (0..points)
        .map(|i| {
            let a = i * vals.len() / points;
            let b = ((i + 1) * vals.len() / points).max(a + 1);
            vals[a..b].iter().sum::<f32>() / (b - a) as f32
        })
        .collect()
}

/// `(updates, security)` from an upgradable list.
pub fn update_counts(u: &UpgradableListRow) -> (u32, u32) {
    let sec = u.packages.iter().filter(|p| p.security).count();
    (u.packages.len() as u32, sec as u32)
}

#[uniffi::export]
impl FleetCore {
    /// Agent version, kernel, uptime, package updates and one hour of CPU
    /// for one connected server (the requests run concurrently; a failure
    /// leaves its fields empty and sets `error`).
    pub async fn fleet_facts(&self, server_id: String) -> Result<FleetFactsRow, FleetError> {
        let now = fleet_core::now_ms();
        let (health, info, upg, cpu) = tokio::join!(
            self.agent_health(server_id.clone()),
            self.system_info(server_id.clone()),
            self.pkg_upgradable(server_id.clone()),
            self.metrics_query(
                server_id.clone(),
                Some(now.saturating_sub(HOUR_MS)),
                None,
                true,
                Vec::new(),
            ),
        );
        let mut error = None;
        let mut note = |e: &FleetError| {
            if error.is_none() {
                error = Some(e.to_string());
            }
        };
        let health = health.map_err(|e| note(&e)).ok();
        let info = info.map_err(|e| note(&e)).ok();
        let upg = upg.map_err(|e| note(&e)).ok();
        let cpu = cpu.map_err(|e| note(&e)).ok();
        let counts = upg.as_ref().map(update_counts);
        Ok(FleetFactsRow {
            server_id,
            agent_version: health.as_ref().map(|h| h.agent_version.clone()),
            kernel: info.as_ref().map(|i| i.kernel.clone()),
            uptime_s: health
                .as_ref()
                .map(|h| h.uptime_s)
                .or(info.as_ref().map(|i| i.uptime_s)),
            updates: counts.map(|c| c.0),
            security_updates: counts.map(|c| c.1),
            reboot_required: upg.as_ref().is_some_and(|u| u.reboot_required),
            cpu_spark: cpu.map(|h| cpu_spark(&h, SPARK_POINTS)).unwrap_or_default(),
            error,
        })
    }
}

// ---- health note ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum NoteTone {
    Ok,
    Warn,
    Critical,
}

/// The line under a server's status pill.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HealthNoteRow {
    pub text: String,
    pub tone: NoteTone,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct HealthNoteInput {
    pub online: bool,
    pub disk_percent: Option<f32>,
    pub mem_percent: Option<f32>,
    /// Worst open alert: rule id, subject, severity.
    pub alert_rule: Option<String>,
    pub alert_subject: Option<String>,
    pub alert_severity: Option<AlertSeverity>,
}

/// Human wording for an alert rule id (rule ids are agent-defined tokens;
/// unknown ones are shown as-is).
pub fn alert_title(rule_id: &str, subject: &str) -> String {
    let on = |what: &str| {
        if subject.is_empty() {
            what.to_string()
        } else {
            format!("{what}: {subject}")
        }
    };
    match rule_id {
        r if r.starts_with("disk") => on("Disk usage high"),
        r if r.starts_with("memory") || r.starts_with("mem") => on("Memory usage high"),
        r if r.starts_with("cpu") => on("CPU usage high"),
        r if r.starts_with("load") => on("Load high"),
        r if r.starts_with("service") => on("Service down"),
        r if r.starts_with("container") => on("Container down"),
        r if r.starts_with("brute") => on("SSH brute force"),
        r if r.starts_with("cert") => on("Certificate expiring"),
        r if r.starts_with("reboot") => "Reboot required".into(),
        r if r.starts_with("security") => on("Security updates pending"),
        r => on(r),
    }
}

/// Picks the most important thing to say about a server. Offline servers
/// get no note (the UI shows the offline duration).
pub fn health_note(i: &HealthNoteInput) -> HealthNoteRow {
    let note = |text: String, tone| HealthNoteRow { text, tone };
    if !i.online {
        return note(String::new(), NoteTone::Ok);
    }
    if let (Some(rule), Some(sev)) = (&i.alert_rule, i.alert_severity)
        && sev != AlertSeverity::Info
    {
        let tone = if sev == AlertSeverity::Critical {
            NoteTone::Critical
        } else {
            NoteTone::Warn
        };
        return note(
            alert_title(rule, i.alert_subject.as_deref().unwrap_or("")),
            tone,
        );
    }
    if let Some(d) = i.disk_percent
        && d >= 85.0
    {
        let tone = if d >= 90.0 {
            NoteTone::Critical
        } else {
            NoteTone::Warn
        };
        return note(format!("Disk {}%", d.round() as u32), tone);
    }
    if let Some(m) = i.mem_percent
        && m >= 90.0
    {
        return note(format!("Memory {}%", m.round() as u32), NoteTone::Warn);
    }
    // Pending updates and reboots have their own columns and cards; they
    // do not make a server "need attention".
    note("Healthy".into(), NoteTone::Ok)
}

/// Note text for [`health_note`] (exported for the table).
#[uniffi::export]
pub fn fleet_health_note(input: HealthNoteInput) -> HealthNoteRow {
    health_note(&input)
}

// ---- "While you were away" ----

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DigestLineRow {
    pub title: String,
    pub detail: String,
    pub tone: NoteTone,
    /// A server to open for this line, if it is about one.
    pub server_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DigestRow {
    pub since_ms: u64,
    /// At most three lines, most important first; empty when nothing
    /// happened.
    pub lines: Vec<DigestLineRow>,
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// Summarizes timeline items newer than `since_ms`.
pub fn build_digest(items: &[TimelineItemRow], since_ms: u64) -> DigestRow {
    let new: Vec<&TimelineItemRow> = items.iter().filter(|i| i.time_ms > since_ms).collect();
    let mut lines: Vec<DigestLineRow> = Vec::new();

    // Critical or warning alerts first (fired, not cleared).
    let mut alerts: Vec<&TimelineItemRow> = new
        .iter()
        .copied()
        .filter(|i| {
            i.category == TimelineCategory::Alert
                && i.title.starts_with("Alert:")
                && matches!(
                    i.severity,
                    Some(AlertSeverity::Critical | AlertSeverity::Warning)
                )
        })
        .collect();
    alerts.sort_by_key(|i| {
        (
            i.severity != Some(AlertSeverity::Critical),
            std::cmp::Reverse(i.time_ms),
        )
    });
    let mut seen = BTreeSet::new();
    for a in alerts {
        let rule = a.title.trim_start_matches("Alert:").trim();
        let subject = a.detail.split(" (").next().unwrap_or("");
        if !seen.insert((a.server_id.clone(), rule.to_string())) {
            continue;
        }
        lines.push(DigestLineRow {
            title: format!("{} on {}", alert_title(rule, ""), a.server_name),
            detail: subject.to_string(),
            tone: if a.severity == Some(AlertSeverity::Critical) {
                NoteTone::Critical
            } else {
                NoteTone::Warn
            },
            server_id: Some(a.server_id.clone()),
        });
        if lines.len() >= 2 {
            break;
        }
    }

    // Security: failed logins and bans.
    let failed = new
        .iter()
        .filter(|i| i.category == TimelineCategory::Login && i.title.starts_with("Failed login"))
        .count();
    let bans: Vec<&&TimelineItemRow> = new
        .iter()
        .filter(|i| i.category == TimelineCategory::Security && i.title.starts_with("Banned "))
        .collect();
    let ban_addrs: BTreeSet<&str> = bans.iter().map(|i| i.title.as_str()).collect();
    let ban_servers: BTreeSet<&str> = bans.iter().map(|i| i.server_id.as_str()).collect();
    if failed > 0 || !bans.is_empty() {
        let title = if failed > 0 {
            format!("{} blocked", plural(failed, "failed login", "failed logins"))
        } else {
            format!("{} banned", plural(ban_addrs.len(), "IP", "IPs"))
        };
        let detail = if bans.is_empty() {
            String::new()
        } else {
            format!(
                "{} banned across {}",
                plural(ban_addrs.len(), "IP", "IPs"),
                plural(ban_servers.len(), "server", "servers")
            )
        };
        lines.push(DigestLineRow {
            title,
            detail,
            tone: NoteTone::Ok,
            server_id: None,
        });
    }

    // Config and service changes.
    if lines.len() < 3 {
        let mut changes: Vec<&&TimelineItemRow> = new
            .iter()
            .filter(|i| {
                matches!(
                    i.category,
                    TimelineCategory::Config | TimelineCategory::Service
                ) && i.actor.is_none()
            })
            .collect();
        changes.sort_by_key(|i| std::cmp::Reverse(i.time_ms));
        if let Some(c) = changes.first() {
            let (title, detail) = if c.category == TimelineCategory::Service {
                (format!("{} changed on {}", c.title, c.server_name), c.detail.clone())
            } else {
                (
                    format!("{} on {}", c.title, c.server_name),
                    c.detail.clone(),
                )
            };
            // Timers and restarts cycle through activating/inactive/active
            // all day; only a unit that ended up failed is worth a warning
            // (the timeline detail is "from → to"). Config edits always are.
            let routine = c.category == TimelineCategory::Service && !c.detail.ends_with("→ failed");
            lines.push(DigestLineRow {
                title,
                detail,
                tone: if routine { NoteTone::Ok } else { NoteTone::Warn },
                server_id: Some(c.server_id.clone()),
            });
        }
    }
    lines.truncate(3);
    DigestRow { since_ms, lines }
}

/// Digest of a fleet timeline (`timeline_fleet`) since `since_ms`.
#[uniffi::export]
pub fn fleet_digest(items: Vec<TimelineItemRow>, since_ms: u64) -> DigestRow {
    build_digest(&items, since_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rows::{MetricSeriesRow, MetricUnitRow, SeriesRollupRow};

    fn hist(avg: Vec<f32>) -> MetricsHistoryRow {
        MetricsHistoryRow {
            start_ms: 0,
            step_ms: 60_000,
            catalog: vec![
                MetricSeriesRow {
                    id: 3,
                    name: "mem.used".into(),
                    unit: MetricUnitRow::Percent,
                },
                MetricSeriesRow {
                    id: 7,
                    name: "cpu.busy".into(),
                    unit: MetricUnitRow::Percent,
                },
            ],
            series: vec![SeriesRollupRow {
                id: 7,
                min: vec![],
                avg,
                max: vec![],
            }],
        }
    }

    #[test]
    fn spark_keeps_short_series_and_drops_gaps() {
        let h = hist(vec![1.0, f32::NAN, 3.0, 250.0]);
        assert_eq!(cpu_spark(&h, 30), vec![1.0, 3.0, 100.0]);
    }

    #[test]
    fn spark_downsamples_to_bucket_means() {
        let h = hist((0..60).map(|i| i as f32).collect());
        let s = cpu_spark(&h, 30);
        assert_eq!(s.len(), 30);
        assert_eq!(s[0], 0.5);
        assert_eq!(s[29], 58.5);
    }

    #[test]
    fn spark_without_cpu_series_is_empty() {
        let mut h = hist(vec![1.0]);
        h.catalog.retain(|s| s.name != "cpu.busy");
        assert!(cpu_spark(&h, 30).is_empty());
    }

    fn input() -> HealthNoteInput {
        HealthNoteInput {
            online: true,
            disk_percent: Some(40.0),
            mem_percent: Some(40.0),
            alert_rule: None,
            alert_subject: None,
            alert_severity: None,
        }
    }

    #[test]
    fn note_priorities() {
        assert_eq!(health_note(&input()).text, "Healthy");
        let mut i = input();
        i.mem_percent = Some(93.0);
        assert_eq!(health_note(&i).text, "Memory 93%");
        i.disk_percent = Some(91.2);
        let n = health_note(&i);
        assert_eq!((n.text.as_str(), n.tone), ("Disk 91%", NoteTone::Critical));
        i.disk_percent = Some(86.0);
        assert_eq!(health_note(&i).tone, NoteTone::Warn);
        i.alert_rule = Some("service_down".into());
        i.alert_subject = Some("nginx.service".into());
        i.alert_severity = Some(AlertSeverity::Critical);
        let n = health_note(&i);
        assert_eq!(n.text, "Service down: nginx.service");
        assert_eq!(n.tone, NoteTone::Critical);
        i.online = false;
        assert!(health_note(&i).text.is_empty());
    }

    fn item(
        server: &str,
        t: u64,
        cat: TimelineCategory,
        title: &str,
        detail: &str,
        sev: Option<AlertSeverity>,
    ) -> TimelineItemRow {
        TimelineItemRow {
            id: format!("{server}{t}"),
            server_id: server.into(),
            server_name: server.into(),
            time_ms: t,
            category: cat,
            name: String::new(),
            title: title.into(),
            detail: detail.into(),
            severity: sev,
            actor: None,
            ai: false,
        }
    }

    #[test]
    fn digest_summarizes_only_new_items() {
        use TimelineCategory as C;
        let items = vec![
            item("old", 1, C::Login, "Failed login: root", "", None),
            item("a", 10, C::Login, "Failed login: root", "", None),
            item("a", 11, C::Login, "Failed login: admin", "", None),
            item("a", 12, C::Security, "Banned 1.2.3.4", "brute force", None),
            item("b", 13, C::Security, "Banned 5.6.7.8", "brute force", None),
            item(
                "b",
                14,
                C::Alert,
                "Alert: disk_used",
                "/ (91)",
                Some(AlertSeverity::Critical),
            ),
            item("b", 15, C::Service, "nginx", "active → activating", None),
        ];
        let d = build_digest(&items, 5);
        assert_eq!(d.lines.len(), 3);
        assert_eq!(d.lines[0].title, "Disk usage high on b");
        assert_eq!(d.lines[0].tone, NoteTone::Critical);
        assert_eq!(d.lines[0].server_id.as_deref(), Some("b"));
        assert_eq!(d.lines[1].title, "2 failed logins blocked");
        assert_eq!(d.lines[1].detail, "2 IPs banned across 2 servers");
        assert_eq!(d.lines[2].title, "nginx changed on b");
        assert_eq!(d.lines[2].tone, NoteTone::Ok);
        let failed = [item("b", 16, C::Service, "nginx", "active → failed", None)];
        assert_eq!(build_digest(&failed, 5).lines[0].tone, NoteTone::Warn);
        let config = [item("b", 17, C::Config, "/etc/ssh/sshd_config", "", None)];
        assert_eq!(build_digest(&config, 5).lines[0].tone, NoteTone::Warn);
    }

    #[test]
    fn digest_is_empty_when_nothing_happened() {
        let items = vec![item("a", 1, TimelineCategory::Login, "Failed login: x", "", None)];
        assert!(build_digest(&items, 100).lines.is_empty());
    }
}
