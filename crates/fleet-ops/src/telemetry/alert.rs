//! Agent-side alert evaluation (design §4.5).
//!
//! Every [`AlertRule`] is one of three shapes:
//!
//! - **Level** — a value per subject compared with the threshold: the
//!   metric kinds (fed from each [`Snapshot`]) and the state kinds other
//!   lanes report through [`AlertInput::observe`] as
//!   [`Observation::Level`] (service or container down, health check,
//!   certificate days left, security updates, reboot required).
//! - **Occurrence** — a discrete change (new port, user, `authorized_keys`,
//!   new login source, integrity): fires once per occurrence, never clears.
//! - **Rate** — `BruteForce`: occurrences within the sliding `for_s` window,
//!   then level semantics on the count.
//!
//! Hysteresis for levels: the condition must hold `for_s` before
//! `AlertFired`; once fired, it clears only after the value has dropped
//! below the threshold minus a margin ([`clear_margin`]) and stayed there
//! for `min(for_s, 60 s)`. A subject that disappears (unmounted
//! filesystem) counts as not holding. Changing or removing a rule clears
//! its fired alerts.

use super::collect::Snapshot;
use fleet_proto::Event;
use fleet_proto::alert::{AlertKind, AlertRule, AlertRuleSet};
use std::collections::{HashMap, VecDeque};

/// Receives alert events (exec signs, stores and pushes them).
pub trait AlertSink {
    fn emit(&self, event: Event);
}

/// Collects events (tests, and callers that forward in bulk).
#[derive(Default)]
pub struct VecSink(pub std::cell::RefCell<Vec<Event>>);

impl AlertSink for VecSink {
    fn emit(&self, event: Event) {
        self.0.borrow_mut().push(event);
    }
}

/// What other event sources (services, logins, certificates, docker, …)
/// report. `kind` names the rule kind it matches, with its parameters
/// (`ServiceDown { unit }` matches only rules for that unit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    /// Current value of a state, in the kind's threshold unit; for kinds
    /// without a threshold, non-zero means "bad" (down, failing, required).
    Level {
        kind: AlertKind,
        subject: String,
        value: u64,
    },
    /// One discrete occurrence (a failed SSH login for `BruteForce`, a new
    /// port, a user change, …).
    Occurrence { kind: AlertKind, subject: String },
}

/// The entry point for other lanes' event sources. Implemented by
/// [`super::Telemetry`]; evaluation and emission happen immediately.
pub trait AlertInput {
    fn observe(&self, obs: Observation, now_ms: u64);
}

/// Longest subject kept (mounts, units … are untrusted server text).
const MAX_SUBJECT: usize = 256;
/// Occurrences remembered per `BruteForce` rule window.
const MAX_WINDOW: usize = 100_000;
/// Clear delay cap.
const MAX_CLEAR_DELAY_MS: u64 = 60_000;

fn clip(s: &str) -> String {
    s.chars().take(MAX_SUBJECT).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Level,
    Occurrence,
    Rate,
}

fn shape(kind: &AlertKind) -> Shape {
    match kind {
        AlertKind::NewListeningPort
        | AlertKind::UserChange
        | AlertKind::AuthorizedKeysChange
        | AlertKind::LoginNewSource
        | AlertKind::IntegrityViolation => Shape::Occurrence,
        AlertKind::BruteForce => Shape::Rate,
        _ => Shape::Level,
    }
}

/// Kinds evaluated from snapshots (the rest come through [`AlertInput`]).
fn is_metric(kind: &AlertKind) -> bool {
    matches!(
        kind,
        AlertKind::DiskUsage { .. }
            | AlertKind::InodeUsage { .. }
            | AlertKind::MemoryUsage
            | AlertKind::SwapUsage
            | AlertKind::CpuUsage
            | AlertKind::CpuSteal
            | AlertKind::Load
    )
}

/// Kinds whose threshold is unused: non-zero value = condition.
fn boolean(kind: &AlertKind) -> bool {
    matches!(
        kind,
        AlertKind::ServiceDown { .. }
            | AlertKind::ContainerDown { .. }
            | AlertKind::HealthCheckFailed { .. }
            | AlertKind::RebootRequired
    )
}

/// Value margin below the threshold before a fired alert may clear: 5 %
/// of the threshold, at least 1 (0 for boolean kinds).
pub fn clear_margin(rule: &AlertRule) -> u64 {
    if boolean(&rule.kind) {
        0
    } else {
        (u64::from(rule.threshold) / 20).max(1)
    }
}

fn holds(rule: &AlertRule, value: u64, fired: bool) -> bool {
    let t = u64::from(rule.threshold);
    if boolean(&rule.kind) {
        return value != 0;
    }
    let m = if fired { clear_margin(rule) } else { 0 };
    if rule.kind == AlertKind::CertExpiry {
        // Fires below the threshold (days left).
        value < t + m
    } else {
        value >= t.saturating_sub(m)
    }
}

#[derive(Debug, Clone, Default)]
struct CondState {
    /// Condition holding since (not yet fired).
    since_ms: Option<u64>,
    fired: bool,
    /// Condition false since (fired, waiting to clear).
    clear_since_ms: Option<u64>,
    /// Last observed value (external levels are re-evaluated each tick).
    value: u64,
    /// Seen in the current metric pass.
    seen: bool,
}

#[derive(Default)]
pub struct AlertEngine {
    rules: Vec<AlertRule>,
    /// (rule index, subject) → state.
    states: HashMap<(usize, String), CondState>,
    /// Rate rules: rule index → occurrence times.
    windows: HashMap<usize, VecDeque<u64>>,
}

impl AlertEngine {
    pub fn new(rules: &AlertRuleSet) -> Self {
        let mut e = Self::default();
        e.set_rules(rules, &VecSink::default());
        e
    }

    /// Replaces the rules. States of unchanged rules carry over; fired
    /// alerts of changed, disabled or removed rules are cleared.
    pub fn set_rules(&mut self, set: &AlertRuleSet, sink: &dyn AlertSink) {
        let new: Vec<AlertRule> = set.rules.iter().filter(|r| r.enabled).cloned().collect();
        let mut states = HashMap::new();
        let mut windows = HashMap::new();
        for ((idx, subject), st) in std::mem::take(&mut self.states) {
            let old = &self.rules[idx];
            match new.iter().position(|r| r == old) {
                Some(n) => {
                    states.insert((n, subject), st);
                }
                None if st.fired => sink.emit(Event::AlertCleared {
                    rule_id: old.id.as_str().to_owned(),
                    subject,
                }),
                None => {}
            }
        }
        for (idx, w) in std::mem::take(&mut self.windows) {
            if let Some(n) = new.iter().position(|r| *r == self.rules[idx]) {
                windows.insert(n, w);
            }
        }
        self.rules = new;
        self.states = states;
        self.windows = windows;
    }

    /// Updates one level condition.
    fn level(&mut self, idx: usize, subject: &str, value: u64, now: u64, sink: &dyn AlertSink) {
        let rule = &self.rules[idx];
        let key = (idx, subject.to_owned());
        let st = self.states.entry(key).or_default();
        st.value = value;
        st.seen = true;
        let h = holds(rule, value, st.fired);
        step(rule, subject, st, h, now, sink);
        if !st.fired && st.since_ms.is_none() {
            self.states.remove(&(idx, subject.to_owned()));
        }
    }

    /// Metric rules against one snapshot; also advances timers of every
    /// level condition reported by other sources.
    pub fn evaluate(&mut self, snap: &Snapshot, sink: &dyn AlertSink) {
        let now = snap.time_ms;
        for st in self.states.values_mut() {
            st.seen = false;
        }
        for idx in 0..self.rules.len() {
            let kind = self.rules[idx].kind.clone();
            if !is_metric(&kind) {
                continue;
            }
            for (subject, value) in metric_values(&kind, snap) {
                self.level(idx, &subject, value, now, sink);
            }
        }
        // Unseen metric subjects: not holding. External levels: re-check
        // with their last value (the `for_s` timer runs without new input).
        let keys: Vec<(usize, String)> = self.states.keys().cloned().collect();
        for key in keys {
            let rule = self.rules[key.0].clone();
            let Some(st) = self.states.get_mut(&key) else {
                continue;
            };
            if st.seen {
                continue;
            }
            let h = match shape(&rule.kind) {
                Shape::Level if is_metric(&rule.kind) => false,
                Shape::Level => holds(&rule, st.value, st.fired),
                Shape::Rate => {
                    let n = self.windows.get_mut(&key.0).map_or(0, |w| {
                        prune_window(w, now, rule.for_s);
                        w.len() as u64
                    });
                    st.value = n;
                    holds(&rule, n, st.fired)
                }
                Shape::Occurrence => continue,
            };
            step(&rule, &key.1, st, h, now, sink);
            if !st.fired && st.since_ms.is_none() {
                self.states.remove(&key);
            }
        }
    }

    /// An observation from another event source.
    pub fn observe(&mut self, obs: &Observation, now: u64, sink: &dyn AlertSink) {
        let (kind, subject) = match obs {
            Observation::Level { kind, subject, .. }
            | Observation::Occurrence { kind, subject } => (kind, clip(subject)),
        };
        for idx in 0..self.rules.len() {
            let rule = &self.rules[idx];
            if rule.kind != *kind || is_metric(kind) {
                continue;
            }
            match (shape(kind), obs) {
                (Shape::Level, Observation::Level { value, .. }) => {
                    self.level(idx, &subject, *value, now, sink);
                }
                (Shape::Occurrence, Observation::Occurrence { .. }) => {
                    sink.emit(Event::AlertFired {
                        rule_id: rule.id.as_str().to_owned(),
                        severity: rule.severity,
                        subject: subject.clone(),
                        value: 1,
                    });
                }
                (Shape::Rate, Observation::Occurrence { .. }) => {
                    let for_s = rule.for_s;
                    let w = self.windows.entry(idx).or_default();
                    if w.len() >= MAX_WINDOW {
                        w.pop_front();
                    }
                    w.push_back(now);
                    prune_window(w, now, for_s);
                    let n = w.len() as u64;
                    // One alert per rule, whatever the source address.
                    self.level(idx, "ssh", n, now, sink);
                }
                _ => {}
            }
        }
    }

    /// Currently fired alerts: (rule id, subject).
    pub fn fired(&self) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = self
            .states
            .iter()
            .filter(|(_, s)| s.fired)
            .map(|((i, subj), _)| (self.rules[*i].id.as_str().to_owned(), subj.clone()))
            .collect();
        v.sort();
        v
    }
}

fn prune_window(w: &mut VecDeque<u64>, now: u64, for_s: u32) {
    let start = now.saturating_sub(u64::from(for_s.max(1)) * 1000);
    while w.front().is_some_and(|t| *t <= start) {
        w.pop_front();
    }
}

/// Advances one condition's hysteresis state machine.
fn step(
    rule: &AlertRule,
    subject: &str,
    st: &mut CondState,
    holds: bool,
    now: u64,
    sink: &dyn AlertSink,
) {
    let for_ms = u64::from(rule.for_s) * 1000;
    // For a rate rule `for_s` is the counting window, not a delay.
    let fire_delay = if shape(&rule.kind) == Shape::Rate {
        0
    } else {
        for_ms
    };
    if holds {
        st.clear_since_ms = None;
        if !st.fired {
            let since = *st.since_ms.get_or_insert(now);
            if now.saturating_sub(since) >= fire_delay {
                st.fired = true;
                st.since_ms = None;
                sink.emit(Event::AlertFired {
                    rule_id: rule.id.as_str().to_owned(),
                    severity: rule.severity,
                    subject: subject.to_owned(),
                    value: st.value,
                });
            }
        }
    } else if st.fired {
        let since = *st.clear_since_ms.get_or_insert(now);
        if now.saturating_sub(since) >= for_ms.min(MAX_CLEAR_DELAY_MS) {
            st.fired = false;
            st.clear_since_ms = None;
            sink.emit(Event::AlertCleared {
                rule_id: rule.id.as_str().to_owned(),
                subject: subject.to_owned(),
            });
        }
    } else {
        st.since_ms = None;
    }
}

/// (subject, value in the kind's unit) for a metric kind.
fn metric_values(kind: &AlertKind, s: &Snapshot) -> Vec<(String, u64)> {
    let permille = |part: u64, whole: u64| {
        if whole == 0 {
            None
        } else {
            Some((u128::from(part) * 1000 / u128::from(whole)) as u64)
        }
    };
    let pct = |p: f32| ((p * 10.0).round().clamp(0.0, 1000.0)) as u64;
    match kind {
        AlertKind::DiskUsage { mount } | AlertKind::InodeUsage { mount } => {
            s.fs.iter()
                .filter(|f| mount.as_ref().is_none_or(|m| m.as_str() == f.mount))
                .filter(|f| !matches!(kind, AlertKind::InodeUsage { .. }) || f.stat.files > 0)
                .map(|f| {
                    let v = if matches!(kind, AlertKind::DiskUsage { .. }) {
                        f.used_permille()
                    } else {
                        f.inode_permille()
                    };
                    (f.mount.clone(), v)
                })
                .collect()
        }
        AlertKind::MemoryUsage => s
            .mem
            .and_then(|m| permille(m.used(), m.total))
            .map(|v| ("memory".to_owned(), v))
            .into_iter()
            .collect(),
        AlertKind::SwapUsage => s
            .mem
            .and_then(|m| permille(m.swap_used(), m.swap_total))
            .map(|v| ("swap".to_owned(), v))
            .into_iter()
            .collect(),
        AlertKind::CpuUsage => s
            .cpu
            .map(|c| ("cpu".to_owned(), pct(c.busy())))
            .into_iter()
            .collect(),
        AlertKind::CpuSteal => s
            .cpu
            .map(|c| ("cpu".to_owned(), pct(c.steal)))
            .into_iter()
            .collect(),
        AlertKind::Load => s
            .load_per_core_x100()
            .map(|v| ("load".to_owned(), v))
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::collect::{CpuPct, FsStat, FsUsage};
    use fleet_proto::alert::Severity;
    use fleet_proto::args::{AbsPath, RuleId, UnitName};

    fn rule(id: &str, kind: AlertKind, threshold: u32, for_s: u32) -> AlertRule {
        AlertRule {
            id: RuleId::new(id).unwrap(),
            kind,
            threshold,
            for_s,
            severity: Severity::Warning,
            enabled: true,
        }
    }

    fn snap(t: u64, disk_used: u64, steal: f32) -> Snapshot {
        Snapshot {
            time_ms: t,
            cpu: Some(CpuPct {
                steal,
                ..Default::default()
            }),
            fs: vec![FsUsage {
                mount: "/".into(),
                stat: FsStat {
                    total_bytes: 1000,
                    used_bytes: disk_used,
                    avail_bytes: 1000 - disk_used,
                    files: 0,
                    files_free: 0,
                },
            }],
            ..Default::default()
        }
    }

    fn take(s: &VecSink) -> Vec<Event> {
        std::mem::take(&mut *s.0.borrow_mut())
    }

    #[test]
    fn disk_rule_hysteresis() {
        let set = AlertRuleSet {
            version: 1,
            rules: vec![rule("disk", AlertKind::DiskUsage { mount: None }, 900, 60)],
        };
        let mut e = AlertEngine::new(&set);
        let sink = VecSink::default();
        e.evaluate(&snap(0, 950, 0.0), &sink);
        e.evaluate(&snap(30_000, 950, 0.0), &sink);
        assert!(take(&sink).is_empty(), "not for 60 s yet");
        e.evaluate(&snap(60_000, 950, 0.0), &sink);
        assert_eq!(
            take(&sink),
            [Event::AlertFired {
                rule_id: "disk".into(),
                severity: Severity::Warning,
                subject: "/".into(),
                value: 950
            }]
        );
        // Within the margin (900 - 45): stays fired.
        e.evaluate(&snap(70_000, 880, 0.0), &sink);
        e.evaluate(&snap(200_000, 880, 0.0), &sink);
        assert!(take(&sink).is_empty());
        // Below the margin: clears after min(for_s, 60 s).
        e.evaluate(&snap(210_000, 800, 0.0), &sink);
        assert!(take(&sink).is_empty());
        e.evaluate(&snap(270_000, 800, 0.0), &sink);
        assert_eq!(
            take(&sink),
            [Event::AlertCleared {
                rule_id: "disk".into(),
                subject: "/".into()
            }]
        );
        assert!(e.fired().is_empty());
        // A blip shorter than for_s never fires.
        e.evaluate(&snap(300_000, 990, 0.0), &sink);
        e.evaluate(&snap(310_000, 100, 0.0), &sink);
        e.evaluate(&snap(400_000, 990, 0.0), &sink);
        assert!(take(&sink).is_empty());
    }

    #[test]
    fn unmounted_subject_clears_and_rule_removal_clears() {
        let set = AlertRuleSet {
            version: 1,
            rules: vec![
                rule(
                    "root",
                    AlertKind::DiskUsage {
                        mount: Some(AbsPath::new("/").unwrap()),
                    },
                    500,
                    0,
                ),
                rule("steal", AlertKind::CpuSteal, 100, 0),
            ],
        };
        let mut e = AlertEngine::new(&set);
        let sink = VecSink::default();
        e.evaluate(&snap(0, 600, 20.0), &sink);
        assert_eq!(take(&sink).len(), 2);
        assert_eq!(e.fired().len(), 2);
        let mut gone = snap(1000, 0, 20.0);
        gone.fs.clear();
        e.evaluate(&gone, &sink);
        assert!(
            matches!(&take(&sink)[..], [Event::AlertCleared { rule_id, .. }] if rule_id == "root")
        );
        // Removing the steal rule clears its alert.
        e.set_rules(
            &AlertRuleSet {
                version: 2,
                rules: vec![],
            },
            &sink,
        );
        assert!(
            matches!(&take(&sink)[..], [Event::AlertCleared { rule_id, .. }] if rule_id == "steal")
        );
    }

    #[test]
    fn external_sources() {
        let unit = UnitName::new("nginx.service").unwrap();
        let set = AlertRuleSet {
            version: 1,
            rules: vec![
                rule("svc", AlertKind::ServiceDown { unit: unit.clone() }, 0, 30),
                rule("bf", AlertKind::BruteForce, 3, 60),
                rule("port", AlertKind::NewListeningPort, 0, 0),
                rule("cert", AlertKind::CertExpiry, 14, 0),
            ],
        };
        let mut e = AlertEngine::new(&set);
        let sink = VecSink::default();
        let down = Observation::Level {
            kind: AlertKind::ServiceDown { unit },
            subject: "nginx.service".into(),
            value: 1,
        };
        e.observe(&down, 0, &sink);
        // Other unit's rule doesn't match; timer runs on snapshots.
        e.evaluate(&snap(10_000, 0, 0.0), &sink);
        assert!(take(&sink).is_empty());
        e.evaluate(&snap(30_000, 0, 0.0), &sink);
        assert!(
            matches!(&take(&sink)[..], [Event::AlertFired { rule_id, .. }] if rule_id == "svc")
        );

        let fail = Observation::Occurrence {
            kind: AlertKind::BruteForce,
            subject: "203.0.113.9".into(),
        };
        e.observe(&fail, 1000, &sink);
        e.observe(&fail, 2000, &sink);
        assert!(take(&sink).is_empty());
        e.observe(&fail, 3000, &sink);
        assert!(
            matches!(&take(&sink)[..], [Event::AlertFired { rule_id, value: 3, .. }] if rule_id == "bf")
        );
        // Window slides: count drops, clears after 60 s below.
        e.evaluate(&snap(70_000, 0, 0.0), &sink);
        e.evaluate(&snap(130_000, 0, 0.0), &sink);
        assert!(
            matches!(&take(&sink)[..], [Event::AlertCleared { rule_id, .. }] if rule_id == "bf")
        );

        let port = Observation::Occurrence {
            kind: AlertKind::NewListeningPort,
            subject: "tcp/8080".into(),
        };
        e.observe(&port, 5000, &sink);
        e.observe(&port, 6000, &sink);
        assert_eq!(take(&sink).len(), 2);

        let cert = |days| Observation::Level {
            kind: AlertKind::CertExpiry,
            subject: "example.org".into(),
            value: days,
        };
        e.observe(&cert(30), 0, &sink);
        assert!(take(&sink).is_empty());
        e.observe(&cert(10), 0, &sink);
        assert_eq!(take(&sink).len(), 1);
    }

    #[test]
    fn disabled_rules_ignored() {
        let mut r = rule("disk", AlertKind::DiskUsage { mount: None }, 1, 0);
        r.enabled = false;
        let mut e = AlertEngine::new(&AlertRuleSet {
            version: 1,
            rules: vec![r],
        });
        let sink = VecSink::default();
        e.evaluate(&snap(0, 999, 0.0), &sink);
        assert!(take(&sink).is_empty());
    }
}
