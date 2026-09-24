//! Agent-evaluated alert rules and health checks (design §2.2, §4.5).
//!
//! Thresholds are integers so rule sets compare and hash exactly; each
//! [`AlertKind`] documents its unit.

use super::args::{
    AbsPath, ArgError, CheckId, ContainerName, HttpPath, Port, RuleId, UnitName, at_most, ensure,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// What a rule watches. Variant order is the postcard index: append only.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlertKind {
    /// Used space in permille (0..=1000); `None` = every real filesystem.
    DiskUsage { mount: Option<AbsPath> },
    /// Used inodes in permille.
    InodeUsage { mount: Option<AbsPath> },
    /// Used memory (total − available) in permille.
    MemoryUsage,
    /// Used swap in permille.
    SwapUsage,
    /// Busy CPU (all cores) in permille.
    CpuUsage,
    /// CPU steal in permille.
    CpuSteal,
    /// 5-minute load average per core, × 100.
    Load,
    /// Fires when the unit is failed or inactive; threshold unused (0).
    ServiceDown { unit: UnitName },
    /// Failed SSH authentications per `for_s` window, from any source.
    BruteForce,
    /// Days until the earliest discovered certificate expires.
    CertExpiry,
    /// A new listening port appears; threshold unused (0).
    NewListeningPort,
    /// A user, group or sudoer is added; threshold unused (0).
    UserChange,
    /// Any `authorized_keys` changes; threshold unused (0).
    AuthorizedKeysChange,
    /// Login from a source (IP or country) not seen before; threshold unused (0).
    LoginNewSource,
    /// An integrity violation is detected; threshold unused (0).
    IntegrityViolation,
    /// Container not running (or unhealthy); threshold unused (0).
    ContainerDown { name: ContainerName },
    /// Health check failing for `for_s`; threshold unused (0).
    HealthCheckFailed { check: CheckId },
    /// Pending security updates count.
    SecurityUpdates,
    /// Reboot required (kernel/libc update); threshold unused (0).
    RebootRequired,
}

impl AlertKind {
    /// Largest meaningful threshold, or 0 if the kind takes none.
    fn max_threshold(&self) -> u32 {
        match self {
            AlertKind::DiskUsage { .. }
            | AlertKind::InodeUsage { .. }
            | AlertKind::MemoryUsage
            | AlertKind::SwapUsage
            | AlertKind::CpuUsage
            | AlertKind::CpuSteal => 1000,
            AlertKind::Load => 100_000,
            AlertKind::BruteForce => 1_000_000,
            AlertKind::CertExpiry => 3650,
            AlertKind::SecurityUpdates => 100_000,
            AlertKind::ServiceDown { .. }
            | AlertKind::NewListeningPort
            | AlertKind::UserChange
            | AlertKind::AuthorizedKeysChange
            | AlertKind::LoginNewSource
            | AlertKind::IntegrityViolation
            | AlertKind::ContainerDown { .. }
            | AlertKind::HealthCheckFailed { .. }
            | AlertKind::RebootRequired => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: RuleId,
    pub kind: AlertKind,
    /// Fires when the value is at or above this (below, for `CertExpiry`),
    /// in the unit documented on `kind`.
    pub threshold: u32,
    /// The condition must hold this long (seconds, at most one day).
    pub for_s: u32,
    pub severity: Severity,
    pub enabled: bool,
}

impl AlertRule {
    pub fn validate(&self) -> Result<(), ArgError> {
        ensure(
            self.threshold <= self.kind.max_threshold(),
            "alert threshold",
        )?;
        ensure(self.for_s <= 86_400, "alert duration")
    }
}

/// Every rule of one server, pushed by the Elevated `alert_rules.update`.
/// `version` must increase, like a policy's.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AlertRuleSet {
    pub version: u64,
    pub rules: Vec<AlertRule>,
}

impl AlertRuleSet {
    pub const MAX_RULES: usize = 256;

    pub fn validate(&self) -> Result<(), ArgError> {
        at_most(&self.rules, Self::MAX_RULES, "alert rules")?;
        let mut ids: Vec<&RuleId> = self.rules.iter().map(|r| &r.id).collect();
        ids.sort();
        ensure(ids.windows(2).all(|w| w[0] != w[1]), "duplicate rule id")?;
        self.rules.iter().try_for_each(AlertRule::validate)
    }
}

/// A probe against a local service (design §2.2): loopback only, so a
/// health check can't be turned into a network scanner.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Probe {
    Tcp {
        port: Port,
        ipv6: bool,
    },
    Http {
        port: Port,
        ipv6: bool,
        tls: bool,
        path: HttpPath,
        /// Expected status, 100..=599.
        expect_status: u16,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HealthCheck {
    pub id: CheckId,
    pub probe: Probe,
    /// 5..=3600 seconds.
    pub interval_s: u16,
    /// 100..=30000 milliseconds.
    pub timeout_ms: u16,
}

impl HealthCheck {
    pub fn validate(&self) -> Result<(), ArgError> {
        ensure((5..=3600).contains(&self.interval_s), "check interval")?;
        ensure((100..=30_000).contains(&self.timeout_ms), "check timeout")?;
        if let Probe::Http { expect_status, .. } = self.probe {
            ensure((100..=599).contains(&expect_status), "expected status")?;
        }
        Ok(())
    }
}

/// Every health check of one server, pushed by `health_checks.update`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HealthCheckSet {
    pub version: u64,
    pub checks: Vec<HealthCheck>,
}

impl HealthCheckSet {
    pub const MAX_CHECKS: usize = 64;

    pub fn validate(&self) -> Result<(), ArgError> {
        at_most(&self.checks, Self::MAX_CHECKS, "health checks")?;
        let mut ids: Vec<&CheckId> = self.checks.iter().map(|c| &c.id).collect();
        ids.sort();
        ensure(ids.windows(2).all(|w| w[0] != w[1]), "duplicate check id")?;
        self.checks.iter().try_for_each(HealthCheck::validate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn rule(id: &str, kind: AlertKind, threshold: u32) -> AlertRule {
        AlertRule {
            id: RuleId::new(id).unwrap(),
            kind,
            threshold,
            for_s: 300,
            severity: Severity::Warning,
            enabled: true,
        }
    }

    #[test]
    fn examples() {
        let set = AlertRuleSet {
            version: 3,
            rules: vec![
                rule("disk", AlertKind::DiskUsage { mount: None }, 900),
                rule(
                    "ssh-down",
                    AlertKind::ServiceDown {
                        unit: UnitName::new("ssh.service").unwrap(),
                    },
                    0,
                ),
            ],
        };
        assert!(set.validate().is_ok());
        let back: AlertRuleSet = crate::decode(&crate::encode(&set)).unwrap();
        assert_eq!(back, set);

        let mut dup = set.clone();
        dup.rules.push(rule("disk", AlertKind::MemoryUsage, 1));
        assert!(dup.validate().is_err());
        assert!(rule("x", AlertKind::MemoryUsage, 1001).validate().is_err());
        assert!(
            rule("x", AlertKind::NewListeningPort, 1)
                .validate()
                .is_err()
        );

        let check = HealthCheck {
            id: CheckId::new("api").unwrap(),
            probe: Probe::Http {
                port: Port::new(8080).unwrap(),
                ipv6: false,
                tls: false,
                path: HttpPath::new("/healthz").unwrap(),
                expect_status: 200,
            },
            interval_s: 30,
            timeout_ms: 2000,
        };
        assert!(check.validate().is_ok());
        assert!(
            HealthCheck {
                interval_s: 1,
                ..check.clone()
            }
            .validate()
            .is_err()
        );
    }

    proptest! {
        #[test]
        fn permille_bounds(t in any::<u32>()) {
            prop_assert_eq!(rule("m", AlertKind::MemoryUsage, t).validate().is_ok(), t <= 1000);
        }

        #[test]
        fn rule_count(n in 0usize..300) {
            let set = AlertRuleSet {
                version: 1,
                rules: (0..n).map(|i| rule(&format!("r{i}"), AlertKind::Load, 200)).collect(),
            };
            prop_assert_eq!(set.validate().is_ok(), n <= 256);
        }
    }
}
