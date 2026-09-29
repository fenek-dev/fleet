//! Data behind the Mac app's shell screens (Settings, alerts): per-server
//! alert rules (`alert_rules.get/update`), roster and recovery status
//! details, AI activity, and the synced collections. Server text is
//! escaped (rule 6).

use crate::admin_ops::{invalid, unexpected};
use crate::api::{FleetCore, lock};
use crate::fleet_mgmt::device_hex;
use crate::text;
use crate::types::{AlertSeverity, FleetError};
use fleet_core::roster_mgmt as rm;
use fleet_core::sync::Collection;
use fleet_hardening::{modules, profile};
use fleet_proto::op::{ProfileLevel, ProfileRole};
use fleet_proto::alert::{AlertKind, AlertRule, AlertRuleSet, Severity};
use fleet_proto::args::{AbsPath, CheckId, ContainerName, RuleId, UnitName};
use fleet_proto::{Actor, AuditEntry, KeyRef, Op, Payload, Phase, ServerId};
use std::collections::HashMap;

const SETTING_RECOVERY_DRILL: &str = "recovery_drill_ms";

// ---- alert rules ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AlertKindRow {
    DiskUsage,
    InodeUsage,
    MemoryUsage,
    SwapUsage,
    CpuUsage,
    CpuSteal,
    Load,
    ServiceDown,
    BruteForce,
    CertExpiry,
    NewListeningPort,
    UserChange,
    AuthorizedKeysChange,
    LoginNewSource,
    IntegrityViolation,
    ContainerDown,
    HealthCheckFailed,
    SecurityUpdates,
    RebootRequired,
}

/// One alert rule. `param` is the mount (disk, inode; empty = every
/// filesystem), unit, container or check the kind names; empty otherwise.
/// Thresholds are integers in the unit documented on `fleet_proto::alert`
/// (permille for usage kinds, load × 100, days for certificates).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AlertRuleRow {
    pub id: String,
    pub kind: AlertKindRow,
    pub param: String,
    pub threshold: u32,
    pub for_s: u32,
    pub severity: AlertSeverity,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AlertRuleSetRow {
    pub version: u64,
    pub rules: Vec<AlertRuleRow>,
}

fn kind_row(k: &AlertKind) -> (AlertKindRow, String) {
    use AlertKindRow as R;
    let mount = |m: &Option<AbsPath>| m.as_ref().map(|p| p.as_str().to_string()).unwrap_or_default();
    match k {
        AlertKind::DiskUsage { mount: m } => (R::DiskUsage, mount(m)),
        AlertKind::InodeUsage { mount: m } => (R::InodeUsage, mount(m)),
        AlertKind::MemoryUsage => (R::MemoryUsage, String::new()),
        AlertKind::SwapUsage => (R::SwapUsage, String::new()),
        AlertKind::CpuUsage => (R::CpuUsage, String::new()),
        AlertKind::CpuSteal => (R::CpuSteal, String::new()),
        AlertKind::Load => (R::Load, String::new()),
        AlertKind::ServiceDown { unit } => (R::ServiceDown, unit.as_str().to_string()),
        AlertKind::BruteForce => (R::BruteForce, String::new()),
        AlertKind::CertExpiry => (R::CertExpiry, String::new()),
        AlertKind::NewListeningPort => (R::NewListeningPort, String::new()),
        AlertKind::UserChange => (R::UserChange, String::new()),
        AlertKind::AuthorizedKeysChange => (R::AuthorizedKeysChange, String::new()),
        AlertKind::LoginNewSource => (R::LoginNewSource, String::new()),
        AlertKind::IntegrityViolation => (R::IntegrityViolation, String::new()),
        AlertKind::ContainerDown { name } => (R::ContainerDown, name.as_str().to_string()),
        AlertKind::HealthCheckFailed { check } => {
            (R::HealthCheckFailed, check.as_str().to_string())
        }
        AlertKind::SecurityUpdates => (R::SecurityUpdates, String::new()),
        AlertKind::RebootRequired => (R::RebootRequired, String::new()),
    }
}

fn kind_args(k: AlertKindRow, param: &str) -> Result<AlertKind, FleetError> {
    use AlertKindRow as R;
    let param = param.trim();
    let mount = || -> Result<Option<AbsPath>, FleetError> {
        if param.is_empty() {
            Ok(None)
        } else {
            AbsPath::new(param).map(Some).map_err(|_| invalid("mount"))
        }
    };
    Ok(match k {
        R::DiskUsage => AlertKind::DiskUsage { mount: mount()? },
        R::InodeUsage => AlertKind::InodeUsage { mount: mount()? },
        R::MemoryUsage => AlertKind::MemoryUsage,
        R::SwapUsage => AlertKind::SwapUsage,
        R::CpuUsage => AlertKind::CpuUsage,
        R::CpuSteal => AlertKind::CpuSteal,
        R::Load => AlertKind::Load,
        R::ServiceDown => AlertKind::ServiceDown {
            unit: UnitName::new(param).map_err(|_| invalid("unit"))?,
        },
        R::BruteForce => AlertKind::BruteForce,
        R::CertExpiry => AlertKind::CertExpiry,
        R::NewListeningPort => AlertKind::NewListeningPort,
        R::UserChange => AlertKind::UserChange,
        R::AuthorizedKeysChange => AlertKind::AuthorizedKeysChange,
        R::LoginNewSource => AlertKind::LoginNewSource,
        R::IntegrityViolation => AlertKind::IntegrityViolation,
        R::ContainerDown => AlertKind::ContainerDown {
            name: ContainerName::new(param).map_err(|_| invalid("container"))?,
        },
        R::HealthCheckFailed => AlertKind::HealthCheckFailed {
            check: CheckId::new(param).map_err(|_| invalid("check"))?,
        },
        R::SecurityUpdates => AlertKind::SecurityUpdates,
        R::RebootRequired => AlertKind::RebootRequired,
    })
}

fn severity_args(s: AlertSeverity) -> Severity {
    match s {
        AlertSeverity::Info => Severity::Info,
        AlertSeverity::Warning => Severity::Warning,
        AlertSeverity::Critical => Severity::Critical,
    }
}

fn rule_row(r: &AlertRule) -> AlertRuleRow {
    let (kind, param) = kind_row(&r.kind);
    AlertRuleRow {
        id: text::line(r.id.as_str().to_string()),
        kind,
        param: text::line(param),
        threshold: r.threshold,
        for_s: r.for_s,
        severity: r.severity.into(),
        enabled: r.enabled,
    }
}

fn rule_args(r: &AlertRuleRow) -> Result<AlertRule, FleetError> {
    let rule = AlertRule {
        id: RuleId::new(r.id.trim()).map_err(|_| invalid("rule id"))?,
        kind: kind_args(r.kind, &r.param)?,
        threshold: r.threshold,
        for_s: r.for_s,
        severity: severity_args(r.severity),
        enabled: r.enabled,
    };
    rule.validate().map_err(|_| invalid("alert rule"))?;
    Ok(rule)
}

/// The rule set `rules` as the next version after `current`, validated.
pub(crate) fn next_rule_set(
    current: u64,
    rules: &[AlertRuleRow],
) -> Result<AlertRuleSet, FleetError> {
    let set = AlertRuleSet {
        version: current + 1,
        rules: rules.iter().map(rule_args).collect::<Result<_, _>>()?,
    };
    set.validate().map_err(|_| invalid("alert rules"))?;
    Ok(set)
}

#[uniffi::export]
impl FleetCore {
    /// The server's alert rules and the version to pass to
    /// [`FleetCore::alert_rules_set`].
    pub async fn alert_rules_get(&self, server_id: String) -> Result<AlertRuleSetRow, FleetError> {
        match self.send_op(&server_id, Op::AlertRulesGet, None).await? {
            Payload::AlertRules(set) => Ok(AlertRuleSetRow {
                version: set.version,
                rules: set.rules.iter().map(rule_row).collect(),
            }),
            p => unexpected(p),
        }
    }

    /// Replaces every rule of the server. Elevated: root-key approval
    /// (Touch ID). `expected_version` is the version read by
    /// `alert_rules_get`; a concurrent edit answers a version conflict.
    pub async fn alert_rules_set(
        &self,
        server_id: String,
        rules: Vec<AlertRuleRow>,
        expected_version: u64,
    ) -> Result<(), FleetError> {
        let set = next_rule_set(expected_version, &rules)?;
        self.send_op(&server_id, Op::AlertRulesUpdate(set), Some(expected_version))
            .await
            .map(|_| ())
    }
}

// ---- roster, recovery, AI activity ----

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeviceActivityRow {
    pub device_id: String,
    /// Newest mirrored audit entry signed by this Mac; `None` if none seen.
    pub last_active_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RosterExtrasRow {
    /// Name of the Mac that signed the latest roster ("Recovery code" for a
    /// recovery roster).
    pub signed_by: String,
    pub issued_at_ms: u64,
    /// When the current recovery code's keys entered the roster chain.
    pub recovery_created_ms: u64,
    /// Last recovery drill run on this Mac (`record_recovery_drill`).
    pub last_drill_ms: Option<u64>,
    pub devices: Vec<DeviceActivityRow>,
}

/// Newest audit entries per server to scan; enough for "last active" and
/// "actions today" without reading whole mirrors.
const SCAN_PER_SERVER: usize = 300;

impl FleetCore {
    fn mirrored_entries(&self) -> Vec<AuditEntry> {
        let cache = lock(&self.cache);
        let ids: Vec<ServerId> = cache
            .servers()
            .map(|v| v.into_iter().map(|r| r.id).collect())
            .unwrap_or_default();
        ids.iter()
            .filter_map(|id| cache.audit_mirror(id, SCAN_PER_SERVER).ok())
            .flatten()
            .filter_map(|(_, raw)| fleet_proto::decode::<AuditEntry>(&raw).ok())
            .collect()
    }
}

/// Per device id (hex): newest entry time.
pub(crate) fn last_active(entries: &[AuditEntry]) -> HashMap<String, u64> {
    let mut m: HashMap<String, u64> = HashMap::new();
    for e in entries {
        let t = m.entry(device_hex(&e.device_id)).or_insert(0);
        *t = (*t).max(e.time);
    }
    m
}

/// AI-issued operations (intent entries) at or after `since_ms`.
pub(crate) fn ai_actions(entries: &[AuditEntry], since_ms: u64) -> u32 {
    let n = entries
        .iter()
        .filter(|e| {
            e.time >= since_ms
                && e.phase == Phase::Intent
                && matches!(e.actor, Actor::Ai { .. })
        })
        .count();
    u32::try_from(n).unwrap_or(u32::MAX)
}

#[uniffi::export]
impl FleetCore {
    pub fn roster_extras(&self) -> Result<RosterExtrasRow, FleetError> {
        let activity = last_active(&self.mirrored_entries());
        let me = self.me().ok();
        let now = fleet_core::now_ms();
        let cache = lock(&self.cache);
        let chain = rm::chain(&cache)?;
        let latest = chain.last().ok_or(FleetError::UnexpectedReply)?;
        let name_of = |id| {
            chain.iter().rev().find_map(|r| {
                r.roster
                    .device(id)
                    .map(|d| text::line(d.name.as_str().to_string()))
            })
        };
        let signed_by = match &latest.signer {
            KeyRef::Root(id) => name_of(id).unwrap_or_else(|| device_hex(id)),
            KeyRef::Recovery => "Recovery code".to_string(),
        };
        let key = latest.roster.recovery_key;
        let recovery_created_ms = chain
            .iter()
            .rev()
            .take_while(|r| r.roster.recovery_key == key)
            .last()
            .map_or(latest.roster.issued_at_ms, |r| r.roster.issued_at_ms);
        let last_drill_ms = cache
            .setting(SETTING_RECOVERY_DRILL)
            .ok()
            .flatten()
            .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
            .map(u64::from_be_bytes);
        let devices = latest
            .roster
            .devices
            .iter()
            .map(|d| {
                let hex = device_hex(&d.id);
                let last = if Some(d.id) == me {
                    Some(now)
                } else {
                    activity.get(&hex).copied()
                };
                DeviceActivityRow {
                    device_id: hex,
                    last_active_ms: last,
                }
            })
            .collect();
        Ok(RosterExtrasRow {
            signed_by,
            issued_at_ms: latest.roster.issued_at_ms,
            recovery_created_ms,
            last_drill_ms,
            devices,
        })
    }

    /// Remembers that a recovery drill ran on this Mac now.
    pub fn record_recovery_drill(&self) -> Result<(), FleetError> {
        lock(&self.cache)
            .set_setting(SETTING_RECOVERY_DRILL, &fleet_core::now_ms().to_be_bytes())
            .map_err(|e| FleetError::Internal {
                message: e.to_string(),
            })
    }

    /// Operations AI clients started since `since_ms`, from the mirrored
    /// audit logs.
    pub fn ai_actions_since(&self, since_ms: u64) -> u32 {
        ai_actions(&self.mirrored_entries(), since_ms)
    }
}

/// What syncs between Macs, in reader's words (design §7.6).
#[uniffi::export]
pub fn synced_collections() -> Vec<String> {
    Collection::ALL
        .iter()
        .filter_map(|c| match c {
            Collection::Servers => Some("Servers"),
            Collection::Groups => Some("Groups"),
            Collection::Snippets => Some("Snippets"),
            Collection::Runbooks => Some("Runbooks"),
            Collection::Profiles => Some("Profiles"),
            Collection::AlertRules => Some("Alert rules"),
            Collection::AuditMirror => Some("Audit mirrors"),
            Collection::PinnedKeys => Some("Pinned keys"),
            Collection::SudoPasswords => Some("Sudo passwords"),
            Collection::RosterChain | Collection::Settings | Collection::DeviceKeys => None,
        })
        .map(str::to_string)
        .collect()
}

// ---- built-in profiles ----

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ProfileModuleRow {
    pub id: String,
    pub title: String,
}

/// A built-in provisioning profile or role add-on (design §9).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ProfileCatalogRow {
    /// `baseline`, `strict`, `docker`, `web` or `game`.
    pub id: String,
    pub name: String,
    /// `level` or `role`.
    pub kind: String,
    pub summary: String,
    /// `strict` extends `baseline`: its list holds only the additions.
    pub extends: Option<String>,
    pub modules: Vec<ProfileModuleRow>,
    pub packages: Vec<String>,
    pub tracked_paths: Vec<String>,
    pub firewall_rules: u32,
}

fn module_rows(ids: &[String]) -> Vec<ProfileModuleRow> {
    ids.iter()
        .map(|id| ProfileModuleRow {
            id: id.clone(),
            title: modules::by_id(id).map_or_else(|| id.clone(), |m| m.title().to_string()),
        })
        .collect()
}

pub(crate) fn profile_catalog() -> Vec<ProfileCatalogRow> {
    let base = profile::builtin(ProfileLevel::Baseline, &[]).ok();
    let strict = profile::builtin(ProfileLevel::Strict, &[]).ok();
    let mut out = Vec::new();
    if let Some(b) = &base {
        out.push(ProfileCatalogRow {
            id: "baseline".into(),
            name: "Baseline".into(),
            kind: "level".into(),
            summary: "Admin access, SSH and firewall hardening, updates, audit logging.".into(),
            extends: None,
            modules: module_rows(&b.modules),
            packages: b.settings.packages.clone(),
            tracked_paths: Vec::new(),
            firewall_rules: 0,
        });
    }
    if let (Some(b), Some(s)) = (&base, &strict) {
        let added: Vec<String> = s
            .modules
            .iter()
            .filter(|m| !b.modules.contains(m))
            .cloned()
            .collect();
        out.push(ProfileCatalogRow {
            id: "strict".into(),
            name: "Strict".into(),
            kind: "level".into(),
            summary: "Baseline plus tighter mounts, cron and sudo policy, SSH only from allowed sources."
                .into(),
            extends: Some("baseline".into()),
            modules: module_rows(&added),
            packages: s
                .settings
                .packages
                .iter()
                .filter(|p| !b.settings.packages.contains(p))
                .cloned()
                .collect(),
            tracked_paths: Vec::new(),
            firewall_rules: 0,
        });
    }
    for (role, id, name) in [
        (ProfileRole::Docker, "docker", "Docker host"),
        (ProfileRole::Web, "web", "Web server"),
        (ProfileRole::Game, "game", "Game server"),
    ] {
        if let Ok(m) = profile::role_manifest(role) {
            out.push(ProfileCatalogRow {
                id: id.into(),
                name: name.into(),
                kind: "role".into(),
                summary: m.description.clone(),
                extends: None,
                modules: module_rows(&m.modules),
                packages: m.packages.clone(),
                tracked_paths: m.tracked_paths.clone(),
                firewall_rules: u32::try_from(m.firewall.len()).unwrap_or(u32::MAX),
            });
        }
    }
    out
}

/// Baseline, Strict and the role add-ons the agent ships.
#[uniffi::export]
pub fn builtin_profiles() -> Vec<ProfileCatalogRow> {
    profile_catalog()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(kind: AlertKindRow, param: &str, threshold: u32) -> AlertRuleRow {
        AlertRuleRow {
            id: "r1".into(),
            kind,
            param: param.into(),
            threshold,
            for_s: 300,
            severity: AlertSeverity::Warning,
            enabled: true,
        }
    }

    #[test]
    fn rule_roundtrips_through_the_wire_type() {
        for r in [
            rule(AlertKindRow::DiskUsage, "/var", 900),
            rule(AlertKindRow::DiskUsage, "", 900),
            rule(AlertKindRow::ServiceDown, "nginx.service", 0),
            rule(AlertKindRow::ContainerDown, "web", 0),
            rule(AlertKindRow::HealthCheckFailed, "http.api", 0),
            rule(AlertKindRow::CertExpiry, "", 14),
        ] {
            let args = rule_args(&r).unwrap();
            assert_eq!(rule_row(&args), r);
        }
    }

    #[test]
    fn invalid_rules_are_refused_before_signing() {
        // Permille above 1000, bad ids and parameters, relative mount.
        assert!(rule_args(&rule(AlertKindRow::CpuUsage, "", 1001)).is_err());
        assert!(rule_args(&rule(AlertKindRow::ServiceDown, "", 0)).is_err());
        assert!(rule_args(&rule(AlertKindRow::ServiceDown, "a b; rm", 0)).is_err());
        assert!(rule_args(&rule(AlertKindRow::DiskUsage, "var", 900)).is_err());
        let mut bad_id = rule(AlertKindRow::MemoryUsage, "", 900);
        bad_id.id = "Bad Id".into();
        assert!(rule_args(&bad_id).is_err());
        let mut long = rule(AlertKindRow::MemoryUsage, "", 900);
        long.for_s = 86_401;
        assert!(rule_args(&long).is_err());
    }

    #[test]
    fn rule_set_bumps_the_version_and_rejects_duplicates() {
        let a = rule(AlertKindRow::MemoryUsage, "", 900);
        let set = next_rule_set(4, std::slice::from_ref(&a)).unwrap();
        assert_eq!(set.version, 5);
        assert!(next_rule_set(4, &[a.clone(), a]).is_err());
    }

    #[test]
    fn profile_catalog_lists_levels_and_roles() {
        let c = profile_catalog();
        let ids: Vec<&str> = c.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["baseline", "strict", "docker", "web", "game"]);
        let base = &c[0];
        let strict = &c[1];
        assert!(!base.modules.is_empty());
        // Strict lists only its additions, none already in Baseline.
        assert!(!strict.modules.is_empty());
        assert!(strict.modules.iter().all(|m| !base.modules.contains(m)));
        assert!(c.iter().all(|r| r.modules.iter().all(|m| !m.title.is_empty())));
    }

    fn entry(time: u64, device: u8, actor: Actor, phase: Phase) -> AuditEntry {
        use fleet_proto::{DeviceId, OpSummary, ResultSummary, Signature};
        AuditEntry {
            seq: time,
            time,
            prev_hash: [0; 32],
            actor,
            device_id: DeviceId([device; 16]),
            command_hash: [0; 32],
            signature: Signature([0; 64]),
            op: OpSummary::from(&Op::PkgRefresh),
            phase,
            result: ResultSummary::Pending,
        }
    }

    #[test]
    fn activity_is_read_from_the_mirrored_audit_entries() {
        let ai = || Actor::Ai {
            client: fleet_proto::BoundedString::new("claude").unwrap(),
            session: [0; 16],
        };
        let entries = [
            entry(10, 1, Actor::Human, Phase::Intent),
            entry(30, 1, Actor::Human, Phase::Result),
            entry(20, 2, ai(), Phase::Intent),
            entry(21, 2, ai(), Phase::Result),
            entry(5, 2, ai(), Phase::Intent),
        ];
        let last = last_active(&entries);
        assert_eq!(last[&device_hex(&fleet_proto::DeviceId([1; 16]))], 30);
        assert_eq!(last[&device_hex(&fleet_proto::DeviceId([2; 16]))], 21);
        // Only AI intents at or after the cutoff count.
        assert_eq!(ai_actions(&entries, 0), 2);
        assert_eq!(ai_actions(&entries, 20), 1);
        assert_eq!(ai_actions(&entries, 22), 0);
    }

    #[test]
    fn synced_collections_name_the_user_visible_data() {
        let c = synced_collections();
        assert!(c.contains(&"Alert rules".to_string()));
        assert!(c.contains(&"Audit mirrors".to_string()));
        assert!(!c.iter().any(|s| s.contains("Device")));
    }
}
