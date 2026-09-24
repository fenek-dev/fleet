//! Pushed events (design §4.5), carried in `SignedEvent` and stored in the
//! agent's `events` table. Tagged like `Op`, so newer agents can add events
//! without breaking older apps (they see [`Event::Unknown`]). Strings are
//! untrusted server data.

use super::alert::Severity;
use super::args::Protocol;
use super::payload::{BanReason, ChangeSource, IntegrityKind, PackageChange, UnitActiveState};
use super::{DeviceId, Hash32, PendingRecovery};
use crate::tagged::tagged_enum;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UserChangeKind {
    UserAdded,
    UserRemoved,
    UserLocked,
    UserUnlocked,
    GroupAdded,
    GroupRemoved,
    MembershipChanged,
    SudoerAdded,
    SudoerRemoved,
}

/// Docker event action; others map to `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ContainerAction {
    Create,
    Start,
    Stop,
    Die,
    Oom,
    Restart,
    Destroy,
    Unhealthy,
    Healthy,
    Other,
}

tagged_enum! {
    pub enum Event, tags = event_tag, expecting = "(event tag, payload)" {
        RosterChanged { epoch: u32, version: u64 } = ROSTER_CHANGED(0, "roster.changed"),
        RecoveryPending(p: PendingRecovery) = RECOVERY_PENDING(1, "recovery.pending"),
        RecoveryVetoed { hash: Hash32 } = RECOVERY_VETOED(2, "recovery.vetoed"),
        PolicyChanged { version: u64 } = POLICY_CHANGED(3, "policy.changed"),
        /// An auto-revert timer fired and restored a pending change (design §4.10).
        ChangeReverted {
            change_id: [u8; 16],
            /// Seq of the `Actor::System` audit entry that recorded the revert.
            audit_seq: u64,
        } = CHANGE_REVERTED(4, "change.reverted"),

        /// An alert rule's condition started holding.
        AlertFired {
            rule_id: String,
            severity: Severity,
            /// What it fired on: a mount, unit, container, port, …
            subject: String,
            /// Current value in the rule's threshold unit.
            value: u64,
        } = ALERT_FIRED(10, "alert.fired"),
        AlertCleared { rule_id: String, subject: String } = ALERT_CLEARED(11, "alert.cleared"),
        ServiceStateChanged { unit: String, from: UnitActiveState, to: UnitActiveState }
            = SERVICE_STATE_CHANGED(12, "service.state_changed"),
        Login {
            user: String,
            source: Option<IpAddr>,
            success: bool,
            /// First login from this source (design §2.4 change alerts).
            new_source: bool,
            device_id: Option<DeviceId>,
        } = LOGIN(13, "login"),
        BanChanged { addr: IpAddr, banned: bool, until_ms: Option<u64>, reason: BanReason }
            = BAN_CHANGED(14, "ban.changed"),
        PackagesChanged { changes: Vec<PackageChange> } = PACKAGES_CHANGED(15, "packages.changed"),
        ConfigChanged { path: String, version: u64, source: ChangeSource, secret: bool }
            = CONFIG_CHANGED(16, "config.changed"),
        NewListeningPort {
            proto: Protocol,
            addr: IpAddr,
            port: u16,
            process: Option<String>,
            /// Fleet's Managed chain would block it (design §4.8).
            blocked: bool,
        } = NEW_LISTENING_PORT(17, "port.new"),
        UserChanged { kind: UserChangeKind, name: String } = USER_CHANGED(18, "user.changed"),
        AuthorizedKeysChanged { user: String, source: ChangeSource }
            = AUTHORIZED_KEYS_CHANGED(19, "authorized_keys.changed"),
        IntegrityViolation { path: String, kind: IntegrityKind }
            = INTEGRITY_VIOLATION(20, "integrity.violation"),
        CertExpiring { source: String, subject: String, not_after_ms: u64 }
            = CERT_EXPIRING(21, "cert.expiring"),
        Container { id: String, name: String, action: ContainerAction, exit_code: Option<i32> }
            = CONTAINER(22, "container"),
        HealthCheckChanged { check_id: String, ok: bool } = HEALTH_CHECK_CHANGED(23, "health_check.changed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tagged::Bytes;
    use crate::{decode, encode};
    use std::collections::HashSet;

    pub(crate) fn samples() -> Vec<Event> {
        fn _exhaustive(e: &Event) {
            match e {
                Event::RosterChanged { .. }
                | Event::RecoveryPending(_)
                | Event::RecoveryVetoed { .. }
                | Event::PolicyChanged { .. }
                | Event::ChangeReverted { .. }
                | Event::AlertFired { .. }
                | Event::AlertCleared { .. }
                | Event::ServiceStateChanged { .. }
                | Event::Login { .. }
                | Event::BanChanged { .. }
                | Event::PackagesChanged { .. }
                | Event::ConfigChanged { .. }
                | Event::NewListeningPort { .. }
                | Event::UserChanged { .. }
                | Event::AuthorizedKeysChanged { .. }
                | Event::IntegrityViolation { .. }
                | Event::CertExpiring { .. }
                | Event::Container { .. }
                | Event::HealthCheckChanged { .. }
                | Event::Unknown { .. } => {}
            }
        }
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        vec![
            Event::RosterChanged {
                epoch: 1,
                version: 2,
            },
            Event::RecoveryPending(PendingRecovery {
                hash: [1; 32],
                activates_at_ms: 3,
            }),
            Event::RecoveryVetoed { hash: [2; 32] },
            Event::PolicyChanged { version: 4 },
            Event::ChangeReverted {
                change_id: [5; 16],
                audit_seq: 6,
            },
            Event::AlertFired {
                rule_id: "disk".into(),
                severity: Severity::Critical,
                subject: "/".into(),
                value: 951,
            },
            Event::AlertCleared {
                rule_id: "disk".into(),
                subject: "/".into(),
            },
            Event::ServiceStateChanged {
                unit: "nginx.service".into(),
                from: UnitActiveState::Active,
                to: UnitActiveState::Failed,
            },
            Event::Login {
                user: "ops".into(),
                source: Some(ip),
                success: true,
                new_source: false,
                device_id: Some(DeviceId([1; 16])),
            },
            Event::BanChanged {
                addr: ip,
                banned: true,
                until_ms: Some(9),
                reason: BanReason::SshBruteForce,
            },
            Event::PackagesChanged {
                changes: vec![PackageChange {
                    name: "curl".into(),
                    action: crate::v1::payload::PkgAction::Upgrade,
                    from: Some("1".into()),
                    to: Some("2".into()),
                }],
            },
            Event::ConfigChanged {
                path: "/etc/hosts".into(),
                version: 3,
                source: ChangeSource::Unknown,
                secret: false,
            },
            Event::NewListeningPort {
                proto: Protocol::Udp,
                addr: "::".parse().unwrap(),
                port: 27015,
                process: Some("srcds".into()),
                blocked: true,
            },
            Event::UserChanged {
                kind: UserChangeKind::SudoerAdded,
                name: "eve".into(),
            },
            Event::AuthorizedKeysChanged {
                user: "ops".into(),
                source: ChangeSource::Fleet {
                    op_tag: 821,
                    audit_seq: 7,
                },
            },
            Event::IntegrityViolation {
                path: "/usr/bin/sudo".into(),
                kind: IntegrityKind::Modified,
            },
            Event::CertExpiring {
                source: "/etc/letsencrypt/live/x/fullchain.pem".into(),
                subject: "example.com".into(),
                not_after_ms: 10,
            },
            Event::Container {
                id: "abc".into(),
                name: "web".into(),
                action: ContainerAction::Die,
                exit_code: Some(137),
            },
            Event::HealthCheckChanged {
                check_id: "api".into(),
                ok: false,
            },
        ]
    }

    #[test]
    fn tags_unique_and_roundtrip() {
        let mut tags = HashSet::new();
        for e in samples() {
            assert!(tags.insert(e.tag()), "duplicate event tag {}", e.tag());
            assert_eq!(decode::<Event>(&encode(&e)).unwrap(), e, "{}", e.name());
        }
        assert_eq!(tags.len(), event_tag::ALL.len());
        let names: HashSet<_> = event_tag::NAMES.iter().collect();
        assert_eq!(names.len(), event_tag::NAMES.len());
        assert_eq!(
            (
                event_tag::ROSTER_CHANGED,
                event_tag::RECOVERY_PENDING,
                event_tag::RECOVERY_VETOED,
                event_tag::POLICY_CHANGED,
                event_tag::CHANGE_REVERTED
            ),
            (0, 1, 2, 3, 4)
        );
    }

    #[test]
    fn unknown_and_bad_events() {
        let bytes = encode(&(900u16, Bytes(&[1, 2, 3]), 42u8));
        let (e, rest): (Event, u8) = decode(&bytes).unwrap();
        assert_eq!((e, rest), (Event::Unknown { tag: 900 }, 42));
        let bytes = encode(&(event_tag::POLICY_CHANGED, Bytes(&[])));
        assert!(decode::<Event>(&bytes).is_err());
        let bytes = encode(&(event_tag::CHANGE_REVERTED, Bytes(&[0; 16])));
        assert!(decode::<Event>(&bytes).is_err());
    }
}
