//! Agent release manifests (design §5.7, §10.2).
//!
//! A Mac root key signs `ReleaseManifest { version, blake3, min_proto,
//! target }` once for the fleet (Touch ID). Agents accept a build only when
//! the signer is a device of their **current** roster, the version is above
//! the running one, the target is their architecture and they speak the
//! build's `min_proto`.

use crate::Error;
use crate::sig::{self, Signer};
use fleet_proto::{
    AgentTarget, AgentVersion, DeviceId, ReleaseManifest, Roster, SignedReleaseManifest,
};

/// Why a manifest was refused. Maps to wire codes in the agent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReleaseError {
    #[error("signer is not a device of the current roster")]
    UnknownSigner,
    #[error("manifest signature does not verify")]
    BadSignature,
    #[error("version {got:?} is not above the running {running:?}")]
    NotNewer {
        got: AgentVersion,
        running: AgentVersion,
    },
    #[error("build is for {got:?}, this host is {host:?}")]
    WrongTarget {
        got: AgentTarget,
        host: Option<AgentTarget>,
    },
    #[error("build needs protocol {min_proto}, this agent speaks {proto}")]
    Protocol { min_proto: u16, proto: u16 },
    #[error("binary hash differs from the manifest")]
    HashMismatch,
}

/// Signs `manifest` with a Mac root key.
pub fn sign_release(
    manifest: ReleaseManifest,
    device_id: DeviceId,
    root: &(impl Signer + ?Sized),
) -> Result<SignedReleaseManifest, Error> {
    let signature = sig::p256_sign(root, &SignedReleaseManifest::signed_message(&manifest))?;
    Ok(SignedReleaseManifest {
        manifest,
        device_id,
        signature,
    })
}

/// The signature alone: a root key of a device in `roster` (low-S, raw).
pub fn verify_signature(
    signed: &SignedReleaseManifest,
    roster: &Roster,
) -> Result<(), ReleaseError> {
    let dev = roster
        .device(&signed.device_id)
        .ok_or(ReleaseError::UnknownSigner)?;
    sig::p256_verify(
        &dev.root_key,
        &SignedReleaseManifest::signed_message(&signed.manifest),
        &signed.signature,
    )
    .map_err(|_| ReleaseError::BadSignature)
}

/// What the receiving agent is.
#[derive(Debug, Clone, Copy)]
pub struct Host {
    pub running: AgentVersion,
    pub target: Option<AgentTarget>,
    pub proto: u16,
}

/// Every agent-side check but the binary hash: signature by the current
/// roster, strictly newer version, same target, protocol compatible.
pub fn verify_release(
    signed: &SignedReleaseManifest,
    roster: &Roster,
    host: Host,
) -> Result<(), ReleaseError> {
    verify_signature(signed, roster)?;
    let m = &signed.manifest;
    if m.version <= host.running {
        return Err(ReleaseError::NotNewer {
            got: m.version,
            running: host.running,
        });
    }
    if host.target != Some(m.target) {
        return Err(ReleaseError::WrongTarget {
            got: m.target,
            host: host.target,
        });
    }
    if m.min_proto > host.proto {
        return Err(ReleaseError::Protocol {
            min_proto: m.min_proto,
            proto: host.proto,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sig::SoftwareP256Signer;
    use fleet_proto::{BoundedString, Device, FleetId, Role, Signature};

    fn v(major: u16, minor: u16, patch: u16) -> AgentVersion {
        AgentVersion {
            major,
            minor,
            patch,
        }
    }

    fn roster(root: &SoftwareP256Signer) -> Roster {
        let k = root.public();
        Roster {
            fleet_id: FleetId([1; 16]),
            epoch: 0,
            version: 1,
            prev_hash: [0; 32],
            issued_at_ms: 0,
            devices: vec![Device {
                id: DeviceId([2; 16]),
                name: BoundedString::new("mac").unwrap(),
                role: Role::Admin,
                root_key: k,
                device_key: k,
                monitor_key: k,
                ssh_key: k,
                monitor_ssh_key: k,
                noise_static: fleet_proto::X25519Public([6; 32]),
                added_at: 0,
                added_by: DeviceId([2; 16]),
            }],
            recovery_key: fleet_proto::Ed25519Public([3; 32]),
            recovery_ssh_key: fleet_proto::Ed25519Public([4; 32]),
            recovery_escrow_key: fleet_proto::X25519Public([5; 32]),
            recovery_delay_s: 60,
            prev_recovery: None,
        }
    }

    fn manifest(version: AgentVersion) -> ReleaseManifest {
        ReleaseManifest {
            version,
            blake3: [9; 32],
            min_proto: 1,
            target: AgentTarget::X86_64,
        }
    }

    fn host() -> Host {
        Host {
            running: v(0, 1, 0),
            target: Some(AgentTarget::X86_64),
            proto: 1,
        }
    }

    #[test]
    fn accepts_signed_newer_matching_build() {
        let root = SoftwareP256Signer::from_bytes(&[7; 32]).unwrap();
        let r = roster(&root);
        let s = sign_release(manifest(v(0, 2, 0)), DeviceId([2; 16]), &root).unwrap();
        verify_release(&s, &r, host()).unwrap();
    }

    #[test]
    fn refuses_downgrade_same_version_wrong_target_and_protocol() {
        let root = SoftwareP256Signer::from_bytes(&[7; 32]).unwrap();
        let r = roster(&root);
        let sign = |m| sign_release(m, DeviceId([2; 16]), &root).unwrap();
        for ver in [v(0, 1, 0), v(0, 0, 9)] {
            assert!(matches!(
                verify_release(&sign(manifest(ver)), &r, host()),
                Err(ReleaseError::NotNewer { .. })
            ));
        }
        let mut arm = manifest(v(0, 2, 0));
        arm.target = AgentTarget::Aarch64;
        assert!(matches!(
            verify_release(&sign(arm), &r, host()),
            Err(ReleaseError::WrongTarget { .. })
        ));
        let mut proto = manifest(v(0, 2, 0));
        proto.min_proto = 2;
        assert!(matches!(
            verify_release(&sign(proto), &r, host()),
            Err(ReleaseError::Protocol { .. })
        ));
    }

    #[test]
    fn refuses_foreign_signer_and_tampering() {
        let root = SoftwareP256Signer::from_bytes(&[7; 32]).unwrap();
        let other = SoftwareP256Signer::from_bytes(&[8; 32]).unwrap();
        let r = roster(&root);
        let forged = sign_release(manifest(v(0, 2, 0)), DeviceId([2; 16]), &other).unwrap();
        assert_eq!(
            verify_release(&forged, &r, host()),
            Err(ReleaseError::BadSignature)
        );
        let unknown = sign_release(manifest(v(0, 2, 0)), DeviceId([6; 16]), &root).unwrap();
        assert_eq!(
            verify_release(&unknown, &r, host()),
            Err(ReleaseError::UnknownSigner)
        );
        let mut tampered = sign_release(manifest(v(0, 2, 0)), DeviceId([2; 16]), &root).unwrap();
        tampered.manifest.blake3 = [1; 32];
        assert_eq!(
            verify_release(&tampered, &r, host()),
            Err(ReleaseError::BadSignature)
        );
        let mut zero = tampered.clone();
        zero.signature = Signature([0; 64]);
        assert!(verify_release(&zero, &r, host()).is_err());
    }
}
