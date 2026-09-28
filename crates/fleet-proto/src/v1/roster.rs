//! Device roster (design §5.3) and release manifests (§5.7).

use super::{BoundedString, DeviceId, Ed25519Public, FleetId, P256Public, Signature, X25519Public};
use crate::{domain, encode};
use serde::{Deserialize, Serialize};

pub type Hash32 = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roster {
    pub fleet_id: FleetId,
    /// Incremented only by a recovery roster.
    pub epoch: u32,
    /// Strictly increasing across epochs.
    pub version: u64,
    /// BLAKE3 of the previous `SignedRoster` encoding (zeros for the genesis roster).
    pub prev_hash: Hash32,
    /// Unix ms when the signing Mac built this roster. Non-decreasing.
    pub issued_at_ms: u64,
    pub devices: Vec<Device>,
    pub recovery_key: Ed25519Public,
    pub recovery_ssh_key: Ed25519Public,
    pub recovery_escrow_key: X25519Public,
    /// 0 when a passphrase is set; 72 h by default otherwise.
    pub recovery_delay_s: u32,
    /// Recovery keys replaced by a normal update, still accepted for recovery
    /// until `valid_until_ms` (design §5.3 rule 6).
    pub prev_recovery: Option<PrevRecovery>,
}

impl Roster {
    pub fn device(&self, id: &DeviceId) -> Option<&Device> {
        self.devices.iter().find(|d| d.id == *id)
    }

    /// `(recovery_key, recovery_ssh_key, recovery_escrow_key)`.
    pub fn recovery_keys(&self) -> (Ed25519Public, Ed25519Public, X25519Public) {
        (
            self.recovery_key,
            self.recovery_ssh_key,
            self.recovery_escrow_key,
        )
    }
}

/// Grace record for a rotated recovery key set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrevRecovery {
    pub recovery_key: Ed25519Public,
    pub recovery_ssh_key: Ed25519Public,
    pub recovery_escrow_key: X25519Public,
    /// The replaced roster's `recovery_delay_s`. While the grace window is
    /// open a recovery roster waits `min(current delay, this)`, so a rotation
    /// can't lengthen the delay the real recovery code faces.
    pub recovery_delay_s: u32,
    /// Unix ms; the old keys are accepted strictly before this (agents may
    /// extend the window on their own clock, see fleet-crypto `RecoveryClock`).
    pub valid_until_ms: u64,
}

impl PrevRecovery {
    pub fn recovery_keys(&self) -> (Ed25519Public, Ed25519Public, X25519Public) {
        (
            self.recovery_key,
            self.recovery_ssh_key,
            self.recovery_escrow_key,
        )
    }

    pub fn active_at(&self, now_ms: u64) -> bool {
        now_ms < self.valid_until_ms
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    Admin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub id: DeviceId,
    pub name: BoundedString<64>,
    pub role: Role,
    pub root_key: P256Public,
    pub device_key: P256Public,
    pub monitor_key: P256Public,
    pub ssh_key: P256Public,
    /// SSH key of read-only monitor sessions (Secure Enclave, usable while
    /// the app is locked). `authorized_keys` pins it to
    /// `fleet-agent bridge --monitor` (design §5.9).
    pub monitor_ssh_key: P256Public,
    pub noise_static: X25519Public,
    pub added_at: u64,
    pub added_by: DeviceId,
}

/// Which key signed a roster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyRef {
    /// Root key of this device in the *current* (previous) roster.
    Root(DeviceId),
    /// Recovery key of the current roster.
    Recovery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRoster {
    pub roster: Roster,
    pub signer: KeyRef,
    /// Over `domain::ROSTER ‖ postcard(roster)`.
    pub signature: Signature,
}

impl SignedRoster {
    pub fn signed_message(roster: &Roster) -> Vec<u8> {
        domain::concat(domain::ROSTER, &[&encode(roster)])
    }
}

/// Semantic agent version, ordered by (major, minor, patch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AgentVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

/// CPU architecture of a static (musl) agent build (design §5.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentTarget {
    X86_64,
    Aarch64,
}

impl AgentTarget {
    /// The architecture this code was compiled for; `None` on any other
    /// (e.g. a Mac building for tests is `aarch64` too, which is fine: the
    /// agent compares against its own build).
    pub fn current() -> Option<Self> {
        match std::env::consts::ARCH {
            "x86_64" => Some(Self::X86_64),
            "aarch64" => Some(Self::Aarch64),
            _ => None,
        }
    }

    /// Rust/Debian-neutral name (`x86_64`, `aarch64`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }

    /// Parses [`AgentTarget::as_str`] and the Debian names (`amd64`, `arm64`).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "x86_64" | "amd64" => Some(Self::X86_64),
            "aarch64" | "arm64" => Some(Self::Aarch64),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseManifest {
    /// Agents refuse any version not above the running one (design §5.7).
    pub version: AgentVersion,
    /// BLAKE3 of the agent binary.
    pub blake3: Hash32,
    /// Oldest wire protocol the build still speaks; an agent refuses a
    /// build whose `min_proto` is above its own `PROTO_VERSION` (the Macs
    /// talking to it now couldn't talk to the new build).
    pub min_proto: u16,
    /// Architecture the binary was built for; staging refuses a mismatch.
    pub target: AgentTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedReleaseManifest {
    pub manifest: ReleaseManifest,
    /// Mac whose root key signed.
    pub device_id: DeviceId,
    /// Over `domain::RELEASE ‖ postcard(manifest)`.
    pub signature: Signature,
}

impl SignedReleaseManifest {
    pub fn signed_message(manifest: &ReleaseManifest) -> Vec<u8> {
        domain::concat(domain::RELEASE, &[&encode(manifest)])
    }
}
