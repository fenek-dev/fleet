//! Protocol version 1 wire types. Frozen once released (design §6.2).

mod actor;
mod audit;
mod command;
mod error;
mod ids;
mod keys;
mod message;
pub mod op;
pub mod policy;
mod roster;

pub use actor::Actor;
pub use audit::{
    AuditEntry, Checkpoint, OpSummary, Outcome, Phase, Receipt, ResultSummary, SignedCheckpoint,
    SignedReceipt,
};
pub use command::{
    ApprovalBody, ApprovalItem, CommandBody, MerkleProof, RootApproval, SignedCommand,
};
pub use error::ErrorCode;
pub use ids::{BoundedString, DeviceId, FleetId, IdError, ServerId};
pub use keys::{Ed25519Public, KeyKind, P256Public, Signature, X25519Public};
pub use message::{
    AgentHealth, Event, Message, MessageKind, Payload, PendingRecovery, RequestId, SignedEvent,
    SystemInfo, event_tag, payload_tag,
};
pub use op::{Authorization, Group, Op, Tier};
pub use policy::{Policy, PolicyError};
pub use roster::{
    AgentVersion, Device, Hash32, KeyRef, PrevRecovery, ReleaseManifest, Role, Roster,
    SignedReleaseManifest, SignedRoster,
};

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub fn signed_roster() -> SignedRoster {
        let mut key = [0x11; 33];
        key[0] = 0x02;
        SignedRoster {
            roster: Roster {
                fleet_id: FleetId([1; 16]),
                epoch: 0,
                version: 1,
                prev_hash: [0; 32],
                issued_at_ms: 1_700_000_000_000,
                devices: vec![Device {
                    id: DeviceId([2; 16]),
                    name: BoundedString::new("MacBook Pro 16").unwrap(),
                    role: Role::Admin,
                    root_key: P256Public(key),
                    device_key: P256Public(key),
                    monitor_key: P256Public(key),
                    ssh_key: P256Public(key),
                    noise_static: X25519Public([3; 32]),
                    added_at: 1_700_000_000_000,
                    added_by: DeviceId([2; 16]),
                }],
                recovery_key: Ed25519Public([4; 32]),
                recovery_ssh_key: Ed25519Public([5; 32]),
                recovery_escrow_key: X25519Public([6; 32]),
                recovery_delay_s: 72 * 3600,
                prev_recovery: None,
            },
            signer: KeyRef::Root(DeviceId([2; 16])),
            signature: Signature([9; 64]),
        }
    }
}
