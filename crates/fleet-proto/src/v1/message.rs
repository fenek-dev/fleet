//! Application frames inside the Noise session (design §6.3).

use super::{
    AgentVersion, DeviceId, ErrorCode, Hash32, KeyKind, ServerId, Signature, SignedCommand,
    SignedReceipt,
};
use crate::tagged::{Tagged, tagged_serde, unit};
use crate::{DecodeError, decode, domain, encode};
use serde::{Deserialize, Serialize};

pub type RequestId = u32;

/// Variant order is the postcard wire index (see [`MessageKind`]); append
/// only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
    /// Mac → agent. `sig` is over [`Message::device_auth_message`].
    DeviceAuth {
        device_id: DeviceId,
        key: KeyKind,
        sig: Signature,
    },
    /// **Advisory only** (design §5.5): nothing here is signed by the agent
    /// key, so a compromised gate can lie about roster status and
    /// `pending_recovery`. Use it for version negotiation and the clock-skew
    /// warning; confirm roster/recovery state with a signed `agent.health`
    /// (or `roster.pending`) response at session start.
    Hello {
        proto_min: u16,
        proto_max: u16,
        agent_version: AgentVersion,
        server_id: ServerId,
        time_ms: u64,
        roster_epoch: u32,
        roster_version: u64,
        pending_recovery: Option<PendingRecovery>,
    },
    Request {
        id: RequestId,
        cmd: SignedCommand,
    },
    /// `receipt` is `Some` for every response exec gives to a command it
    /// could decode (success or error, design §5.6). It is `None` only when
    /// no signed statement is possible: exec could not decode the
    /// `SignedCommand`, or the gate answered itself (rate limit, session
    /// mode). Clients treat `None` as "outcome unknown" for state-changing
    /// ops and never as proof of failure or success.
    Response {
        id: RequestId,
        result: Result<Payload, ErrorCode>,
        receipt: Option<SignedReceipt>,
    },
    StreamOpen {
        id: RequestId,
        cmd: SignedCommand,
    },
    StreamData {
        id: RequestId,
        seq: u64,
        chunk: Vec<u8>,
    },
    StreamEnd {
        id: RequestId,
        status: Result<(), ErrorCode>,
    },
    StreamCancel {
        id: RequestId,
    },
    /// Agent → Mac, signed by the agent key.
    Event(SignedEvent),
    /// Noise control (design §5.5). The sender sends it, then rekeys its
    /// outgoing cipher; the receiver rekeys its incoming cipher right after
    /// decrypting it. Handled by the gate (agent side) and the Mac core; it is
    /// always a single one-chunk frame, recognized with [`Message::kind_tag`]
    /// without reassembly.
    Rekey,
}

/// Postcard variant index of each [`Message`] variant: the first byte of
/// every encoded frame (a varint below 128 is one byte). Lets the gate route
/// a chunk without decoding it. Pinned by tests against real encodings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageKind {
    DeviceAuth = 0,
    Hello = 1,
    Request = 2,
    Response = 3,
    StreamOpen = 4,
    StreamData = 5,
    StreamEnd = 6,
    StreamCancel = 7,
    Event = 8,
    Rekey = 9,
}

impl MessageKind {
    pub const ALL: [MessageKind; 10] = [
        MessageKind::DeviceAuth,
        MessageKind::Hello,
        MessageKind::Request,
        MessageKind::Response,
        MessageKind::StreamOpen,
        MessageKind::StreamData,
        MessageKind::StreamEnd,
        MessageKind::StreamCancel,
        MessageKind::Event,
        MessageKind::Rekey,
    ];

    /// The frame's first byte for this kind.
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

impl Message {
    pub fn kind(&self) -> MessageKind {
        match self {
            Message::DeviceAuth { .. } => MessageKind::DeviceAuth,
            Message::Hello { .. } => MessageKind::Hello,
            Message::Request { .. } => MessageKind::Request,
            Message::Response { .. } => MessageKind::Response,
            Message::StreamOpen { .. } => MessageKind::StreamOpen,
            Message::StreamData { .. } => MessageKind::StreamData,
            Message::StreamEnd { .. } => MessageKind::StreamEnd,
            Message::StreamCancel { .. } => MessageKind::StreamCancel,
            Message::Event(_) => MessageKind::Event,
            Message::Rekey => MessageKind::Rekey,
        }
    }

    /// Kind of an encoded frame from its first byte, without decoding it.
    /// `None` for empty input or an unknown index. Only a hint for routing:
    /// the frame may still fail to decode.
    pub fn kind_tag(frame: &[u8]) -> Option<MessageKind> {
        let first = *frame.first()?;
        MessageKind::ALL.into_iter().find(|k| k.tag() == first)
    }

    /// `domain::AUTH ‖ postcard(key) ‖ device_id (16) ‖ handshake_hash`.
    /// `postcard(key)` is one byte; `device_id` is raw, so the signer's
    /// claimed identity is authenticated.
    pub fn device_auth_message(
        key: KeyKind,
        device_id: &DeviceId,
        handshake_hash: &[u8],
    ) -> Vec<u8> {
        domain::concat(domain::AUTH, &[&encode(&key), &device_id.0, handshake_hash])
    }
}

/// A recovery roster waiting out its delay (design §5.3 rule 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRecovery {
    /// BLAKE3 of the pending `SignedRoster` encoding; the `roster.veto` argument.
    pub hash: Hash32,
    pub activates_at_ms: u64,
}

/// `Payload` wire tags (design §6.2). Explicit; never reorder or reuse.
pub mod payload_tag {
    pub const EMPTY: u16 = 0;
    pub const SYSTEM_INFO: u16 = 1;
    pub const AGENT_HEALTH: u16 = 2;
    pub const ROSTER_PENDING: u16 = 3;
}

/// Successful response payloads. Tagged like `Op`: an app that doesn't know a
/// tag gets [`Payload::Unknown`] instead of a decode failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    Empty,
    SystemInfo(SystemInfo),
    AgentHealth(AgentHealth),
    RosterPending(Option<PendingRecovery>),
    /// A tag this build doesn't know. Serializes with an empty payload.
    Unknown {
        tag: u16,
    },
}

impl Payload {
    pub fn tag(&self) -> u16 {
        match self {
            Payload::Empty => payload_tag::EMPTY,
            Payload::SystemInfo(_) => payload_tag::SYSTEM_INFO,
            Payload::AgentHealth(_) => payload_tag::AGENT_HEALTH,
            Payload::RosterPending(_) => payload_tag::ROSTER_PENDING,
            Payload::Unknown { tag } => *tag,
        }
    }
}

impl Tagged for Payload {
    const EXPECTING: &'static str = "(payload tag, payload)";

    fn wire_tag(&self) -> u16 {
        self.tag()
    }

    fn wire_payload(&self) -> Vec<u8> {
        match self {
            Payload::Empty | Payload::Unknown { .. } => Vec::new(),
            Payload::SystemInfo(v) => encode(v),
            Payload::AgentHealth(v) => encode(v),
            Payload::RosterPending(v) => encode(v),
        }
    }

    fn from_wire(tag: u16, payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(match tag {
            payload_tag::EMPTY => unit(Payload::Empty, payload)?,
            payload_tag::SYSTEM_INFO => Payload::SystemInfo(decode(payload)?),
            payload_tag::AGENT_HEALTH => Payload::AgentHealth(decode(payload)?),
            payload_tag::ROSTER_PENDING => Payload::RosterPending(decode(payload)?),
            tag => Payload::Unknown { tag },
        })
    }
}

tagged_serde!(Payload);

/// Server-reported strings are untrusted data (security rule 6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub os_id: String,
    pub os_version: String,
    pub kernel: String,
    pub arch: String,
    pub cpu_count: u32,
    pub mem_total_bytes: u64,
    pub uptime_s: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentHealth {
    pub agent_version: AgentVersion,
    pub proto_version: u16,
    pub uptime_s: u64,
    pub gate_rss_bytes: u64,
    pub exec_rss_bytes: u64,
    pub audit_seq: u64,
    pub roster_epoch: u32,
    pub roster_version: u64,
    pub policy_version: u64,
    /// Signed counterpart of `Hello.pending_recovery`: one receipted
    /// `agent.health` read confirms the roster state at session start.
    pub pending_recovery: Option<PendingRecovery>,
    /// Random per exec start; every [`SignedEvent`] of this run carries it,
    /// so the Mac can refuse events replayed from an earlier run.
    pub run_id: [u8; 16],
}

/// An event signed by the agent key over
/// `domain::EVENT ‖ postcard((server_id, run_id, seq, time_ms, event))`
/// ([`SignedEvent::signed_message`]). `run_id` names the exec run (see
/// [`AgentHealth::run_id`]) and `seq` is that run's event sequence, so the
/// Mac can detect dropped or replayed events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEvent {
    pub server_id: ServerId,
    pub run_id: [u8; 16],
    pub seq: u64,
    pub time_ms: u64,
    pub event: Event,
    pub sig: Signature,
}

impl SignedEvent {
    pub fn signed_message(
        server_id: &ServerId,
        run_id: &[u8; 16],
        seq: u64,
        time_ms: u64,
        event: &Event,
    ) -> Vec<u8> {
        domain::concat(
            domain::EVENT,
            &[&encode(&(server_id, run_id, seq, time_ms, event))],
        )
    }
}

/// `Event` wire tags (design §6.2). Explicit; never reorder or reuse.
pub mod event_tag {
    pub const ROSTER_CHANGED: u16 = 0;
    pub const RECOVERY_PENDING: u16 = 1;
    pub const RECOVERY_VETOED: u16 = 2;
    pub const POLICY_CHANGED: u16 = 3;
    pub const CHANGE_REVERTED: u16 = 4;
}

/// Pushed events. Tagged like `Op`, so newer agents can add events without
/// breaking older apps (they see [`Event::Unknown`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    RosterChanged {
        epoch: u32,
        version: u64,
    },
    RecoveryPending(PendingRecovery),
    RecoveryVetoed {
        hash: Hash32,
    },
    PolicyChanged {
        version: u64,
    },
    /// An auto-revert timer fired and restored a pending change (design §4.10).
    ChangeReverted {
        change_id: [u8; 16],
        /// Seq of the `Actor::System` audit entry that recorded the revert.
        audit_seq: u64,
    },
    /// A tag this build doesn't know. Serializes with an empty payload.
    Unknown {
        tag: u16,
    },
}

impl Event {
    pub fn tag(&self) -> u16 {
        match self {
            Event::RosterChanged { .. } => event_tag::ROSTER_CHANGED,
            Event::RecoveryPending(_) => event_tag::RECOVERY_PENDING,
            Event::RecoveryVetoed { .. } => event_tag::RECOVERY_VETOED,
            Event::PolicyChanged { .. } => event_tag::POLICY_CHANGED,
            Event::ChangeReverted { .. } => event_tag::CHANGE_REVERTED,
            Event::Unknown { tag } => *tag,
        }
    }
}

impl Tagged for Event {
    const EXPECTING: &'static str = "(event tag, payload)";

    fn wire_tag(&self) -> u16 {
        self.tag()
    }

    fn wire_payload(&self) -> Vec<u8> {
        match self {
            Event::RosterChanged { epoch, version } => encode(&(epoch, version)),
            Event::RecoveryPending(p) => encode(p),
            Event::RecoveryVetoed { hash } => encode(hash),
            Event::PolicyChanged { version } => encode(version),
            Event::ChangeReverted {
                change_id,
                audit_seq,
            } => encode(&(change_id, audit_seq)),
            Event::Unknown { .. } => Vec::new(),
        }
    }

    fn from_wire(tag: u16, payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(match tag {
            event_tag::ROSTER_CHANGED => {
                let (epoch, version) = decode(payload)?;
                Event::RosterChanged { epoch, version }
            }
            event_tag::RECOVERY_PENDING => Event::RecoveryPending(decode(payload)?),
            event_tag::RECOVERY_VETOED => Event::RecoveryVetoed {
                hash: decode(payload)?,
            },
            event_tag::POLICY_CHANGED => Event::PolicyChanged {
                version: decode(payload)?,
            },
            event_tag::CHANGE_REVERTED => {
                let (change_id, audit_seq) = decode(payload)?;
                Event::ChangeReverted {
                    change_id,
                    audit_seq,
                }
            }
            tag => Event::Unknown { tag },
        })
    }
}

tagged_serde!(Event);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tagged::Bytes;

    fn payloads() -> Vec<Payload> {
        fn _exhaustive(p: &Payload) {
            match p {
                Payload::Empty
                | Payload::SystemInfo(_)
                | Payload::AgentHealth(_)
                | Payload::RosterPending(_)
                | Payload::Unknown { .. } => {}
            }
        }
        let v = AgentVersion {
            major: 1,
            minor: 2,
            patch: 3,
        };
        vec![
            Payload::Empty,
            Payload::SystemInfo(SystemInfo {
                hostname: "h".into(),
                os_id: "debian".into(),
                os_version: "12".into(),
                kernel: "6.1".into(),
                arch: "x86_64".into(),
                cpu_count: 4,
                mem_total_bytes: 1 << 30,
                uptime_s: 9,
            }),
            Payload::AgentHealth(AgentHealth {
                agent_version: v,
                proto_version: 1,
                uptime_s: 1,
                gate_rss_bytes: 2,
                exec_rss_bytes: 3,
                audit_seq: 4,
                roster_epoch: 5,
                roster_version: 6,
                policy_version: 7,
                pending_recovery: Some(PendingRecovery {
                    hash: [8; 32],
                    activates_at_ms: 9,
                }),
                run_id: [10; 16],
            }),
            Payload::RosterPending(None),
        ]
    }

    fn events() -> Vec<Event> {
        fn _exhaustive(e: &Event) {
            match e {
                Event::RosterChanged { .. }
                | Event::RecoveryPending(_)
                | Event::RecoveryVetoed { .. }
                | Event::PolicyChanged { .. }
                | Event::ChangeReverted { .. }
                | Event::Unknown { .. } => {}
            }
        }
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
        ]
    }

    #[test]
    fn tags_unique_and_roundtrip() {
        let mut tags = std::collections::HashSet::new();
        for p in payloads() {
            assert!(tags.insert(p.tag()), "duplicate payload tag {}", p.tag());
            assert_eq!(decode::<Payload>(&encode(&p)).unwrap(), p);
        }
        let mut tags = std::collections::HashSet::new();
        for e in events() {
            assert!(tags.insert(e.tag()), "duplicate event tag {}", e.tag());
            assert_eq!(decode::<Event>(&encode(&e)).unwrap(), e);
        }
    }

    #[test]
    fn unknown_tags_skip_payload() {
        let bytes = encode(&(900u16, Bytes(&[1, 2, 3]), 42u8));
        let (p, rest): (Payload, u8) = decode(&bytes).unwrap();
        assert_eq!((p, rest), (Payload::Unknown { tag: 900 }, 42));
        let (e, rest): (Event, u8) = decode(&bytes).unwrap();
        assert_eq!((e, rest), (Event::Unknown { tag: 900 }, 42));
        // Inside a full frame.
        let ev = Message::Event(SignedEvent {
            server_id: ServerId::new("srv_abcdef").unwrap(),
            run_id: [0; 16],
            seq: 7,
            time_ms: 1,
            event: Event::Unknown { tag: 900 },
            sig: Signature([0; 64]),
        });
        assert_eq!(decode::<Message>(&encode(&ev)).unwrap(), ev);
    }

    /// One value per `Message` variant; the match makes a new variant a
    /// compile error until it is listed.
    fn messages() -> Vec<Message> {
        fn _exhaustive(m: &Message) {
            match m {
                Message::DeviceAuth { .. }
                | Message::Hello { .. }
                | Message::Request { .. }
                | Message::Response { .. }
                | Message::StreamOpen { .. }
                | Message::StreamData { .. }
                | Message::StreamEnd { .. }
                | Message::StreamCancel { .. }
                | Message::Event(_)
                | Message::Rekey => {}
            }
        }
        let cmd = SignedCommand {
            body: vec![1, 2, 3],
            device_id: DeviceId([1; 16]),
            key: KeyKind::Device,
            signature: Signature([2; 64]),
            approval: None,
        };
        let server_id = ServerId::new("srv_abcdef").unwrap();
        vec![
            Message::DeviceAuth {
                device_id: DeviceId([1; 16]),
                key: KeyKind::Monitor,
                sig: Signature([3; 64]),
            },
            Message::Hello {
                proto_min: 1,
                proto_max: 1,
                agent_version: AgentVersion {
                    major: 0,
                    minor: 1,
                    patch: 0,
                },
                server_id: server_id.clone(),
                time_ms: 5,
                roster_epoch: 0,
                roster_version: 1,
                pending_recovery: None,
            },
            Message::Request {
                id: 300,
                cmd: cmd.clone(),
            },
            Message::Response {
                id: 1,
                result: Err(ErrorCode::Busy),
                receipt: None,
            },
            Message::StreamOpen { id: 2, cmd },
            Message::StreamData {
                id: 3,
                seq: 4,
                chunk: vec![5],
            },
            Message::StreamEnd {
                id: 3,
                status: Ok(()),
            },
            Message::StreamCancel { id: 3 },
            Message::Event(SignedEvent {
                server_id,
                run_id: [5; 16],
                seq: 1,
                time_ms: 2,
                event: Event::PolicyChanged { version: 3 },
                sig: Signature([4; 64]),
            }),
            Message::Rekey,
        ]
    }

    #[test]
    fn kind_tags_pinned_to_encoding() {
        let msgs = messages();
        assert_eq!(msgs.len(), MessageKind::ALL.len());
        for (m, k) in msgs.iter().zip(MessageKind::ALL) {
            assert_eq!(m.kind(), k);
            let bytes = encode(m);
            assert_eq!(bytes[0], k.tag(), "{k:?}");
            assert_eq!(Message::kind_tag(&bytes), Some(k));
            assert_eq!(decode::<Message>(&bytes).unwrap(), *m);
        }
        // Pinned values the gate relies on.
        assert_eq!(MessageKind::Request.tag(), 2);
        assert_eq!(MessageKind::StreamOpen.tag(), 4);
        assert_eq!(MessageKind::StreamCancel.tag(), 7);
        assert_eq!(MessageKind::Rekey.tag(), 9);
        assert_eq!(encode(&Message::Rekey), [9]);
        assert_eq!(Message::kind_tag(&[]), None);
        assert_eq!(Message::kind_tag(&[10]), None);
        assert_eq!(Message::kind_tag(&[0x80, 0x01]), None);
    }

    #[test]
    fn known_tags_reject_bad_payload() {
        let bytes = encode(&(payload_tag::EMPTY, Bytes(&[0])));
        assert!(decode::<Payload>(&bytes).is_err());
        let bytes = encode(&(event_tag::POLICY_CHANGED, Bytes(&[])));
        assert!(decode::<Event>(&bytes).is_err());
        let bytes = encode(&(event_tag::CHANGE_REVERTED, Bytes(&[0; 16])));
        assert!(decode::<Event>(&bytes).is_err());
    }
}
