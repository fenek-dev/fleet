//! Application frames inside the Noise session (design §6.3).

use super::{
    AgentVersion, DeviceId, ErrorCode, Event, Hash32, KeyKind, Payload, ServerId, Signature,
    SignedCommand, SignedReceipt,
};
use crate::{domain, encode};
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode;

    #[test]
    fn unknown_event_inside_frame() {
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
}
