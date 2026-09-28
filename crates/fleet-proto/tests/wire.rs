//! Wire-format tests: roundtrips, strict decoding, golden vectors.
//!
//! Regenerate vectors (only for a deliberate format change in a NEW proto
//! version): `FLEET_REGEN_VECTORS=1 cargo test -p fleet-proto --test wire golden`.

use fleet_proto::*;
use proptest::prelude::*;
use serde::{Serialize, de::DeserializeOwned};
use std::fmt::Debug;
use std::path::PathBuf;

// ---------- strategies ----------

fn arr<const N: usize>() -> impl Strategy<Value = [u8; N]> {
    prop::collection::vec(any::<u8>(), N).prop_map(|v| v.try_into().unwrap())
}

fn server_id() -> impl Strategy<Value = ServerId> {
    "srv_[a-z0-9]{6,32}".prop_map(|s| ServerId::new(s).unwrap())
}

fn p256() -> impl Strategy<Value = P256Public> {
    (any::<bool>(), arr::<32>()).prop_map(|(odd, x)| {
        let mut k = [0u8; 33];
        k[0] = if odd { 3 } else { 2 };
        k[1..].copy_from_slice(&x);
        P256Public(k)
    })
}

fn sig() -> impl Strategy<Value = Signature> {
    arr::<64>().prop_map(Signature)
}

fn actor() -> impl Strategy<Value = Actor> {
    prop_oneof![
        Just(Actor::Human),
        ("[a-zA-Z0-9 ._-]{0,64}", arr::<16>()).prop_map(|(c, session)| Actor::Ai {
            client: BoundedString::new(c).unwrap(),
            session
        }),
        arr::<16>().prop_map(|id| Actor::Runbook { id }),
        Just(Actor::Recovery),
        Just(Actor::System),
    ]
}

fn device() -> impl Strategy<Value = Device> {
    (
        arr::<16>(),
        "[a-zA-Z0-9 ]{0,64}",
        [p256(), p256(), p256(), p256(), p256()],
        arr::<32>(),
        any::<u64>(),
        arr::<16>(),
    )
        .prop_map(|(id, name, k, noise, added_at, by)| Device {
            id: DeviceId(id),
            name: BoundedString::new(name).unwrap(),
            role: Role::Admin,
            root_key: k[0],
            device_key: k[1],
            monitor_key: k[2],
            ssh_key: k[3],
            monitor_ssh_key: k[4],
            noise_static: X25519Public(noise),
            added_at,
            added_by: DeviceId(by),
        })
}

fn prev_recovery() -> impl Strategy<Value = PrevRecovery> {
    (
        arr::<32>(),
        arr::<32>(),
        arr::<32>(),
        any::<u32>(),
        any::<u64>(),
    )
        .prop_map(|(rk, rs, re, delay, until)| PrevRecovery {
            recovery_key: Ed25519Public(rk),
            recovery_ssh_key: Ed25519Public(rs),
            recovery_escrow_key: X25519Public(re),
            recovery_delay_s: delay,
            valid_until_ms: until,
        })
}

fn roster() -> impl Strategy<Value = Roster> {
    (
        (
            arr::<16>(),
            any::<u32>(),
            any::<u64>(),
            arr::<32>(),
            any::<u64>(),
        ),
        prop::collection::vec(device(), 0..4),
        (arr::<32>(), arr::<32>(), arr::<32>(), any::<u32>()),
        prop::option::of(prev_recovery()),
    )
        .prop_map(
            |((fleet, epoch, version, prev, issued), devices, (rk, rs, re, delay), pr)| Roster {
                fleet_id: FleetId(fleet),
                epoch,
                version,
                prev_hash: prev,
                issued_at_ms: issued,
                devices,
                recovery_key: Ed25519Public(rk),
                recovery_ssh_key: Ed25519Public(rs),
                recovery_escrow_key: X25519Public(re),
                recovery_delay_s: delay,
                prev_recovery: pr,
            },
        )
}

fn signed_roster() -> impl Strategy<Value = SignedRoster> {
    let signer = prop_oneof![
        arr::<16>().prop_map(|d| KeyRef::Root(DeviceId(d))),
        Just(KeyRef::Recovery)
    ];
    (roster(), signer, sig()).prop_map(|(roster, signer, signature)| SignedRoster {
        roster,
        signer,
        signature,
    })
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        Just(Op::SystemInfo),
        Just(Op::AgentHealth),
        signed_roster().prop_map(|r| Op::RosterUpdate {
            roster: Box::new(r)
        }),
        Just(Op::RosterPending),
        arr::<32>().prop_map(|pending_hash| Op::RosterVeto { pending_hash }),
        ".{0,200}".prop_map(|policy_toml| Op::PolicyUpdate { policy_toml }),
        any::<u16>()
            .prop_filter("unknown", |t| !Op::is_known_tag(*t))
            .prop_map(|tag| Op::Unknown { tag }),
    ]
}

fn command_body() -> impl Strategy<Value = CommandBody> {
    (
        (
            any::<u16>(),
            arr::<16>(),
            server_id(),
            any::<u64>(),
            any::<u32>(),
            arr::<16>(),
        ),
        (actor(), op(), any::<Option<u64>>()),
    )
        .prop_map(
            |(
                (v, fleet, server_id, issued_at_ms, ttl_ms, nonce),
                (actor, op, expected_version),
            )| {
                CommandBody {
                    v,
                    fleet_id: FleetId(fleet),
                    server_id,
                    issued_at_ms,
                    ttl_ms,
                    nonce,
                    actor,
                    op,
                    expected_version,
                }
            },
        )
}

fn key_kind() -> impl Strategy<Value = KeyKind> {
    prop_oneof![
        Just(KeyKind::Device),
        Just(KeyKind::Monitor),
        Just(KeyKind::Recovery)
    ]
}

fn root_approval() -> impl Strategy<Value = RootApproval> {
    (
        arr::<16>(),
        prop::collection::vec(any::<u8>(), 0..80),
        sig(),
        any::<u32>(),
        any::<u32>(),
        prop::collection::vec(arr::<32>(), 0..8),
    )
        .prop_map(
            |(d, body, signature, leaf_index, leaf_count, siblings)| RootApproval {
                device_id: DeviceId(d),
                body,
                signature,
                proof: MerkleProof {
                    leaf_index,
                    leaf_count,
                    siblings,
                },
            },
        )
}

fn signed_command() -> impl Strategy<Value = SignedCommand> {
    (
        command_body(),
        arr::<16>(),
        key_kind(),
        sig(),
        prop::option::of(root_approval()),
    )
        .prop_map(|(body, d, key, signature, approval)| SignedCommand {
            body: encode(&body),
            device_id: DeviceId(d),
            key,
            signature,
            approval,
        })
}

fn error_code() -> impl Strategy<Value = ErrorCode> {
    prop_oneof![
        Just(ErrorCode::Unauthorized),
        Just(ErrorCode::Replay),
        Just(ErrorCode::ApprovalRequired),
        any::<u64>().prop_map(|current| ErrorCode::VersionConflict { current }),
        Just(ErrorCode::Unsupported),
    ]
}

fn message() -> impl Strategy<Value = Message> {
    let pending = || {
        (arr::<32>(), any::<u64>()).prop_map(|(hash, activates_at_ms)| PendingRecovery {
            hash,
            activates_at_ms,
        })
    };
    let version =
        (any::<u16>(), any::<u16>(), any::<u16>()).prop_map(|(major, minor, patch)| AgentVersion {
            major,
            minor,
            patch,
        });
    let receipt = (
        server_id(),
        arr::<32>(),
        prop::option::of(any::<u64>()),
        prop_oneof![
            Just(Outcome::Ok),
            error_code().prop_map(Outcome::Failed),
            Just(Outcome::Reverted),
        ],
        arr::<32>(),
        any::<u64>(),
        sig(),
    )
        .prop_map(
            |(server_id, command_hash, audit_seq, outcome, payload_hash, time_ms, signature)| {
                SignedReceipt {
                    receipt: Receipt {
                        server_id,
                        command_hash,
                        audit_seq,
                        outcome,
                        payload_hash,
                        time_ms,
                    },
                    signature,
                }
            },
        );
    let signed_event = |event: BoxedStrategy<Event>| {
        (
            server_id(),
            arr::<16>(),
            any::<u64>(),
            any::<u64>(),
            event,
            sig(),
        )
            .prop_map(|(server_id, run_id, seq, time_ms, event, sig)| {
                Message::Event(SignedEvent {
                    server_id,
                    run_id,
                    seq,
                    time_ms,
                    event,
                    sig,
                })
            })
    };
    prop_oneof![
        (arr::<16>(), key_kind(), sig()).prop_map(|(d, key, sig)| Message::DeviceAuth {
            device_id: DeviceId(d),
            key,
            sig
        }),
        (
            any::<u16>(),
            any::<u16>(),
            version,
            server_id(),
            any::<u64>(),
            any::<u32>(),
            any::<u64>(),
            prop::option::of(pending())
        )
            .prop_map(
                |(
                    proto_min,
                    proto_max,
                    agent_version,
                    server_id,
                    time_ms,
                    roster_epoch,
                    roster_version,
                    pending_recovery,
                )| {
                    Message::Hello {
                        proto_min,
                        proto_max,
                        agent_version,
                        server_id,
                        time_ms,
                        roster_epoch,
                        roster_version,
                        pending_recovery,
                    }
                }
            ),
        (any::<u32>(), signed_command()).prop_map(|(id, cmd)| Message::Request { id, cmd }),
        (
            any::<u32>(),
            prop_oneof![
                Just(Ok(Payload::Empty)),
                prop::option::of(pending()).prop_map(|p| Ok(Payload::RosterPending(p))),
                any::<u16>()
                    .prop_filter("unknown", |t| !Payload::is_known_tag(*t))
                    .prop_map(|tag| Ok(Payload::Unknown { tag })),
                error_code().prop_map(Err),
            ],
            prop::option::of(receipt)
        )
            .prop_map(|(id, result, receipt)| Message::Response {
                id,
                result,
                receipt
            }),
        (any::<u32>(), signed_command()).prop_map(|(id, cmd)| Message::StreamOpen { id, cmd }),
        (
            any::<u32>(),
            any::<u64>(),
            prop::collection::vec(any::<u8>(), 0..256)
        )
            .prop_map(|(id, seq, chunk)| Message::StreamData { id, seq, chunk }),
        (any::<u32>(), prop::option::of(error_code())).prop_map(|(id, e)| Message::StreamEnd {
            id,
            status: e.map_or(Ok(()), Err)
        }),
        any::<u32>().prop_map(|id| Message::StreamCancel { id }),
        signed_event(
            any::<u64>()
                .prop_map(|version| Event::PolicyChanged { version })
                .boxed()
        ),
        signed_event(
            (arr::<16>(), any::<u64>())
                .prop_map(|(change_id, audit_seq)| Event::ChangeReverted {
                    change_id,
                    audit_seq,
                })
                .boxed()
        ),
        signed_event((5u16..).prop_map(|tag| Event::Unknown { tag }).boxed()),
        Just(Message::Rekey),
    ]
}

fn roundtrip<T: Serialize + DeserializeOwned + PartialEq + Debug>(
    v: &T,
) -> Result<(), TestCaseError> {
    let bytes = encode(v);
    prop_assert_eq!(&decode::<T>(&bytes).unwrap(), v);
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn command_body_roundtrip(v in command_body()) { roundtrip(&v)?; }

    #[test]
    fn signed_command_roundtrip(v in signed_command()) {
        roundtrip(&v)?;
        prop_assert!(v.decode_body().is_ok());
    }

    #[test]
    fn roster_roundtrip(v in signed_roster()) { roundtrip(&v)?; }

    #[test]
    fn message_roundtrip(v in message()) { roundtrip(&v)?; }

    #[test]
    fn decode_rejects_trailing_bytes(v in command_body(), extra in prop::collection::vec(any::<u8>(), 1..8)) {
        let mut bytes = encode(&v);
        bytes.extend_from_slice(&extra);
        prop_assert_eq!(decode::<CommandBody>(&bytes), Err(DecodeError::TrailingBytes(extra.len())));
    }
}

// ---------- strict decoding ----------

#[test]
fn decode_rejects_oversize() {
    let big = vec![0u8; MAX_FRAME + 1];
    assert_eq!(
        decode::<Message>(&big),
        Err(DecodeError::TooLarge(MAX_FRAME + 1))
    );
}

#[test]
fn decode_rejects_bad_key_encoding() {
    let mut bytes = encode(&P256Public([2; 33]));
    bytes[0] = 4; // uncompressed prefix
    assert!(decode::<P256Public>(&bytes).is_err());
}

#[test]
fn decode_rejects_bad_server_id() {
    let bytes = encode("srv_BAD");
    assert!(decode::<ServerId>(&bytes).is_err());
}

#[test]
fn unknown_op_inside_command_still_decodes() {
    let mut body = fixture_body();
    body.op = Op::Unknown { tag: 1234 };
    let cmd = SignedCommand {
        body: encode(&body),
        ..fixture_command()
    };
    let msg = decode::<Message>(&encode(&Message::Request { id: 1, cmd })).unwrap();
    let Message::Request { cmd, .. } = msg else {
        panic!()
    };
    assert_eq!(cmd.decode_body().unwrap().op, Op::Unknown { tag: 1234 });
}

// ---------- golden vectors ----------

fn fixture_roster() -> SignedRoster {
    let key = |b: u8| {
        P256Public([
            0x02, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b,
            b, b, b, b, b,
        ])
    };
    SignedRoster {
        roster: Roster {
            fleet_id: FleetId([0xf1; 16]),
            epoch: 1,
            version: 7,
            prev_hash: [0xaa; 32],
            issued_at_ms: 1_750_000_000_000,
            devices: vec![Device {
                id: DeviceId([0xd1; 16]),
                name: BoundedString::new("MacBook Pro 16").unwrap(),
                role: Role::Admin,
                root_key: key(0x10),
                device_key: key(0x11),
                monitor_key: key(0x12),
                ssh_key: key(0x13),
                monitor_ssh_key: key(0x15),
                noise_static: X25519Public([0x14; 32]),
                added_at: 1_750_000_000_000,
                added_by: DeviceId([0xd1; 16]),
            }],
            recovery_key: Ed25519Public([0x20; 32]),
            recovery_ssh_key: Ed25519Public([0x21; 32]),
            recovery_escrow_key: X25519Public([0x22; 32]),
            recovery_delay_s: 259_200,
            prev_recovery: Some(PrevRecovery {
                recovery_key: Ed25519Public([0x23; 32]),
                recovery_ssh_key: Ed25519Public([0x24; 32]),
                recovery_escrow_key: X25519Public([0x25; 32]),
                recovery_delay_s: 0,
                valid_until_ms: 1_750_259_200_000,
            }),
        },
        signer: KeyRef::Root(DeviceId([0xd1; 16])),
        signature: Signature([0x5a; 64]),
    }
}

fn fixture_body() -> CommandBody {
    CommandBody {
        v: PROTO_VERSION,
        fleet_id: FleetId([0xf1; 16]),
        server_id: ServerId::new("srv_7f3a9c").unwrap(),
        issued_at_ms: 1_750_000_000_123,
        ttl_ms: 60_000,
        nonce: [0x4e; 16],
        actor: Actor::Ai {
            client: BoundedString::new("claude-code").unwrap(),
            session: [0x5e; 16],
        },
        op: Op::SystemInfo,
        expected_version: None,
    }
}

fn fixture_approval() -> RootApproval {
    let body = ApprovalBody {
        fleet_id: FleetId([0xf1; 16]),
        approval_id: [0xa1; 16],
        issued_at_ms: 1_750_000_000_000,
        expires_at_ms: 1_750_001_800_000,
        items_root: [0xbb; 32],
    };
    RootApproval {
        device_id: DeviceId([0xd1; 16]),
        body: encode(&body),
        signature: Signature([0x6b; 64]),
        proof: MerkleProof {
            leaf_index: 2,
            leaf_count: 5,
            siblings: vec![[0xc1; 32], [0xc2; 32], [0xc3; 32]],
        },
    }
}

fn fixture_command() -> SignedCommand {
    SignedCommand {
        body: encode(&fixture_body()),
        device_id: DeviceId([0xd1; 16]),
        key: KeyKind::Device,
        signature: Signature([0x7c; 64]),
        approval: None,
    }
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/v1")
}

fn check<T: Serialize + DeserializeOwned + PartialEq + Debug>(
    name: &str,
    value: &T,
    failures: &mut Vec<String>,
) {
    let path = vectors_dir().join(format!("{name}.hex"));
    let actual = hex::encode(encode(value));
    if std::env::var_os("FLEET_REGEN_VECTORS").is_some() {
        std::fs::create_dir_all(vectors_dir()).unwrap();
        std::fs::write(&path, format!("{actual}\n")).unwrap();
        return;
    }
    let expected =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let expected = expected.trim();
    if expected != actual {
        failures.push(format!("{name}: encoding changed"));
    }
    match decode::<T>(&hex::decode(expected).unwrap()) {
        Ok(v) if &v == value => {}
        other => failures.push(format!("{name}: vector decodes to {other:?}")),
    }
}

#[test]
fn golden_vectors_v1() {
    let mut f = Vec::new();
    let body = fixture_body();

    check("command_body_system_info", &body, &mut f);
    check(
        "command_body_policy_update",
        &CommandBody {
            op: Op::PolicyUpdate {
                policy_toml: "version = 13\n".into(),
            },
            expected_version: Some(12),
            actor: Actor::Human,
            ..body.clone()
        },
        &mut f,
    );
    check(
        "command_body_roster_veto",
        &CommandBody {
            op: Op::RosterVeto {
                pending_hash: [0x99; 32],
            },
            actor: Actor::Runbook { id: [0x33; 16] },
            ..body.clone()
        },
        &mut f,
    );
    check("op_agent_health", &Op::AgentHealth, &mut f);
    check("op_roster_pending", &Op::RosterPending, &mut f);
    check("op_roster_get", &Op::RosterGet, &mut f);
    check(
        "op_profile_apply_accounts",
        &Op::ProfileApply {
            spec: op::ProfileSpec {
                source: op::ProfileSource::Builtin {
                    level: op::ProfileLevel::Baseline,
                    roles: vec![op::ProfileRole::Docker],
                },
                only: vec![],
            },
            plan_hash: [0x7a; 32],
            phase: op::ProfilePhase::Accounts,
            password_hash: Some(
                args::SudoPasswordHash::crypt(
                    "$y$j9T$abcdefghijklmnop$ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
                )
                .unwrap(),
            ),
        },
        &mut f,
    );
    check(
        "op_roster_update",
        &Op::RosterUpdate {
            roster: Box::new(fixture_roster()),
        },
        &mut f,
    );
    check("op_unknown_1234", &Op::Unknown { tag: 1234 }, &mut f);
    check("signed_roster", &fixture_roster(), &mut f);
    check("signed_command", &fixture_command(), &mut f);
    check(
        "signed_command_with_approval",
        &SignedCommand {
            approval: Some(fixture_approval()),
            key: KeyKind::Monitor,
            ..fixture_command()
        },
        &mut f,
    );
    check(
        "message_device_auth",
        &Message::DeviceAuth {
            device_id: DeviceId([0xd1; 16]),
            key: KeyKind::Recovery,
            sig: Signature([0x8d; 64]),
        },
        &mut f,
    );
    check(
        "message_hello",
        &Message::Hello {
            proto_min: 1,
            proto_max: 1,
            agent_version: AgentVersion {
                major: 0,
                minor: 1,
                patch: 0,
            },
            server_id: ServerId::new("srv_7f3a9c").unwrap(),
            time_ms: 1_750_000_000_500,
            roster_epoch: 1,
            roster_version: 7,
            pending_recovery: Some(PendingRecovery {
                hash: [0x9e; 32],
                activates_at_ms: 1_750_259_200_000,
            }),
        },
        &mut f,
    );
    check(
        "message_request",
        &Message::Request {
            id: 42,
            cmd: fixture_command(),
        },
        &mut f,
    );
    check(
        "message_response_ok",
        &Message::Response {
            id: 42,
            result: Ok(Payload::AgentHealth(AgentHealth {
                agent_version: AgentVersion {
                    major: 0,
                    minor: 1,
                    patch: 0,
                },
                proto_version: 1,
                uptime_s: 3600,
                gate_rss_bytes: 3_000_000,
                exec_rss_bytes: 12_000_000,
                audit_seq: 99,
                roster_epoch: 1,
                roster_version: 7,
                policy_version: 12,
                pending_recovery: None,
                run_id: [0x2a; 16],
            })),
            receipt: Some(SignedReceipt {
                receipt: Receipt {
                    server_id: ServerId::new("srv_7f3a9c").unwrap(),
                    command_hash: [0xcc; 32],
                    audit_seq: None,
                    outcome: Outcome::Ok,
                    payload_hash: [0xa1; 32],
                    time_ms: 1_750_000_000_600,
                },
                signature: Signature([0xee; 64]),
            }),
        },
        &mut f,
    );
    check(
        "message_response_err",
        &Message::Response {
            id: 43,
            result: Err(ErrorCode::VersionConflict { current: 12 }),
            receipt: Some(SignedReceipt {
                receipt: Receipt {
                    server_id: ServerId::new("srv_7f3a9c").unwrap(),
                    command_hash: [0xcd; 32],
                    audit_seq: Some(100),
                    outcome: Outcome::Failed(ErrorCode::VersionConflict { current: 12 }),
                    payload_hash: [0; 32],
                    time_ms: 1_750_000_000_700,
                },
                signature: Signature([0xef; 64]),
            }),
        },
        &mut f,
    );
    check(
        "message_response_undecodable",
        &Message::Response {
            id: 44,
            result: Err(ErrorCode::InvalidArgument),
            receipt: None,
        },
        &mut f,
    );
    check("message_rekey", &Message::Rekey, &mut f);
    check(
        "message_stream_end",
        &Message::StreamEnd {
            id: 7,
            status: Err(ErrorCode::Timeout),
        },
        &mut f,
    );
    let seal = StreamSeal {
        server_id: body.server_id.clone(),
        command_hash: [0x5e; 32],
        audit_seq: Some(77),
        count: 33,
        chain: [0xc1; 32],
        outcome: None,
        time_ms: 1_750_000_000_300,
    };
    check(
        "stream_chunk_data",
        &StreamChunk::Data(vec![0x0b, 0x01]),
        &mut f,
    );
    check(
        "stream_chunk_checkpoint",
        &StreamChunk::Checkpoint(SignedStreamSeal {
            seal: seal.clone(),
            signature: Signature([0x51; 64]),
        }),
        &mut f,
    );
    check(
        "stream_chunk_final",
        &StreamChunk::Final(SignedStreamSeal {
            seal: StreamSeal {
                audit_seq: None,
                outcome: Some(Outcome::Failed(ErrorCode::Busy)),
                ..seal
            },
            signature: Signature([0x52; 64]),
        }),
        &mut f,
    );
    check(
        "audit_entry",
        &AuditEntry {
            seq: 100,
            time: 1_750_000_000_200,
            prev_hash: [0xab; 32],
            actor: Actor::Human,
            device_id: DeviceId([0xd1; 16]),
            command_hash: [0xcd; 32],
            signature: Signature([0x7c; 64]),
            op: OpSummary::from(&Op::RosterVeto {
                pending_hash: [0x99; 32],
            }),
            phase: Phase::Result,
            result: ResultSummary::Done(Outcome::Failed(ErrorCode::ApprovalInvalid)),
        },
        &mut f,
    );

    check(
        "message_event_change_reverted",
        &Message::Event(SignedEvent {
            server_id: ServerId::new("srv_7f3a9c").unwrap(),
            run_id: [0x3b; 16],
            seq: 5,
            time_ms: 1_750_000_090_001,
            event: Event::ChangeReverted {
                change_id: [0xc4; 16],
                audit_seq: 101,
            },
            sig: Signature([0x5e; 64]),
        }),
        &mut f,
    );
    check(
        "audit_entry_system_reverted",
        &AuditEntry {
            seq: 101,
            time: 1_750_000_090_000,
            prev_hash: [0xac; 32],
            actor: Actor::System,
            device_id: DeviceId([0xd1; 16]),
            command_hash: [0xcd; 32],
            signature: Signature([0x7c; 64]),
            op: OpSummary::from(&Op::SystemInfo),
            phase: Phase::Result,
            result: ResultSummary::Done(Outcome::Reverted),
        },
        &mut f,
    );

    catalog_vectors(&body, &mut f);
    assert!(f.is_empty(), "golden vector mismatches:\n{}", f.join("\n"));
}

/// A representative sample of the full operation catalog, payloads and
/// events (not every variant).
fn catalog_vectors(body: &CommandBody, f: &mut Vec<String>) {
    use args::*;
    use fleet_proto::op::{CronEntry, PkgSpec};

    let ruleset = FirewallRuleSet {
        mode: FirewallMode::Managed,
        rules: vec![FirewallRule {
            chain: FwChain::Input,
            action: FwAction::Accept,
            proto: Protocol::Tcp,
            ports: vec![
                PortRange::single(Port::new(22).unwrap()),
                PortRange::new(Port::new(60000).unwrap(), Port::new(61000).unwrap()).unwrap(),
            ],
            source: Some("198.51.100.0/24".parse().unwrap()),
            rate_limit: Some(RateLimit {
                per_minute: 30,
                burst: 10,
            }),
            comment: FwComment::new("ssh office").unwrap(),
        }],
    };
    check(
        "op_unit_restart",
        &Op::UnitRestart {
            unit: UnitName::new("nginx.service").unwrap(),
        },
        f,
    );
    check("op_firewall_apply", &Op::FirewallApply(ruleset.clone()), f);
    check(
        "command_body_firewall_apply",
        &CommandBody {
            op: Op::FirewallApply(ruleset),
            expected_version: Some(41),
            ..body.clone()
        },
        f,
    );
    check(
        "op_pkg_install",
        &Op::PkgInstall {
            packages: vec![
                PkgSpec {
                    name: DebPackageName::new("htop").unwrap(),
                    version: None,
                },
                PkgSpec {
                    name: DebPackageName::new("libssl3").unwrap(),
                    version: Some(DebVersion::new("3.0.15-1~deb12u1").unwrap()),
                },
            ],
        },
        f,
    );
    check(
        "op_cron_set",
        &Op::CronSet {
            user: UserName::new("ops").unwrap(),
            entries: vec![CronEntry {
                schedule: CronSpec::new("*/15 2-4 * * 1-5").unwrap(),
                command: CronCommand::new("/usr/local/bin/backup --quiet").unwrap(),
                comment: Label::new("nightly backup").unwrap(),
            }],
        },
        f,
    );
    let mut blob = Vec::new();
    for part in [&b"ssh-ed25519"[..], &[0x5a; 32][..]] {
        blob.extend_from_slice(&(part.len() as u32).to_be_bytes());
        blob.extend_from_slice(part);
    }
    check(
        "op_authorized_keys_set",
        &Op::AuthorizedKeysSet {
            user: UserName::new("ops").unwrap(),
            keys: vec![SshPublicKey::new(SshKeyAlgo::Ed25519, blob, "ci@build".into()).unwrap()],
        },
        f,
    );
    check(
        "op_compose_deploy",
        &Op::ComposeDeploy {
            project: ComposeProject::new("blog").unwrap(),
            file: ComposeFile::new("services:\n  web:\n    image: ghost:5\n").unwrap(),
            pull: true,
        },
        f,
    );
    check(
        "op_agent_update_stage",
        &Op::AgentUpdateStage {
            manifest: Box::new(SignedReleaseManifest {
                manifest: ReleaseManifest {
                    version: AgentVersion {
                        major: 0,
                        minor: 2,
                        patch: 0,
                    },
                    blake3: [0xb3; 32],
                    min_proto: 1,
                    target: fleet_proto::AgentTarget::X86_64,
                },
                device_id: DeviceId([0xd1; 16]),
                signature: Signature([0x51; 64]),
            }),
            staged_path_hash: [0xb3; 32],
        },
        f,
    );
    check(
        "op_alert_rules_update",
        &Op::AlertRulesUpdate(alert::AlertRuleSet {
            version: 7,
            rules: vec![
                alert::AlertRule {
                    id: RuleId::new("disk-root").unwrap(),
                    kind: alert::AlertKind::DiskUsage {
                        mount: Some(AbsPath::new("/").unwrap()),
                    },
                    threshold: 900,
                    for_s: 300,
                    severity: alert::Severity::Critical,
                    enabled: true,
                },
                alert::AlertRule {
                    id: RuleId::new("ssh-down").unwrap(),
                    kind: alert::AlertKind::ServiceDown {
                        unit: UnitName::new("ssh.service").unwrap(),
                    },
                    threshold: 0,
                    for_s: 60,
                    severity: alert::Severity::Critical,
                    enabled: true,
                },
            ],
        }),
        f,
    );
    check(
        "op_journal_follow",
        &Op::JournalFollow(JournalQuery {
            units: vec![UnitName::new("ssh.service").unwrap()],
            priority: Some(Priority::Warning),
            range: TimeRange {
                since_ms: Some(1_750_000_000_000),
                until_ms: None,
            },
            grep: Some(GrepPattern::new("Failed password").unwrap()),
            after_cursor: None,
            limit: 500,
        }),
        f,
    );
    check(
        "payload_metrics_sample",
        &Payload::MetricsSample(payload::MetricsSample {
            time_ms: 1_750_000_000_123,
            values: vec![(0, F32(12.5)), (7, F32(0.0)), (255, F32(f32::NAN))],
        }),
        f,
    );
    check(
        "payload_change_pending",
        &Payload::ChangePending {
            change: payload::PendingChange {
                change_id: [0xc4; 16],
                kind: payload::ChangeKind::Firewall,
                op_tag: op::tag::FIREWALL_APPLY,
                created_ms: 1_750_000_000_000,
                deadline_ms: 1_750_000_060_000,
                new_version: Some(42),
            },
            inner: None,
        },
        f,
    );
    check(
        "payload_change_pending_profile_applied",
        &Payload::ChangePending {
            change: payload::PendingChange {
                change_id: [0xc5; 16],
                kind: payload::ChangeKind::Profile,
                op_tag: op::tag::PROFILE_APPLY,
                created_ms: 1_750_000_000_000,
                deadline_ms: 1_750_000_060_000,
                new_version: None,
            },
            inner: Some(Box::new(Payload::ProfileApplied(payload::ProfileApplied {
                modules: vec![payload::ModuleResult {
                    id: "ssh.hardening".into(),
                    outcome: payload::ModuleOutcome::Applied,
                    detail: String::new(),
                }],
                pending: None,
                score_before: 41,
                score_after: 77,
            }))),
        },
        f,
    );
    check(
        "payload_roster_state",
        &Payload::RosterState(Box::new(payload::RosterState {
            roster: fixture_roster(),
            epoch_hashes: vec![[0x5a; 32]],
        })),
        f,
    );
    check(
        "payload_packages_with_source",
        &Payload::Packages(payload::Packages {
            packages: vec![payload::PackageInfo {
                name: "libssl3".into(),
                version: "3.0.11-1~deb12u2".into(),
                arch: "amd64".into(),
                held: false,
                auto_installed: true,
                source: Some("openssl".into()),
                source_version: Some("3.0.11-1~deb12u2".into()),
            }],
        }),
        f,
    );
    check(
        "payload_profile_check_pending_reboot",
        &Payload::ProfileCheck(payload::ProfileCheck {
            score: 88,
            modules: vec![payload::ModuleCheck {
                id: "auditd".into(),
                status: payload::ModuleStatus::PendingReboot,
                detail: "immutable audit rules load at boot".into(),
            }],
        }),
        f,
    );
    check(
        "event_alert_fired",
        &Event::AlertFired {
            rule_id: "disk-root".into(),
            severity: alert::Severity::Critical,
            subject: "/".into(),
            value: 951,
        },
        f,
    );
    check(
        "event_service_state_changed",
        &Event::ServiceStateChanged {
            unit: "nginx.service".into(),
            from: payload::UnitActiveState::Active,
            to: payload::UnitActiveState::Failed,
        },
        f,
    );
}

#[test]
fn signed_message_layouts() {
    let body = encode(&fixture_body());
    let id = DeviceId([0xd1; 16]);
    let m = SignedCommand::signed_message(KeyKind::Monitor, &id, &body);
    assert_eq!(&m[..12], b"fleet/cmd/v1");
    assert_eq!(m[12], 1); // KeyKind::Monitor
    assert_eq!(&m[13..29], &id.0);
    assert_eq!(&m[29..], &body[..]);
    let a = Message::device_auth_message(KeyKind::Device, &id, &[0xee; 32]);
    assert_eq!(a.len(), 13 + 1 + 16 + 32);
    assert!(a.starts_with(domain::AUTH));
    assert_eq!(a[13], 0); // KeyKind::Device
    assert_eq!(&a[14..30], &id.0);
    assert_eq!(&a[30..], &[0xee; 32]);
}
