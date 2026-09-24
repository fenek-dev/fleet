//! Agent-key signatures (Ed25519): response receipts (design §5.6), events
//! (§6.3) and audit checkpoints (§5.8).
//!
//! Exec signs a receipt for **every** response to a command it could decode,
//! so the Mac can tell a real result (success *or* error) from one forged by a
//! compromised gate: [`verify_response`] ties the receipt to the command hash
//! and to the exact payload or error code the Mac received.

use crate::sig::{self, Ed25519Signer};
use crate::{Error, blake3};
use fleet_proto::{
    Checkpoint, Ed25519Public, ErrorCode, Event, Hash32, Outcome, Payload, Receipt, ServerId,
    SignedCheckpoint, SignedEvent, SignedReceipt, encode,
};

/// `Receipt.payload_hash` for an `Ok` response: BLAKE3 of `postcard(payload)`.
pub fn payload_hash(payload: &Payload) -> Hash32 {
    blake3(&encode(payload))
}

/// Builds the receipt for a response `result` to the command `command_hash`:
/// `Ok(p)` → `(Outcome::Ok, payload_hash(p))`, `Err(c)` →
/// `(Outcome::Failed(c), [0; 32])`.
pub fn receipt_for(
    server_id: ServerId,
    command_hash: Hash32,
    audit_seq: Option<u64>,
    result: &Result<Payload, ErrorCode>,
    time_ms: u64,
) -> Receipt {
    let (outcome, payload_hash) = match result {
        Ok(p) => (Outcome::Ok, self::payload_hash(p)),
        Err(c) => (Outcome::Failed(*c), [0; 32]),
    };
    Receipt {
        server_id,
        command_hash,
        audit_seq,
        outcome,
        payload_hash,
        time_ms,
    }
}

pub fn sign_receipt(receipt: Receipt, key: &Ed25519Signer) -> SignedReceipt {
    let signature = key.sign(&SignedReceipt::signed_message(&receipt));
    SignedReceipt { receipt, signature }
}

/// Signature only, against the pinned agent signing key. Prefer
/// [`verify_response`], which also binds the receipt to the response.
pub fn verify_receipt(signed: &SignedReceipt, agent_key: &Ed25519Public) -> Result<(), Error> {
    sig::ed25519_verify(
        agent_key,
        &SignedReceipt::signed_message(&signed.receipt),
        &signed.signature,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResponseError {
    #[error("receipt signature invalid")]
    Signature,
    #[error("receipt is for another server")]
    WrongServer,
    #[error("receipt is for another command")]
    WrongCommand,
    #[error("receipt outcome does not match the response")]
    Outcome,
    #[error("receipt payload hash does not match the response")]
    Payload,
}

/// Mac side: checks a `Response`'s receipt against the pinned agent key and
/// the response itself. `result` must be exactly what the `Response`
/// carried; `command_hash` is BLAKE3 of the `SignedCommand` the Mac sent.
pub fn verify_response(
    signed: &SignedReceipt,
    agent_key: &Ed25519Public,
    server_id: &ServerId,
    command_hash: &Hash32,
    result: &Result<Payload, ErrorCode>,
) -> Result<(), ResponseError> {
    verify_receipt(signed, agent_key).map_err(|_| ResponseError::Signature)?;
    let r = &signed.receipt;
    if r.server_id != *server_id {
        return Err(ResponseError::WrongServer);
    }
    if r.command_hash != *command_hash {
        return Err(ResponseError::WrongCommand);
    }
    match result {
        Ok(p) => {
            if r.outcome != Outcome::Ok {
                return Err(ResponseError::Outcome);
            }
            if r.payload_hash != payload_hash(p) {
                return Err(ResponseError::Payload);
            }
        }
        Err(c) => {
            if r.outcome != Outcome::Failed(*c) {
                return Err(ResponseError::Outcome);
            }
            if r.payload_hash != [0; 32] {
                return Err(ResponseError::Payload);
            }
        }
    }
    Ok(())
}

/// Agent side: signs event number `seq` of exec run `run_id`.
pub fn sign_event(
    server_id: ServerId,
    run_id: [u8; 16],
    seq: u64,
    time_ms: u64,
    event: Event,
    key: &Ed25519Signer,
) -> SignedEvent {
    let sig = key.sign(&SignedEvent::signed_message(
        &server_id, &run_id, seq, time_ms, &event,
    ));
    SignedEvent {
        server_id,
        run_id,
        seq,
        time_ms,
        event,
        sig,
    }
}

/// Mac side: signature by the pinned agent key and the expected server.
/// Run binding (`run_id`), freshness and ordering (`seq` gaps or repeats)
/// are the caller's job.
pub fn verify_event(
    signed: &SignedEvent,
    agent_key: &Ed25519Public,
    server_id: &ServerId,
) -> Result<(), Error> {
    if signed.server_id != *server_id {
        return Err(Error::BadSignature);
    }
    sig::ed25519_verify(
        agent_key,
        &SignedEvent::signed_message(
            &signed.server_id,
            &signed.run_id,
            signed.seq,
            signed.time_ms,
            &signed.event,
        ),
        &signed.sig,
    )
}

pub fn sign_checkpoint(checkpoint: Checkpoint, key: &Ed25519Signer) -> SignedCheckpoint {
    let signature = key.sign(&SignedCheckpoint::signed_message(&checkpoint));
    SignedCheckpoint {
        checkpoint,
        signature,
    }
}

pub fn verify_checkpoint(
    signed: &SignedCheckpoint,
    agent_key: &Ed25519Public,
) -> Result<(), Error> {
    sig::ed25519_verify(
        agent_key,
        &SignedCheckpoint::signed_message(&signed.checkpoint),
        &signed.signature,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_proto::PendingRecovery;

    fn srv() -> ServerId {
        ServerId::new("srv_abcdef").unwrap()
    }

    #[test]
    fn receipt_and_checkpoint_roundtrip() {
        let k = Ed25519Signer::from_seed(&[3; 32]);
        let r = sign_receipt(
            receipt_for(srv(), [1; 32], Some(7), &Ok(Payload::Empty), 5),
            &k,
        );
        verify_receipt(&r, &k.public()).unwrap();
        let mut forged = r.clone();
        forged.receipt.audit_seq = Some(8);
        assert!(verify_receipt(&forged, &k.public()).is_err());
        let other = Ed25519Signer::from_seed(&[4; 32]);
        assert!(verify_receipt(&r, &other.public()).is_err());

        let c = sign_checkpoint(
            Checkpoint {
                server_id: srv(),
                seq: 9,
                entry_hash: [2; 32],
                time_ms: 1,
            },
            &k,
        );
        verify_checkpoint(&c, &k.public()).unwrap();
        // A receipt signature never verifies as a checkpoint (domain separation).
        let cross = SignedCheckpoint {
            checkpoint: c.checkpoint.clone(),
            signature: r.signature,
        };
        assert!(verify_checkpoint(&cross, &k.public()).is_err());
    }

    #[test]
    fn response_bound_to_command_and_result() {
        let k = Ed25519Signer::from_seed(&[3; 32]);
        let pk = k.public();
        let (s, h) = (srv(), [1u8; 32]);
        let ok = Ok(Payload::RosterPending(Some(PendingRecovery {
            hash: [5; 32],
            activates_at_ms: 6,
        })));
        let err: Result<Payload, ErrorCode> = Err(ErrorCode::PolicyDenied);

        let ok_r = sign_receipt(receipt_for(s.clone(), h, None, &ok, 1), &k);
        let err_r = sign_receipt(receipt_for(s.clone(), h, Some(3), &err, 1), &k);
        verify_response(&ok_r, &pk, &s, &h, &ok).unwrap();
        verify_response(&err_r, &pk, &s, &h, &err).unwrap();

        // A gate swapping results or payloads is caught.
        assert_eq!(
            verify_response(&ok_r, &pk, &s, &h, &err),
            Err(ResponseError::Outcome)
        );
        assert_eq!(
            verify_response(&err_r, &pk, &s, &h, &ok),
            Err(ResponseError::Outcome)
        );
        assert_eq!(
            verify_response(&ok_r, &pk, &s, &h, &Ok(Payload::RosterPending(None))),
            Err(ResponseError::Payload)
        );
        assert_eq!(
            verify_response(&err_r, &pk, &s, &h, &Err(ErrorCode::Internal)),
            Err(ResponseError::Outcome)
        );
        assert_eq!(
            verify_response(&ok_r, &pk, &s, &[2; 32], &ok),
            Err(ResponseError::WrongCommand)
        );
        let other = ServerId::new("srv_zzzzzz").unwrap();
        assert_eq!(
            verify_response(&ok_r, &pk, &other, &h, &ok),
            Err(ResponseError::WrongServer)
        );
        let mut forged = ok_r.clone();
        forged.receipt.payload_hash = payload_hash(&Payload::Empty);
        assert_eq!(
            verify_response(&forged, &pk, &s, &h, &Ok(Payload::Empty)),
            Err(ResponseError::Signature)
        );
        // Error receipts must carry a zero payload hash.
        let mut bad = receipt_for(s.clone(), h, None, &err, 1);
        bad.payload_hash = [9; 32];
        let bad = sign_receipt(bad, &k);
        assert_eq!(
            verify_response(&bad, &pk, &s, &h, &err),
            Err(ResponseError::Payload)
        );
    }

    #[test]
    fn events_signed() {
        let k = Ed25519Signer::from_seed(&[3; 32]);
        let e = sign_event(
            srv(),
            [7; 16],
            4,
            100,
            Event::PolicyChanged { version: 2 },
            &k,
        );
        verify_event(&e, &k.public(), &srv()).unwrap();
        let other = ServerId::new("srv_zzzzzz").unwrap();
        assert!(verify_event(&e, &k.public(), &other).is_err());
        let tampers: [fn(&mut SignedEvent); 5] = [
            |e| e.run_id[0] ^= 1,
            |e| e.seq += 1,
            |e| e.time_ms += 1,
            |e| e.event = Event::PolicyChanged { version: 3 },
            |e| e.server_id = ServerId::new("srv_zzzzzz").unwrap(),
        ];
        for tamper in tampers {
            let mut t = e.clone();
            tamper(&mut t);
            assert!(verify_event(&t, &k.public(), &t.server_id.clone()).is_err());
        }
        // A receipt signature over the same bytes never verifies as an event.
        let body = encode(&(&e.server_id, &e.run_id, e.seq, e.time_ms, &e.event));
        let as_receipt = k.sign(&[fleet_proto::domain::RECEIPT, &body[..]].concat());
        let mut cross = e.clone();
        cross.sig = as_receipt;
        assert!(verify_event(&cross, &k.public(), &srv()).is_err());
    }
}
