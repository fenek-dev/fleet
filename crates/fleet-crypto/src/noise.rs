//! `Noise_XX_25519_ChaChaPoly_BLAKE2s` sessions (design §5.5) and the
//! `DeviceAuth` binding of a session to a roster key.
//!
//! Each Noise transport message carries one chunk
//! (`fleet_proto::chunk`: `frame_id ‖ flags ‖ data`, design §6.1); splitting
//! and reassembly live there, not here. The outer transport length-prefixes
//! each Noise message.
//!
//! **Rekey** (design §5.5): each direction is rekeyed every
//! [`REKEY_INTERVAL_MS`] or [`REKEY_MAX_MESSAGES`] messages, whichever comes
//! first. When [`Transport::needs_rekey`] is true, the sender encrypts a
//! one-chunk `Message::Rekey` frame under the old key and then calls
//! [`Transport::rekey_outgoing`]; the receiver calls
//! [`Transport::rekey_incoming`] right after decrypting that chunk. Noise
//! messages are ordered, so both sides switch at the same message.

use crate::sig::{self, Ed25519Signer, Signer};
use crate::{Error, random_bytes};
use fleet_proto::{DeviceId, ErrorCode, KeyKind, Message, Roster, Signature, X25519Public};
use zeroize::Zeroizing;

pub const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
/// Largest Noise message.
pub const MAX_MESSAGE: usize = 65535;
pub const TAG_LEN: usize = 16;
/// Largest plaintext per transport message.
pub const MAX_PLAINTEXT: usize = MAX_MESSAGE - TAG_LEN;
/// Rekey each direction at least this often (10 minutes).
pub const REKEY_INTERVAL_MS: u64 = 10 * 60_000;
/// ... or after this many messages under one key (2³²), counting the
/// `Rekey` message itself.
pub const REKEY_MAX_MESSAGES: u64 = 1 << 32;

/// Noise prologue for an agent session: `"fleet/noise/v1" ‖ mode`, where
/// `mode` is the bridge header byte (0 normal, 1 recovery). Both sides must
/// agree on the mode or the handshake fails.
pub fn prologue(mode: u8) -> Vec<u8> {
    let mut p = b"fleet/noise/v1".to_vec();
    p.push(mode);
    p
}

/// X25519 static key (Mac Noise key, agent Noise key). Zeroized on drop.
pub struct StaticKeypair {
    secret: x25519_dalek::StaticSecret,
}

impl StaticKeypair {
    pub fn generate() -> Result<Self, Error> {
        let mut b = Zeroizing::new([0u8; 32]);
        random_bytes(b.as_mut())?;
        Ok(Self::from_bytes(&b))
    }

    /// From a stored secret. Takes a `Zeroizing` buffer so callers keep no
    /// plain copy; `StaticSecret` zeroizes its own copy on drop.
    pub fn from_bytes(secret: &Zeroizing<[u8; 32]>) -> Self {
        Self {
            secret: x25519_dalek::StaticSecret::from(**secret),
        }
    }

    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    pub fn public(&self) -> X25519Public {
        X25519Public(x25519_dalek::PublicKey::from(&self.secret).to_bytes())
    }
}

fn params() -> snow::params::NoiseParams {
    NOISE_PARAMS.parse().expect("valid noise params")
}

/// Handshake in progress. XX: initiator writes, responder reads, 3 messages.
pub struct Handshake {
    state: snow::HandshakeState,
}

impl Handshake {
    pub fn initiator(local: &StaticKeypair, prologue: &[u8]) -> Result<Self, Error> {
        let key = local.secret_bytes();
        let state = snow::Builder::new(params())
            .local_private_key(key.as_ref())?
            .prologue(prologue)?
            .build_initiator()?;
        Ok(Self { state })
    }

    pub fn responder(local: &StaticKeypair, prologue: &[u8]) -> Result<Self, Error> {
        let key = local.secret_bytes();
        let state = snow::Builder::new(params())
            .local_private_key(key.as_ref())?
            .prologue(prologue)?
            .build_responder()?;
        Ok(Self { state })
    }

    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; MAX_MESSAGE];
        let n = self.state.write_message(payload, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        if message.len() > MAX_MESSAGE {
            return Err(Error::TooLarge(message.len()));
        }
        let mut buf = vec![0u8; MAX_MESSAGE];
        let n = self.state.read_message(message, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    pub fn is_my_turn(&self) -> bool {
        self.state.is_my_turn()
    }

    pub fn remote_static(&self) -> Option<X25519Public> {
        remote(self.state.get_remote_static())
    }

    /// Final after the handshake completes; what `DeviceAuth` signs.
    pub fn handshake_hash(&self) -> [u8; 32] {
        hash32(self.state.get_handshake_hash())
    }

    /// `now_ms` starts the rekey clock of both directions.
    pub fn into_transport(self, now_ms: u64) -> Result<Transport, Error> {
        let handshake_hash = self.handshake_hash();
        let remote_static = self.remote_static().ok_or(Error::BadKey)?;
        Ok(Transport {
            state: self.state.into_transport_mode()?,
            handshake_hash,
            remote_static,
            rekeyed_at_ms: now_ms,
            sent_at_rekey: 0,
        })
    }
}

fn rekey_due(elapsed_ms: u64, sent: u64) -> bool {
    elapsed_ms >= REKEY_INTERVAL_MS || sent >= REKEY_MAX_MESSAGES - 1
}

fn remote(bytes: Option<&[u8]>) -> Option<X25519Public> {
    bytes.and_then(|b| b.try_into().ok()).map(X25519Public)
}

fn hash32(b: &[u8]) -> [u8; 32] {
    b.try_into().expect("BLAKE2s handshake hash is 32 bytes")
}

/// Established session.
pub struct Transport {
    state: snow::TransportState,
    handshake_hash: [u8; 32],
    remote_static: X25519Public,
    /// When the outgoing key was last (re)established.
    rekeyed_at_ms: u64,
    /// `sending_nonce` at that point.
    sent_at_rekey: u64,
}

impl Transport {
    pub fn handshake_hash(&self) -> &[u8; 32] {
        &self.handshake_hash
    }

    /// Peer static key; the caller compares it with the pinned/roster value.
    pub fn remote_static(&self) -> &X25519Public {
        &self.remote_static
    }

    /// Encrypts one Noise message; `plaintext` ≤ [`MAX_PLAINTEXT`].
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(Error::TooLarge(plaintext.len()));
        }
        let mut buf = vec![0u8; plaintext.len() + TAG_LEN];
        let n = self.state.write_message(plaintext, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn decrypt(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        if message.len() > MAX_MESSAGE {
            return Err(Error::TooLarge(message.len()));
        }
        let mut buf = vec![0u8; message.len()];
        let n = self.state.read_message(message, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Whether the outgoing direction is due for a rekey at `now_ms`: send a
    /// `Message::Rekey` chunk, then call [`Self::rekey_outgoing`]. Checked
    /// before each send; the `- 1` leaves room for the `Rekey` message itself
    /// under the old key.
    pub fn needs_rekey(&self, now_ms: u64) -> bool {
        rekey_due(
            now_ms.saturating_sub(self.rekeyed_at_ms),
            self.sending_nonce().saturating_sub(self.sent_at_rekey),
        )
    }

    /// Advances the send key (Noise `REKEY`). Call right after encrypting the
    /// `Message::Rekey` chunk; restarts the rekey clock and message count.
    pub fn rekey_outgoing(&mut self, now_ms: u64) {
        self.state.rekey_outgoing();
        self.rekeyed_at_ms = now_ms;
        self.sent_at_rekey = self.sending_nonce();
    }

    /// Advances the receive key. Call right after decrypting a chunk whose
    /// frame is `Message::Rekey` (see [`Message::kind_tag`]).
    pub fn rekey_incoming(&mut self) {
        self.state.rekey_incoming();
    }

    pub fn sending_nonce(&self) -> u64 {
        self.state.sending_nonce()
    }

    pub fn receiving_nonce(&self) -> u64 {
        self.state.receiving_nonce()
    }
}

// ---- DeviceAuth ----------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    #[error("device not in the roster")]
    UnknownDevice,
    #[error("session Noise key differs from the device's registered key")]
    NoiseKeyMismatch,
    #[error("key kind not accepted on this bridge")]
    WrongMode,
    #[error("signature invalid")]
    Signature,
}

impl AuthError {
    pub fn code(&self) -> ErrorCode {
        ErrorCode::Unauthorized
    }
}

/// Mac side: `DeviceAuth.sig` with the device or monitor key.
pub fn sign_device_auth(
    signer: &(impl Signer + ?Sized),
    key: KeyKind,
    device_id: &DeviceId,
    handshake_hash: &[u8; 32],
) -> Result<Signature, Error> {
    sig::p256_sign(
        signer,
        &Message::device_auth_message(key, device_id, handshake_hash),
    )
}

/// Recovery Mac: `DeviceAuth.sig` with the recovery key. `device_id` is the
/// recovering Mac's new id.
pub fn sign_recovery_auth(
    recovery: &Ed25519Signer,
    device_id: &DeviceId,
    handshake_hash: &[u8; 32],
) -> Signature {
    recovery.sign(&Message::device_auth_message(
        KeyKind::Recovery,
        device_id,
        handshake_hash,
    ))
}

/// Gate side. `recovery_bridge`: the bridge was started with `--recovery`;
/// it accepts only `Recovery`, a normal bridge only `Device`/`Monitor`.
/// For `Recovery` the Noise key isn't in the roster; the signature over the
/// handshake hash binds it instead. While a rotation's grace window is open
/// under `clock`, only the rotated-out recovery key is accepted (design §5.3
/// rule 6).
#[allow(clippy::too_many_arguments)]
pub fn verify_device_auth(
    roster: &Roster,
    device_id: &DeviceId,
    key: KeyKind,
    signature: &Signature,
    handshake_hash: &[u8; 32],
    remote_static: &X25519Public,
    recovery_bridge: bool,
    clock: crate::roster::RecoveryClock,
) -> Result<(), AuthError> {
    let msg = Message::device_auth_message(key, device_id, handshake_hash);
    match (key, recovery_bridge) {
        (KeyKind::Recovery, true) => {
            crate::roster::verify_recovery_sig(roster, clock, &msg, signature)
                .map_err(|_| AuthError::Signature)
        }
        (KeyKind::Device | KeyKind::Monitor, false) => {
            let dev = roster.device(device_id).ok_or(AuthError::UnknownDevice)?;
            if dev.noise_static != *remote_static {
                return Err(AuthError::NoiseKeyMismatch);
            }
            let pk = if key == KeyKind::Device {
                &dev.device_key
            } else {
                &dev.monitor_key
            };
            sig::p256_verify(pk, &msg, signature).map_err(|_| AuthError::Signature)
        }
        _ => Err(AuthError::WrongMode),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roster::RecoveryClock;
    use crate::testutil::*;

    fn pair() -> (Transport, Transport, StaticKeypair, StaticKeypair) {
        let (mk, ak) = (
            StaticKeypair::from_bytes(&Zeroizing::new([1; 32])),
            StaticKeypair::from_bytes(&Zeroizing::new([2; 32])),
        );
        let mut i = Handshake::initiator(&mk, b"fleet").unwrap();
        let mut r = Handshake::responder(&ak, b"fleet").unwrap();
        let m1 = i.write_message(&[]).unwrap();
        r.read_message(&m1).unwrap();
        let m2 = r.write_message(&[]).unwrap();
        i.read_message(&m2).unwrap();
        let m3 = i.write_message(&[]).unwrap();
        r.read_message(&m3).unwrap();
        assert!(i.is_finished() && r.is_finished());
        assert_eq!(i.handshake_hash(), r.handshake_hash());
        let (it, rt) = (
            i.into_transport(NOW).unwrap(),
            r.into_transport(NOW).unwrap(),
        );
        (it, rt, mk, ak)
    }

    #[test]
    fn handshake_transport_rekey() {
        let (mut i, mut r, mk, ak) = pair();
        assert_eq!(*i.remote_static(), ak.public());
        assert_eq!(*r.remote_static(), mk.public());
        let ct = i.encrypt(b"hi").unwrap();
        assert_eq!(r.decrypt(&ct).unwrap(), b"hi");
        let mut bad = i.encrypt(b"yo").unwrap();
        bad[0] ^= 1;
        assert!(r.decrypt(&bad).is_err());

        let (mut i, mut r, ..) = pair();
        i.rekey_outgoing(NOW);
        r.rekey_incoming();
        let ct = i.encrypt(b"after").unwrap();
        assert_eq!(r.decrypt(&ct).unwrap(), b"after");
        assert!(i.encrypt(&vec![0; MAX_PLAINTEXT + 1]).is_err());
        let chunk = fleet_proto::chunk::MAX_CHUNK;
        assert!(chunk <= MAX_PLAINTEXT);
        assert_eq!(i.encrypt(&vec![0; chunk]).unwrap().len(), MAX_MESSAGE);
    }

    /// One-chunk `Message::Rekey` frame, as the gate and Mac send it.
    fn rekey_chunk(frame_id: u32) -> Vec<u8> {
        let mut c =
            fleet_proto::chunk::split_frame(frame_id, &fleet_proto::encode(&Message::Rekey));
        assert_eq!(c.len(), 1);
        c.remove(0)
    }

    /// Receiver: decrypt, and rekey the incoming side on a `Rekey` frame.
    fn recv(t: &mut Transport, ct: &[u8]) -> Vec<u8> {
        let pt = t.decrypt(ct).unwrap();
        let (h, data) = fleet_proto::chunk::parse_chunk(&pt).unwrap();
        if h.last && Message::kind_tag(data) == Some(fleet_proto::MessageKind::Rekey) {
            t.rekey_incoming();
        }
        data.to_vec()
    }

    #[test]
    fn rekey_by_time_and_control_message() {
        assert!(!rekey_due(0, REKEY_MAX_MESSAGES - 2));
        assert!(rekey_due(0, REKEY_MAX_MESSAGES - 1));
        assert!(rekey_due(REKEY_INTERVAL_MS, 0));

        let (mut i, mut r, ..) = pair();
        assert!(!i.needs_rekey(NOW));
        assert!(!i.needs_rekey(NOW - 1), "clock going back never triggers");
        assert!(!i.needs_rekey(NOW + REKEY_INTERVAL_MS - 1));
        assert!(i.needs_rekey(NOW + REKEY_INTERVAL_MS));
        let later = NOW + REKEY_INTERVAL_MS;

        let data = |d: &[u8]| fleet_proto::chunk::split_frame(1, d).remove(0);
        // Initiator → responder: Rekey under the old key, then switch.
        let ct = i.encrypt(&rekey_chunk(7)).unwrap();
        i.rekey_outgoing(later);
        assert!(!i.needs_rekey(later));
        assert!(i.needs_rekey(later + REKEY_INTERVAL_MS));
        assert_eq!(recv(&mut r, &ct), [fleet_proto::MessageKind::Rekey.tag()]);
        let ct = i.encrypt(&data(b"new key")).unwrap();
        assert_eq!(recv(&mut r, &ct), b"new key");

        // Responder → initiator still on its original key (independent).
        let ct = r.encrypt(&data(b"old dir")).unwrap();
        assert_eq!(recv(&mut i, &ct), b"old dir");

        // A receiver that ignores the Rekey can't read the next message.
        let (mut i, mut r, ..) = pair();
        let ct = i.encrypt(&rekey_chunk(1)).unwrap();
        i.rekey_outgoing(NOW);
        r.decrypt(&ct).unwrap();
        let ct = i.encrypt(&data(b"x")).unwrap();
        assert!(r.decrypt(&ct).is_err());
    }

    #[test]
    fn device_auth() {
        let fx = Fixture::new(1);
        let r = fx.roster();
        let m = &fx.macs[0];
        let hh = [9u8; 32];
        let ns = m.noise.public();
        let v = |r: &Roster, id: &DeviceId, k, s: &Signature, hh: &[u8; 32], ns, rb, now| {
            verify_device_auth(r, id, k, s, hh, ns, rb, RecoveryClock::at(now))
        };
        let s = sign_device_auth(&m.device, KeyKind::Device, &m.id, &hh).unwrap();
        v(&r, &m.id, KeyKind::Device, &s, &hh, &ns, false, NOW).unwrap();
        // Different handshake, wrong Noise key, wrong kind, recovery bridge.
        assert_eq!(
            v(&r, &m.id, KeyKind::Device, &s, &[8; 32], &ns, false, NOW),
            Err(AuthError::Signature)
        );
        let zero = X25519Public([0; 32]);
        assert_eq!(
            v(&r, &m.id, KeyKind::Device, &s, &hh, &zero, false, NOW),
            Err(AuthError::NoiseKeyMismatch)
        );
        assert_eq!(
            v(&r, &m.id, KeyKind::Monitor, &s, &hh, &ns, false, NOW),
            Err(AuthError::Signature)
        );
        assert_eq!(
            v(&r, &m.id, KeyKind::Device, &s, &hh, &ns, true, NOW),
            Err(AuthError::WrongMode)
        );
        let rid = DeviceId([0x77; 16]);
        let rs = sign_recovery_auth(&fx.recovery, &rid, &hh);
        v(&r, &rid, KeyKind::Recovery, &rs, &hh, &ns, true, NOW).unwrap();
        assert_eq!(
            v(&r, &rid, KeyKind::Recovery, &rs, &hh, &ns, false, NOW),
            Err(AuthError::WrongMode)
        );
        // The claimed device id is signed.
        assert_eq!(
            v(&r, &m.id, KeyKind::Recovery, &rs, &hh, &ns, true, NOW),
            Err(AuthError::Signature)
        );
    }

    #[test]
    fn device_id_bound_in_device_auth() {
        let fx = Fixture::new(2);
        let r = fx.roster();
        let (a, b) = (&fx.macs[0], &fx.macs[1]);
        let hh = [9u8; 32];
        // Mac a signs, claims to be b; b's Noise key is presented too.
        let s = sign_device_auth(&a.device, KeyKind::Device, &b.id, &hh).unwrap();
        let bn = b.noise.public();
        assert_eq!(
            verify_device_auth(
                &r,
                &b.id,
                KeyKind::Device,
                &s,
                &hh,
                &bn,
                false,
                RecoveryClock::at(NOW)
            ),
            Err(AuthError::Signature)
        );
    }

    #[test]
    fn recovery_auth_with_rotated_key() {
        let fx = Fixture::new(1);
        let mut r = fx.roster();
        r.recovery_key = recovery_signer(66).public();
        r.prev_recovery = Some(fleet_proto::PrevRecovery {
            recovery_key: fx.recovery.public(),
            recovery_ssh_key: fx.genesis.roster.recovery_ssh_key,
            recovery_escrow_key: fx.genesis.roster.recovery_escrow_key,
            recovery_delay_s: 0,
            valid_until_ms: NOW + 1000,
        });
        let (hh, ns, rid) = ([9u8; 32], X25519Public([1; 32]), DeviceId([0x77; 16]));
        let old = sign_recovery_auth(&fx.recovery, &rid, &hh);
        let new = sign_recovery_auth(&recovery_signer(66), &rid, &hh);
        let v = |s: &Signature, now| {
            let c = RecoveryClock::at(now);
            verify_device_auth(&r, &rid, KeyKind::Recovery, s, &hh, &ns, true, c)
        };
        v(&old, NOW + 999).unwrap();
        // Inside the window only the rotated-out key recovers.
        assert_eq!(v(&new, NOW + 999), Err(AuthError::Signature));
        assert_eq!(v(&old, NOW + 1000), Err(AuthError::Signature));
        v(&new, NOW + 1000).unwrap();
    }
}
