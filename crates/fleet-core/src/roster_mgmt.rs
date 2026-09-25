//! Adding and revoking Macs (design §5.3, §5.12).
//!
//! **Adding a Mac**
//!
//! 1. The new Mac creates its keys and shows a [`PairingOffer`] as a QR code
//!    (or a pasteable code, [`PairingOffer::to_code`]): its public keys,
//!    Noise key, sync key-agreement key and a one-time nonce.
//! 2. An enrolled Mac scans or pastes it and publishes a [`PairingResponse`]
//!    (fleet id, its own root key, a fresh nonce of its own) as a pairing
//!    record in iCloud ([`pairing_record_name`]); the new Mac finds it by
//!    the offer nonce. Both show [`sas`], six digits over offer, response
//!    and both nonces, and the operator confirms they match. A substituted
//!    offer (QR or paste channel) or a modified response (iCloud) changes
//!    the digits; the responder's nonce is chosen after the offer is
//!    committed, so an attacker can't grind an offer to collide.
//! 3. The enrolled Mac builds roster *v+1* ([`add_mac_roster`]), signs it
//!    with its root key (Touch ID, reason "add Mac <name>"), stores it and
//!    pushes the chain to every server ([`push_chain`]); offline servers are
//!    queued ([`pending_servers`]) and catch up on their next connect.
//! 4. It seals the sync key to the new Mac's key-agreement key (see
//!    `sync::keys`) and publishes it with the records through iCloud.
//!
//! **Revoking a Mac:** [`revoke_mac_roster`] (from any *other* Mac), push,
//! then rotate the sync key (re-encrypt for the remaining Macs, re-escrow).
//!
//! The roster chain cache is only a copy: servers are authoritative
//! (design §7.6). [`store_chain_link`] still checks every link before
//! caching it, so a synced copy can't smuggle a forged roster into the
//! chain this Mac pushes.

use crate::cache::{Cache, CacheError, RosterRow};
use crate::runner::{OpRunner, RunError};
use crate::signer::{DeviceSigner, KeyRole, RoleSigner, SignerError, root_reason};
use fleet_crypto::approval::{ApprovalParams, build_approvals, op_digest};
use fleet_crypto::roster::{RecoveryClock, RosterError, evaluate, roster_hash, sign_root};
use fleet_crypto::sig::p256_key;
use fleet_proto::{
    Actor, ApprovalItem, BoundedString, Device, DeviceId, ErrorCode, FleetId, Hash32, KeyRef, Op,
    P256Public, Payload, Role, Roster, ServerId, SignedRoster, X25519Public, decode, encode,
};
use serde::{Deserialize, Serialize};

pub const PAIRING_PREFIX: &str = "FLEETPAIR1-";
/// An offer older than this is refused.
pub const OFFER_TTL_MS: u64 = 15 * 60 * 1000;
/// `settings` key prefix: last roster `(epoch, version)` a server confirmed.
pub const SEEN_PREFIX: &str = "roster_seen/";
const SAS_DOMAIN: &[u8] = b"fleet/pairing-sas/v1";
const RECORD_DOMAIN: &[u8] = b"fleet/pairing-record/v1";
/// Root approvals for a veto live this long.
const VETO_APPROVAL_MS: u64 = 5 * 60 * 1000;

#[derive(Debug, thiserror::Error)]
pub enum RosterMgmtError {
    #[error("pairing code is malformed")]
    BadCode,
    #[error("pairing offer expired")]
    Expired,
    #[error("invalid device name")]
    Name,
    #[error("key in the offer is invalid")]
    BadKey,
    #[error("that Mac is already in the roster")]
    AlreadyMember,
    #[error("no such Mac in the roster")]
    UnknownDevice,
    /// A Mac can't revoke itself, and the roster can't become empty.
    #[error("refused: {0}")]
    Refused(&'static str),
    #[error("roster check failed: {0}")]
    Roster(#[from] RosterError),
    #[error("signer: {0}")]
    Signer(#[from] SignerError),
    #[error("crypto: {0}")]
    Crypto(#[from] fleet_crypto::Error),
    #[error(transparent)]
    Cache(#[from] CacheError),
    #[error("no roster in the cache")]
    NoRoster,
}

/// What the new Mac shows (design §5.12 step 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingOffer {
    pub device_id: DeviceId,
    pub name: String,
    pub root_key: P256Public,
    pub device_key: P256Public,
    pub monitor_key: P256Public,
    pub ssh_key: P256Public,
    pub monitor_ssh_key: P256Public,
    pub noise_static: X25519Public,
    /// Secure Enclave P-256 key-agreement key, uncompressed SEC1 (65 bytes).
    pub agreement_key: Vec<u8>,
    pub nonce: [u8; 16],
    pub created_ms: u64,
}

impl PairingOffer {
    /// Collects this Mac's public keys.
    pub fn build(
        keys: &dyn DeviceSigner,
        agreement_key: Vec<u8>,
        noise_static: X25519Public,
        device_id: DeviceId,
        name: &str,
        now_ms: u64,
    ) -> Result<Self, RosterMgmtError> {
        let mut nonce = [0u8; 16];
        fleet_crypto::random_bytes(&mut nonce)?;
        let o = Self {
            device_id,
            name: name.trim().to_string(),
            root_key: keys.public_key(KeyRole::Root)?,
            device_key: keys.public_key(KeyRole::Device)?,
            monitor_key: keys.public_key(KeyRole::Monitor)?,
            ssh_key: keys.public_key(KeyRole::Ssh)?,
            monitor_ssh_key: keys.public_key(KeyRole::MonitorSsh)?,
            noise_static,
            agreement_key,
            nonce,
            created_ms: now_ms,
        };
        o.check(now_ms)?;
        Ok(o)
    }

    /// `FLEETPAIR1-` + uppercase hex of the encoding + 4-byte checksum
    /// (QR alphanumeric mode; typos in a pasted code are caught).
    pub fn to_code(&self) -> String {
        let body = encode(self);
        let sum = fleet_crypto::blake3(&body);
        format!(
            "{PAIRING_PREFIX}{}{}",
            hex::encode_upper(&body),
            hex::encode_upper(&sum[..4])
        )
    }

    /// Parses and validates a scanned or pasted code (whitespace ignored).
    pub fn parse(code: &str, now_ms: u64) -> Result<Self, RosterMgmtError> {
        let code: String = code.split_whitespace().collect();
        let hexpart = code
            .strip_prefix(PAIRING_PREFIX)
            .ok_or(RosterMgmtError::BadCode)?;
        let raw = hex::decode(hexpart).map_err(|_| RosterMgmtError::BadCode)?;
        if raw.len() < 5 {
            return Err(RosterMgmtError::BadCode);
        }
        let (body, sum) = raw.split_at(raw.len() - 4);
        if fleet_crypto::blake3(body)[..4] != *sum {
            return Err(RosterMgmtError::BadCode);
        }
        let o: Self = decode(body).map_err(|_| RosterMgmtError::BadCode)?;
        o.check(now_ms)?;
        Ok(o)
    }

    fn check(&self, now_ms: u64) -> Result<(), RosterMgmtError> {
        if now_ms.saturating_sub(self.created_ms) > OFFER_TTL_MS
            || self.created_ms > now_ms.saturating_add(OFFER_TTL_MS)
        {
            return Err(RosterMgmtError::Expired);
        }
        bounded_name(&self.name)?;
        for k in [
            &self.root_key,
            &self.device_key,
            &self.monitor_key,
            &self.ssh_key,
            &self.monitor_ssh_key,
        ] {
            p256_key(k).map_err(|_| RosterMgmtError::BadKey)?;
        }
        fleet_crypto::hpke::p256_check_public(&self.agreement_key)
            .map_err(|_| RosterMgmtError::BadKey)?;
        Ok(())
    }
}

fn bounded_name(name: &str) -> Result<BoundedString<64>, RosterMgmtError> {
    let n = BoundedString::new(name.trim()).map_err(|_| RosterMgmtError::Name)?;
    if n.as_str().is_empty() || n.as_str().chars().any(char::is_control) {
        return Err(RosterMgmtError::Name);
    }
    Ok(n)
}

/// The enrolled Mac's answer, published as a pairing record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingResponse {
    pub fleet_id: FleetId,
    pub fleet_name: String,
    pub by: DeviceId,
    pub by_name: String,
    pub by_root_key: P256Public,
    /// Echo of the offer nonce.
    pub offer_nonce: [u8; 16],
    /// Chosen after the offer was received.
    pub nonce: [u8; 16],
}

impl PairingResponse {
    pub fn new(
        offer: &PairingOffer,
        fleet_id: FleetId,
        fleet_name: &str,
        by: DeviceId,
        by_name: &str,
        by_root_key: P256Public,
    ) -> Result<Self, RosterMgmtError> {
        let mut nonce = [0u8; 16];
        fleet_crypto::random_bytes(&mut nonce)?;
        Ok(Self {
            fleet_id,
            fleet_name: fleet_name.to_string(),
            by,
            by_name: by_name.to_string(),
            by_root_key,
            offer_nonce: offer.nonce,
            nonce,
        })
    }
}

/// The six-digit verification code both screens show (design §5.12 step 2).
pub fn sas(offer: &PairingOffer, resp: &PairingResponse) -> String {
    let mut m = SAS_DOMAIN.to_vec();
    m.extend_from_slice(&encode(offer));
    m.extend_from_slice(&encode(resp));
    let h = fleet_crypto::blake3(&m);
    let n = u32::from_le_bytes([h[0], h[1], h[2], h[3]]) % 1_000_000;
    format!("{n:06}")
}

/// iCloud record name of a pairing record (`what`: `"response"`,
/// `"keybox"`), derived from the offer nonce so the new Mac can find it.
pub fn pairing_record_name(offer_nonce: &[u8; 16], what: &str) -> String {
    let mut m = RECORD_DOMAIN.to_vec();
    m.extend_from_slice(what.as_bytes());
    m.push(0);
    m.extend_from_slice(offer_nonce);
    hex::encode(&fleet_crypto::blake3(&m)[..16])
}

/// The roster entry for an offer.
pub fn device_from_offer(
    offer: &PairingOffer,
    added_by: DeviceId,
    now_ms: u64,
) -> Result<Device, RosterMgmtError> {
    Ok(Device {
        id: offer.device_id,
        name: bounded_name(&offer.name)?,
        role: Role::Admin,
        root_key: offer.root_key,
        device_key: offer.device_key,
        monitor_key: offer.monitor_key,
        ssh_key: offer.ssh_key,
        monitor_ssh_key: offer.monitor_ssh_key,
        noise_static: offer.noise_static,
        added_at: now_ms,
        added_by,
    })
}

/// Roster *v+1* after `current` with `devices` (normal update, rule 1):
/// same epoch, chained, recovery settings and `prev_recovery` carried
/// forward unchanged (rule 6), `issued_at_ms` never going backwards.
pub fn next_roster(current: &SignedRoster, devices: Vec<Device>, now_ms: u64) -> Roster {
    let c = &current.roster;
    Roster {
        fleet_id: c.fleet_id,
        epoch: c.epoch,
        version: c.version + 1,
        prev_hash: roster_hash(current),
        issued_at_ms: now_ms.max(c.issued_at_ms),
        devices,
        recovery_key: c.recovery_key,
        recovery_ssh_key: c.recovery_ssh_key,
        recovery_escrow_key: c.recovery_escrow_key,
        recovery_delay_s: c.recovery_delay_s,
        prev_recovery: c.prev_recovery,
    }
}

pub fn add_mac_roster(
    current: &SignedRoster,
    offer: &PairingOffer,
    me: DeviceId,
    now_ms: u64,
) -> Result<Roster, RosterMgmtError> {
    let c = &current.roster;
    let dup = c.devices.iter().any(|d| {
        d.id == offer.device_id
            || [d.root_key, d.device_key, d.monitor_key, d.ssh_key].contains(&offer.device_key)
            || d.noise_static == offer.noise_static
    });
    if dup {
        return Err(RosterMgmtError::AlreadyMember);
    }
    if c.device(&me).is_none() {
        return Err(RosterMgmtError::Refused("this Mac is not in the roster"));
    }
    let mut devices = c.devices.clone();
    devices.push(device_from_offer(offer, me, now_ms)?);
    Ok(next_roster(current, devices, now_ms))
}

pub fn revoke_mac_roster(
    current: &SignedRoster,
    target: DeviceId,
    me: DeviceId,
    now_ms: u64,
) -> Result<Roster, RosterMgmtError> {
    if target == me {
        return Err(RosterMgmtError::Refused("revoke this Mac from another Mac"));
    }
    let c = &current.roster;
    if c.device(&target).is_none() {
        return Err(RosterMgmtError::UnknownDevice);
    }
    if c.device(&me).is_none() {
        return Err(RosterMgmtError::Refused("this Mac is not in the roster"));
    }
    let devices: Vec<Device> = c
        .devices
        .iter()
        .filter(|d| d.id != target)
        .cloned()
        .collect();
    Ok(next_roster(current, devices, now_ms))
}

/// Signs `roster` with this Mac's root key (Touch ID showing `what` and
/// the server count), then checks it against `current` exactly as an agent
/// would, so a bad roster never leaves the Mac.
pub fn sign_next(
    keys: &dyn DeviceSigner,
    me: DeviceId,
    current: &SignedRoster,
    roster: Roster,
    what: &str,
    servers: usize,
    now_ms: u64,
) -> Result<SignedRoster, RosterMgmtError> {
    let root = RoleSigner::with_reason(keys, KeyRole::Root, root_reason(what, servers))?;
    let signed = sign_root(roster, me, &root)?;
    evaluate(current, &[], &signed, RecoveryClock::at(now_ms))?;
    Ok(signed)
}

// ---- the local chain copy ----

pub fn chain(cache: &Cache) -> Result<Vec<SignedRoster>, RosterMgmtError> {
    cache
        .roster_chain()?
        .into_iter()
        .map(|r| {
            decode(&r.signed)
                .map_err(|_| RosterMgmtError::Cache(CacheError::Corrupt("roster".into())))
        })
        .collect()
}

pub fn latest(cache: &Cache) -> Result<SignedRoster, RosterMgmtError> {
    chain(cache)?.pop().ok_or(RosterMgmtError::NoRoster)
}

fn row(s: &SignedRoster) -> RosterRow {
    RosterRow {
        epoch: s.roster.epoch,
        version: s.roster.version,
        hash: roster_hash(s),
        signed: encode(s),
    }
}

/// Stores a roster this Mac signed (already checked by [`sign_next`]).
pub fn store_own(cache: &Cache, s: &SignedRoster) -> Result<(), RosterMgmtError> {
    cache.put_roster(&row(s))?;
    Ok(())
}

/// Caches a roster copy from sync (or a server), after checking it links
/// to a roster already in the chain: rule 1 for a normal update, rule 3
/// against any roster of the previous epoch for a recovery roster. Judged
/// at the roster's own `issued_at_ms`. Returns whether it was new.
pub fn store_chain_link(cache: &Cache, s: &SignedRoster) -> Result<bool, RosterMgmtError> {
    let have = chain(cache)?;
    let (e, v) = (s.roster.epoch, s.roster.version);
    if have
        .iter()
        .any(|r| r.roster.epoch == e && r.roster.version == v)
    {
        return Ok(false);
    }
    let clock = RecoveryClock::at(s.roster.issued_at_ms);
    let ok = match s.signer {
        KeyRef::Root(_) => have
            .iter()
            .find(|r| r.roster.epoch == e && r.roster.version + 1 == v)
            .map(|prev| evaluate(prev, &[], s, clock).map(|_| ())),
        KeyRef::Recovery => {
            let prev_epoch: Vec<&SignedRoster> =
                have.iter().filter(|r| r.roster.epoch + 1 == e).collect();
            let hashes: Vec<Hash32> = prev_epoch.iter().map(|r| roster_hash(r)).collect();
            let mut last = None;
            for cur in &prev_epoch {
                last = Some(evaluate(cur, &hashes, s, clock).map(|_| ()));
                if matches!(last, Some(Ok(()))) {
                    break;
                }
            }
            last
        }
    };
    match ok {
        Some(Ok(())) => {
            cache.put_roster(&row(s))?;
            Ok(true)
        }
        Some(Err(err)) => Err(err.into()),
        // Its predecessor isn't here yet (sync order): not an error.
        None => Ok(false),
    }
}

/// Every roster after `(epoch, version)`, in order: what a server that
/// confirmed that roster needs to catch up (rule 2).
pub fn links_after(chain: &[SignedRoster], epoch: u32, version: u64) -> Vec<SignedRoster> {
    chain
        .iter()
        .filter(|r| (r.roster.epoch, r.roster.version) > (epoch, version))
        .cloned()
        .collect()
}

pub fn seen(cache: &Cache, server: &ServerId) -> Result<Option<(u32, u64)>, CacheError> {
    match cache.setting(&format!("{SEEN_PREFIX}{server}"))? {
        Some(v) => decode(&v)
            .map(Some)
            .map_err(|_| CacheError::Corrupt("roster seen".into())),
        None => Ok(None),
    }
}

pub fn set_seen(cache: &Cache, server: &ServerId, at: (u32, u64)) -> Result<(), CacheError> {
    cache.set_setting(&format!("{SEEN_PREFIX}{server}"), &encode(&at))
}

/// A server and the `(epoch, version)` it last confirmed, if any.
pub type PendingServer = (ServerId, Option<(u32, u64)>);

/// Servers not known to hold the latest roster (design §5.3 "Offline
/// servers"): until they get it they still trust a revoked Mac.
pub fn pending_servers(
    cache: &Cache,
    servers: &[ServerId],
) -> Result<Vec<PendingServer>, RosterMgmtError> {
    let l = latest(cache)?;
    let want = (l.roster.epoch, l.roster.version);
    let mut out = Vec::new();
    for s in servers {
        let at = seen(cache, s)?;
        if at.is_none_or(|a| a < want) {
            out.push((s.clone(), at));
        }
    }
    Ok(out)
}

/// Result of [`push_chain`] on one server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushOutcome {
    /// The server now holds `(epoch, version)` (possibly already did).
    Current { epoch: u32, version: u64 },
    /// Not reachable or locked: stays queued.
    Queued,
    /// The server refused a link (receipted): needs attention.
    Rejected { at_version: u64, code: ErrorCode },
    /// A link was sent but the answer was lost; the next connect retries.
    Unknown(String),
}

/// Brings `server` up to the end of `chain` (rule 2): reads its roster
/// version (signed `agent.health`), then sends each missing link in order
/// with `roster.update`.
pub async fn push_chain<R: OpRunner>(
    runner: &R,
    server: &ServerId,
    chain: &[SignedRoster],
) -> PushOutcome {
    let (epoch, version) = match runner
        .run(server, Op::AgentHealth, Actor::Human, None)
        .await
    {
        Ok(Payload::AgentHealth(h)) => (h.roster_epoch, h.roster_version),
        Ok(_) => return PushOutcome::Unknown("unexpected agent.health reply".into()),
        Err(RunError::Offline | RunError::Locked) => return PushOutcome::Queued,
        Err(e) => return PushOutcome::Unknown(e.to_string()),
    };
    let mut at = (epoch, version);
    for link in links_after(chain, epoch, version) {
        let op = Op::RosterUpdate {
            roster: Box::new(link.clone()),
        };
        match runner.run(server, op, Actor::Human, None).await {
            Ok(_) => at = (link.roster.epoch, link.roster.version),
            Err(RunError::Offline | RunError::Locked) => return PushOutcome::Queued,
            Err(RunError::Agent(code)) => {
                return PushOutcome::Rejected {
                    at_version: link.roster.version,
                    code,
                };
            }
            Err(RunError::Other(m)) => return PushOutcome::Unknown(m),
        }
    }
    PushOutcome::Current {
        epoch: at.0,
        version: at.1,
    }
}

// ---- change descriptions (alerts) ----

/// What a roster change did, for the "Mac added/revoked by …" alerts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterChange {
    pub epoch: u32,
    pub version: u64,
    /// Signing Mac, or `None` for the recovery key.
    pub by: Option<(DeviceId, String)>,
    pub added: Vec<(DeviceId, String)>,
    pub removed: Vec<(DeviceId, String)>,
    pub recovery_changed: bool,
}

pub fn describe(prev: &Roster, next: &SignedRoster) -> RosterChange {
    let n = &next.roster;
    let name = |d: &Device| (d.id, d.name.as_str().to_string());
    let by = match next.signer {
        KeyRef::Root(id) => Some(
            prev.device(&id)
                .or_else(|| n.device(&id))
                .map_or((id, hex::encode(id.0)), name),
        ),
        KeyRef::Recovery => None,
    };
    RosterChange {
        epoch: n.epoch,
        version: n.version,
        by,
        added: n
            .devices
            .iter()
            .filter(|d| prev.device(&d.id).is_none())
            .map(name)
            .collect(),
        removed: prev
            .devices
            .iter()
            .filter(|d| n.device(&d.id).is_none())
            .map(name)
            .collect(),
        recovery_changed: prev.recovery_keys() != n.recovery_keys()
            || prev.recovery_delay_s != n.recovery_delay_s,
    }
}

/// Describes the change to `(epoch, version)` from the local chain, if
/// that roster (and the one before it) is known.
pub fn describe_version(chain: &[SignedRoster], epoch: u32, version: u64) -> Option<RosterChange> {
    let i = chain
        .iter()
        .position(|r| r.roster.epoch == epoch && r.roster.version == version)?;
    let prev = chain[..i].last()?;
    Some(describe(&prev.roster, &chain[i]))
}

// ---- recovery veto (rule 4) ----

/// `roster.veto{pending_hash}` with a root-key approval for one server
/// (Touch ID names the veto). Returns the op and approval to send.
pub fn veto_command(
    keys: &dyn DeviceSigner,
    fleet_id: FleetId,
    me: DeviceId,
    server: &ServerId,
    pending_hash: Hash32,
    now_ms: u64,
) -> Result<(Op, fleet_proto::RootApproval), RosterMgmtError> {
    let op = Op::RosterVeto { pending_hash };
    let mut approval_id = [0u8; 16];
    fleet_crypto::random_bytes(&mut approval_id)?;
    let params = ApprovalParams {
        fleet_id,
        approval_id,
        issued_at_ms: now_ms,
        expires_at_ms: now_ms + VETO_APPROVAL_MS,
    };
    let item = ApprovalItem {
        server_id: server.clone(),
        op_digest: op_digest(&op, None),
    };
    let root = RoleSigner::with_reason(
        keys,
        KeyRole::Root,
        root_reason("vetoing a pending fleet recovery", 1),
    )?;
    let mut a = build_approvals(&root, me, &params, &[item])
        .map_err(|_| RosterMgmtError::Refused("approval"))?;
    Ok((op, a.remove(0)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::SoftwareDeviceSigner;
    use fleet_crypto::hpke::{P256Recipient, SoftwareP256Recipient};
    use fleet_crypto::roster::{ChainOutcome, apply_chain};
    use fleet_crypto::sig::Signer;
    use fleet_proto::{AgentHealth, AgentVersion, RootApproval};
    use std::cell::RefCell;
    use std::collections::HashMap;

    const NOW: u64 = 1_750_000_000_000;

    struct Mac {
        id: DeviceId,
        keys: SoftwareDeviceSigner,
        noise: X25519Public,
    }

    fn mac(i: u8) -> Mac {
        Mac {
            id: DeviceId([i; 16]),
            keys: SoftwareDeviceSigner::generate().unwrap(),
            noise: X25519Public([i; 32]),
        }
    }

    fn offer(m: &Mac, name: &str) -> PairingOffer {
        let agree = SoftwareP256Recipient::generate().unwrap();
        PairingOffer::build(&m.keys, agree.public().to_vec(), m.noise, m.id, name, NOW).unwrap()
    }

    fn genesis(m: &Mac) -> SignedRoster {
        let d = Device {
            id: m.id,
            name: BoundedString::new("First").unwrap(),
            role: Role::Admin,
            root_key: m.keys.root.public(),
            device_key: m.keys.device.public(),
            monitor_key: m.keys.monitor.public(),
            ssh_key: m.keys.ssh.public(),
            monitor_ssh_key: m.keys.monitor_ssh.public(),
            noise_static: m.noise,
            added_at: NOW,
            added_by: m.id,
        };
        let r = Roster {
            fleet_id: FleetId([9; 16]),
            epoch: 0,
            version: 1,
            prev_hash: [0; 32],
            issued_at_ms: NOW,
            devices: vec![d],
            recovery_key: fleet_proto::Ed25519Public([1; 32]),
            recovery_ssh_key: fleet_proto::Ed25519Public([2; 32]),
            recovery_escrow_key: X25519Public([3; 32]),
            recovery_delay_s: 0,
            prev_recovery: None,
        };
        sign_root(r, m.id, &m.keys.root).unwrap()
    }

    /// An agent's roster state: applies `roster.update` with the agent's own
    /// rules (`fleet_crypto::roster::apply_chain`).
    struct FakeFleet {
        rosters: RefCell<HashMap<ServerId, SignedRoster>>,
        offline: RefCell<Vec<ServerId>>,
        updates: RefCell<u32>,
    }

    impl OpRunner for FakeFleet {
        async fn run(
            &self,
            server: &ServerId,
            op: Op,
            _: Actor,
            _: Option<RootApproval>,
        ) -> Result<Payload, RunError> {
            if self.offline.borrow().contains(server) {
                return Err(RunError::Offline);
            }
            let mut rosters = self.rosters.borrow_mut();
            let cur = rosters.get(server).unwrap().clone();
            match op {
                Op::AgentHealth => Ok(Payload::AgentHealth(AgentHealth {
                    agent_version: AgentVersion {
                        major: 0,
                        minor: 1,
                        patch: 0,
                    },
                    proto_version: 1,
                    uptime_s: 0,
                    gate_rss_bytes: 0,
                    exec_rss_bytes: 0,
                    audit_seq: 0,
                    roster_epoch: cur.roster.epoch,
                    roster_version: cur.roster.version,
                    policy_version: 1,
                    pending_recovery: None,
                    run_id: [0; 16],
                })),
                Op::RosterUpdate { roster } => {
                    *self.updates.borrow_mut() += 1;
                    let out: ChainOutcome = apply_chain(
                        &cur,
                        &[],
                        std::slice::from_ref(&*roster),
                        RecoveryClock::at(NOW + 1000),
                    )
                    .map_err(|e| RunError::Agent(e.code()))?;
                    assert_eq!(out.accepted, 1);
                    rosters.insert(server.clone(), *roster);
                    Ok(Payload::Empty)
                }
                _ => Err(RunError::Agent(ErrorCode::Unsupported)),
            }
        }
    }

    fn sid(i: u8) -> ServerId {
        ServerId::new(format!("srv_{i:06}")).unwrap()
    }

    #[test]
    fn pairing_code_roundtrip_and_validation() {
        let m = mac(2);
        let o = offer(&m, "MacBook Air");
        let code = o.to_code();
        assert!(code.starts_with(PAIRING_PREFIX));
        let spaced = format!(" {}\n{} ", &code[..40], &code[40..]);
        assert_eq!(PairingOffer::parse(&spaced, NOW + 1).unwrap(), o);
        // Typo: checksum.
        let mut bad = code.clone().into_bytes();
        let i = bad.len() - 12;
        bad[i] = if bad[i] == b'A' { b'B' } else { b'A' };
        assert!(matches!(
            PairingOffer::parse(std::str::from_utf8(&bad).unwrap(), NOW),
            Err(RosterMgmtError::BadCode)
        ));
        assert!(matches!(
            PairingOffer::parse(&code, NOW + OFFER_TTL_MS + 1),
            Err(RosterMgmtError::Expired)
        ));
        assert!(PairingOffer::parse("FLEETPAIR1-00", NOW).is_err());
    }

    #[test]
    fn sas_binds_both_sides() {
        let (a, b) = (mac(1), mac(2));
        let o = offer(&b, "New");
        let r = PairingResponse::new(
            &o,
            FleetId([9; 16]),
            "Prod",
            a.id,
            "Old",
            a.keys.root.public(),
        )
        .unwrap();
        let code = sas(&o, &r);
        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|c| c.is_ascii_digit()));
        assert_eq!(sas(&o, &r), code, "deterministic");
        let swapped = offer(&mac(3), "Evil");
        assert_ne!(sas(&swapped, &r), code);
        let mut r2 = r.clone();
        r2.by_root_key = b.keys.root.public();
        assert_ne!(sas(&o, &r2), code);
        assert_ne!(
            pairing_record_name(&o.nonce, "response"),
            pairing_record_name(&o.nonce, "keybox")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn add_revoke_push_and_offline_catch_up() {
        let (a, b) = (mac(1), mac(2));
        let g = genesis(&a);
        let cache = Cache::open_in_memory().unwrap();
        store_own(&cache, &g).unwrap();
        let servers = [sid(1), sid(2), sid(3)];
        let fleet = FakeFleet {
            rosters: RefCell::new(servers.iter().map(|s| (s.clone(), g.clone())).collect()),
            offline: RefCell::new(vec![sid(3)]),
            updates: RefCell::new(0),
        };

        // Add B (v2).
        let o = offer(&b, "MacBook Air");
        let r2 = add_mac_roster(&g, &o, a.id, NOW + 10).unwrap();
        assert!(matches!(
            add_mac_roster(&g, &offer(&a, "Dup"), a.id, NOW),
            Err(RosterMgmtError::AlreadyMember)
        ));
        let s2 = sign_next(&a.keys, a.id, &g, r2, "add Mac MacBook Air", 3, NOW + 10).unwrap();
        store_own(&cache, &s2).unwrap();
        // Revoke B again (v3), signed by A.
        let r3 = revoke_mac_roster(&s2, b.id, a.id, NOW + 20).unwrap();
        assert!(matches!(
            revoke_mac_roster(&s2, a.id, a.id, NOW),
            Err(RosterMgmtError::Refused(_))
        ));
        let s3 = sign_next(
            &a.keys,
            a.id,
            &s2,
            r3,
            "revoke Mac MacBook Air",
            3,
            NOW + 20,
        )
        .unwrap();
        store_own(&cache, &s3).unwrap();
        let ch = chain(&cache).unwrap();
        assert_eq!(ch.len(), 3);

        for s in &servers {
            let out = push_chain(&fleet, s, &ch).await;
            if let PushOutcome::Current { epoch, version } = out {
                set_seen(&cache, s, (epoch, version)).unwrap();
            }
        }
        assert_eq!(
            *fleet.updates.borrow(),
            4,
            "two links to each online server"
        );
        let pending = pending_servers(&cache, &servers).unwrap();
        assert_eq!(pending, vec![(sid(3), None)]);

        // The offline server comes back: the whole chain catches it up.
        fleet.offline.borrow_mut().clear();
        let out = push_chain(&fleet, &sid(3), &ch).await;
        assert_eq!(
            out,
            PushOutcome::Current {
                epoch: 0,
                version: 3
            }
        );
        set_seen(&cache, &sid(3), (0, 3)).unwrap();
        assert!(pending_servers(&cache, &servers).unwrap().is_empty());
        // Already current: nothing sent.
        let before = *fleet.updates.borrow();
        push_chain(&fleet, &sid(1), &ch).await;
        assert_eq!(*fleet.updates.borrow(), before);

        // Descriptions for the alerts.
        let add = describe_version(&ch, 0, 2).unwrap();
        assert_eq!(add.added, vec![(b.id, "MacBook Air".to_string())]);
        assert_eq!(add.by.as_ref().unwrap().0, a.id);
        let rev = describe_version(&ch, 0, 3).unwrap();
        assert_eq!(rev.removed.len(), 1);
        assert!(!rev.recovery_changed);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_revoked_mac_cannot_push_and_forged_links_are_not_cached() {
        let (a, b, c) = (mac(1), mac(2), mac(3));
        let g = genesis(&a);
        let s2 = sign_next(
            &a.keys,
            a.id,
            &g,
            add_mac_roster(&g, &offer(&b, "B"), a.id, NOW).unwrap(),
            "x",
            1,
            NOW,
        )
        .unwrap();
        let s3 = sign_next(
            &a.keys,
            a.id,
            &s2,
            revoke_mac_roster(&s2, b.id, a.id, NOW).unwrap(),
            "x",
            1,
            NOW,
        )
        .unwrap();
        // B, revoked in v3, signs a v4 adding C: servers at v3 refuse it.
        let evil = next_roster(
            &s3,
            {
                let mut d = s3.roster.devices.clone();
                d.push(device_from_offer(&offer(&c, "C"), b.id, NOW).unwrap());
                d
            },
            NOW,
        );
        let evil = sign_root(evil, b.id, &b.keys.root).unwrap();
        let fleet = FakeFleet {
            rosters: RefCell::new([(sid(1), s3.clone())].into_iter().collect()),
            offline: RefCell::new(vec![]),
            updates: RefCell::new(0),
        };
        let out = push_chain(
            &fleet,
            &sid(1),
            &[g.clone(), s2.clone(), s3.clone(), evil.clone()],
        )
        .await;
        assert!(matches!(out, PushOutcome::Rejected { at_version: 4, .. }));

        let cache = Cache::open_in_memory().unwrap();
        store_own(&cache, &g).unwrap();
        assert!(store_chain_link(&cache, &s2).unwrap());
        assert!(!store_chain_link(&cache, &s2).unwrap(), "already there");
        assert!(store_chain_link(&cache, &s3).unwrap());
        assert!(store_chain_link(&cache, &evil).is_err());
        assert_eq!(latest(&cache).unwrap(), s3);
    }

    #[test]
    fn veto_approval_verifies() {
        let a = mac(1);
        let g = genesis(&a);
        let (op, approval) =
            veto_command(&a.keys, FleetId([9; 16]), a.id, &sid(1), [7; 32], NOW).unwrap();
        fleet_crypto::approval::verify_approval(
            &approval,
            &g.roster,
            &sid(1),
            &op_digest(&op, None),
            NOW + 1,
        )
        .unwrap();
        assert!(
            fleet_crypto::approval::verify_approval(
                &approval,
                &g.roster,
                &sid(2),
                &op_digest(&op, None),
                NOW + 1
            )
            .is_err()
        );
    }
}
