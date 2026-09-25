//! Recovery with the printed code, and the recovery drill (design §5.11).
//!
//! **Recover fleet** (a fresh Mac, every other Mac lost):
//!
//! 1. The operator types the 24 words and passphrase; [`derive`] runs
//!    Argon2id and yields the recovery keys (memory only, zeroized).
//! 2. [`escrow_name`] names the escrow record in iCloud; `sync::keys::
//!    open_escrow` opens it with the escrow secret, giving the fleet id and
//!    sync key. The synced records (servers, pins, roster chain copies) are
//!    then applied like any sync (checked against the chain).
//! 3. The Mac creates its own Secure Enclave keys; a new recovery code is
//!    generated **before** touching servers, since the used code was typed
//!    into this machine ([`NewCode`]).
//! 4. [`build_recovery_roster`]: epoch + 1 on top of the latest known
//!    roster, only this Mac as a device, the new recovery keys, no
//!    `prev_recovery`; signed by the recovery key.
//! 5. Per server ([`RecoveryTransport`], [`SshRecovery`] in the app): SSH
//!    with the recovery SSH key (forced to `bridge --recovery`), a recovery
//!    `DeviceAuth`, `roster.update`. With a recovery delay the roster is
//!    pending; the app shows a countdown per server (vetoable by any
//!    remaining Mac, `roster_mgmt::veto_command`).
//! 6. The sync key is re-escrowed to the new code's escrow key.
//!
//! **Without the synced roster chain** (no iCloud roster copies, or only
//! the local cache's servers and pins): [`roster_from_servers`] reads the
//! roster each server enforces with `roster.get` in a recovery session
//! (allowed there, receipt-verified against the pinned agent key), keeps
//! the newest one whose recovery key (current or rotated-out) is this
//! code's and which lists its own hash in `epoch_hashes`, and the recovery
//! roster chains to it (fleet id, epoch + 1, `prev_hash`). Servers are
//! authoritative, so no copy is needed. Servers still need pinned host and
//! agent keys: a receipt can't be checked against a key trusted on first
//! use, so typing servers in by hand without their pins isn't supported.
//!
//! **Drill** ([`drill`]): on an enrolled Mac, derive from the code and
//! check that the public keys equal the recovery keys the roster on each
//! server holds (by the version each server reports, looked up in the
//! verified local chain). Nothing changes on servers; afterwards the app
//! offers [`rotation_roster`].

use crate::manager::ServerSpec;
use crate::runner::{OpRunner, RunError};
use crate::session::{ClientError, CommandSigner, Session, SessionConfig, SessionMode};
use crate::ssh::{SshConnection, SshError, SshOptions};
use fleet_crypto::noise::StaticKeypair;
use fleet_crypto::recovery::{KdfParams, RecoveryCode, RecoveryKeys, RecoveryPublics, delay_for};
use fleet_crypto::roster::{
    RECOVERY_GRACE_MS, RecoveryClock, recovery_key_at, roster_hash, sign_recovery,
};
use fleet_proto::payload::RosterState;
use fleet_proto::{
    Actor, Device, DeviceId, ErrorCode, FleetId, Hash32, KeyKind, Op, Payload, PrevRecovery,
    Roster, ServerId, SignedRoster, X25519Public,
};
use std::future::Future;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("recovery code invalid")]
    BadCode,
    #[error("crypto: {0}")]
    Crypto(#[from] fleet_crypto::Error),
    #[error("no roster: no synced copy and no server answered roster.get")]
    NeedsRosterCopy,
    #[error("the recovery code does not match this fleet's roster")]
    WrongCode,
    #[error("the previous recovery code is still in its rotation grace window")]
    RotationTooSoon,
    #[error("ssh: {0}")]
    Ssh(#[from] SshError),
    #[error("session: {0}")]
    Session(#[from] ClientError),
    #[error("server refused the recovery roster: {0:?}")]
    Refused(ErrorCode),
    #[error("timed out")]
    Timeout,
}

/// Argon2id + HKDF (slow: run off the main thread).
pub fn derive(
    words: &str,
    passphrase: &str,
    params: KdfParams,
) -> Result<RecoveryKeys, RecoveryError> {
    let code = RecoveryCode::parse(words).map_err(|_| RecoveryError::BadCode)?;
    Ok(code.derive(passphrase, params)?)
}

/// iCloud record name of the escrow the code opens.
pub fn escrow_name(keys: &RecoveryKeys) -> String {
    crate::sync::keys::escrow_record_name(&keys.publics().recovery_escrow_key)
}

/// The replacement code, generated before servers are touched.
pub struct NewCode {
    pub code: RecoveryCode,
    pub keys: RecoveryKeys,
    pub delay_s: u32,
}

impl NewCode {
    pub fn generate(passphrase: &str, params: KdfParams) -> Result<Self, RecoveryError> {
        let code = RecoveryCode::generate()?;
        let keys = code.derive(passphrase, params)?;
        Ok(Self {
            code,
            keys,
            delay_s: delay_for(passphrase),
        })
    }
}

/// Epoch + 1 recovery roster (rule 3) listing only `me`, with the new
/// recovery keys, signed by the recovery key from the code.
pub fn build_recovery_roster(
    latest: &SignedRoster,
    me: Device,
    old: &RecoveryKeys,
    new: &RecoveryPublics,
    new_delay_s: u32,
    now_ms: u64,
) -> Result<SignedRoster, RecoveryError> {
    let c = &latest.roster;
    // The code must be this fleet's (current or rotated-out key).
    let p = old.publics();
    let ours = c.recovery_key == p.recovery_key
        || c.prev_recovery
            .is_some_and(|pr| pr.recovery_key == p.recovery_key);
    if !ours {
        return Err(RecoveryError::WrongCode);
    }
    let roster = Roster {
        fleet_id: c.fleet_id,
        epoch: c.epoch + 1,
        version: c.version + 1,
        prev_hash: roster_hash(latest),
        issued_at_ms: now_ms.max(c.issued_at_ms),
        devices: vec![me],
        recovery_key: new.recovery_key,
        recovery_ssh_key: new.recovery_ssh_key,
        recovery_escrow_key: new.recovery_escrow_key,
        recovery_delay_s: new_delay_s,
        prev_recovery: None,
    };
    Ok(sign_recovery(roster, &old.sign))
}

/// Per-server result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerRecovery {
    Installed,
    /// Waiting out the delay (vetoable until then).
    Pending {
        hash: Hash32,
        activates_at_ms: u64,
    },
}

pub trait RecoveryTransport {
    fn submit(
        &self,
        server: &ServerSpec,
        roster: &SignedRoster,
    ) -> impl Future<Output = Result<ServerRecovery, RecoveryError>>;

    /// `roster.get` in a recovery session: the roster the agent enforces
    /// and its epoch's hashes (receipt-verified against the pinned agent
    /// key).
    fn fetch_roster(
        &self,
        _server: &ServerSpec,
    ) -> impl Future<Output = Result<RosterState, RecoveryError>> {
        std::future::ready(Err(RecoveryError::NeedsRosterCopy))
    }
}

/// Servers (address + pinned host and agent keys) from synced records,
/// when no roster copy synced to verify their signatures against. Only the
/// sync key (AEAD, opened from the escrow with the code) vouches for them:
/// they are used to ask those servers for their roster ([`roster_from_servers`],
/// whose answers are receipt-checked against these pins); once that
/// roster is in the chain, the records are ingested and verified as usual.
/// Newest record per server; servers without agent pins are skipped.
pub fn specs_from_records(
    key: &crate::sync::keys::SyncKey,
    records: &[crate::sync::CloudRecord],
) -> Vec<ServerSpec> {
    use crate::sync::Collection;
    use crate::sync::bridge::{PinsDoc, ServerDoc};
    use std::collections::HashMap;
    let mut newest: HashMap<(u8, String), crate::sync::SyncRecord> = HashMap::new();
    for r in records {
        let Ok(s) = key.open_record(r) else { continue };
        let slot = match s.record.collection {
            Collection::Servers => 0u8,
            Collection::PinnedKeys => 1,
            _ => continue,
        };
        let k = (slot, s.record.key.clone());
        if newest.get(&k).is_none_or(|o| o.hlc < s.record.hlc) {
            newest.insert(k, s.record);
        }
    }
    let mut out = Vec::new();
    for ((slot, id), rec) in &newest {
        if *slot != 0 || rec.deleted {
            continue;
        }
        let Ok(sid) = ServerId::new(id.clone()) else {
            continue;
        };
        let Ok(doc) = fleet_proto::decode::<ServerDoc>(&rec.body) else {
            continue;
        };
        let Ok(server) = doc.to_record(sid.clone()) else {
            continue;
        };
        let Some(pins) = newest
            .get(&(1, id.clone()))
            .filter(|p| !p.deleted)
            .and_then(|p| fleet_proto::decode::<PinsDoc>(&p.body).ok())
            .and_then(|d| d.to_pins().ok())
        else {
            continue;
        };
        let (Some(agent_noise), Some(agent_signing)) = (pins.agent_noise, pins.agent_signing)
        else {
            continue;
        };
        out.push(ServerSpec {
            id: sid,
            target: server.target,
            host_key: pins.host_key,
            agent_noise,
            agent_signing,
        });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

/// The newest roster the reachable `servers` hold that this code belongs
/// to (current or rotated-out recovery key), for a recovery without the
/// synced roster chain. The servers are authoritative (design §7.6); each
/// answer comes over a session with pinned host and agent keys, and must
/// list its own hash last in `epoch_hashes`. Rosters of another fleet or
/// code are ignored; nothing matching is [`RecoveryError::WrongCode`].
pub async fn roster_from_servers<T: RecoveryTransport>(
    transport: &T,
    servers: &[ServerSpec],
    code: &RecoveryPublics,
) -> Result<SignedRoster, RecoveryError> {
    let mut best: Option<SignedRoster> = None;
    let mut last_err = None;
    let mut mismatched = false;
    for s in servers {
        let st = match transport.fetch_roster(s).await {
            Ok(st) => st,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        let r = &st.roster.roster;
        let ours = r.recovery_key == code.recovery_key
            || r.prev_recovery
                .is_some_and(|p| p.recovery_key == code.recovery_key);
        if !ours || st.epoch_hashes.last() != Some(&roster_hash(&st.roster)) {
            mismatched = true;
            continue;
        }
        if let Some(b) = &best
            && b.roster.fleet_id != r.fleet_id
        {
            mismatched = true;
            continue;
        }
        let newer = best
            .as_ref()
            .is_none_or(|b| (r.epoch, r.version) > (b.roster.epoch, b.roster.version));
        if newer {
            best = Some(st.roster);
        }
    }
    match (best, mismatched, last_err) {
        (Some(b), _, _) => Ok(b),
        (None, true, _) => Err(RecoveryError::WrongCode),
        (None, false, Some(e)) => Err(e),
        (None, false, None) => Err(RecoveryError::NeedsRosterCopy),
    }
}

/// Submits over SSH with the recovery SSH key and a recovery session.
pub struct SshRecovery<'a> {
    pub keys: &'a RecoveryKeys,
    /// The new Mac's Noise key (bound by the recovery `DeviceAuth`).
    pub noise: &'a StaticKeypair,
    pub fleet_id: FleetId,
    pub device_id: DeviceId,
    pub ssh: SshOptions,
    pub timeout: Duration,
}

impl RecoveryTransport for SshRecovery<'_> {
    async fn submit(
        &self,
        server: &ServerSpec,
        roster: &SignedRoster,
    ) -> Result<ServerRecovery, RecoveryError> {
        let op = Op::RosterUpdate {
            roster: Box::new(roster.clone()),
        };
        outcome(self.request(server, op).await?)
    }

    async fn fetch_roster(&self, server: &ServerSpec) -> Result<RosterState, RecoveryError> {
        match self.request(server, Op::RosterGet).await? {
            Ok(Payload::RosterState(st)) => Ok(*st),
            Ok(_) => Err(RecoveryError::Session(ClientError::Malformed)),
            Err(code) => Err(RecoveryError::Refused(code)),
        }
    }
}

impl SshRecovery<'_> {
    /// One op in a fresh recovery session (SSH with the recovery key).
    async fn request(
        &self,
        server: &ServerSpec,
        op: Op,
    ) -> Result<Result<Payload, ErrorCode>, RecoveryError> {
        let (conn, obs) = SshConnection::connect_with(
            &server.target,
            &self.keys.ssh,
            server.host_key.clone(),
            &self.ssh,
        )
        .await?;
        if !obs.all_matched() {
            conn.disconnect().await;
            return Err(RecoveryError::Ssh(SshError::HostKeyUnconfirmed));
        }
        let run = async {
            let stream = conn.open_agent_channel_mode(SessionMode::Recovery).await?;
            let cfg = SessionConfig {
                mode: SessionMode::Recovery,
                noise: self.noise,
                pinned_agent_noise: server.agent_noise,
                pinned_agent_signing: server.agent_signing,
                fleet_id: self.fleet_id,
                server_id: server.id.clone(),
                device_id: self.device_id,
                key: KeyKind::Recovery,
                signer: CommandSigner::Recovery(&self.keys.sign),
            };
            let mut s = Session::connect_bridged(stream, cfg).await?;
            let reply = s.request(op, &server.id, Actor::Recovery, None).await?;
            Ok(reply.result)
        };
        let res = tokio::time::timeout(self.timeout, run)
            .await
            .unwrap_or(Err(RecoveryError::Timeout));
        conn.disconnect().await;
        res
    }
}

fn outcome(r: Result<Payload, ErrorCode>) -> Result<ServerRecovery, RecoveryError> {
    match r {
        Ok(Payload::RosterPending(Some(p))) => Ok(ServerRecovery::Pending {
            hash: p.hash,
            activates_at_ms: p.activates_at_ms,
        }),
        Ok(_) => Ok(ServerRecovery::Installed),
        Err(code) => Err(RecoveryError::Refused(code)),
    }
}

/// Submits `roster` to every server; one result per server.
pub async fn recover_all<T: RecoveryTransport>(
    transport: &T,
    servers: &[ServerSpec],
    roster: &SignedRoster,
) -> Vec<(ServerId, Result<ServerRecovery, RecoveryError>)> {
    let mut out = Vec::with_capacity(servers.len());
    for s in servers {
        out.push((s.id.clone(), transport.submit(s, roster).await));
    }
    out
}

// ---- drill ----

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrillResult {
    /// The code opens this server's recovery.
    Match,
    /// The server's roster names other recovery keys.
    Mismatch,
    /// The server holds a roster this Mac has no copy of.
    UnknownRoster {
        epoch: u32,
        version: u64,
    },
    Unreachable(String),
}

/// Checks the code against every server (design §5.11 "Recovery drill").
pub async fn drill<R: OpRunner>(
    runner: &R,
    servers: &[ServerId],
    chain: &[SignedRoster],
    publics: &RecoveryPublics,
    now_ms: u64,
) -> Vec<(ServerId, DrillResult)> {
    let mut out = Vec::with_capacity(servers.len());
    for s in servers {
        let r = match runner.run(s, Op::AgentHealth, Actor::Human, None).await {
            Ok(Payload::AgentHealth(h)) => {
                match chain.iter().find(|r| {
                    r.roster.epoch == h.roster_epoch && r.roster.version == h.roster_version
                }) {
                    Some(r) => {
                        let rk = recovery_key_at(&r.roster, RecoveryClock::at(now_ms));
                        let all = r.roster.recovery_key == publics.recovery_key
                            && r.roster.recovery_ssh_key == publics.recovery_ssh_key
                            && r.roster.recovery_escrow_key == publics.recovery_escrow_key;
                        if all || *rk == publics.recovery_key {
                            DrillResult::Match
                        } else {
                            DrillResult::Mismatch
                        }
                    }
                    None => DrillResult::UnknownRoster {
                        epoch: h.roster_epoch,
                        version: h.roster_version,
                    },
                }
            }
            Ok(_) => DrillResult::Unreachable("unexpected reply".into()),
            Err(RunError::Agent(c)) => DrillResult::Unreachable(format!("{c:?}")),
            Err(e) => DrillResult::Unreachable(e.to_string()),
        };
        out.push((s.clone(), r));
    }
    out
}

/// A normal (root-signed) update rotating to a new code (rule 6): the old
/// keys and delay go into `prev_recovery` for the 72 h grace window.
/// Refused while a previous rotation's window is still open.
pub fn rotation_roster(
    current: &SignedRoster,
    new: &RecoveryPublics,
    new_delay_s: u32,
    now_ms: u64,
) -> Result<Roster, RecoveryError> {
    let c = &current.roster;
    if c.prev_recovery.is_some_and(|p| p.active_at(now_ms)) {
        return Err(RecoveryError::RotationTooSoon);
    }
    let issued = now_ms.max(c.issued_at_ms);
    let mut r = crate::roster_mgmt::next_roster(current, c.devices.clone(), now_ms);
    r.recovery_key = new.recovery_key;
    r.recovery_ssh_key = new.recovery_ssh_key;
    r.recovery_escrow_key = new.recovery_escrow_key;
    r.recovery_delay_s = new_delay_s;
    r.prev_recovery = Some(PrevRecovery {
        recovery_key: c.recovery_key,
        recovery_ssh_key: c.recovery_ssh_key,
        recovery_escrow_key: c.recovery_escrow_key,
        recovery_delay_s: c.recovery_delay_s,
        valid_until_ms: issued + RECOVERY_GRACE_MS,
    });
    Ok(r)
}

/// Escrow public key for re-sealing after recovery or rotation.
pub fn escrow_public(p: &RecoveryPublics) -> X25519Public {
    p.recovery_escrow_key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::Cache;
    use crate::roster_mgmt::{sign_next, store_own};
    use crate::signer::SoftwareDeviceSigner;
    use crate::ssh::SshTarget;
    use crate::sync::bridge::{PinsDoc, ServerDoc, apply_to_cache, roster_body, roster_key};
    use crate::sync::engine::SyncEngine;
    use crate::sync::keys::{SyncKey, open_escrow, seal_escrow};
    use crate::sync::store::SyncStore;
    use crate::sync::{CloudRecord, Collection};
    use fleet_crypto::roster::{RosterDecision, evaluate, sign_root};
    use fleet_crypto::sig::Signer;
    use fleet_proto::{BoundedString, Ed25519Public, Role};
    use std::cell::RefCell;
    use std::collections::HashMap;

    const TINY: KdfParams = KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    };
    const NOW: u64 = 1_750_000_000_000;

    fn device(id: DeviceId, k: &SoftwareDeviceSigner, noise: X25519Public) -> Device {
        Device {
            id,
            name: BoundedString::new("Mac").unwrap(),
            role: Role::Admin,
            root_key: k.root.public(),
            device_key: k.device.public(),
            monitor_key: k.monitor.public(),
            ssh_key: k.ssh.public(),
            monitor_ssh_key: k.monitor_ssh.public(),
            noise_static: noise,
            added_at: NOW,
            added_by: id,
        }
    }

    /// Agents' roster state under the real acceptance rules.
    struct FakeServers {
        rosters: RefCell<HashMap<ServerId, SignedRoster>>,
    }

    impl RecoveryTransport for FakeServers {
        async fn submit(
            &self,
            server: &ServerSpec,
            roster: &SignedRoster,
        ) -> Result<ServerRecovery, RecoveryError> {
            let cur = self.rosters.borrow().get(&server.id).unwrap().clone();
            match evaluate(&cur, &[], roster, RecoveryClock::at(NOW + 5)) {
                Ok(RosterDecision::Accept) => {
                    self.rosters
                        .borrow_mut()
                        .insert(server.id.clone(), roster.clone());
                    Ok(ServerRecovery::Installed)
                }
                Ok(RosterDecision::Pending { activates_at_ms }) => Ok(ServerRecovery::Pending {
                    hash: roster_hash(roster),
                    activates_at_ms,
                }),
                Err(e) => Err(RecoveryError::Refused(e.code())),
            }
        }

        async fn fetch_roster(&self, server: &ServerSpec) -> Result<RosterState, RecoveryError> {
            let cur = self
                .rosters
                .borrow()
                .get(&server.id)
                .cloned()
                .ok_or(RecoveryError::Timeout)?;
            Ok(RosterState {
                epoch_hashes: vec![roster_hash(&cur)],
                roster: cur,
            })
        }
    }

    fn spec(i: u8) -> ServerSpec {
        ServerSpec {
            id: ServerId::new(format!("srv_rec00{i}")).unwrap(),
            target: SshTarget::new(format!("10.0.0.{i}"), 22, "admin"),
            host_key: None,
            agent_noise: X25519Public([i; 32]),
            agent_signing: Ed25519Public([i; 32]),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn recovery_happy_path_from_escrow() {
        // ---- The lost fleet: Mac A, code with a strong passphrase. ----
        let code = RecoveryCode::generate().unwrap();
        let pass = "correct horse battery staple zebra";
        let old = code.derive(pass, TINY).unwrap();
        let a_keys = SoftwareDeviceSigner::generate().unwrap();
        let a = DeviceId([1; 16]);
        let fleet = FleetId([5; 16]);
        let p = old.publics();
        let g = sign_root(
            Roster {
                fleet_id: fleet,
                epoch: 0,
                version: 1,
                prev_hash: [0; 32],
                issued_at_ms: NOW,
                devices: vec![device(a, &a_keys, X25519Public([1; 32]))],
                recovery_key: p.recovery_key,
                recovery_ssh_key: p.recovery_ssh_key,
                recovery_escrow_key: p.recovery_escrow_key,
                recovery_delay_s: delay_for(pass),
                prev_recovery: None,
            },
            a,
            &a_keys.root,
        )
        .unwrap();
        // A's synced state in "iCloud": escrow + server, pins, roster copy.
        let key = SyncKey::generate().unwrap();
        let mut cloud: Vec<CloudRecord> =
            vec![seal_escrow(&key, fleet, &p.recovery_escrow_key).unwrap()];
        {
            let mut e = SyncEngine::new(
                SyncStore::open_in_memory(&[0; 32]).unwrap(),
                SyncKey::from_bytes(&key.to_bytes()).unwrap(),
                a,
            )
            .unwrap();
            let s = spec(1);
            let doc = ServerDoc {
                name: "web".into(),
                host: s.target.host.clone(),
                port: 22,
                user: "admin".into(),
                jumps: vec![],
                group: None,
                tags: vec![],
            };
            e.put(
                &a_keys.device,
                Collection::Servers,
                s.id.as_str(),
                fleet_proto::encode(&doc),
                NOW,
            )
            .unwrap();
            let pins = PinsDoc {
                host_key: None,
                agent_noise: Some(s.agent_noise.0),
                agent_signing: Some(s.agent_signing.0),
            };
            e.put(
                &a_keys.device,
                Collection::PinnedKeys,
                s.id.as_str(),
                fleet_proto::encode(&pins),
                NOW,
            )
            .unwrap();
            e.put(
                &a_keys.device,
                Collection::RosterChain,
                &roster_key(&g),
                roster_body(&g),
                NOW,
            )
            .unwrap();
            cloud.extend(e.outgoing().unwrap());
        }
        let servers = FakeServers {
            rosters: RefCell::new(
                [(spec(1).id, g.clone()), (spec(2).id, g.clone())]
                    .into_iter()
                    .collect(),
            ),
        };

        // ---- Fresh Mac B: words + passphrase → escrow → records. ----
        let typed = derive(&code.phrase(), pass, TINY).unwrap();
        let name = escrow_name(&typed);
        let escrow = cloud.iter().find(|r| r.name == name).unwrap();
        let (fid, restored) = open_escrow(escrow, &typed.escrow.secret_bytes()).unwrap();
        assert_eq!(fid, fleet);
        assert!(
            derive(&code.phrase(), "wrong", TINY)
                .map(|k| escrow_name(&k))
                .unwrap()
                != name
        );

        let mut cache = Cache::open_in_memory().unwrap();
        let b = DeviceId([2; 16]);
        let mut engine =
            SyncEngine::new(SyncStore::open_in_memory(&[1; 32]).unwrap(), restored, b).unwrap();
        // Roster copies first (the chain the rest is checked against):
        // the genesis is taken as the trust anchor only if its recovery key
        // matches the code.
        assert_eq!(g.roster.recovery_key, typed.publics().recovery_key);
        store_own(&cache, &g).unwrap();
        let chain = crate::roster_mgmt::chain(&cache).unwrap();
        let rep = engine.apply_remote(&cloud, &chain, NOW).unwrap();
        assert_eq!(rep.rejected, 0);
        let mut applied = rep.applied.clone();
        applied.sort_by_key(|r| r.collection);
        for r in &applied {
            apply_to_cache(&mut cache, r).unwrap();
        }
        assert_eq!(cache.servers().unwrap().len(), 1);
        assert!(
            cache
                .pins(&spec(1).id)
                .unwrap()
                .unwrap()
                .agent_noise
                .is_some()
        );

        // ---- New keys, new code, recovery roster, servers. ----
        let b_keys = SoftwareDeviceSigner::generate().unwrap();
        let next = NewCode::generate("", TINY).unwrap();
        let latest = crate::roster_mgmt::latest(&cache).unwrap();
        let rr = build_recovery_roster(
            &latest,
            device(b, &b_keys, X25519Public([2; 32])),
            &typed,
            &next.keys.publics(),
            next.delay_s,
            NOW + 1,
        )
        .unwrap();
        let res = recover_all(&servers, &[spec(1), spec(2)], &rr).await;
        assert!(
            res.iter()
                .all(|(_, r)| matches!(r, Ok(ServerRecovery::Installed))),
            "{res:?}"
        );
        let installed = servers.rosters.borrow().get(&spec(1).id).unwrap().clone();
        assert_eq!(installed.roster.epoch, 1);
        assert_eq!(installed.roster.devices[0].id, b);
        assert_eq!(installed.roster.recovery_delay_s, DEFAULT_DELAY);

        // The used code no longer recovers; re-escrow to the new code.
        let again = build_recovery_roster(
            &installed,
            device(b, &b_keys, X25519Public([2; 32])),
            &typed,
            &next.keys.publics(),
            0,
            NOW + 2,
        );
        assert!(matches!(again, Err(RecoveryError::WrongCode)));
        let re = seal_escrow(
            engine.key(),
            fleet,
            &next.keys.publics().recovery_escrow_key,
        )
        .unwrap();
        let (_, k2) = open_escrow(&re, &next.keys.escrow.secret_bytes()).unwrap();
        assert_eq!(k2.id, engine.key().id);
    }

    const DEFAULT_DELAY: u32 = fleet_crypto::recovery::DEFAULT_DELAY_S;

    #[tokio::test(flavor = "current_thread")]
    async fn recovery_without_roster_copies_reads_the_servers() {
        // The lost fleet synced servers and pins, but no roster copy.
        let code = RecoveryCode::generate().unwrap();
        let pass = "correct horse battery staple zebra";
        let old = code.derive(pass, TINY).unwrap();
        let a_keys = SoftwareDeviceSigner::generate().unwrap();
        let a = DeviceId([1; 16]);
        let fleet = FleetId([5; 16]);
        let p = old.publics();
        let g = sign_root(
            Roster {
                fleet_id: fleet,
                epoch: 0,
                version: 1,
                prev_hash: [0; 32],
                issued_at_ms: NOW,
                devices: vec![device(a, &a_keys, X25519Public([1; 32]))],
                recovery_key: p.recovery_key,
                recovery_ssh_key: p.recovery_ssh_key,
                recovery_escrow_key: p.recovery_escrow_key,
                recovery_delay_s: delay_for(pass),
                prev_recovery: None,
            },
            a,
            &a_keys.root,
        )
        .unwrap();
        let key = SyncKey::generate().unwrap();
        let mut e = SyncEngine::new(
            SyncStore::open_in_memory(&[0; 32]).unwrap(),
            SyncKey::from_bytes(&key.to_bytes()).unwrap(),
            a,
        )
        .unwrap();
        for i in [1u8, 2] {
            let s = spec(i);
            let doc = ServerDoc {
                name: format!("web-{i}"),
                host: s.target.host.clone(),
                port: 22,
                user: "admin".into(),
                jumps: vec![],
                group: None,
                tags: vec![],
            };
            e.put(
                &a_keys.device,
                Collection::Servers,
                s.id.as_str(),
                fleet_proto::encode(&doc),
                NOW,
            )
            .unwrap();
            let pins = PinsDoc {
                host_key: None,
                agent_noise: Some(s.agent_noise.0),
                agent_signing: Some(s.agent_signing.0),
            };
            e.put(
                &a_keys.device,
                Collection::PinnedKeys,
                s.id.as_str(),
                fleet_proto::encode(&pins),
                NOW,
            )
            .unwrap();
        }
        let cloud: Vec<CloudRecord> = e.outgoing().unwrap();
        let servers = FakeServers {
            rosters: RefCell::new([(spec(1).id, g.clone())].into_iter().collect()),
        };

        // Fresh Mac: the servers named by the records (sync key only)…
        let typed = derive(&code.phrase(), pass, TINY).unwrap();
        let restored = SyncKey::from_bytes(&key.to_bytes()).unwrap();
        let specs = specs_from_records(&restored, &cloud);
        assert_eq!(specs, vec![spec(1), spec(2)]);
        // …answer roster.get (server 2 is unreachable here).
        let latest = roster_from_servers(&servers, &specs, &typed.publics())
            .await
            .unwrap();
        assert_eq!(latest, g);
        // Another code's servers don't count as this fleet's.
        let other = RecoveryCode::generate().unwrap().derive("", TINY).unwrap();
        assert!(matches!(
            roster_from_servers(&servers, &specs, &other.publics()).await,
            Err(RecoveryError::WrongCode)
        ));
        // With that roster as the chain the records verify as usual.
        let mut cache = Cache::open_in_memory().unwrap();
        store_own(&cache, &latest).unwrap();
        let chain = crate::roster_mgmt::chain(&cache).unwrap();
        let mut engine = SyncEngine::new(
            SyncStore::open_in_memory(&[1; 32]).unwrap(),
            restored,
            DeviceId([2; 16]),
        )
        .unwrap();
        let rep = engine.apply_remote(&cloud, &chain, NOW).unwrap();
        assert_eq!(rep.rejected, 0);
        let mut applied = rep.applied.clone();
        applied.sort_by_key(|r| r.collection);
        for r in &applied {
            apply_to_cache(&mut cache, r).unwrap();
        }
        assert_eq!(cache.servers().unwrap().len(), 2);
        // And the recovery roster chains to it.
        let b_keys = SoftwareDeviceSigner::generate().unwrap();
        let next = NewCode::generate("", TINY).unwrap();
        let rr = build_recovery_roster(
            &latest,
            device(DeviceId([2; 16]), &b_keys, X25519Public([2; 32])),
            &typed,
            &next.keys.publics(),
            next.delay_s,
            NOW + 1,
        )
        .unwrap();
        let res = recover_all(&servers, &[spec(1)], &rr).await;
        assert!(matches!(res[0].1, Ok(ServerRecovery::Installed)), "{res:?}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delayed_recovery_is_pending_and_drill_matches() {
        let code = RecoveryCode::generate().unwrap();
        let old = code.derive("", TINY).unwrap();
        let k = SoftwareDeviceSigner::generate().unwrap();
        let a = DeviceId([1; 16]);
        let p = old.publics();
        let g = sign_root(
            Roster {
                fleet_id: FleetId([5; 16]),
                epoch: 0,
                version: 1,
                prev_hash: [0; 32],
                issued_at_ms: NOW,
                devices: vec![device(a, &k, X25519Public([1; 32]))],
                recovery_key: p.recovery_key,
                recovery_ssh_key: p.recovery_ssh_key,
                recovery_escrow_key: p.recovery_escrow_key,
                recovery_delay_s: delay_for(""),
                prev_recovery: None,
            },
            a,
            &k.root,
        )
        .unwrap();
        let servers = FakeServers {
            rosters: RefCell::new([(spec(1).id, g.clone())].into_iter().collect()),
        };
        let next = NewCode::generate("", TINY).unwrap();
        let rr = build_recovery_roster(
            &g,
            device(DeviceId([2; 16]), &k, X25519Public([2; 32])),
            &old,
            &next.keys.publics(),
            0,
            NOW,
        )
        .unwrap();
        let res = recover_all(&servers, &[spec(1)], &rr).await;
        assert!(matches!(res[0].1, Ok(ServerRecovery::Pending { .. })));

        // Drill: the right code matches, another one doesn't.
        struct Health(u32, u64);
        impl OpRunner for Health {
            async fn run(
                &self,
                _: &ServerId,
                _: Op,
                _: Actor,
                _: Option<fleet_proto::RootApproval>,
            ) -> Result<Payload, RunError> {
                Ok(Payload::AgentHealth(fleet_proto::AgentHealth {
                    agent_version: fleet_proto::AgentVersion {
                        major: 0,
                        minor: 1,
                        patch: 0,
                    },
                    proto_version: 1,
                    uptime_s: 0,
                    gate_rss_bytes: 0,
                    exec_rss_bytes: 0,
                    audit_seq: 0,
                    roster_epoch: self.0,
                    roster_version: self.1,
                    policy_version: 1,
                    pending_recovery: None,
                    run_id: [0; 16],
                }))
            }
        }
        let chain = vec![g.clone()];
        let ok = drill(&Health(0, 1), &[spec(1).id], &chain, &p, NOW).await;
        assert_eq!(ok[0].1, DrillResult::Match);
        let bad = drill(
            &Health(0, 1),
            &[spec(1).id],
            &chain,
            &next.keys.publics(),
            NOW,
        )
        .await;
        assert_eq!(bad[0].1, DrillResult::Mismatch);
        let unk = drill(&Health(0, 9), &[spec(1).id], &chain, &p, NOW).await;
        assert!(matches!(unk[0].1, DrillResult::UnknownRoster { .. }));

        // Rotation after the drill: a valid normal update with grace.
        let r = rotation_roster(&g, &next.keys.publics(), 0, NOW + 10).unwrap();
        let signed = sign_next(&k, a, &g, r, "rotate recovery code", 1, NOW + 10).unwrap();
        assert!(signed.roster.prev_recovery.is_some());
        assert!(matches!(
            rotation_roster(&signed, &p, 0, NOW + 20),
            Err(RecoveryError::RotationTooSoon)
        ));
        let cache = Cache::open_in_memory().unwrap();
        store_own(&cache, &signed).unwrap();
    }
}
