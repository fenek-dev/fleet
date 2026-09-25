//! Synced records ↔ the local cache (servers, groups, pins, roster copies).
//!
//! Bodies are postcard docs. Everything coming from another Mac is signed
//! by a roster device, but still validated before it reaches the cache
//! (hosts, users, names, key lengths). Roster copies go through
//! `roster_mgmt::store_chain_link` (checked as chain links). Settings,
//! snippets, runbooks, profiles, alert rules, audit mirrors and sudo
//! passwords stay in the sync store; the app reads them from there.

use super::{Collection, SyncError, SyncRecord};
use crate::cache::{Cache, GroupRecord, PinnedKeys, ServerRecord};
use crate::roster_mgmt;
use crate::ssh::{HostKey, SshTarget};
use fleet_proto::{Ed25519Public, ServerId, SignedRoster, X25519Public, decode, encode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hop {
    pub user: String,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerDoc {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    /// First hop first.
    pub jumps: Vec<Hop>,
    pub group: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupDoc {
    pub name: String,
    pub sort: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinsDoc {
    /// OpenSSH key blob.
    pub host_key: Option<Vec<u8>>,
    pub agent_noise: Option<[u8; 32]>,
    pub agent_signing: Option<[u8; 32]>,
}

fn ok_host(s: &str) -> bool {
    (1..=253).contains(&s.len())
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'-'))
}

fn ok_user(s: &str) -> bool {
    let mut b = s.bytes();
    s.len() <= 32
        && b.next()
            .is_some_and(|c| c.is_ascii_lowercase() || c == b'_')
        && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
}

fn ok_name(s: &str) -> bool {
    (1..=64).contains(&s.chars().count()) && !s.chars().any(char::is_control)
}

fn ok_tag(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

impl ServerDoc {
    pub fn from_record(r: &ServerRecord) -> Self {
        let mut jumps = Vec::new();
        let mut cur = r.target.proxy_jump.as_deref();
        while let Some(j) = cur {
            jumps.push(Hop {
                user: j.user.clone(),
                host: j.host.clone(),
                port: j.port,
            });
            cur = j.proxy_jump.as_deref();
        }
        jumps.reverse();
        Self {
            name: r.name.clone(),
            host: r.target.host.clone(),
            port: r.target.port,
            user: r.target.user.clone(),
            jumps,
            group: r.group.clone(),
            tags: r.tags.clone(),
        }
    }

    pub fn to_record(&self, id: ServerId) -> Result<ServerRecord, SyncError> {
        let hops_ok = self.jumps.len() <= 4
            && self
                .jumps
                .iter()
                .all(|h| ok_host(&h.host) && ok_user(&h.user) && h.port != 0);
        let ok = ok_name(&self.name)
            && ok_host(&self.host)
            && ok_user(&self.user)
            && self.port != 0
            && hops_ok
            && self.tags.len() <= 16
            && self.tags.iter().all(|t| ok_tag(t))
            && self
                .group
                .as_deref()
                .is_none_or(|g| (1..=64).contains(&g.len()));
        if !ok {
            return Err(SyncError::Malformed);
        }
        let mut chain: Option<SshTarget> = None;
        for h in &self.jumps {
            let mut t = SshTarget::new(h.host.clone(), h.port, h.user.clone());
            t.proxy_jump = chain.take().map(Box::new);
            chain = Some(t);
        }
        let mut target = SshTarget::new(self.host.clone(), self.port, self.user.clone());
        target.proxy_jump = chain.map(Box::new);
        Ok(ServerRecord {
            id,
            name: self.name.clone(),
            target,
            group: self.group.clone(),
            tags: self.tags.clone(),
        })
    }
}

impl PinsDoc {
    pub fn from_pins(p: &PinnedKeys) -> Self {
        Self {
            host_key: p.host_key.as_ref().map(|k| k.blob().to_vec()),
            agent_noise: p.agent_noise.map(|k| k.0),
            agent_signing: p.agent_signing.map(|k| k.0),
        }
    }

    pub fn to_pins(&self) -> Result<PinnedKeys, SyncError> {
        Ok(PinnedKeys {
            host_key: self
                .host_key
                .as_deref()
                .map(HostKey::from_blob)
                .transpose()
                .map_err(|_| SyncError::Malformed)?,
            agent_noise: self.agent_noise.map(X25519Public),
            agent_signing: self.agent_signing.map(Ed25519Public),
        })
    }
}

/// What applying a record changed in the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bridged {
    Server(ServerId),
    ServerRemoved(ServerId),
    Group(String),
    Pins(ServerId),
    Roster {
        epoch: u32,
        version: u64,
    },
    /// Kept in the sync store only.
    None,
}

/// Applies one merged record to the cache. Pin *changes* reach here only
/// after the operator confirmed them (`SyncEngine::confirm_pin_change`).
pub fn apply_to_cache(cache: &mut Cache, r: &SyncRecord) -> Result<Bridged, SyncError> {
    match r.collection {
        Collection::Servers => {
            let id = ServerId::new(r.key.clone()).map_err(|_| SyncError::Malformed)?;
            if r.deleted {
                cache.delete_server(&id)?;
                return Ok(Bridged::ServerRemoved(id));
            }
            let doc: ServerDoc = decode(&r.body).map_err(|_| SyncError::Malformed)?;
            let rec = doc.to_record(id.clone())?;
            // The group must exist locally (it may sync later).
            let rec = if rec
                .group
                .as_ref()
                .is_some_and(|g| !cache.groups().is_ok_and(|gs| gs.iter().any(|x| &x.id == g)))
            {
                ServerRecord { group: None, ..rec }
            } else {
                rec
            };
            cache.upsert_server(&rec)?;
            Ok(Bridged::Server(id))
        }
        Collection::Groups => {
            if r.key.is_empty() || r.key.len() > 64 || r.key.chars().any(char::is_control) {
                return Err(SyncError::Malformed);
            }
            if r.deleted {
                cache.delete_group(&r.key)?;
            } else {
                let doc: GroupDoc = decode(&r.body).map_err(|_| SyncError::Malformed)?;
                if !ok_name(&doc.name) {
                    return Err(SyncError::Malformed);
                }
                cache.upsert_group(&GroupRecord {
                    id: r.key.clone(),
                    name: doc.name,
                    sort: doc.sort,
                })?;
            }
            Ok(Bridged::Group(r.key.clone()))
        }
        Collection::PinnedKeys => {
            let id = ServerId::new(r.key.clone()).map_err(|_| SyncError::Malformed)?;
            if r.deleted || cache.server(&id)?.is_none() {
                return Ok(Bridged::None);
            }
            let doc: PinsDoc = decode(&r.body).map_err(|_| SyncError::Malformed)?;
            cache.set_pins(&id, &doc.to_pins()?)?;
            Ok(Bridged::Pins(id))
        }
        Collection::RosterChain => {
            let s: SignedRoster = decode(&r.body).map_err(|_| SyncError::Malformed)?;
            match roster_mgmt::store_chain_link(cache, &s) {
                Ok(_) => Ok(Bridged::Roster {
                    epoch: s.roster.epoch,
                    version: s.roster.version,
                }),
                Err(_) => Err(SyncError::Signature),
            }
        }
        _ => Ok(Bridged::None),
    }
}

/// Record key of a roster copy.
pub fn roster_key(s: &SignedRoster) -> String {
    format!("{:010}-{:020}", s.roster.epoch, s.roster.version)
}

pub fn roster_body(s: &SignedRoster) -> Vec<u8> {
    encode(s)
}
