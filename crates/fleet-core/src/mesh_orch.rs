//! Fleet-level WireGuard mesh (design §2.5): the Mac picks the members,
//! gives each an address in the mesh network, joins them, reads their
//! public keys and distributes every member's key to the others.
//!
//! Private keys never leave a server (`mesh.join` generates them there);
//! only public keys and addresses travel as arguments. Every mesh change
//! (and the firewall rule for the listen port) is auto-reverted by the
//! agent and confirmed here over a fresh connection
//! ([`crate::autorevert::confirm_fresh`]).
//!
//! Order per run:
//! 1. `mesh.status` on each member: joined members keep their address and
//!    key (they must already be inside `network`).
//! 2. Managed firewalls without an input UDP accept for the listen port
//!    get one (`firewall.apply` at the version just read, confirmed).
//! 3. Members not joined yet get the next free address and `mesh.join`
//!    (no peers), confirmed; then `mesh.status` for the new public key.
//! 4. `mesh.peers.set` on every member with every other member as a peer
//!    (`allowed_ips` = the peer's address as a host route, endpoint = its
//!    public address when known, keepalive 25 s). The version is the
//!    join's `new_version`, else the agent's `VersionConflict` answer.
//!
//! The first failing server stops the run; earlier steps stay (each was
//! confirmed and is a consistent state on its own).

use crate::autorevert::{self, confirm_fresh};
use crate::manager::{ManagerHandle, RequestError, RequestOpts};
use crate::session::now_ms;
use fleet_proto::args::{
    Cidr, Endpoint, FirewallMode, FirewallRule, FirewallRuleSet, FwAction, FwChain, FwComment,
    Port, PortRange, Protocol, WgKey, WgPeer,
};
use fleet_proto::op::MeshConfig;
use fleet_proto::payload::{MeshStatus, PendingChange};
use fleet_proto::{Actor, ErrorCode, Op, Payload, ServerId};
use std::collections::HashSet;
use std::net::IpAddr;

/// Members per mesh (the agent's peer limit is 256).
pub const MAX_MEMBERS: usize = 64;
/// Persistent keepalive for every peer (NAT-friendly).
pub const KEEPALIVE_S: u16 = 25;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshMember {
    pub server: ServerId,
    /// Public address other members dial; `None`: this member only dials.
    pub endpoint: Option<IpAddr>,
}

/// A member with its mesh address and (once known) public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Planned {
    pub server: ServerId,
    pub address: IpAddr,
    pub endpoint: Option<IpAddr>,
    pub public_key: Option<[u8; 32]>,
    /// Already in the mesh before this run.
    pub joined: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum MeshError {
    #[error("between 2 and {MAX_MEMBERS} distinct servers")]
    Members,
    #[error("mesh network too small for the members")]
    NetworkFull,
    #[error("{0}: already in a mesh outside this network")]
    OtherMesh(ServerId),
    #[error("{server}: {step}: {reason}")]
    Step {
        server: ServerId,
        step: &'static str,
        reason: String,
    },
}

fn step_err(server: &ServerId, step: &'static str, reason: impl ToString) -> MeshError {
    MeshError::Step {
        server: server.clone(),
        step,
        reason: reason.to_string(),
    }
}

fn to_bits(a: IpAddr) -> u128 {
    match a {
        IpAddr::V4(a) => u128::from(u32::from(a)),
        IpAddr::V6(a) => u128::from(a),
    }
}

fn from_bits(v4: bool, b: u128) -> Option<IpAddr> {
    if v4 {
        u32::try_from(b).ok().map(|b| IpAddr::V4(b.into()))
    } else {
        Some(IpAddr::V6(b.into()))
    }
}

/// Usable host addresses of `net` in order, skipping `taken` (IPv4: not
/// the network or broadcast address).
fn free_addresses(net: Cidr, taken: &HashSet<IpAddr>) -> impl Iterator<Item = IpAddr> + '_ {
    let v4 = net.addr().is_ipv4();
    let width: u32 = if v4 { 32 } else { 128 };
    let host_bits = width - u32::from(net.prefix());
    let size: u128 = if host_bits >= 127 {
        u128::MAX
    } else {
        1u128 << host_bits
    };
    let base = to_bits(net.addr());
    let last = if v4 && size > 2 { size - 1 } else { size };
    (1..last)
        .take(1 << 16)
        .filter_map(move |i| from_bits(v4, base + i))
        .filter(move |a| !taken.contains(a))
}

/// Addresses for members not in `existing` (server → address of an
/// already joined member). Pure; the run's first step.
pub fn plan(
    network: Cidr,
    members: &[MeshMember],
    existing: &[(ServerId, IpAddr, [u8; 32])],
) -> Result<Vec<Planned>, MeshError> {
    let distinct: HashSet<_> = members.iter().map(|m| &m.server).collect();
    if members.len() < 2 || members.len() > MAX_MEMBERS || distinct.len() != members.len() {
        return Err(MeshError::Members);
    }
    for (s, addr, _) in existing {
        if !network.contains(*addr) {
            return Err(MeshError::OtherMesh(s.clone()));
        }
    }
    let taken: HashSet<IpAddr> = existing.iter().map(|e| e.1).collect();
    let mut free = free_addresses(network, &taken);
    members
        .iter()
        .map(|m| {
            if let Some((_, addr, key)) = existing.iter().find(|e| e.0 == m.server) {
                return Ok(Planned {
                    server: m.server.clone(),
                    address: *addr,
                    endpoint: m.endpoint,
                    public_key: Some(*key),
                    joined: true,
                });
            }
            let address = free.next().ok_or(MeshError::NetworkFull)?;
            Ok(Planned {
                server: m.server.clone(),
                address,
                endpoint: m.endpoint,
                public_key: None,
                joined: false,
            })
        })
        .collect()
}

/// Every other member of `all` as a peer of `me` (members without a key
/// yet are skipped).
pub fn peers_for(me: &ServerId, all: &[Planned], listen_port: Port) -> Vec<WgPeer> {
    all.iter()
        .filter(|p| &p.server != me)
        .filter_map(|p| {
            let key = WgKey::new(p.public_key?).ok()?;
            Some(WgPeer {
                public_key: key,
                endpoint: p.endpoint.map(|addr| Endpoint {
                    addr,
                    port: listen_port,
                }),
                allowed_ips: vec![Cidr::host(p.address)],
                keepalive_s: KEEPALIVE_S,
            })
        })
        .collect()
}

/// Whether a Managed rule set already accepts UDP `port` on input from
/// anywhere; `None` if nothing needs adding (bans-only).
pub fn firewall_with_port(set: &FirewallRuleSet, port: Port) -> Option<FirewallRuleSet> {
    if set.mode != FirewallMode::Managed {
        return None;
    }
    let covered = set.rules.iter().any(|r| {
        r.chain == FwChain::Input
            && r.action == FwAction::Accept
            && r.proto == Protocol::Udp
            && r.source.is_none()
            && r.ports
                .iter()
                .any(|p| p.start().get() <= port.get() && port.get() <= p.end().get())
    });
    if covered {
        return None;
    }
    let mut next = set.clone();
    next.rules.push(FirewallRule {
        chain: FwChain::Input,
        action: FwAction::Accept,
        proto: Protocol::Udp,
        ports: vec![PortRange::single(port)],
        source: None,
        rate_limit: None,
        comment: FwComment::new("wireguard mesh").ok()?,
    });
    Some(next)
}

/// Progress for the UI: one line per finished step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshProgress {
    pub server: ServerId,
    pub step: &'static str,
    pub detail: String,
}

struct Runner<'a> {
    handle: &'a ManagerHandle,
    actor: Actor,
}

impl Runner<'_> {
    async fn call(
        &self,
        id: &ServerId,
        op: Op,
        expected_version: Option<u64>,
        step: &'static str,
    ) -> Result<Payload, MeshError> {
        let reply = self
            .handle
            .request_with(
                id,
                op,
                self.actor.clone(),
                None,
                RequestOpts { expected_version },
            )
            .await
            .map_err(|e: RequestError| step_err(id, step, e))?;
        reply.result.map_err(|c| MeshError::Step {
            server: id.clone(),
            step,
            reason: format!("{c:?}"),
        })
    }

    /// A versioned auto-revert op: `version` if known, else the version
    /// named by the agent's conflict answer. Confirmed from a fresh
    /// connection; the new version.
    async fn change(
        &self,
        id: &ServerId,
        op: Op,
        version: Option<u64>,
        step: &'static str,
    ) -> Result<Option<u64>, MeshError> {
        let reply = self
            .handle
            .request_with(
                id,
                op.clone(),
                self.actor.clone(),
                None,
                RequestOpts {
                    expected_version: version
                        .or(Some(0))
                        .filter(|_| op.requires_expected_version()),
                },
            )
            .await
            .map_err(|e| step_err(id, step, e))?;
        let pending = match reply.result {
            Ok(p) => p,
            Err(ErrorCode::VersionConflict { current }) if version.is_none() => {
                self.call(id, op, Some(current), step).await?
            }
            Err(c) => return Err(step_err(id, step, format!("{c:?}"))),
        };
        let Payload::ChangePending {
            change:
                PendingChange {
                    change_id,
                    deadline_ms,
                    new_version,
                    ..
                },
            ..
        } = pending
        else {
            return Err(step_err(id, step, "unexpected reply"));
        };
        confirm_fresh(
            self.handle,
            id,
            change_id,
            self.actor.clone(),
            autorevert::budget(deadline_ms, now_ms()),
        )
        .await
        .map_err(|e| step_err(id, step, e))?;
        Ok(new_version)
    }

    async fn status(&self, id: &ServerId) -> Result<MeshStatus, MeshError> {
        match self.call(id, Op::MeshStatus, None, "status").await? {
            Payload::MeshStatus(s) => Ok(s),
            _ => Err(step_err(id, "status", "unexpected reply")),
        }
    }
}

/// Runs the whole flow (module docs). `progress` sees each finished step.
pub async fn run(
    handle: &ManagerHandle,
    actor: Actor,
    network: Cidr,
    listen_port: Port,
    members: &[MeshMember],
    mut progress: impl FnMut(MeshProgress),
) -> Result<Vec<Planned>, MeshError> {
    let r = Runner { handle, actor };
    let mut say = |server: &ServerId, step: &'static str, detail: String| {
        progress(MeshProgress {
            server: server.clone(),
            step,
            detail,
        })
    };
    // 1. What's there.
    let mut existing = Vec::new();
    for m in members {
        let s = r.status(&m.server).await?;
        if let (true, Some(addr), Some(key)) = (s.joined, s.address, s.public_key) {
            existing.push((m.server.clone(), addr, key));
        }
    }
    let mut planned = plan(network, members, &existing)?;
    // 2. Firewalls.
    for p in &planned {
        let fw = match r.call(&p.server, Op::FirewallGet, None, "firewall").await? {
            Payload::Firewall(f) => f,
            _ => return Err(step_err(&p.server, "firewall", "unexpected reply")),
        };
        let current = FirewallRuleSet {
            mode: fw.mode,
            rules: fw.rules,
        };
        if let Some(next) = firewall_with_port(&current, listen_port) {
            r.change(
                &p.server,
                Op::FirewallApply(next),
                Some(fw.version),
                "firewall",
            )
            .await?;
            say(
                &p.server,
                "firewall",
                format!("allowed udp/{}", listen_port.get()),
            );
        }
    }
    // 3. Joins.
    let mut versions: Vec<Option<u64>> = vec![None; planned.len()];
    for (i, p) in planned.iter_mut().enumerate() {
        if p.joined {
            continue;
        }
        let cfg = MeshConfig {
            address: p.address,
            network,
            listen_port,
            peers: Vec::new(),
        };
        cfg.validate().map_err(|e| step_err(&p.server, "join", e))?;
        versions[i] = r.change(&p.server, Op::MeshJoin(cfg), None, "join").await?;
        let s = r.status(&p.server).await?;
        p.public_key = Some(
            s.public_key
                .ok_or_else(|| step_err(&p.server, "join", "no public key"))?,
        );
        say(&p.server, "join", format!("joined as {}", p.address));
    }
    // 4. Peers.
    for (i, p) in planned.iter().enumerate() {
        let peers = peers_for(&p.server, &planned, listen_port);
        let n = peers.len();
        r.change(&p.server, Op::MeshPeersSet { peers }, versions[i], "peers")
            .await?;
        say(&p.server, "peers", format!("{n} peers"));
    }
    Ok(planned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(n: u8) -> ServerId {
        ServerId::new(format!("srv_member{n}")).unwrap()
    }

    fn member(n: u8) -> MeshMember {
        MeshMember {
            server: sid(n),
            endpoint: Some(format!("203.0.113.{n}").parse().unwrap()),
        }
    }

    #[test]
    fn plans_addresses_around_existing() {
        let net: Cidr = "10.8.0.0/24".parse().unwrap();
        let existing = vec![(sid(2), "10.8.0.1".parse().unwrap(), [7; 32])];
        let p = plan(net, &[member(1), member(2), member(3)], &existing).unwrap();
        assert_eq!(p[0].address, "10.8.0.2".parse::<IpAddr>().unwrap());
        assert!(p[1].joined && p[1].public_key == Some([7; 32]));
        assert_eq!(p[2].address, "10.8.0.3".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn plan_rejects_bad_input() {
        let net: Cidr = "10.8.0.0/30".parse().unwrap();
        assert!(matches!(
            plan(net, &[member(1)], &[]),
            Err(MeshError::Members)
        ));
        assert!(matches!(
            plan(net, &[member(1), member(1)], &[]),
            Err(MeshError::Members)
        ));
        // /30: two usable addresses.
        assert!(plan(net, &[member(1), member(2)], &[]).is_ok());
        assert!(matches!(
            plan(net, &[member(1), member(2), member(3)], &[]),
            Err(MeshError::NetworkFull)
        ));
        let other = vec![(sid(1), "10.9.0.1".parse().unwrap(), [1; 32])];
        assert!(matches!(
            plan(net, &[member(1), member(2)], &other),
            Err(MeshError::OtherMesh(_))
        ));
    }

    #[test]
    fn peers_exclude_self_and_keyless() {
        let net: Cidr = "10.8.0.0/24".parse().unwrap();
        let mut p = plan(net, &[member(1), member(2), member(3)], &[]).unwrap();
        p[0].public_key = Some([1; 32]);
        p[1].public_key = Some([2; 32]);
        let port = Port::new(51820).unwrap();
        let peers = peers_for(&sid(1), &p, port);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].allowed_ips, vec![Cidr::host(p[1].address)]);
        assert_eq!(peers[0].endpoint.unwrap().port, port);
        let cfg = MeshConfig {
            address: p[0].address,
            network: net,
            listen_port: port,
            peers,
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn firewall_rule_added_once() {
        let port = Port::new(51820).unwrap();
        let set = FirewallRuleSet {
            mode: FirewallMode::Managed,
            rules: vec![],
        };
        let next = firewall_with_port(&set, port).unwrap();
        assert_eq!(next.rules.len(), 1);
        assert!(next.validate().is_ok());
        assert!(firewall_with_port(&next, port).is_none());
        let bans = FirewallRuleSet {
            mode: FirewallMode::BansOnly,
            rules: vec![],
        };
        assert!(firewall_with_port(&bans, port).is_none());
    }
}
