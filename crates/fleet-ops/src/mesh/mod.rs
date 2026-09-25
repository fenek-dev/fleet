//! WireGuard mesh (design §2.5): `mesh.join`, `mesh.leave`,
//! `mesh.peers.set` (all auto-revert, [`MeshRevert`]) and `mesh.status`.
//!
//! - The server's key pair is made here: `/usr/bin/wg genkey` once, stored
//!   as `/etc/wireguard/fleet0.key` (0600, root). The private key never
//!   leaves the server: it is not in any argument, payload, event or
//!   snapshot, and `/etc/wireguard` is secret-listed in config history
//!   (hash only). `mesh.status` answers the public key (`wg pubkey`), which
//!   the Mac distributes to the other members with `mesh.peers.set`.
//! - `/etc/wireguard/fleet0.conf` (0600) is rendered from the typed
//!   arguments ([`render_conf`]); the interface loads the key file with a
//!   fixed `PostUp = wg set %i private-key …` line. Written atomically.
//! - `wg-quick@fleet0.service`: `enable --now` on the first join, `restart`
//!   on a re-join, `reload` (the unit's `wg syncconf`) after
//!   `mesh.peers.set`, `disable --now` on leave. Leave keeps the key, so a
//!   re-join keeps the server's identity and a revert needs no secret.
//! - Firewall: the listen port (UDP) is not opened here. Fleet's firewall
//!   is a versioned model the Mac owns (`firewall.apply`); the Mac adds an
//!   accept rule for the port in Managed mode (design §4.8).
//! - `mesh.peers.set` is versioned by the BLAKE3 version of the current
//!   config file (`fswrite::version_of`), returned as `new_version` by every
//!   mesh change.

use crate::ctx::SysCtx;
use crate::fswrite;
use crate::handler::{Invocation, LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput, Registry};
use crate::revertible::Revertible;
use crate::runner::{CommandOutput, CommandSpec, RunError, SYSTEMCTL};
use fleet_proto::args::{Cidr, WgPeer};
use fleet_proto::op::{MeshConfig, tag};
use fleet_proto::payload::{ChangeKind, MeshPeerStatus, MeshStatus, PendingChange};
use fleet_proto::{ErrorCode, Op, Payload};
use serde::{Deserialize, Serialize};
use std::fmt::Write;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::time::Duration;

pub const WG: &str = "/usr/bin/wg";
pub const IFACE: &str = "fleet0";
pub const DIR: &str = "/etc/wireguard";
pub const CONF: &str = "/etc/wireguard/fleet0.conf";
pub const KEY: &str = "/etc/wireguard/fleet0.key";
pub const UNIT: &str = "wg-quick@fleet0.service";
const CONF_MAX: u64 = 256 * 1024;
const WG_TIMEOUT: Duration = Duration::from_secs(15);
const UNIT_TIMEOUT: Duration = Duration::from_secs(60);

// ---- base64 (keys only) ----

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding (WireGuard's key text form).
pub fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A 32-byte key from its 44-character base64 text.
pub fn key_from_b64(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() != 44 || b[43] != b'=' || b[42] == b'=' {
        return None;
    }
    let val = |c: u8| B64.iter().position(|&x| x == c).map(|p| p as u32);
    let mut out = Vec::with_capacity(33);
    for chunk in b[..40].chunks(4) {
        let mut n = 0u32;
        for &c in chunk {
            n = (n << 6) | val(c)?;
        }
        out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]);
    }
    // Last group: 3 symbols + '=' → 2 bytes.
    let mut n = 0u32;
    for &c in &b[40..43] {
        n = (n << 6) | val(c)?;
    }
    if n & 0b11 != 0 {
        return None; // non-canonical
    }
    n <<= 6;
    out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8]);
    out.try_into().ok()
}

// ---- config file ----

fn endpoint(e: &fleet_proto::args::Endpoint) -> String {
    SocketAddr::new(e.addr, e.port.get()).to_string()
}

/// `[Peer]` sections.
pub fn render_peers(peers: &[WgPeer]) -> String {
    let mut s = String::new();
    for p in peers {
        let ips: Vec<String> = p.allowed_ips.iter().map(ToString::to_string).collect();
        let _ = write!(
            s,
            "\n[Peer]\nPublicKey = {}\nAllowedIPs = {}\n",
            b64_encode(p.public_key.bytes()),
            ips.join(", ")
        );
        if let Some(e) = &p.endpoint {
            let _ = writeln!(s, "Endpoint = {}", endpoint(e));
        }
        if p.keepalive_s > 0 {
            let _ = writeln!(s, "PersistentKeepalive = {}", p.keepalive_s);
        }
    }
    s
}

/// The whole `fleet0.conf`. Every token comes from a typed value.
pub fn render_conf(c: &MeshConfig) -> String {
    format!(
        "# Managed by Fleet (mesh.join). Changes are overwritten.\n\
         [Interface]\n\
         Address = {}/{}\n\
         ListenPort = {}\n\
         PostUp = {WG} set %i private-key {KEY}\n{}",
        c.address,
        c.network.prefix(),
        c.listen_port.get(),
        render_peers(&c.peers)
    )
}

/// Interface settings read back from a rendered config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Iface {
    pub address: IpAddr,
    pub network: Cidr,
    pub listen_port: u16,
}

/// Parses the `[Interface]` lines Fleet renders (`Address`, `ListenPort`).
pub fn parse_iface(conf: &str) -> Option<Iface> {
    let (mut addr, mut port) = (None, None);
    for line in conf.lines() {
        if line.trim() == "[Peer]" {
            break;
        }
        if let Some((k, v)) = line.split_once('=') {
            match k.trim() {
                "Address" => addr = Some(v.trim().to_owned()),
                "ListenPort" => port = v.trim().parse::<u16>().ok(),
                _ => {}
            }
        }
    }
    let a = addr?;
    let (ip, prefix) = a.split_once('/')?;
    let ip: IpAddr = ip.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    Some(Iface {
        address: ip,
        network: network_of(ip, prefix)?,
        listen_port: port?,
    })
}

fn network_of(ip: IpAddr, prefix: u8) -> Option<Cidr> {
    let masked = match ip {
        IpAddr::V4(a) => {
            let m = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V4((u32::from(a) & m).into())
        }
        IpAddr::V6(a) => {
            let m = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V6((u128::from(a) & m).into())
        }
    };
    Cidr::new(masked, prefix).ok()
}

/// The config up to its first `[Peer]` (the interface part).
fn iface_part(conf: &str) -> &str {
    let mut at = 0;
    for line in conf.split_inclusive('\n') {
        if line.trim() == "[Peer]" {
            break;
        }
        at += line.len();
    }
    conf[..at].trim_end_matches('\n')
}

/// `wg show fleet0 dump`: the first line is the interface (its private key
/// is dropped unread), then one line per peer.
pub fn parse_dump(text: &str) -> Vec<MeshPeerStatus> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            if f.len() < 8 {
                return None;
            }
            let hs: u64 = f[4].parse().ok()?;
            Some(MeshPeerStatus {
                public_key: key_from_b64(f[0])?,
                endpoint: f[2].parse().ok(),
                allowed_ips: f[3]
                    .split(',')
                    .filter(|s| !s.is_empty() && *s != "(none)")
                    .map(|s| s.chars().take(64).collect())
                    .take(16)
                    .collect(),
                last_handshake_ms: (hs > 0).then(|| hs.saturating_mul(1000)),
                rx_bytes: f[5].parse().ok()?,
                tx_bytes: f[6].parse().ok()?,
            })
        })
        .take(MeshConfig::MAX_PEERS)
        .collect()
}

// ---- commands ----

pub fn genkey_spec() -> CommandSpec {
    CommandSpec::new(WG)
        .arg("genkey")
        .timeout(WG_TIMEOUT)
        .output_cap(256)
}

pub fn pubkey_spec(private_b64: &[u8]) -> CommandSpec {
    CommandSpec::new(WG)
        .arg("pubkey")
        .stdin(private_b64.to_vec())
        .timeout(WG_TIMEOUT)
        .output_cap(256)
}

pub fn dump_spec() -> CommandSpec {
    CommandSpec::new(WG)
        .args(["show", IFACE, "dump"])
        .timeout(WG_TIMEOUT)
        .output_cap(256 * 1024)
}

pub fn systemctl(args: &[&str]) -> CommandSpec {
    CommandSpec::new(SYSTEMCTL)
        .args(args)
        .timeout(UNIT_TIMEOUT)
        .output_cap(8192)
}

fn ran(out: Result<CommandOutput, RunError>, what: &str) -> Result<CommandOutput, OpError> {
    let out = out?;
    if out.success() {
        Ok(out)
    } else {
        Err(OpError::internal(format!("{what} failed: {:?}", out.code)))
    }
}

fn read_conf(ctx: &SysCtx) -> Result<Option<Vec<u8>>, OpError> {
    fswrite::read_regular(ctx, CONF, CONF_MAX)
}

fn remove(ctx: &SysCtx, abs: &str) -> Result<(), OpError> {
    let p = ctx.path(abs).ok_or_else(|| OpError::internal("bad path"))?;
    match std::fs::remove_file(p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(OpError::internal(format!("remove {abs}: {e}"))),
    }
}

/// The server's key pair: generated once (`wg genkey`), then public key
/// via `wg pubkey`.
async fn ensure_key(ctx: &SysCtx) -> Result<[u8; 32], OpError> {
    fswrite::ensure_dir(ctx, DIR, 0o700)?;
    let private = match fswrite::read_regular(ctx, KEY, 256)? {
        Some(k) => k,
        None => {
            let out = ran(ctx.runner.run(genkey_spec()).await, "wg genkey")?;
            let text = String::from_utf8(out.stdout)
                .map_err(|_| OpError::internal("wg genkey: not text"))?;
            key_from_b64(&text).ok_or_else(|| OpError::internal("wg genkey: bad key"))?;
            let line = format!("{}\n", text.trim());
            fswrite::write_atomic(ctx, KEY, line.as_bytes(), 0o600)?;
            line.into_bytes()
        }
    };
    public_key(ctx, &private).await
}

async fn public_key(ctx: &SysCtx, private: &[u8]) -> Result<[u8; 32], OpError> {
    let out = ran(ctx.runner.run(pubkey_spec(private)).await, "wg pubkey")?;
    key_from_b64(&String::from_utf8_lossy(&out.stdout))
        .ok_or_else(|| OpError::internal("wg pubkey: bad key"))
}

async fn is_active(ctx: &SysCtx) -> Result<bool, OpError> {
    Ok(ctx
        .runner
        .run(systemctl(&["is-active", "--quiet", UNIT]))
        .await?
        .success())
}

fn pending(new_version: u64) -> Payload {
    // Exec fills in id, deadline and origin; only `new_version` is read.
    Payload::ChangePending(PendingChange {
        change_id: [0; 16],
        kind: ChangeKind::Mesh,
        op_tag: 0,
        created_ms: 0,
        deadline_ms: 0,
        new_version: Some(new_version),
    })
}

fn not_joined() -> OpError {
    OpError::new(ErrorCode::NotFound).with_detail("mesh not joined")
}

/// Checks for `mesh.peers.set` against the current file; returns it.
fn check_peers(ctx: &SysCtx, peers: &[WgPeer], meta: &OpMeta) -> Result<String, OpError> {
    let conf = read_conf(ctx)?.ok_or_else(not_joined)?;
    let current = fswrite::version_of(&conf);
    if meta.command.body.expected_version != Some(current) {
        return Err(ErrorCode::VersionConflict { current }.into());
    }
    let text = String::from_utf8(conf).map_err(|_| OpError::internal("fleet0.conf: not UTF-8"))?;
    let iface = parse_iface(&text).ok_or_else(|| OpError::internal("fleet0.conf: unparseable"))?;
    let cfg = MeshConfig {
        address: iface.address,
        network: iface.network,
        listen_port: fleet_proto::args::Port::new(iface.listen_port)
            .map_err(|_| OpError::internal("fleet0.conf: port"))?,
        peers: peers.to_vec(),
    };
    cfg.validate()
        .map_err(|_| OpError::new(ErrorCode::InvalidArgument))?;
    Ok(text)
}

pub struct MeshHandler;

impl MeshHandler {
    async fn join(&self, ctx: &SysCtx, cfg: &MeshConfig) -> Result<Payload, OpError> {
        ensure_key(ctx).await?;
        let conf = render_conf(cfg);
        fswrite::write_atomic(ctx, CONF, conf.as_bytes(), 0o600)?;
        if is_active(ctx).await? {
            ran(
                ctx.runner.run(systemctl(&["restart", UNIT])).await,
                "restart",
            )?;
        } else {
            ran(
                ctx.runner.run(systemctl(&["enable", "--now", UNIT])).await,
                "enable",
            )?;
        }
        Ok(pending(fswrite::version_of(conf.as_bytes())))
    }

    async fn leave(&self, ctx: &SysCtx) -> Result<Payload, OpError> {
        ran(
            ctx.runner.run(systemctl(&["disable", "--now", UNIT])).await,
            "disable",
        )?;
        remove(ctx, CONF)?;
        Ok(Payload::Empty)
    }

    async fn peers_set(
        &self,
        ctx: &SysCtx,
        peers: &[WgPeer],
        meta: &OpMeta,
    ) -> Result<Payload, OpError> {
        let text = check_peers(ctx, peers, meta)?;
        let conf = format!("{}\n{}", iface_part(&text), render_peers(peers));
        fswrite::write_atomic(ctx, CONF, conf.as_bytes(), 0o600)?;
        // `wg syncconf` (the unit's ExecReload): peers change without
        // dropping the interface.
        ran(ctx.runner.run(systemctl(&["reload", UNIT])).await, "reload")?;
        Ok(pending(fswrite::version_of(conf.as_bytes())))
    }

    async fn status(&self, ctx: &SysCtx) -> Result<Payload, OpError> {
        let conf = read_conf(ctx)?;
        let iface = conf
            .as_deref()
            .and_then(|c| std::str::from_utf8(c).ok())
            .and_then(parse_iface);
        let public_key = match fswrite::read_regular(ctx, KEY, 256)? {
            Some(k) => Some(public_key(ctx, &k).await?),
            None => None,
        };
        let peers = if conf.is_some() {
            match ctx.runner.run(dump_spec()).await {
                Ok(o) if o.success() => parse_dump(&String::from_utf8_lossy(&o.stdout)),
                _ => Vec::new(), // interface down
            }
        } else {
            Vec::new()
        };
        Ok(Payload::MeshStatus(MeshStatus {
            joined: conf.is_some(),
            public_key,
            address: iface.map(|i| i.address),
            listen_port: iface.map(|i| i.listen_port),
            peers,
        }))
    }
}

impl OpHandler for MeshHandler {
    fn supports(&self, op: &Op, inv: Invocation) -> bool {
        inv == Invocation::Request
            && matches!(
                op,
                Op::MeshStatus | Op::MeshJoin(_) | Op::MeshLeave | Op::MeshPeersSet { .. }
            )
    }

    fn validate(&self, ctx: &SysCtx, op: &Op, meta: &OpMeta) -> Result<(), OpError> {
        match op {
            Op::MeshJoin(c) => c
                .validate()
                .map_err(|_| OpError::new(ErrorCode::InvalidArgument)),
            Op::MeshPeersSet { peers } => check_peers(ctx, peers, meta).map(|_| ()),
            _ => Ok(()),
        }
    }

    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        op: &'a Op,
        meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            let p = match op {
                Op::MeshStatus => self.status(ctx).await?,
                Op::MeshJoin(c) => self.join(ctx, c).await?,
                Op::MeshLeave => self.leave(ctx).await?,
                Op::MeshPeersSet { peers } => self.peers_set(ctx, peers, meta).await?,
                _ => return Err(ErrorCode::Unsupported.into()),
            };
            Ok(OpOutput::Payload(p))
        })
    }
}

pub fn register(r: &mut Registry) {
    let h: Rc<dyn OpHandler> = Rc::new(MeshHandler);
    for t in [
        tag::MESH_STATUS,
        tag::MESH_JOIN,
        tag::MESH_LEAVE,
        tag::MESH_PEERS_SET,
    ] {
        r.register(t, h.clone());
    }
}

// ---- auto-revert ----

/// What a mesh change can touch. No secret: the key stays in its file;
/// only whether it existed (a first join created it) is kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshSnapshot {
    pub conf: Option<Vec<u8>>,
    pub key_present: bool,
    pub active: bool,
    pub enabled: bool,
}

/// [`ChangeKind::Mesh`] snapshot/restore (design §4.10).
pub struct MeshRevert;

impl MeshRevert {
    pub fn take(ctx: &SysCtx) -> Result<MeshSnapshot, OpError> {
        let q = |verb: &str| -> Result<bool, OpError> {
            Ok(ctx
                .runner
                .run_blocking(systemctl(&[verb, "--quiet", UNIT]))?
                .success())
        };
        Ok(MeshSnapshot {
            conf: read_conf(ctx)?,
            key_present: fswrite::walk(ctx, KEY)?.exists,
            active: q("is-active")?,
            enabled: q("is-enabled")?,
        })
    }
}

impl Revertible for MeshRevert {
    fn snapshot(&self, ctx: &SysCtx, _op: &Op) -> Result<Vec<u8>, OpError> {
        Ok(fleet_proto::encode(&Self::take(ctx)?))
    }

    fn restore(&self, ctx: &SysCtx, snapshot: &[u8]) -> Result<(), OpError> {
        let s: MeshSnapshot = fleet_proto::decode(snapshot)
            .map_err(|_| OpError::internal("mesh snapshot: corrupt"))?;
        let run = |args: &[&str]| ran(ctx.runner.run_blocking(systemctl(args)), args[0]);
        match &s.conf {
            Some(c) => {
                fswrite::ensure_dir(ctx, DIR, 0o700)?;
                fswrite::write_atomic(ctx, CONF, c, 0o600)?;
            }
            None => remove(ctx, CONF)?,
        }
        if !s.key_present {
            remove(ctx, KEY)?;
        }
        if s.active && s.conf.is_some() {
            run(&["restart", UNIT])?;
        } else {
            run(&["stop", UNIT])?;
        }
        run(&[if s.enabled { "enable" } else { "disable" }, UNIT])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
