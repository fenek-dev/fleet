//! FFI records for the admin tabs: firewall editing and auto-revert,
//! Docker, cron, config history, users, game servers and the mesh.
//! Server strings pass through `crate::text` (rule 6); values the app sends
//! back (container ids, paths) are the raw ones next to the display form
//! where they differ.

use crate::text;
use fleet_proto::op::RebootWhen;
use fleet_proto::payload::{
    ChangeKind, ChangeSource, ComposeStatus, ConfigVersion, ContainerInfo, ContainerState,
    ContainerStats, CronTab, DockerLogLine, FirewallCounters, GameBackup, GameInfo, GroupInfo,
    ImageInfo, LogStream,
    MeshPeerStatus, MeshStatus, NetworkInfo, PendingChange, TimerInfo, UserInfo, VolumeInfo,
};

// ---- firewall ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FwChainArg {
    Input,
    Forward,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FwActionArg {
    Accept,
    Drop,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FwProtoArg {
    Tcp,
    Udp,
}

/// One operator rule as the editor holds it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FirewallRuleArgs {
    pub chain: FwChainArg,
    pub action: FwActionArg,
    pub proto: FwProtoArg,
    /// `22` or `8000-8100`; 1–16 entries.
    pub ports: Vec<String>,
    /// CIDR or bare address; `None`/empty = any source.
    pub source: Option<String>,
    /// Per-source new connections per minute (accept rules only).
    pub rate_per_minute: Option<u32>,
    pub rate_burst: u16,
    /// `[A-Za-z0-9 ._:/-]`, at most 64 bytes.
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FirewallRulesetArgs {
    /// `true`: Managed (default drop); `false`: bans only (no rules).
    pub managed: bool,
    pub rules: Vec<FirewallRuleArgs>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DiffLineKind {
    Same,
    Added,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DiffLineRow {
    pub kind: DiffLineKind,
    pub text: String,
}

/// An applied auto-revert change waiting for `change.confirm`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PendingChangeRow {
    pub change_id_hex: String,
    /// `firewall`, `ssh`, `network`, `mesh`, `profile`, `authorized-keys`,
    /// `agent-update`.
    pub kind: String,
    pub created_ms: u64,
    pub deadline_ms: u64,
    pub new_version: Option<u64>,
}

impl From<PendingChange> for PendingChangeRow {
    fn from(c: PendingChange) -> Self {
        Self {
            change_id_hex: hex::encode(c.change_id),
            kind: match c.kind {
                ChangeKind::Firewall => "firewall",
                ChangeKind::Ssh => "ssh",
                ChangeKind::Network => "network",
                ChangeKind::Mesh => "mesh",
                ChangeKind::Profile => "profile",
                ChangeKind::AuthorizedKeys => "authorized-keys",
                ChangeKind::AgentUpdate => "agent-update",
            }
            .into(),
            created_ms: c.created_ms,
            deadline_ms: c.deadline_ms,
            new_version: c.new_version,
        }
    }
}

/// Hits on one operator rule of Fleet's firewall table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct RuleCounterRow {
    /// Index into `FirewallRow::rules`.
    pub rule: u32,
    pub packets: u64,
    pub bytes: u64,
}

/// `firewall.counters`: counting restarts whenever Fleet's table is
/// (re)applied (nftables keeps no timestamp), so these are hits "since the
/// last apply", not a 24 h window. `version` is the ruleset version the
/// counters belong to; a rule without an entry has no counter.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FirewallCountersRow {
    pub version: u64,
    pub rules: Vec<RuleCounterRow>,
}

impl From<FirewallCounters> for FirewallCountersRow {
    fn from(c: FirewallCounters) -> Self {
        Self {
            version: c.version,
            rules: c
                .rules
                .into_iter()
                .map(|r| RuleCounterRow {
                    rule: r.rule.into(),
                    packets: r.packets,
                    bytes: r.bytes,
                })
                .collect(),
        }
    }
}

/// When `system.reboot.schedule` reboots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RebootWhenRow {
    In { delay_s: u32 },
    At { at_ms: u64 },
    /// Daily window in the server's local time (minutes since midnight).
    Window { start_min: u32, end_min: u32 },
}

impl From<RebootWhenRow> for RebootWhen {
    /// Out-of-range minutes saturate to a value `Op::check_args` refuses.
    fn from(w: RebootWhenRow) -> Self {
        let min = |m: u32| u16::try_from(m).unwrap_or(u16::MAX);
        match w {
            RebootWhenRow::In { delay_s } => RebootWhen::In { delay_s },
            RebootWhenRow::At { at_ms } => RebootWhen::At { at_ms },
            RebootWhenRow::Window { start_min, end_min } => RebootWhen::Window {
                start_min: min(start_min),
                end_min: min(end_min),
            },
        }
    }
}

/// How a confirmation from a fresh connection ended.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ConfirmOutcome {
    Confirmed,
    /// The revert timer restored the previous state.
    Reverted,
    /// Stopped because the operator chose "Revert now".
    Cancelled,
    /// No fresh connection before the deadline: the timer will revert.
    NoConnection,
    Failed {
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BanConfigRow {
    pub threshold: u16,
    pub window_s: u32,
    pub ban_steps_s: Vec<u32>,
    /// CIDRs never banned.
    pub exempt: Vec<String>,
    pub web_scanners: bool,
}

// ---- docker ----

fn state_name(s: ContainerState) -> String {
    match s {
        ContainerState::Created => "created",
        ContainerState::Running => "running",
        ContainerState::Paused => "paused",
        ContainerState::Restarting => "restarting",
        ContainerState::Removing => "removing",
        ContainerState::Exited => "exited",
        ContainerState::Dead => "dead",
        ContainerState::Other => "other",
    }
    .into()
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ContainerRow {
    /// Raw id (hex, validated here) for actions.
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
    pub created_ms: u64,
    /// `0.0.0.0:8080→80/tcp`.
    pub ports: Vec<String>,
    pub compose_project: Option<String>,
}

impl From<ContainerInfo> for ContainerRow {
    fn from(c: ContainerInfo) -> Self {
        Self {
            id: text::line(c.id),
            name: text::line(c.name),
            image: text::line(c.image),
            state: state_name(c.state),
            status: text::line(c.status),
            created_ms: c.created_ms,
            ports: c
                .ports
                .into_iter()
                .map(|p| {
                    let host = p.host_ip.map(|a| format!("{a}:")).unwrap_or_default();
                    let proto = match p.proto {
                        fleet_proto::args::Protocol::Tcp => "tcp",
                        fleet_proto::args::Protocol::Udp => "udp",
                    };
                    format!("{host}{}→{}/{proto}", p.host_port, p.container_port)
                })
                .collect(),
            compose_project: text::opt(c.compose_project),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DockerContainerAction {
    Start,
    Stop,
    Restart,
    Remove,
    ForceRemove,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ImageRow {
    pub id: String,
    pub tags: Vec<String>,
    pub size_bytes: u64,
    pub created_ms: u64,
    pub in_use: bool,
}

impl From<ImageInfo> for ImageRow {
    fn from(i: ImageInfo) -> Self {
        Self {
            id: text::line(i.id),
            tags: text::lines(i.tags),
            size_bytes: i.size_bytes,
            created_ms: i.created_ms,
            in_use: i.in_use,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VolumeRow {
    pub name: String,
    pub driver: String,
    pub mountpoint: String,
    pub size_bytes: Option<u64>,
    pub in_use: bool,
}

impl From<VolumeInfo> for VolumeRow {
    fn from(v: VolumeInfo) -> Self {
        Self {
            name: text::line(v.name),
            driver: text::line(v.driver),
            mountpoint: text::line(v.mountpoint),
            size_bytes: v.size_bytes,
            in_use: v.in_use,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct NetworkRow {
    pub id: String,
    pub name: String,
    pub driver: String,
    pub subnets: Vec<String>,
}

impl From<NetworkInfo> for NetworkRow {
    fn from(n: NetworkInfo) -> Self {
        Self {
            id: text::line(n.id),
            name: text::line(n.name),
            driver: text::line(n.driver),
            subnets: text::lines(n.subnets),
        }
    }
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct ContainerStatsRow {
    pub id: String,
    pub cpu_pct: f32,
    pub mem_bytes: u64,
    pub mem_limit: u64,
    pub net_rx_bps: u64,
    pub net_tx_bps: u64,
    pub blk_read_bps: u64,
    pub blk_write_bps: u64,
    pub pids: u32,
}

impl From<ContainerStats> for ContainerStatsRow {
    fn from(s: ContainerStats) -> Self {
        Self {
            id: text::line(s.id),
            cpu_pct: s.cpu_pct.0,
            mem_bytes: s.mem_bytes,
            mem_limit: s.mem_limit,
            net_rx_bps: s.net_rx_bps,
            net_tx_bps: s.net_tx_bps,
            blk_read_bps: s.blk_read_bps,
            blk_write_bps: s.blk_write_bps,
            pids: s.pids,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DockerLogLineRow {
    pub time_ms: Option<u64>,
    pub stderr: bool,
    pub text: String,
}

impl From<DockerLogLine> for DockerLogLineRow {
    fn from(l: DockerLogLine) -> Self {
        Self {
            time_ms: l.time_ms,
            stderr: l.stream == LogStream::Stderr,
            text: text::line(l.text),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ComposeServiceRow {
    pub name: String,
    pub container: Option<String>,
    pub state: String,
    pub image: String,
    pub update_available: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ComposeProjectRow {
    pub project: String,
    pub path: String,
    pub file_hash_hex: Option<String>,
    pub services: Vec<ComposeServiceRow>,
}

impl From<ComposeStatus> for ComposeProjectRow {
    fn from(c: ComposeStatus) -> Self {
        Self {
            project: text::line(c.project),
            path: text::line(c.path),
            file_hash_hex: c.file_hash.map(hex::encode),
            services: c
                .services
                .into_iter()
                .map(|s| ComposeServiceRow {
                    name: text::line(s.name),
                    container: text::opt(s.container),
                    state: state_name(s.state),
                    image: text::line(s.image),
                    update_available: s.update_available,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ComposeAction {
    Pull,
    Restart,
    Down,
    DownRemoveVolumes,
}

/// Client-side Compose check (the agent's own validator).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ComposeCheckRow {
    /// Parses and is structurally acceptable.
    pub ok: bool,
    pub errors: Vec<String>,
    /// Deny-listed features: the deploy needs Touch ID (root approval).
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PrunedRow {
    pub removed: u32,
    pub reclaimed_bytes: u64,
}

// ---- cron ----

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CronLineRow {
    pub schedule: String,
    pub command: String,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CronTabRow {
    /// `None`: a system file (`/etc/crontab` or a file in `/etc/cron.d`).
    pub user: Option<String>,
    pub source: String,
    pub version: u64,
    pub entries: Vec<CronLineRow>,
}

impl From<CronTab> for CronTabRow {
    fn from(t: CronTab) -> Self {
        Self {
            user: text::opt(t.user),
            source: text::line(t.source),
            version: t.version,
            entries: t
                .entries
                .into_iter()
                .map(|e| CronLineRow {
                    schedule: text::line(e.schedule),
                    command: text::line(e.command),
                    comment: text::opt(e.comment),
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CronEntryArgs {
    pub schedule: String,
    pub command: String,
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TimerRow {
    pub unit: String,
    pub activates: String,
    pub schedule: String,
    pub next_ms: Option<u64>,
    pub last_ms: Option<u64>,
}

impl From<TimerInfo> for TimerRow {
    fn from(t: TimerInfo) -> Self {
        Self {
            unit: text::line(t.unit),
            activates: text::line(t.activates),
            schedule: text::line(t.schedule),
            next_ms: t.next_ms,
            last_ms: t.last_ms,
        }
    }
}

// ---- config history ----

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ConfigVersionRow {
    /// Raw path (validated again before it is sent back).
    pub path: String,
    pub version: u64,
    pub time_ms: u64,
    pub hash_hex: String,
    pub size: u64,
    /// `Fleet (op 401)`, `external (vim)`, `unknown`.
    pub source: String,
    pub secret: bool,
    pub deleted: bool,
}

impl From<ConfigVersion> for ConfigVersionRow {
    fn from(v: ConfigVersion) -> Self {
        Self {
            path: text::line(v.path),
            version: v.version,
            time_ms: v.time_ms,
            hash_hex: hex::encode(v.hash),
            size: v.size,
            source: match v.source {
                ChangeSource::Fleet { op_tag, .. } => {
                    use fleet_proto::op::tag;
                    let name = tag::ALL
                        .iter()
                        .position(|t| *t == op_tag)
                        .and_then(|i| tag::NAMES.get(i).copied());
                    format!("Fleet ({})", name.unwrap_or("operation"))
                }
                ChangeSource::External { process } => match process {
                    Some(p) => format!("external ({})", text::line(p)),
                    None => "external".into(),
                },
                ChangeSource::Unknown => "unknown".into(),
            },
            secret: v.secret,
            deleted: v.deleted,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ConfigHistoryRow {
    pub versions: Vec<ConfigVersionRow>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ConfigDiffRow {
    pub path: String,
    pub from: u64,
    pub to: Option<u64>,
    /// Unified diff; `\n` kept, other controls escaped.
    pub unified: String,
    pub binary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ConfigPathsRow {
    pub builtin_tracked: Vec<String>,
    pub builtin_secret: Vec<String>,
    pub tracked: Vec<String>,
    pub secret: Vec<String>,
    pub version: u64,
}

// ---- users ----

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UnixUserRow {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
    pub groups: Vec<String>,
    pub locked: bool,
    pub privileged: bool,
    pub system: bool,
    pub last_login_ms: Option<u64>,
}

impl From<UserInfo> for UnixUserRow {
    fn from(u: UserInfo) -> Self {
        Self {
            name: text::line(u.name),
            uid: u.uid,
            gid: u.gid,
            home: text::line(u.home),
            shell: text::line(u.shell),
            groups: text::lines(u.groups),
            locked: u.locked,
            privileged: u.privileged,
            system: u.system,
            last_login_ms: u.last_login_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UnixGroupRow {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

impl From<GroupInfo> for UnixGroupRow {
    fn from(g: GroupInfo) -> Self {
        Self {
            name: text::line(g.name),
            gid: g.gid,
            members: text::lines(g.members),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UnixUsersRow {
    pub users: Vec<UnixUserRow>,
    pub groups: Vec<UnixGroupRow>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum LoginShellArg {
    Bash,
    Sh,
    Nologin,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AuthorizedKeysRow {
    pub user: String,
    pub version: u64,
    /// Fleet's roster section (read-only here).
    pub roster_lines: Vec<String>,
    /// The operator's extra keys.
    pub extra: Vec<String>,
}

// ---- processes ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SignalArg {
    Hup,
    Int,
    Quit,
    Kill,
    Usr1,
    Usr2,
    Term,
    Cont,
    Stop,
}

// ---- game ----

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GameRow {
    pub name: String,
    pub template: String,
    pub running: bool,
    pub players: Option<u32>,
    pub version: Option<String>,
    pub last_backup_ms: Option<u64>,
}

impl From<GameInfo> for GameRow {
    fn from(g: GameInfo) -> Self {
        Self {
            name: text::line(g.name),
            template: text::line(g.template),
            running: g.running,
            players: g.players,
            version: text::opt(g.version),
            last_backup_ms: g.last_backup_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GameBackupRow {
    pub id: u64,
    pub time_ms: u64,
    pub size_bytes: u64,
}

impl From<GameBackup> for GameBackupRow {
    fn from(b: GameBackup) -> Self {
        Self {
            id: b.id,
            time_ms: b.time_ms,
            size_bytes: b.size_bytes,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum GameAction {
    Start,
    Stop,
    Restart,
    Update,
    Backup,
}

// ---- mesh ----

/// Standard base64 (WireGuard's key format).
pub(crate) fn b64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i <= c.len() {
                out.push(char::from(A[((n >> shift) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MeshPeerRow {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub last_handshake_ms: Option<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

impl From<MeshPeerStatus> for MeshPeerRow {
    fn from(p: MeshPeerStatus) -> Self {
        Self {
            public_key: b64(&p.public_key),
            endpoint: p.endpoint.map(|e| e.to_string()),
            allowed_ips: text::lines(p.allowed_ips),
            last_handshake_ms: p.last_handshake_ms,
            rx_bytes: p.rx_bytes,
            tx_bytes: p.tx_bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MeshStatusRow {
    pub joined: bool,
    pub public_key: Option<String>,
    pub address: Option<String>,
    pub listen_port: Option<u16>,
    pub peers: Vec<MeshPeerRow>,
}

impl From<MeshStatus> for MeshStatusRow {
    fn from(s: MeshStatus) -> Self {
        Self {
            joined: s.joined,
            public_key: s.public_key.map(|k| b64(&k)),
            address: s.address.map(|a| a.to_string()),
            listen_port: s.listen_port,
            peers: s.peers.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MeshMemberArgs {
    pub server_id: String,
    /// Public IP other members dial; `None` if unreachable from outside.
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MeshStepRow {
    pub server_id: String,
    pub step: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MeshRunRow {
    pub steps: Vec<MeshStepRow>,
    /// `None`: every member joined and has every other member as a peer.
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648() {
        assert_eq!(b64(b""), "");
        assert_eq!(b64(b"f"), "Zg==");
        assert_eq!(b64(b"fo"), "Zm8=");
        assert_eq!(b64(b"foo"), "Zm9v");
        assert_eq!(b64(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64(&[0xff; 32]).len(), 44);
    }
}
