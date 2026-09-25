//! Mutating admin operations for the server tabs (design §2.5, §2.6):
//! firewall editing with auto-revert, bans, processes, users and SSH keys,
//! cron and config history.
//!
//! - **Arguments** are parsed into the protocol's validated types here,
//!   before anything is signed; exec validates again (rule 3).
//! - **Versions:** ops that replace versioned state carry the version the
//!   operator saw (`expected_version`); a stale one comes back as
//!   `VersionConflict`.
//! - **Elevated** ops get a root-key approval (Touch ID) before sending;
//!   ops exec may escalate (`Op::may_escalate`) are retried once with an
//!   approval when exec answers `ApprovalRequired`.
//! - **Auto-revert** ops answer a [`PendingChangeRow`]; the app then calls
//!   [`FleetCore::confirm_change`], which confirms over a fresh connection
//!   (`fleet_core::autorevert`).

use crate::admin_rows::*;
use crate::api::FleetCore;
use crate::fleet_mgmt::blocking;
use crate::rows::FirewallRuleRow;
use crate::text;
use crate::types::FleetError;
use crate::validate;
use fleet_core::autorevert::{self, ConfirmError};
use fleet_core::bulk::ApproveError;
use fleet_core::manager::RequestOpts;
use fleet_core::opspec;
use fleet_crypto::approval::op_digest;
use fleet_proto::args::{
    AbsPath, Cidr, CronCommand, CronSpec, FirewallMode, FirewallRule, FirewallRuleSet, FwAction,
    FwChain, FwComment, GroupName, Label, Nice, Pid, Port, PortRange, Protocol, RateLimit, Signal,
    SshPublicKey, TimeRange, UserName,
};
use fleet_proto::op::{BanConfig, CronEntry, LoginShell};
use fleet_proto::{Actor, ApprovalItem, ErrorCode, Op, Payload, RootApproval, ServerId};

pub(crate) fn invalid(field: &str) -> FleetError {
    FleetError::InvalidArgument {
        field: field.into(),
    }
}

pub(crate) fn agent_err(code: ErrorCode) -> FleetError {
    FleetError::Agent {
        code: format!("{code:?}"),
    }
}

pub(crate) fn unexpected<T>(_: Payload) -> Result<T, FleetError> {
    Err(FleetError::UnexpectedReply)
}

pub(crate) fn user(name: &str) -> Result<UserName, FleetError> {
    let u = UserName::new(name).map_err(|_| invalid("user"))?;
    // Exec refuses Fleet's own accounts too; fail before signing.
    if u.is_fleet() {
        return Err(invalid("user"));
    }
    Ok(u)
}

fn groups(names: &[String]) -> Result<Vec<GroupName>, FleetError> {
    names
        .iter()
        .map(|g| GroupName::new(g.as_str()).map_err(|_| invalid("groups")))
        .collect()
}

pub(crate) fn abs_path(p: &str) -> Result<AbsPath, FleetError> {
    AbsPath::new(p).map_err(|_| invalid("path"))
}

fn pending(p: Payload) -> Result<PendingChangeRow, FleetError> {
    match p {
        Payload::ChangePending { change, .. } => Ok(change.into()),
        p => unexpected(p),
    }
}

impl FleetCore {
    /// One signed request with `expected_version` and `approval`; the
    /// agent's answer (an error code is not a transport failure here).
    async fn send_raw(
        &self,
        id: &ServerId,
        op: Op,
        expected_version: Option<u64>,
        approval: Option<RootApproval>,
    ) -> Result<Result<Payload, ErrorCode>, FleetError> {
        let (handle, _) = self.running()?;
        let id = id.clone();
        let reply = self
            .on_core(async move {
                handle
                    .request_with(
                        &id,
                        op,
                        Actor::Human,
                        approval,
                        RequestOpts { expected_version },
                    )
                    .await
                    .map_err(FleetError::from)
            })
            .await?;
        Ok(reply.result)
    }

    /// Root-key approval (Touch ID) for exactly this op on this server.
    async fn approve_one(
        &self,
        id: &ServerId,
        op: &Op,
        expected_version: Option<u64>,
    ) -> Result<RootApproval, FleetError> {
        let approver = self.root_approver()?;
        let item = ApprovalItem {
            server_id: id.clone(),
            op_digest: op_digest(op, expected_version),
        };
        let what = op.name().to_string();
        blocking("fleet-approve", move || {
            approver
                .approve(&what, &[item])
                .map_err(|e| match e {
                    ApproveError::Cancelled => FleetError::Cancelled,
                    e => FleetError::Internal {
                        message: e.to_string(),
                    },
                })?
                .into_iter()
                .next()
                .ok_or(FleetError::Internal {
                    message: "no approval".into(),
                })
        })
        .await
    }

    /// Sends `op` as the operator (module docs: versions, approvals).
    pub(crate) async fn send_op(
        &self,
        server_id: &str,
        op: Op,
        expected_version: Option<u64>,
    ) -> Result<Payload, FleetError> {
        let id = validate::server_id(server_id)?;
        op.check_args().map_err(|_| invalid(op.name()))?;
        let approval = if opspec::needs_approval(&op) {
            Some(self.approve_one(&id, &op, expected_version).await?)
        } else {
            None
        };
        let first = approval.is_none();
        match self
            .send_raw(&id, op.clone(), expected_version, approval)
            .await?
        {
            Err(ErrorCode::ApprovalRequired) if first && op.may_escalate() => {
                let a = self.approve_one(&id, &op, expected_version).await?;
                self.send_raw(&id, op, expected_version, Some(a))
                    .await?
                    .map_err(agent_err)
            }
            r => r.map_err(agent_err),
        }
    }

    /// For versioned ops whose version no read op reports (ban config):
    /// the version the agent names in its conflict answer.
    async fn send_latest(&self, server_id: &str, op: Op) -> Result<Payload, FleetError> {
        match self.send_op(server_id, op.clone(), Some(0)).await {
            Err(FleetError::Agent { code }) if code.starts_with("VersionConflict") => {
                let current = code
                    .trim_start_matches("VersionConflict { current: ")
                    .trim_end_matches(" }")
                    .parse()
                    .map_err(|_| FleetError::UnexpectedReply)?;
                self.send_op(server_id, op, Some(current)).await
            }
            r => r,
        }
    }
}

// ---- firewall model ----

fn port_range(s: &str) -> Result<PortRange, FleetError> {
    let bad = || invalid("ports");
    let port = |p: &str| {
        p.trim()
            .parse::<u16>()
            .ok()
            .and_then(|p| Port::new(p).ok())
            .ok_or_else(bad)
    };
    match s.split_once('-') {
        Some((a, b)) => PortRange::new(port(a)?, port(b)?).map_err(|_| bad()),
        None => Ok(PortRange::single(port(s)?)),
    }
}

pub(crate) fn fw_rule(a: &FirewallRuleArgs) -> Result<FirewallRule, FleetError> {
    let source = match a.source.as_deref().map(str::trim) {
        None | Some("") | Some("any") => None,
        Some(s) => Some(s.parse::<Cidr>().map_err(|_| invalid("source"))?),
    };
    let rule = FirewallRule {
        chain: match a.chain {
            FwChainArg::Input => FwChain::Input,
            FwChainArg::Forward => FwChain::Forward,
        },
        action: match a.action {
            FwActionArg::Accept => FwAction::Accept,
            FwActionArg::Drop => FwAction::Drop,
            FwActionArg::Reject => FwAction::Reject,
        },
        proto: match a.proto {
            FwProtoArg::Tcp => Protocol::Tcp,
            FwProtoArg::Udp => Protocol::Udp,
        },
        ports: a
            .ports
            .iter()
            .filter(|p| !p.trim().is_empty())
            .map(|p| port_range(p))
            .collect::<Result<_, _>>()?,
        source,
        rate_limit: a.rate_per_minute.map(|per_minute| RateLimit {
            per_minute,
            burst: a.rate_burst,
        }),
        comment: FwComment::new(a.comment.trim()).map_err(|_| invalid("comment"))?,
    };
    rule.validate().map_err(|_| invalid("rule"))?;
    Ok(rule)
}

pub(crate) fn fw_ruleset(a: &FirewallRulesetArgs) -> Result<FirewallRuleSet, FleetError> {
    let set = FirewallRuleSet {
        mode: if a.managed {
            FirewallMode::Managed
        } else {
            FirewallMode::BansOnly
        },
        rules: a.rules.iter().map(fw_rule).collect::<Result<_, _>>()?,
    };
    set.validate().map_err(|_| invalid("ruleset"))?;
    Ok(set)
}

fn covers(r: &FirewallRule, port: u16) -> bool {
    r.ports
        .iter()
        .any(|p| p.start().get() <= port && port <= p.end().get())
}

/// The agent's safety checks before `firewall.apply` (design §4.8,
/// `fleet_ops::firewall::validate`), in the operator's words. Empty: OK.
pub(crate) fn fw_problems(set: &FirewallRuleSet, ssh_port: u16) -> Vec<String> {
    let mut out = Vec::new();
    if let Err(e) = set.validate() {
        out.push(format!("Rule set: {e}."));
    }
    if set
        .rules
        .iter()
        .any(|r| r.rate_limit.is_some() && r.action != FwAction::Accept)
    {
        out.push("Rate limits are allowed on Allow rules only.".into());
    }
    if set.rules.iter().filter(|r| r.rate_limit.is_some()).count() > 16 {
        out.push("At most 16 rules can have a rate limit.".into());
    }
    if set.mode == FirewallMode::Managed {
        let input = |r: &&FirewallRule| r.chain == FwChain::Input && r.proto == Protocol::Tcp;
        if !set
            .rules
            .iter()
            .filter(input)
            .any(|r| r.action == FwAction::Accept && covers(r, ssh_port))
        {
            out.push(format!(
                "No rule allows SSH (tcp/{ssh_port}): the server would lock you out."
            ));
        }
        if set
            .rules
            .iter()
            .filter(input)
            .any(|r| r.action != FwAction::Accept && r.source.is_none() && covers(r, ssh_port))
        {
            out.push(format!(
                "A Drop/Reject rule from any source covers SSH (tcp/{ssh_port})."
            ));
        }
    }
    out
}

fn rule_text(r: &FirewallRule) -> String {
    let ports: Vec<String> = r
        .ports
        .iter()
        .map(|p| {
            let (a, b) = (p.start().get(), p.end().get());
            if a == b {
                a.to_string()
            } else {
                format!("{a}-{b}")
            }
        })
        .collect();
    let mut s = format!(
        "{} {} {} {} from {}",
        match r.chain {
            FwChain::Input => "input",
            FwChain::Forward => "forward",
        },
        match r.action {
            FwAction::Accept => "allow",
            FwAction::Drop => "drop",
            FwAction::Reject => "reject",
        },
        match r.proto {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        },
        ports.join(","),
        r.source.map_or("any".to_string(), |c| c.to_string()),
    );
    if let Some(l) = r.rate_limit {
        s.push_str(&format!(" limit {}/min burst {}", l.per_minute, l.burst));
    }
    if !r.comment.as_str().is_empty() {
        s.push_str(&format!("  # {}", r.comment.as_str()));
    }
    s
}

fn mode_text(m: FirewallMode) -> String {
    match m {
        FirewallMode::Managed => "mode managed (default drop)".into(),
        FirewallMode::BansOnly => "mode bans-only".into(),
    }
}

/// Line diff (LCS) of two short lists.
pub(crate) fn line_diff(old: &[String], new: &[String]) -> Vec<DiffLineRow> {
    let (n, m) = (old.len(), new.len());
    let mut lcs = vec![vec![0u16; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if old[i] == new[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    let mut out = Vec::new();
    let line = |kind, text: &String| DiffLineRow {
        kind,
        text: text.clone(),
    };
    while i < n || j < m {
        if i < n && j < m && old[i] == new[j] {
            out.push(line(DiffLineKind::Same, &old[i]));
            i += 1;
            j += 1;
        } else if j < m && (i == n || lcs[i][j + 1] >= lcs[i + 1][j]) {
            out.push(line(DiffLineKind::Added, &new[j]));
            j += 1;
        } else {
            out.push(line(DiffLineKind::Removed, &old[i]));
            i += 1;
        }
    }
    out
}

fn set_lines(s: &FirewallRuleSet) -> Vec<String> {
    std::iter::once(mode_text(s.mode))
        .chain(s.rules.iter().map(rule_text))
        .collect()
}

/// Editable copy of a rule the agent reported (`firewall_get`).
fn rule_args(r: &FirewallRuleRow) -> FirewallRuleArgs {
    let (per_minute, burst) = r
        .rate_limit
        .as_deref()
        .and_then(|l| l.split_once('/'))
        .map_or((None, 10), |(a, b)| {
            (a.parse().ok(), b.parse().unwrap_or(10))
        });
    FirewallRuleArgs {
        chain: if r.chain == "forward" {
            FwChainArg::Forward
        } else {
            FwChainArg::Input
        },
        action: match r.action.as_str() {
            "accept" => FwActionArg::Accept,
            "reject" => FwActionArg::Reject,
            _ => FwActionArg::Drop,
        },
        proto: if r.proto == "udp" {
            FwProtoArg::Udp
        } else {
            FwProtoArg::Tcp
        },
        ports: r.ports.clone(),
        source: r.source.clone(),
        rate_per_minute: per_minute,
        rate_burst: burst,
        comment: r.comment.clone(),
    }
}

/// Firewall rows as editable arguments.
#[uniffi::export]
pub fn firewall_rules_to_args(rules: Vec<FirewallRuleRow>) -> Vec<FirewallRuleArgs> {
    rules.iter().map(rule_args).collect()
}

/// Local checks mirroring the agent's (argument limits, rate limits, SSH
/// reachability in Managed mode). Empty: the agent should accept it.
#[uniffi::export]
pub fn firewall_check(ruleset: FirewallRulesetArgs, ssh_port: u16) -> Vec<String> {
    match fw_ruleset(&ruleset) {
        Ok(set) => fw_problems(&set, ssh_port),
        Err(FleetError::InvalidArgument { field }) => vec![format!("Invalid {field}.")],
        Err(_) => vec!["Invalid rule set.".into()],
    }
}

/// Line diff between the current and the proposed rule set.
#[uniffi::export]
pub fn firewall_diff(
    current: FirewallRulesetArgs,
    proposed: FirewallRulesetArgs,
) -> Result<Vec<DiffLineRow>, FleetError> {
    Ok(line_diff(
        &set_lines(&fw_ruleset(&current)?),
        &set_lines(&fw_ruleset(&proposed)?),
    ))
}

fn signal(s: SignalArg) -> Signal {
    match s {
        SignalArg::Hup => Signal::Hup,
        SignalArg::Int => Signal::Int,
        SignalArg::Quit => Signal::Quit,
        SignalArg::Kill => Signal::Kill,
        SignalArg::Usr1 => Signal::Usr1,
        SignalArg::Usr2 => Signal::Usr2,
        SignalArg::Term => Signal::Term,
        SignalArg::Cont => Signal::Cont,
        SignalArg::Stop => Signal::Stop,
    }
}

fn change_id(hex_id: &str) -> Result<[u8; 16], FleetError> {
    hex::decode(hex_id)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| invalid("change_id"))
}

#[uniffi::export]
impl FleetCore {
    // ---- firewall and auto-revert ----

    /// `firewall.apply` at `expected_version` (from `firewall_get`). The
    /// change reverts unless [`FleetCore::confirm_change`] succeeds.
    pub async fn firewall_apply(
        &self,
        server_id: String,
        ruleset: FirewallRulesetArgs,
        expected_version: u64,
    ) -> Result<PendingChangeRow, FleetError> {
        let set = fw_ruleset(&ruleset)?;
        pending(
            self.send_op(&server_id, Op::FirewallApply(set), Some(expected_version))
                .await?,
        )
    }

    /// Confirms an auto-revert change over a fresh connection (the
    /// server's session is reconnected first; design §4.10 step 3).
    pub async fn confirm_change(
        &self,
        server_id: String,
        change_id_hex: String,
        deadline_ms: u64,
    ) -> Result<ConfirmOutcome, FleetError> {
        let id = validate::server_id(&server_id)?;
        let cid = change_id(&change_id_hex)?;
        let (handle, _) = self.running()?;
        let budget = autorevert::budget(deadline_ms, fleet_core::now_ms());
        self.on_core(async move {
            Ok(
                match autorevert::confirm_fresh(&handle, &id, cid, Actor::Human, budget).await {
                    Ok(()) => ConfirmOutcome::Confirmed,
                    Err(ConfirmError::Reverted) => ConfirmOutcome::Reverted,
                    Err(ConfirmError::NoConnection) => ConfirmOutcome::NoConnection,
                    Err(ConfirmError::Agent(c)) => ConfirmOutcome::Failed {
                        message: format!("{c:?}"),
                    },
                    Err(ConfirmError::Request(e)) => ConfirmOutcome::Failed {
                        message: FleetError::from(e).to_string(),
                    },
                },
            )
        })
        .await
    }

    /// Changes waiting for confirmation (`changes.list`).
    pub async fn changes_list(
        &self,
        server_id: String,
    ) -> Result<Vec<PendingChangeRow>, FleetError> {
        match self.send_op(&server_id, Op::ChangesList, None).await? {
            Payload::PendingChanges(p) => Ok(p.changes.into_iter().map(Into::into).collect()),
            p => unexpected(p),
        }
    }

    pub async fn ban_remove(&self, server_id: String, addr: String) -> Result<(), FleetError> {
        let addr = addr.trim().parse().map_err(|_| invalid("address"))?;
        self.send_op(&server_id, Op::BansRemove { addr }, None)
            .await
            .map(|_| ())
    }

    pub async fn bans_config_get(&self, server_id: String) -> Result<BanConfigRow, FleetError> {
        match self.send_op(&server_id, Op::BansConfigGet, None).await? {
            Payload::BanConfig(c) => Ok(BanConfigRow {
                threshold: c.threshold,
                window_s: c.window_s,
                ban_steps_s: c.ban_steps_s,
                exempt: c.exempt.iter().map(|c| c.to_string()).collect(),
                web_scanners: c.web_scanners,
            }),
            p => unexpected(p),
        }
    }

    pub async fn bans_config_set(
        &self,
        server_id: String,
        config: BanConfigRow,
    ) -> Result<(), FleetError> {
        let cfg = BanConfig {
            threshold: config.threshold,
            window_s: config.window_s,
            ban_steps_s: config.ban_steps_s,
            exempt: config
                .exempt
                .iter()
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().parse::<Cidr>().map_err(|_| invalid("exempt")))
                .collect::<Result<_, _>>()?,
            web_scanners: config.web_scanners,
        };
        cfg.validate().map_err(|_| invalid("ban config"))?;
        self.send_latest(&server_id, Op::BansConfigSet(cfg))
            .await
            .map(|_| ())
    }

    // ---- processes ----

    pub async fn process_signal(
        &self,
        server_id: String,
        pid: u32,
        signal: SignalArg,
    ) -> Result<(), FleetError> {
        let pid = Pid::new(pid).map_err(|_| invalid("pid"))?;
        let op = Op::ProcessSignal {
            pid,
            signal: self::signal(signal),
        };
        self.send_op(&server_id, op, None).await.map(|_| ())
    }

    /// `nice` −20…19.
    pub async fn process_renice(
        &self,
        server_id: String,
        pid: u32,
        nice: i8,
    ) -> Result<(), FleetError> {
        let op = Op::ProcessRenice {
            pid: Pid::new(pid).map_err(|_| invalid("pid"))?,
            nice: Nice::new(nice).map_err(|_| invalid("nice"))?,
        };
        self.send_op(&server_id, op, None).await.map(|_| ())
    }

    // ---- users and SSH keys ----

    pub async fn users_list(&self, server_id: String) -> Result<UnixUsersRow, FleetError> {
        match self.send_op(&server_id, Op::UsersList, None).await? {
            Payload::Users(u) => Ok(UnixUsersRow {
                users: u.users.into_iter().map(Into::into).collect(),
                groups: u.groups.into_iter().map(Into::into).collect(),
            }),
            p => unexpected(p),
        }
    }

    /// Privileged groups (`sudo`, `adm`, `docker`, …) need Touch ID.
    pub async fn users_create(
        &self,
        server_id: String,
        name: String,
        groups: Vec<String>,
        shell: LoginShellArg,
        comment: String,
    ) -> Result<(), FleetError> {
        let op = Op::UsersCreate {
            name: user(&name)?,
            groups: self::groups(&groups)?,
            shell: match shell {
                LoginShellArg::Bash => LoginShell::Bash,
                LoginShellArg::Sh => LoginShell::Sh,
                LoginShellArg::Nologin => LoginShell::Nologin,
            },
            comment: Label::new(comment).map_err(|_| invalid("comment"))?,
        };
        self.send_op(&server_id, op, None).await.map(|_| ())
    }

    pub async fn users_lock(
        &self,
        server_id: String,
        name: String,
        locked: bool,
    ) -> Result<(), FleetError> {
        let op = Op::UsersLock {
            name: user(&name)?,
            locked,
        };
        self.send_op(&server_id, op, None).await.map(|_| ())
    }

    pub async fn users_delete(
        &self,
        server_id: String,
        name: String,
        remove_home: bool,
    ) -> Result<(), FleetError> {
        let op = Op::UsersDelete {
            name: user(&name)?,
            remove_home,
        };
        self.send_op(&server_id, op, None).await.map(|_| ())
    }

    pub async fn users_groups_set(
        &self,
        server_id: String,
        name: String,
        groups: Vec<String>,
    ) -> Result<(), FleetError> {
        let op = Op::UsersGroupsSet {
            name: user(&name)?,
            groups: self::groups(&groups)?,
        };
        self.send_op(&server_id, op, None).await.map(|_| ())
    }

    pub async fn groups_create(&self, server_id: String, name: String) -> Result<(), FleetError> {
        let op = Op::GroupsCreate {
            name: GroupName::new(name).map_err(|_| invalid("group"))?,
        };
        self.send_op(&server_id, op, None).await.map(|_| ())
    }

    pub async fn authorized_keys_get(
        &self,
        server_id: String,
        user_name: String,
    ) -> Result<AuthorizedKeysRow, FleetError> {
        let op = Op::AuthorizedKeysGet {
            user: user(&user_name)?,
        };
        match self.send_op(&server_id, op, None).await? {
            Payload::AuthorizedKeys(k) => Ok(AuthorizedKeysRow {
                user: text::line(k.user),
                version: k.version,
                roster_lines: k
                    .roster_section
                    .into_iter()
                    .map(|r| text::line(r.line))
                    .collect(),
                extra: text::lines(k.extra),
            }),
            p => unexpected(p),
        }
    }

    /// Replaces the extra section (Elevated: Touch ID; auto-revert: confirm
    /// with [`FleetCore::confirm_change`]).
    pub async fn authorized_keys_set(
        &self,
        server_id: String,
        user_name: String,
        keys: Vec<String>,
        expected_version: u64,
    ) -> Result<PendingChangeRow, FleetError> {
        let keys = keys
            .iter()
            .map(|k| k.trim())
            .filter(|k| !k.is_empty())
            .map(|k| k.parse::<SshPublicKey>().map_err(|_| invalid("key")))
            .collect::<Result<Vec<_>, _>>()?;
        let op = Op::AuthorizedKeysSet {
            user: user(&user_name)?,
            keys,
        };
        pending(self.send_op(&server_id, op, Some(expected_version)).await?)
    }

    // ---- cron ----

    /// `user`: one user's crontab; `None`: every user plus system files.
    pub async fn cron_list(
        &self,
        server_id: String,
        user_name: Option<String>,
    ) -> Result<Vec<CronTabRow>, FleetError> {
        let op = Op::CronList {
            user: user_name.as_deref().map(user).transpose()?,
        };
        match self.send_op(&server_id, op, None).await? {
            Payload::CronTabs(t) => Ok(t.tabs.into_iter().map(Into::into).collect()),
            p => unexpected(p),
        }
    }

    /// Replaces `user`'s crontab at `expected_version` (from `cron_list`).
    /// root or a privileged user's crontab needs Touch ID.
    pub async fn cron_set(
        &self,
        server_id: String,
        user_name: String,
        entries: Vec<CronEntryArgs>,
        expected_version: u64,
    ) -> Result<(), FleetError> {
        let entries = entries
            .iter()
            .map(|e| {
                Ok(CronEntry {
                    schedule: CronSpec::new(e.schedule.trim()).map_err(|_| invalid("schedule"))?,
                    command: CronCommand::new(e.command.as_str())
                        .map_err(|_| invalid("command"))?,
                    comment: Label::new(e.comment.as_str()).map_err(|_| invalid("comment"))?,
                })
            })
            .collect::<Result<Vec<_>, FleetError>>()?;
        let op = Op::CronSet {
            user: user(&user_name)?,
            entries,
        };
        self.send_op(&server_id, op, Some(expected_version))
            .await
            .map(|_| ())
    }

    pub async fn timers_list(&self, server_id: String) -> Result<Vec<TimerRow>, FleetError> {
        match self.send_op(&server_id, Op::TimersList, None).await? {
            Payload::Timers(t) => Ok(t.timers.into_iter().map(Into::into).collect()),
            p => unexpected(p),
        }
    }

    // ---- config history ----

    /// Newest first; `path` `None` = every tracked file.
    pub async fn config_history(
        &self,
        server_id: String,
        path: Option<String>,
        since_ms: Option<u64>,
        limit: u32,
    ) -> Result<ConfigHistoryRow, FleetError> {
        if !(1..=1000).contains(&limit) {
            return Err(invalid("limit"));
        }
        let range = TimeRange {
            since_ms,
            until_ms: None,
        };
        range.validate().map_err(|_| invalid("range"))?;
        let op = Op::ConfigHistory {
            path: path.as_deref().map(abs_path).transpose()?,
            range,
            limit,
        };
        match self.send_op(&server_id, op, None).await? {
            Payload::ConfigHistory(h) => Ok(ConfigHistoryRow {
                versions: h.versions.into_iter().map(Into::into).collect(),
                truncated: h.truncated,
            }),
            p => unexpected(p),
        }
    }

    /// `to` `None`: against the live file.
    pub async fn config_diff(
        &self,
        server_id: String,
        path: String,
        from: u64,
        to: Option<u64>,
    ) -> Result<ConfigDiffRow, FleetError> {
        let op = Op::ConfigDiff {
            path: abs_path(&path)?,
            from,
            to,
        };
        match self.send_op(&server_id, op, None).await? {
            Payload::ConfigDiff(d) => Ok(ConfigDiffRow {
                path: text::line(d.path),
                from: d.from,
                to: d.to,
                unified: text::text(d.unified),
                binary: d.binary,
            }),
            p => unexpected(p),
        }
    }

    /// Protected paths (`/etc/sudoers*`, `/etc/ssh/`, …) and anything
    /// outside `/etc` and `/srv` need Touch ID.
    pub async fn config_rollback(
        &self,
        server_id: String,
        path: String,
        version: u64,
    ) -> Result<(), FleetError> {
        let op = Op::ConfigRollback {
            path: abs_path(&path)?,
            version,
        };
        self.send_op(&server_id, op, None).await.map(|_| ())
    }

    pub async fn config_paths_get(&self, server_id: String) -> Result<ConfigPathsRow, FleetError> {
        match self.send_op(&server_id, Op::ConfigPathsGet, None).await? {
            Payload::ConfigPaths(p) => Ok(ConfigPathsRow {
                builtin_tracked: text::lines(p.builtin_tracked),
                builtin_secret: text::lines(p.builtin_secret),
                tracked: text::lines(p.tracked),
                secret: text::lines(p.secret),
                version: p.version,
            }),
            p => unexpected(p),
        }
    }
}

/// Groups whose membership makes `users.create` / `users.groups.set`
/// Elevated (`fleet_proto::args::PRIVILEGED_GROUPS`).
#[uniffi::export]
pub fn privileged_groups() -> Vec<String> {
    fleet_proto::args::PRIVILEGED_GROUPS
        .iter()
        .map(|g| g.to_string())
        .collect()
}

/// Whether rolling back `path` is Elevated (Touch ID), as exec decides.
#[uniffi::export]
pub fn config_rollback_needs_approval(path: String) -> bool {
    AbsPath::new(path)
        .is_ok_and(|path| opspec::needs_approval(&Op::ConfigRollback { path, version: 1 }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(action: FwActionArg, ports: &[&str], source: Option<&str>) -> FirewallRuleArgs {
        FirewallRuleArgs {
            chain: FwChainArg::Input,
            action,
            proto: FwProtoArg::Tcp,
            ports: ports.iter().map(|p| p.to_string()).collect(),
            source: source.map(Into::into),
            rate_per_minute: None,
            rate_burst: 10,
            comment: "ssh".into(),
        }
    }

    fn set(rules: Vec<FirewallRuleArgs>) -> FirewallRulesetArgs {
        FirewallRulesetArgs {
            managed: true,
            rules,
        }
    }

    #[test]
    fn parses_rules() {
        let r = fw_rule(&rule(
            FwActionArg::Accept,
            &["22", "8000-8100"],
            Some("10.0.0.0/8"),
        ))
        .unwrap();
        assert_eq!(r.ports.len(), 2);
        assert!(r.source.is_some());
        assert!(fw_rule(&rule(FwActionArg::Accept, &["0"], None)).is_err());
        assert!(fw_rule(&rule(FwActionArg::Accept, &["90-80"], None)).is_err());
        assert!(fw_rule(&rule(FwActionArg::Accept, &[], None)).is_err());
        assert!(fw_rule(&rule(FwActionArg::Accept, &["22"], Some("10.0.0.1/8"))).is_err());
        let mut bad = rule(FwActionArg::Accept, &["22"], None);
        bad.comment = "x; drop".into();
        assert!(fw_rule(&bad).is_err());
        let bans_only = FirewallRulesetArgs {
            managed: false,
            rules: vec![rule(FwActionArg::Accept, &["22"], None)],
        };
        assert!(fw_ruleset(&bans_only).is_err());
    }

    #[test]
    fn ssh_lockout_checks() {
        assert!(firewall_check(set(vec![rule(FwActionArg::Accept, &["22"], None)]), 22).is_empty());
        // Restricted source still counts (exempt sets keep the Macs in).
        assert!(
            firewall_check(
                set(vec![rule(FwActionArg::Accept, &["22"], Some("10.0.0.0/8"))]),
                22
            )
            .is_empty()
        );
        assert_eq!(firewall_check(set(vec![]), 22).len(), 1);
        assert_eq!(
            firewall_check(set(vec![rule(FwActionArg::Accept, &["80"], None)]), 2222).len(),
            1
        );
        let blocked = set(vec![
            rule(FwActionArg::Drop, &["1-1024"], None),
            rule(FwActionArg::Accept, &["22"], None),
        ]);
        assert_eq!(firewall_check(blocked, 22).len(), 1);
        let mut limited = rule(FwActionArg::Drop, &["80"], None);
        limited.rate_per_minute = Some(10);
        let s = set(vec![rule(FwActionArg::Accept, &["22"], None), limited]);
        assert_eq!(firewall_check(s, 22).len(), 1);
        // Bans only: nothing to lock out.
        let b = FirewallRulesetArgs {
            managed: false,
            rules: vec![],
        };
        assert!(firewall_check(b, 22).is_empty());
    }

    #[test]
    fn diff_marks_changes() {
        let a = set(vec![rule(FwActionArg::Accept, &["22"], None)]);
        let b = set(vec![
            rule(FwActionArg::Accept, &["22"], None),
            rule(FwActionArg::Accept, &["443"], None),
        ]);
        let d = firewall_diff(a.clone(), b).unwrap();
        let kinds: Vec<_> = d.iter().map(|l| l.kind).collect();
        assert_eq!(
            kinds,
            vec![DiffLineKind::Same, DiffLineKind::Same, DiffLineKind::Added]
        );
        assert!(d[2].text.contains("443"));
        let removed = firewall_diff(a, set(vec![])).unwrap();
        assert_eq!(removed[1].kind, DiffLineKind::Removed);
    }

    #[test]
    fn rows_round_trip_to_args() {
        let row = FirewallRuleRow {
            chain: "input".into(),
            action: "accept".into(),
            proto: "tcp".into(),
            ports: vec!["22".into()],
            source: None,
            rate_limit: Some("10/5".into()),
            comment: "ssh".into(),
        };
        let a = firewall_rules_to_args(vec![row]);
        assert_eq!(a[0].rate_per_minute, Some(10));
        assert_eq!(a[0].rate_burst, 5);
        assert!(fw_rule(&a[0]).is_ok());
    }

    #[test]
    fn fleet_accounts_refused() {
        assert!(user("fleet").is_err());
        assert!(user("fleet-exec").is_err());
        assert!(user("Bad").is_err());
        assert!(user("deploy").is_ok());
    }

    #[test]
    fn rollback_tier() {
        assert!(!config_rollback_needs_approval(
            "/etc/nginx/nginx.conf".into()
        ));
        assert!(config_rollback_needs_approval("/etc/sudoers".into()));
        assert!(config_rollback_needs_approval("/opt/app.conf".into()));
        assert!(!config_rollback_needs_approval(
            "/srv/app/compose.yaml".into()
        ));
    }
}
