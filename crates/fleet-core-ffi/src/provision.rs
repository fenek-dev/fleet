//! Provisioning wizard, hardening audit and cloud-init export over FFI
//! (design §9.1, §9.7, §2.4). Orchestration: `fleet_core::provision`.
//!
//! ```text
//! add_server → [pin_cloud_init_host_key | probe_host_key + accept_host_key]
//!   → install_agent(admin_user) → provision_begin(choice)
//!   → provision_advance (… Review) → provision_approve_plan(hash)
//!   → provision_advance (Accounts … Done)
//! ```
//!
//! The wizard state is kept in the cache (`provision/<server>` setting,
//! MAC'd JSON) after every step, so a failed or interrupted run resumes
//! with `provision_advance`. The finished choice (level and roles) stays
//! as `profile/<server>` for one-click audit fixes.

use crate::api::{FleetCore, lock};
use crate::approvals::approve_err;
use crate::types::FleetError;
use crate::validate;
use fleet_core::autorevert;
use fleet_core::bulk::{BoxFut, BulkExecutor, Failure};
use fleet_core::cache::Cache;
use fleet_core::manager::{ManagerHandle, RequestOpts};
use fleet_core::provision::{
    self as pv, ConfirmFailure, Level, ProvisionBackend, ProvisionChoice, ProvisionConfig,
    ProvisionEvent, ProvisionState, Role, Step,
};
use fleet_core::signer::{KeyRole, RoleSigner};
use fleet_core::ssh::{P256SshSigner, SshConnection, SshOptions};
use fleet_core::sync::Collection;
use fleet_crypto::Zeroizing;
use fleet_proto::args::SudoPasswordHash;
use fleet_proto::op::{ProfileLevel, ProfilePhase, ProfileSource, ProfileSpec};
use fleet_proto::payload::{ModuleStatus, ProfilePlan};
use fleet_proto::{
    Actor, ApprovalItem, ChangeId, Hash32, Op, Payload, RootApproval, ServerId, SignedRoster,
    args::ModuleId,
};
use std::sync::Arc;

fn perr(e: impl std::fmt::Display) -> FleetError {
    FleetError::Provision {
        reason: e.to_string(),
    }
}

// ---- rows ----

/// Shared with the bulk sheet (`bulk::ProfileLevelRow`).
pub use crate::bulk::ProfileLevelRow;

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ProfileRoleRow {
    Docker,
    Web,
    Game,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ProvisionChoiceRow {
    pub level: ProfileLevelRow,
    pub roles: Vec<ProfileRoleRow>,
    /// The admin the agent was installed with.
    pub admin_user: String,
    /// SSH source ranges (CIDR); empty: anywhere, rate-limited.
    pub allow_from: Vec<String>,
    /// e.g. `Sun 04:00-05:00 UTC`; `None`: never reboot automatically.
    pub reboot_window: Option<String>,
    pub name: String,
    pub group_id: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ProvisionStepRow {
    PushRoster,
    AuditBefore,
    Plan,
    Review,
    Accounts,
    VerifyAdmin,
    Access,
    ConfirmAccess,
    System,
    AuditAfter,
    AddToFleet,
    Done,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PlanChangeRow {
    pub module: String,
    /// Server text (escaped).
    pub description: String,
    pub diff: String,
    pub auto_revert: bool,
}

/// Plan changes per area, as the wizard's plan preview lists them.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PlanGroupRow {
    pub label: String,
    pub changes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ModuleResultRow {
    pub step: ProvisionStepRow,
    pub module: String,
    pub outcome: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ProvisionStateRow {
    pub server_id: String,
    pub choice: ProvisionChoiceRow,
    /// Operator TOML (source ranges or reboot window): each phase needs
    /// the root key (Touch ID).
    pub custom_profile: bool,
    pub step: ProvisionStepRow,
    pub step_label: String,
    /// Hex; pass back to `provision_approve_plan`.
    pub plan_hash: Option<String>,
    pub plan: Vec<PlanChangeRow>,
    pub plan_groups: Vec<PlanGroupRow>,
    pub score_before: Option<u8>,
    pub score_after: Option<u8>,
    /// Profile score after the last phase (roles included).
    pub profile_score: Option<u8>,
    /// Auto-revert deadline of the SSH/firewall phase, while pending.
    pub pending_deadline_ms: Option<u64>,
    pub modules: Vec<ModuleResultRow>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ProvisionEventRow {
    Step {
        step: ProvisionStepRow,
        label: String,
    },
    /// The package manager holds the dpkg lock; retrying.
    Waiting {
        attempt: u32,
    },
    RevertArmed {
        deadline_ms: u64,
    },
    Modules {
        step: ProvisionStepRow,
        modules: Vec<ModuleResultRow>,
    },
}

/// Provisioning progress; called on the core thread.
#[uniffi::export(callback_interface)]
pub trait ProvisionListener: Send + Sync {
    fn on_event(&self, event: ProvisionEventRow);
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AuditFindingRow {
    pub module: String,
    /// `compliant`, `drifted`, `not_applicable`, `skipped`, `error`,
    /// `pending_reboot` (counts as compliant; shown with a badge).
    pub status: String,
    pub severity: String,
    /// Server text (escaped).
    pub title: String,
    pub fixable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AuditReportRow {
    pub score: u8,
    pub level: ProfileLevelRow,
    pub findings: Vec<AuditFindingRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AuditFixPlanRow {
    pub module: String,
    pub plan_hash: String,
    pub changes: Vec<PlanChangeRow>,
    /// The fix touches sshd or the firewall: applied under auto-revert
    /// and confirmed from a fresh connection.
    pub auto_revert: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AuditFixResultRow {
    pub modules: Vec<ModuleResultRow>,
    pub score_before: u8,
    pub score_after: u8,
    pub confirmed: bool,
}

#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct CloudInitExportRow {
    /// Contains the new host **private** key: save it only where the
    /// operator chose (save panel, file created 0600), never log it.
    pub yaml: String,
    /// Pass to `pin_cloud_init_host_key` for the server created from it
    /// (single use: consumed by the pin).
    pub export_id: String,
    /// SHA-256 fingerprint of the host key (`SHA256:…`).
    pub fingerprint: String,
}

/// Never prints the YAML (it holds the host private key).
impl std::fmt::Debug for CloudInitExportRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudInitExportRow")
            .field("yaml", &"<redacted>")
            .field("export_id", &self.export_id)
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

// ---- conversions ----

fn level(l: ProfileLevelRow) -> Level {
    match l {
        ProfileLevelRow::Baseline => Level::Baseline,
        ProfileLevelRow::Strict => Level::Strict,
    }
}

fn level_row(l: Level) -> ProfileLevelRow {
    match l {
        Level::Baseline => ProfileLevelRow::Baseline,
        Level::Strict => ProfileLevelRow::Strict,
    }
}

fn role(r: ProfileRoleRow) -> Role {
    match r {
        ProfileRoleRow::Docker => Role::Docker,
        ProfileRoleRow::Web => Role::Web,
        ProfileRoleRow::Game => Role::Game,
    }
}

pub(crate) fn role_row(r: Role) -> ProfileRoleRow {
    match r {
        Role::Docker => ProfileRoleRow::Docker,
        Role::Web => ProfileRoleRow::Web,
        Role::Game => ProfileRoleRow::Game,
    }
}

fn to_choice(c: ProvisionChoiceRow) -> Result<ProvisionChoice, FleetError> {
    let ch = ProvisionChoice {
        level: level(c.level),
        roles: c.roles.into_iter().map(role).collect(),
        admin_user: validate::user(&c.admin_user)?,
        allow_from: c
            .allow_from
            .into_iter()
            .map(|s| s.trim().to_string())
            .collect(),
        reboot_window: c.reboot_window.filter(|w| !w.trim().is_empty()),
        name: validate::name(&c.name, "name")?,
        group: c.group_id.map(|g| validate::group_id(&g)).transpose()?,
        tags: validate::tags(&c.tags)?,
    };
    ch.validate().map_err(perr)?;
    Ok(ch)
}

fn choice_row(c: &ProvisionChoice) -> ProvisionChoiceRow {
    ProvisionChoiceRow {
        level: level_row(c.level),
        roles: c.roles.iter().copied().map(role_row).collect(),
        admin_user: c.admin_user.clone(),
        allow_from: c.allow_from.clone(),
        reboot_window: c.reboot_window.clone(),
        name: c.name.clone(),
        group_id: c.group.clone(),
        tags: c.tags.clone(),
    }
}

fn step_row(s: Step) -> ProvisionStepRow {
    match s {
        Step::PushRoster => ProvisionStepRow::PushRoster,
        Step::AuditBefore => ProvisionStepRow::AuditBefore,
        Step::Plan => ProvisionStepRow::Plan,
        Step::Review => ProvisionStepRow::Review,
        Step::Accounts => ProvisionStepRow::Accounts,
        Step::VerifyAdmin => ProvisionStepRow::VerifyAdmin,
        Step::Access => ProvisionStepRow::Access,
        Step::ConfirmAccess => ProvisionStepRow::ConfirmAccess,
        Step::System => ProvisionStepRow::System,
        Step::AuditAfter => ProvisionStepRow::AuditAfter,
        Step::AddToFleet => ProvisionStepRow::AddToFleet,
        Step::Done => ProvisionStepRow::Done,
    }
}

fn change_row(module: &str, description: &str, diff: &str, auto_revert: bool) -> PlanChangeRow {
    PlanChangeRow {
        module: crate::text::line(module.to_string()),
        description: crate::text::line(description.to_string()),
        diff: crate::text::text(diff.to_string()),
        auto_revert,
    }
}

/// Module id → plan preview area (design §9.4 headings).
fn area(module: &str) -> &'static str {
    match module {
        "admin.user" | "admin.shell" | "sudo.policy" | "ssh.hardening" | "accounts.lock"
        | "umask" => "Accounts and SSH",
        "firewall.baseline" => "Firewall",
        "sysctl" | "kernel.modules" | "coredump" => "Kernel settings",
        "updates" => "Automatic updates",
        "services.disable" => "Unneeded services removed",
        "auditd" | "journald" => "Auditing and logs",
        "apparmor" => "Integrity and platform",
        "role.docker" => "Docker role",
        "role.web" => "Web role",
        "role.game" => "Game server role",
        "mounts.tmp" | "cron.allow" | "sudo.pwquality" => "Strict additions",
        _ => "Basics",
    }
}

fn groups(plan: &[pv::PlanChange]) -> Vec<PlanGroupRow> {
    let mut out: Vec<PlanGroupRow> = Vec::new();
    for c in plan {
        let label = area(&c.module);
        match out.iter_mut().find(|g| g.label == label) {
            Some(g) => g.changes += 1,
            None => out.push(PlanGroupRow {
                label: label.into(),
                changes: 1,
            }),
        }
    }
    out
}

/// `skew_ms`: agent clock minus ours, so the countdown shown for the
/// agent's auto-revert deadline runs on this Mac's clock.
fn state_row(st: &ProvisionState, skew_ms: Option<i64>) -> ProvisionStateRow {
    ProvisionStateRow {
        server_id: st.server_id.clone(),
        choice: choice_row(&st.choice),
        custom_profile: st.choice.is_custom(),
        step: step_row(st.step),
        step_label: st.step.label().into(),
        plan_hash: st.plan_hash.map(hex::encode),
        plan: st
            .plan
            .iter()
            .map(|c| change_row(&c.module, &c.description, &c.diff, c.auto_revert))
            .collect(),
        plan_groups: groups(&st.plan),
        score_before: st.score_before,
        score_after: st.score_after,
        profile_score: st.profile_score,
        pending_deadline_ms: st
            .pending_deadline_ms
            .map(|d| fleet_core::autorevert::local_deadline(d, skew_ms)),
        modules: st
            .modules
            .iter()
            .map(|m| ModuleResultRow {
                step: step_row(m.step),
                module: crate::text::line(m.id.clone()),
                outcome: m.outcome.clone(),
                detail: crate::text::line(m.detail.clone()),
            })
            .collect(),
        last_error: st.last_error.clone().map(crate::text::line),
    }
}

fn event_row(e: ProvisionEvent) -> ProvisionEventRow {
    match e {
        ProvisionEvent::Step(s) => ProvisionEventRow::Step {
            step: step_row(s),
            label: s.label().into(),
        },
        ProvisionEvent::Waiting { attempt } => ProvisionEventRow::Waiting { attempt },
        ProvisionEvent::RevertArmed { deadline_ms } => {
            ProvisionEventRow::RevertArmed { deadline_ms }
        }
        ProvisionEvent::Modules { step, modules } => ProvisionEventRow::Modules {
            step: step_row(step),
            modules: modules
                .into_iter()
                .map(|m| ModuleResultRow {
                    step: step_row(step),
                    module: crate::text::line(m.id),
                    outcome: format!("{:?}", m.outcome),
                    detail: crate::text::line(m.detail),
                })
                .collect(),
        },
    }
}

fn hash_from_hex(s: &str) -> Result<Hash32, FleetError> {
    let b: [u8; 32] =
        hex::decode(s)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(FleetError::InvalidArgument {
                field: "plan_hash".into(),
            })?;
    Ok(b)
}

// ---- persisted state ----

fn state_key(id: &ServerId) -> String {
    format!("provision/{id}")
}

fn profile_key(id: &ServerId) -> String {
    format!("profile/{id}")
}

fn load_state(cache: &Cache, id: &ServerId) -> Result<Option<ProvisionState>, FleetError> {
    let Some(raw) = cache.setting(&state_key(id))? else {
        return Ok(None);
    };
    if raw.is_empty() {
        return Ok(None);
    }
    serde_json::from_slice(&raw)
        .map(Some)
        .map_err(|_| perr("saved provisioning state is unreadable"))
}

fn save_state(cache: &Cache, st: &ProvisionState) -> Result<(), FleetError> {
    let id = ServerId::new(st.server_id.clone()).map_err(|_| FleetError::UnknownServer)?;
    let raw = serde_json::to_vec(st).map_err(perr)?;
    cache.set_setting(&state_key(&id), &raw)?;
    Ok(())
}

/// The choice a server was provisioned with (audit fixes re-use its
/// level, roles, source ranges and reboot window).
pub(crate) fn provisioned_profile(cache: &Cache, id: &ServerId) -> Option<ProvisionChoice> {
    let raw = cache.setting(&profile_key(id)).ok().flatten()?;
    serde_json::from_slice(&raw).ok()
}

// ---- backend ----

struct Adapter {
    core: Arc<FleetCore>,
    handle: ManagerHandle,
}

/// Cache setting (encrypted at rest) holding the sudo password a
/// provisioning run sends, so a resumed run sends the same one.
pub(crate) fn sudo_secret_key(id: &ServerId) -> String {
    format!("provision-sudo/{id}")
}

impl Adapter {
    /// The server's sudo password, chosen once per provisioning run: the
    /// one saved by an earlier attempt, else the synced one, else a new
    /// one. It is saved (encrypted cache) **before** it is ever sent, then
    /// put into the Keychain and sync (idempotent), so a resumed run sends
    /// the same password the Keychain holds. Plaintext only in memory.
    fn sudo_password(&self, id: &ServerId) -> Result<Zeroizing<String>, String> {
        let key = sudo_secret_key(id);
        let valid = |b: &[u8]| {
            std::str::from_utf8(b)
                .ok()
                .filter(|s| fleet_core::sudo::is_valid(s))
                .map(|s| Zeroizing::new(s.to_string()))
        };
        let saved = lock(&self.core.cache)
            .secret_setting(&key)
            .map_err(|e| e.to_string())?
            .and_then(|b| valid(&b));
        let pw = match saved {
            Some(pw) => pw,
            None => {
                let synced = lock(&self.core.fleet.sync)
                    .as_ref()
                    .and_then(|e| e.get(Collection::SudoPasswords, id.as_str()).ok().flatten())
                    .map(|r| Zeroizing::new(r.body));
                let pw = match synced.and_then(|b| valid(&b)) {
                    Some(pw) => pw,
                    None => fleet_core::sudo::generate().map_err(|_| "rng")?,
                };
                lock(&self.core.cache)
                    .set_secret_setting(&key, pw.as_bytes())
                    .map_err(|e| format!("can't save the sudo password: {e}"))?;
                pw
            }
        };
        self.core
            .put_sudo_password(id, &pw)
            .map_err(|e| format!("can't store the sudo password: {e}"))?;
        Ok(pw)
    }
}

impl ProvisionBackend for Adapter {
    fn request(
        &self,
        server: &ServerId,
        op: Op,
        opts: RequestOpts,
    ) -> BoxFut<Result<Payload, Failure>> {
        self.handle
            .execute_with(server.clone(), op, Actor::Human, opts)
    }

    fn approve(&self, what: String, item: ApprovalItem) -> BoxFut<Result<RootApproval, String>> {
        let approver = self.core.root_approver();
        Box::pin(async move {
            let a = approver.map_err(|e| e.to_string())?;
            let mut list = tokio::task::spawn_blocking(move || a.approve(&what, &[item]))
                .await
                .map_err(|_| "approval task failed".to_string())?
                .map_err(|e| approve_err(e).to_string())?;
            list.pop().ok_or_else(|| "no approval".to_string())
        })
    }

    fn roster_chain(&self) -> Result<Vec<SignedRoster>, String> {
        fleet_core::roster_mgmt::chain(&lock(&self.core.cache)).map_err(|e| e.to_string())
    }

    fn sudo_password_hash(&self, server: &ServerId) -> Result<SudoPasswordHash, String> {
        let pw = self.sudo_password(server)?;
        pv::sudo_password_hash(&pw).map_err(|e| e.to_string())
    }

    fn verify_admin_login(&self, server: &ServerId, admin: &str) -> BoxFut<Result<(), String>> {
        let core = self.core.clone();
        let handle = self.handle.clone();
        let server = server.clone();
        let admin = admin.to_string();
        Box::pin(async move {
            let rec = core.server_record(&server).map_err(|e| e.to_string())?;
            let pin = lock(&core.cache)
                .pins(&server)
                .map_err(|e| e.to_string())?
                .and_then(|p| p.host_key)
                .ok_or("host key not pinned")?;
            let mut target = rec.target.clone();
            target.user = admin.clone();
            let login = async {
                let signer =
                    RoleSigner::new(&*core.keys, KeyRole::Ssh).map_err(|e| format!("{e:?}"))?;
                let ssh = P256SshSigner(signer);
                let (conn, obs) =
                    SshConnection::connect_with(&target, &ssh, Some(pin), &SshOptions::default())
                        .await
                        .map_err(|e| e.to_string())?;
                conn.disconnect().await;
                if obs.all_matched() {
                    Ok(())
                } else {
                    Err("host key not confirmed".to_string())
                }
            };
            match login.await {
                Ok(()) => Ok(()),
                // Before the SSH phase sshd reads ~/.ssh/authorized_keys
                // only: an admin created by the profile can't log in yet.
                // Its roster keys must be in place for the phase to work.
                Err(e) if admin != rec.target.user => {
                    let user = fleet_proto::args::UserName::new(admin.clone())
                        .map_err(|_| "admin user".to_string())?;
                    let reply = handle
                        .request_with(
                            &server,
                            Op::AuthorizedKeysGet { user },
                            Actor::Human,
                            RequestOpts::default(),
                        )
                        .await
                        .map_err(|r| r.to_string())?;
                    match reply.result {
                        Ok(Payload::AuthorizedKeys(k)) if !k.roster_section.is_empty() => Ok(()),
                        _ => Err(format!(
                            "{e}; and {admin} has no Fleet keys in /etc/fleet/authorized_keys"
                        )),
                    }
                }
                Err(e) => Err(e),
            }
        })
    }

    fn set_ssh_user(&self, server: &ServerId, user: &str) -> Result<(), String> {
        {
            let mut cache = lock(&self.core.cache);
            let mut rec = cache
                .server(server)
                .map_err(|e| e.to_string())?
                .ok_or("unknown server")?;
            if rec.target.user == user {
                return Ok(());
            }
            rec.target.user = user.to_string();
            cache.upsert_server(&rec).map_err(|e| e.to_string())?;
        }
        self.core.connect_pinned(server).map_err(|e| e.to_string())
    }

    fn confirm_change(
        &self,
        server: &ServerId,
        change: ChangeId,
        deadline_ms: u64,
    ) -> BoxFut<Result<(), ConfirmFailure>> {
        let h = self.handle.clone();
        let server = server.clone();
        Box::pin(async move {
            let res = match autorevert::confirm_window(
                deadline_ms,
                h.clock_skew_ms(&server),
                fleet_core::now_ms(),
                autorevert::CONFIRM_TIMEOUT,
            ) {
                Ok(window) => {
                    autorevert::confirm_fresh(&h, &server, change, Actor::Human, window).await
                }
                Err(e) => Err(e),
            };
            res.map_err(|e| match e {
                autorevert::ConfirmError::Reverted => ConfirmFailure::Reverted,
                other => ConfirmFailure::Other(other.to_string()),
            })
        })
    }

    fn clock_skew_ms(&self, server: &ServerId) -> Option<i64> {
        self.handle.clock_skew_ms(server)
    }

    fn add_to_fleet(
        &self,
        server: &ServerId,
        name: &str,
        group: Option<&str>,
        tags: &[String],
    ) -> Result<(), String> {
        let mut cache = lock(&self.core.cache);
        let mut rec = cache
            .server(server)
            .map_err(|e| e.to_string())?
            .ok_or("unknown server")?;
        rec.name = name.to_string();
        rec.group = group
            .filter(|g| cache.groups().is_ok_and(|gs| gs.iter().any(|x| x.id == *g)))
            .map(str::to_string);
        rec.tags = tags.to_vec();
        cache.upsert_server(&rec).map_err(|e| e.to_string())?;
        if let Some(st) = load_state(&cache, server).map_err(|e| e.to_string())? {
            let raw = serde_json::to_vec(&st.choice).map_err(|e| e.to_string())?;
            cache
                .set_setting(&profile_key(server), &raw)
                .map_err(|e| e.to_string())?;
        }
        // The run is over: the Keychain and sync hold the password now.
        cache
            .set_setting(&sudo_secret_key(server), &[])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn save(&self, state: &ProvisionState) -> Result<(), String> {
        save_state(&lock(&self.core.cache), state).map_err(|e| e.to_string())
    }
}

// ---- exported ----

#[uniffi::export]
impl FleetCore {
    /// Starts (or restarts before any change) provisioning of an installed
    /// server (agent keys pinned) with the wizard's choice.
    pub fn provision_begin(
        &self,
        server_id: String,
        choice: ProvisionChoiceRow,
    ) -> Result<ProvisionStateRow, FleetError> {
        let id = validate::server_id(&server_id)?;
        let ch = to_choice(choice)?;
        let cache = lock(&self.cache);
        let rec = cache.server(&id)?.ok_or(FleetError::UnknownServer)?;
        let pinned = cache
            .pins(&id)?
            .is_some_and(|p| p.agent_noise.is_some() && p.agent_signing.is_some());
        if !pinned {
            return Err(perr("install the agent first"));
        }
        if let Some(old) = load_state(&cache, &id)?
            && !matches!(
                old.step,
                Step::PushRoster | Step::AuditBefore | Step::Plan | Step::Review | Step::Done
            )
        {
            return Err(perr(
                "provisioning is already applying changes on this server; resume it",
            ));
        }
        let st = ProvisionState::new(&id, ch, &rec.target.user);
        save_state(&cache, &st)?;
        Ok(state_row(&st, None))
    }

    /// The saved wizard state, if provisioning was started.
    pub fn provision_state(
        &self,
        server_id: String,
    ) -> Result<Option<ProvisionStateRow>, FleetError> {
        let id = validate::server_id(&server_id)?;
        let skew = self.clock_skew(&id);
        Ok(load_state(&lock(&self.cache), &id)?
            .as_ref()
            .map(|st| state_row(st, skew)))
    }

    /// Servers with provisioning started but not finished.
    pub fn provision_in_progress(&self) -> Result<Vec<ProvisionStateRow>, FleetError> {
        let cache = lock(&self.cache);
        let mut out = Vec::new();
        for s in cache.servers()? {
            if let Some(st) = load_state(&cache, &s.id)?
                && st.step != Step::Done
            {
                out.push(state_row(&st, self.clock_skew(&s.id)));
            }
        }
        Ok(out)
    }

    /// The operator reviewed the plan with this hash: apply may start.
    pub fn provision_approve_plan(
        &self,
        server_id: String,
        plan_hash: String,
    ) -> Result<ProvisionStateRow, FleetError> {
        let id = validate::server_id(&server_id)?;
        let hash = hash_from_hex(&plan_hash)?;
        let cache = lock(&self.cache);
        let mut st = load_state(&cache, &id)?.ok_or_else(|| perr("not started"))?;
        st.approve_plan(&hash).map_err(perr)?;
        save_state(&cache, &st)?;
        Ok(state_row(&st, None))
    }

    /// Forgets the wizard state (changes already applied stay).
    pub fn provision_cancel(&self, server_id: String) -> Result<(), FleetError> {
        let id = validate::server_id(&server_id)?;
        lock(&self.cache).set_setting(&state_key(&id), &[])?;
        Ok(())
    }

    /// Runs steps until the plan review, the end, or a failure (the state
    /// keeps the failed step and `last_error`; call again to resume).
    pub async fn provision_advance(
        self: Arc<Self>,
        server_id: String,
        listener: Box<dyn ProvisionListener>,
    ) -> Result<ProvisionStateRow, FleetError> {
        let id = validate::server_id(&server_id)?;
        let mut st = load_state(&lock(&self.cache), &id)?.ok_or_else(|| perr("not started"))?;
        let (handle, _) = self.running()?;
        let core = self.clone();
        let listener: Arc<dyn ProvisionListener> = Arc::from(listener);
        self.on_core(async move {
            let skew = handle.clock_skew_ms(&id);
            let backend = Adapter { core, handle };
            let l = listener.clone();
            let r = pv::advance(&backend, &mut st, &ProvisionConfig::default(), move |e| {
                l.on_event(event_row(e))
            })
            .await;
            match r {
                Ok(_) => Ok(state_row(&st, skew)),
                Err(e) => Err(perr(e)),
            }
        })
        .await
    }

    // ---- hardening audit (Security tab) ----

    /// `audit.run` at `level` (the level the server was provisioned with
    /// when omitted, else Baseline).
    pub async fn audit_run(
        &self,
        server_id: String,
        level: Option<ProfileLevelRow>,
    ) -> Result<AuditReportRow, FleetError> {
        let id = validate::server_id(&server_id)?;
        let lvl = level.map(self::level).unwrap_or_else(|| {
            provisioned_profile(&lock(&self.cache), &id).map_or(Level::Baseline, |c| c.level)
        });
        let proto = match lvl {
            Level::Baseline => ProfileLevel::Baseline,
            Level::Strict => ProfileLevel::Strict,
        };
        match self
            .request(&server_id, Op::AuditRun { level: proto })
            .await?
        {
            Payload::AuditReport(r) => Ok(AuditReportRow {
                score: r.score,
                level: level_row(lvl),
                findings: r
                    .findings
                    .into_iter()
                    .map(|f| AuditFindingRow {
                        module: crate::text::line(f.module),
                        status: match f.status {
                            ModuleStatus::Compliant => "compliant",
                            ModuleStatus::Drifted => "drifted",
                            ModuleStatus::NotApplicable => "not_applicable",
                            ModuleStatus::Skipped => "skipped",
                            ModuleStatus::Error => "error",
                            ModuleStatus::PendingReboot => "pending_reboot",
                        }
                        .into(),
                        severity: format!("{:?}", f.severity).to_lowercase(),
                        title: crate::text::line(f.title),
                        fixable: f.fixable,
                    })
                    .collect(),
            }),
            _ => Err(FleetError::UnexpectedReply),
        }
    }

    /// Plans the one-click fix of `module` (`profile.plan` with
    /// `only = [module]`, the server's provisioned level and roles).
    pub async fn audit_fix_plan(
        &self,
        server_id: String,
        module: String,
    ) -> Result<AuditFixPlanRow, FleetError> {
        let id = validate::server_id(&server_id)?;
        let spec = self.fix_spec(&id, &module)?;
        match self.request(&server_id, Op::ProfilePlan(spec)).await? {
            Payload::ProfilePlan(ProfilePlan { plan_hash, changes }) => Ok(AuditFixPlanRow {
                auto_revert: ProfilePhase::is_access_module(&module),
                module,
                plan_hash: hex::encode(plan_hash),
                changes: changes
                    .iter()
                    .map(|c| change_row(&c.module, &c.description, &c.diff, c.auto_revert))
                    .collect(),
            }),
            _ => Err(FleetError::UnexpectedReply),
        }
    }

    /// Applies a reviewed fix (`profile.apply` phase All, `only = [module]`);
    /// an SSH/firewall fix is confirmed from a fresh connection.
    pub async fn audit_fix_apply(
        self: Arc<Self>,
        server_id: String,
        module: String,
        plan_hash: String,
    ) -> Result<AuditFixResultRow, FleetError> {
        let id = validate::server_id(&server_id)?;
        let spec = self.fix_spec(&id, &module)?;
        let op = Op::ProfileApply {
            spec,
            plan_hash: hash_from_hex(&plan_hash)?,
            phase: ProfilePhase::All,
            password_hash: None,
        };
        let p = self.request_opts(&server_id, op, None).await?;
        let pending = match &p {
            Payload::ChangePending { change, .. } => Some(change.clone()),
            _ => None,
        };
        let Payload::ProfileApplied(a) = p.result().clone() else {
            return Err(FleetError::UnexpectedReply);
        };
        let mut confirmed = false;
        if let Some(change) = pending {
            let (h, _) = self.running()?;
            let sid = id.clone();
            self.on_core(async move {
                autorevert::confirm_pending(&h, &sid, &change, Actor::Human)
                    .await
                    .map_err(perr)
            })
            .await?;
            confirmed = true;
        }
        Ok(AuditFixResultRow {
            modules: a
                .modules
                .into_iter()
                .map(|m| ModuleResultRow {
                    step: ProvisionStepRow::Done,
                    module: crate::text::line(m.id),
                    outcome: format!("{:?}", m.outcome),
                    detail: crate::text::line(m.detail),
                })
                .collect(),
            score_before: a.score_before,
            score_after: a.score_after,
            confirmed,
        })
    }

    // ---- cloud-init (design §9.7) ----

    /// A cloud-config creating `admin_user` with every enrolled Mac's SSH
    /// key and a new Ed25519 host key generated here; the host key's pin
    /// is kept under `export_id` for the server created from the file.
    pub fn export_cloud_init(
        &self,
        admin_user: String,
        hostname: Option<String>,
    ) -> Result<CloudInitExportRow, FleetError> {
        let admin = validate::user(&admin_user)?;
        let hostname = hostname.filter(|h| !h.trim().is_empty());
        let cache = lock(&self.cache);
        let roster = fleet_core::roster_mgmt::latest(&cache)?;
        let ex =
            fleet_core::cloudinit_export::export(&admin, &roster.roster, hostname).map_err(perr)?;
        let export_id = validate::random_id("ci_")?;
        cache.set_setting(&format!("cloudinit/{export_id}"), ex.host_key.blob())?;
        Ok(CloudInitExportRow {
            yaml: ex.yaml.to_string(),
            export_id,
            fingerprint: ex.host_key.fingerprint(),
        })
    }

    /// Pins the host key of cloud-init export `export_id` for a server
    /// created from it, so its first connection trusts nothing on first use.
    pub fn pin_cloud_init_host_key(
        &self,
        server_id: String,
        export_id: String,
    ) -> Result<(), FleetError> {
        let id = validate::server_id(&server_id)?;
        if !export_id.starts_with("ci_") || export_id.len() > 64 {
            return Err(FleetError::InvalidArgument {
                field: "export_id".into(),
            });
        }
        let cache = lock(&self.cache);
        cache.server(&id)?.ok_or(FleetError::UnknownServer)?;
        if cache.pins(&id)?.and_then(|p| p.host_key).is_some() {
            return Err(FleetError::HostKeyAlreadyPinned);
        }
        let blob = cache
            .setting(&format!("cloudinit/{export_id}"))?
            .filter(|b| !b.is_empty())
            .ok_or(FleetError::InvalidArgument {
                field: "export_id".into(),
            })?;
        let key = fleet_core::ssh::HostKey::from_blob(&blob)?;
        cache.pin_host_key(&id, &key)?;
        // Single use: one exported host key, one server.
        cache.set_setting(&format!("cloudinit/{export_id}"), &[])?;
        Ok(())
    }
}

impl FleetCore {
    /// Agent clock minus ours on `id`'s current link, if connected.
    fn clock_skew(&self, id: &ServerId) -> Option<i64> {
        self.running().ok().and_then(|(h, _)| h.clock_skew_ms(id))
    }

    /// The fix spec: the profile the server was provisioned with (so role
    /// exceptions, source ranges and the reboot window stay), plain
    /// Baseline otherwise; `only = [module]`.
    fn fix_spec(&self, id: &ServerId, module: &str) -> Result<ProfileSpec, FleetError> {
        let m = ModuleId::new(module.to_string()).map_err(|_| FleetError::InvalidArgument {
            field: "module".into(),
        })?;
        let mut spec = match provisioned_profile(&lock(&self.cache), id) {
            Some(c) => c.spec(id).map_err(perr)?,
            None => ProfileSpec {
                source: ProfileSource::Builtin {
                    level: ProfileLevel::Baseline,
                    roles: Vec::new(),
                },
                only: Vec::new(),
            },
        };
        spec.only = vec![m];
        Ok(spec)
    }
}
