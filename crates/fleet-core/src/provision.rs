//! Provisioning orchestration (design §9.1): what the wizard runs after
//! the agent is installed (`install`: provider SSH access with this Mac's
//! key, host key pinned on first use or injected by the Fleet cloud-init
//! file, agent keys pinned).
//!
//! ```text
//! PushRoster → AuditBefore → Plan → Review (operator) → Accounts →
//! VerifyAdmin → Access (auto-revert) → ConfirmAccess (fresh connection) →
//! System → AuditAfter → AddToFleet → Done
//! ```
//!
//! - **Roster**: the chain links newer than the genesis the agent was
//!   installed with (`roster.update`, in order). The default policy went
//!   in at install.
//! - **Plan**: `profile.plan` of the whole spec; the operator reviews the
//!   diff and approves its `plan_hash`. Before each phase the Mac plans
//!   again (the hash changes as phases apply) and refuses to go on if the
//!   fresh plan touches a module the reviewed plan didn't
//!   ([`ProvisionError::PlanChanged`]: back to Review).
//! - **Accounts**: admin user, shell files, sudo. The per-server sudo
//!   password is generated on the Mac (Keychain + sync, `sudo`), hashed
//!   here with SHA-512 crypt ([`sudo_password_hash`]) and sent as
//!   `password_hash`; the plaintext never leaves the Mac.
//! - **VerifyAdmin**: an SSH login as the admin over a new connection.
//!   Before the Access phase sshd still reads `~/.ssh/authorized_keys`,
//!   so the admin can log in only when it is the provider user or was
//!   created by the Fleet cloud-init file; otherwise the backend checks
//!   through the agent that the admin's roster keys are in place and the
//!   login itself is proven by the confirm below (under auto-revert).
//! - **Access**: sshd hardening and the firewall, under auto-revert
//!   (`ChangePending`). The manager then connects **as the admin** over a
//!   fresh connection and sends `change.confirm` there (`confirm`). If
//!   that fails, the connection goes back to the provider user and the
//!   change reverts on its own; a change already reverted when the
//!   confirm arrives (`NotFound`) sends the flow back to Access. A resumed
//!   Access phase with nothing left to apply first asks `changes.list`: a
//!   profile change still pending goes to ConfirmAccess instead of being
//!   skipped (and reverting silently). AuditAfter checks the access
//!   modules are compliant, else back to Access.
//! - **System**: every other module and the roles; long-running
//!   (`profile_apply_timeout`). `Busy` (dpkg lock held by
//!   `unattended-upgrades`) is retried with a delay.
//! - **Audit**: `audit.run` of the chosen level before and after.
//! - **AddToFleet**: name, group and tags.
//!
//! Every step saves the state ([`ProvisionBackend::save`]) and is safe to
//! run again, so a failed or interrupted run resumes at the step that
//! failed. A custom profile (source ranges, reboot window) is operator
//! TOML, so each `profile.apply` phase is Elevated: one root approval
//! (Touch ID) per phase, since the plan hash changes between phases.

use crate::bulk::{BoxFut, Failure};
use crate::manager::RequestOpts;
use fleet_crypto::approval::op_digest;
use fleet_proto::args::{ProfileToml, SudoPasswordHash, UserName};
use fleet_proto::op::{ProfileLevel, ProfilePhase, ProfileRole, ProfileSource, ProfileSpec};
use fleet_proto::payload::{
    AuditReport, ChangeKind, ModuleResult, ModuleStatus, PlannedChange, ProfileApplied, ProfilePlan,
};
use fleet_proto::{
    ApprovalItem, ChangeId, ErrorCode, Hash32, Op, Payload, RootApproval, ServerId, SignedRoster,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::Duration;

/// Phase 1 modules (`fleet-hardening` phase table).
pub const ACCOUNTS_MODULES: [&str; 3] = ["admin.user", "admin.shell", "sudo.policy"];

// ---- sudo password hash ----

/// SHA-512 crypt (`$6$rounds=5000$<16 salt chars>$…`) of `password` with a
/// random 12-byte salt. glibc's `crypt(3)` and `chpasswd --encrypted`
/// accept it; yescrypt (`$y$`, Debian's default) has no mature pure-Rust
/// implementation.
pub fn sudo_password_hash(password: &str) -> Result<SudoPasswordHash, ProvisionError> {
    use sha_crypt::{PasswordHasher, ShaCrypt};
    let mut salt = [0u8; 12];
    fleet_crypto::random_bytes(&mut salt).map_err(|_| ProvisionError::Backend("rng".into()))?;
    let h = ShaCrypt::SHA512
        .hash_password_with_salt(password.as_bytes(), &salt)
        .map_err(|_| ProvisionError::Backend("sha-crypt".into()))?;
    SudoPasswordHash::crypt(h.to_string())
        .map_err(|_| ProvisionError::Backend("sha-crypt output".into()))
}

// ---- what the operator chose ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Level {
    Baseline,
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Role {
    Docker,
    Web,
    Game,
}

impl Role {
    fn proto(self) -> ProfileRole {
        match self {
            Role::Docker => ProfileRole::Docker,
            Role::Web => ProfileRole::Web,
            Role::Game => ProfileRole::Game,
        }
    }

    fn toml_name(self) -> &'static str {
        match self {
            Role::Docker => "docker",
            Role::Web => "web",
            Role::Game => "game",
        }
    }
}

/// The wizard's form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisionChoice {
    pub level: Level,
    pub roles: Vec<Role>,
    /// The admin the agent was installed with (`--admin-user`).
    pub admin_user: String,
    /// SSH source ranges (CIDR); empty means anywhere (rate-limited).
    pub allow_from: Vec<String>,
    /// e.g. `Sun 04:00-05:00 UTC`; `None`: no automatic reboots.
    pub reboot_window: Option<String>,
    pub name: String,
    pub group: Option<String>,
    pub tags: Vec<String>,
}

fn valid_cidr(s: &str) -> bool {
    let (ip, bits) = s.split_once('/').unwrap_or((s, ""));
    match ip.parse::<std::net::IpAddr>() {
        Ok(a) => {
            let max = if a.is_ipv4() { 32 } else { 128 };
            bits.is_empty() || bits.parse::<u8>().is_ok_and(|b| b <= max)
        }
        Err(_) => false,
    }
}

impl ProvisionChoice {
    pub fn validate(&self) -> Result<(), ProvisionError> {
        let bad = |w: &str| ProvisionError::InvalidChoice(w.into());
        let admin = UserName::new(self.admin_user.clone()).map_err(|_| bad("admin user"))?;
        if admin.is_root() || admin.is_fleet() {
            return Err(bad("admin user can't be root or a fleet account"));
        }
        if self.allow_from.len() > 64 || !self.allow_from.iter().all(|c| valid_cidr(c)) {
            return Err(bad("SSH source ranges (CIDR)"));
        }
        if let Some(w) = &self.reboot_window
            && !(w.len() <= 40
                && w.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b" :-".contains(&b)))
        {
            return Err(bad("reboot window"));
        }
        let mut r = self.roles.clone();
        r.sort();
        r.dedup();
        if r.len() != self.roles.len() {
            return Err(bad("roles"));
        }
        if self.name.trim().is_empty() || self.name.len() > 128 {
            return Err(bad("name"));
        }
        Ok(())
    }

    /// Source ranges or a reboot window need operator TOML (Elevated).
    pub fn is_custom(&self) -> bool {
        !self.allow_from.is_empty() || self.reboot_window.is_some()
    }

    /// The operator TOML (design §9.2), serialized (never string-built).
    pub fn custom_toml(&self, server: &ServerId) -> Result<String, ProvisionError> {
        use toml::{Table, Value};
        let arr = |v: Vec<String>| Value::Array(v.into_iter().map(Value::String).collect());
        let mut profile = Table::new();
        profile.insert("name".into(), Value::String(format!("provision-{server}")));
        profile.insert(
            "extends".into(),
            Value::String(match self.level {
                Level::Baseline => "baseline".into(),
                Level::Strict => "strict".into(),
            }),
        );
        profile.insert(
            "roles".into(),
            arr(self
                .roles
                .iter()
                .map(|r| r.toml_name().to_string())
                .collect()),
        );
        let mut admin = Table::new();
        admin.insert("user".into(), Value::String(self.admin_user.clone()));
        let mut doc = Table::new();
        doc.insert("profile".into(), Value::Table(profile));
        doc.insert("admin".into(), Value::Table(admin));
        if !self.allow_from.is_empty() {
            let mut ssh = Table::new();
            ssh.insert("allow_from".into(), arr(self.allow_from.clone()));
            doc.insert("ssh".into(), Value::Table(ssh));
        }
        if let Some(w) = &self.reboot_window {
            let mut up = Table::new();
            up.insert("reboot_window".into(), Value::String(w.clone()));
            doc.insert("updates".into(), Value::Table(up));
        }
        toml::to_string(&doc).map_err(|e| ProvisionError::InvalidChoice(e.to_string()))
    }

    pub fn spec(&self, server: &ServerId) -> Result<ProfileSpec, ProvisionError> {
        self.validate()?;
        let source = if self.is_custom() {
            ProfileSource::Custom(
                ProfileToml::new(self.custom_toml(server)?)
                    .map_err(|_| ProvisionError::InvalidChoice("profile toml".into()))?,
            )
        } else {
            ProfileSource::Builtin {
                level: self.level_proto(),
                roles: self.roles.iter().map(|r| r.proto()).collect(),
            }
        };
        Ok(ProfileSpec {
            source,
            only: Vec::new(),
        })
    }

    pub fn level_proto(&self) -> ProfileLevel {
        match self.level {
            Level::Baseline => ProfileLevel::Baseline,
            Level::Strict => ProfileLevel::Strict,
        }
    }
}

// ---- state ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Step {
    PushRoster,
    AuditBefore,
    Plan,
    /// Waiting for the operator to approve the plan.
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

impl Step {
    pub fn label(self) -> &'static str {
        match self {
            Step::PushRoster => "Pushing the roster",
            Step::AuditBefore => "Auditing the current state",
            Step::Plan => "Planning",
            Step::Review => "Waiting for plan review",
            Step::Accounts => "Phase 1: admin user, keys and sudo",
            Step::VerifyAdmin => "Verifying the admin login",
            Step::Access => "Phase 2: SSH and firewall (auto-revert armed)",
            Step::ConfirmAccess => "Confirming from a fresh connection",
            Step::System => "Phase 3: system hardening and roles",
            Step::AuditAfter => "Auditing the result",
            Step::AddToFleet => "Adding to the fleet",
            Step::Done => "Done",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanChange {
    pub module: String,
    pub description: String,
    pub diff: String,
    pub auto_revert: bool,
}

impl From<&PlannedChange> for PlanChange {
    fn from(c: &PlannedChange) -> Self {
        Self {
            module: c.module.clone(),
            description: c.description.clone(),
            diff: c.diff.clone(),
            auto_revert: c.auto_revert,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleRecord {
    pub step: Step,
    pub id: String,
    pub outcome: String,
    pub detail: String,
}

/// Everything needed to resume; the app keeps it in the cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisionState {
    pub server_id: String,
    pub choice: ProvisionChoice,
    /// The SSH user the agent was installed over (provider access).
    pub install_user: String,
    pub step: Step,
    /// The plan under review (or last reviewed).
    pub plan_hash: Option<Hash32>,
    pub plan: Vec<PlanChange>,
    /// Modules of the approved plan; later re-plans must stay inside.
    pub approved_modules: Vec<String>,
    pub pending_change: Option<ChangeId>,
    pub pending_deadline_ms: Option<u64>,
    pub score_before: Option<u8>,
    pub score_after: Option<u8>,
    /// Profile score after each phase (`ProfileApplied::score_after`).
    pub profile_score: Option<u8>,
    pub modules: Vec<ModuleRecord>,
    pub last_error: Option<String>,
    pub updated_ms: u64,
}

impl ProvisionState {
    pub fn new(server: &ServerId, choice: ProvisionChoice, install_user: &str) -> Self {
        Self {
            server_id: server.to_string(),
            choice,
            install_user: install_user.to_string(),
            step: Step::PushRoster,
            plan_hash: None,
            plan: Vec::new(),
            approved_modules: Vec::new(),
            pending_change: None,
            pending_deadline_ms: None,
            score_before: None,
            score_after: None,
            profile_score: None,
            modules: Vec::new(),
            last_error: None,
            updated_ms: crate::now_ms(),
        }
    }

    pub fn server(&self) -> Result<ServerId, ProvisionError> {
        ServerId::new(self.server_id.clone())
            .map_err(|_| ProvisionError::InvalidChoice("server id".into()))
    }

    /// The operator approved the plan they saw (`plan_hash`).
    pub fn approve_plan(&mut self, plan_hash: &Hash32) -> Result<(), ProvisionError> {
        if self.step != Step::Review || self.plan_hash.as_ref() != Some(plan_hash) {
            return Err(ProvisionError::PlanChanged);
        }
        self.approved_modules = modules_of(&self.plan);
        self.step = Step::Accounts;
        Ok(())
    }
}

fn modules_of(plan: &[PlanChange]) -> Vec<String> {
    let set: BTreeSet<String> = plan.iter().map(|c| c.module.clone()).collect();
    set.into_iter().collect()
}

// ---- errors, events, backend ----

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProvisionError {
    #[error("invalid choice: {0}")]
    InvalidChoice(String),
    #[error("{op} failed: {why}")]
    Request { op: &'static str, why: String },
    #[error("the plan changed since it was reviewed; review it again")]
    PlanChanged,
    #[error("the admin login didn't work: {0}")]
    AdminLogin(String),
    #[error(
        "the SSH/firewall change could not be confirmed from a new connection ({0}); it reverts automatically"
    )]
    Confirm(String),
    #[error("the SSH/firewall change reverted before it was confirmed; apply it again")]
    Reverted,
    #[error("root approval not given: {0}")]
    Approval(String),
    #[error("roster push refused at version {version}: {code:?}")]
    Roster { version: u64, code: ErrorCode },
    #[error("{0}")]
    Backend(String),
    #[error("the operator hasn't approved the plan yet")]
    NeedsReview,
    #[error("SSH/firewall settings are not in place after provisioning ({0}); apply them again")]
    AccessNotCompliant(String),
}

fn describe_failure(f: &Failure) -> String {
    match f {
        Failure::Agent(ErrorCode::Busy) => "the server is busy (package manager running)".into(),
        Failure::Agent(ErrorCode::VersionConflict { .. }) => {
            "the plan changed on the server (re-plan)".into()
        }
        Failure::Agent(code) => format!("the agent refused: {code:?}"),
        Failure::UnknownServer => "unknown server".into(),
        Failure::NotReady(s) => format!("not connected ({s})"),
        Failure::Locked => "the app is locked".into(),
        Failure::Timeout => "timed out".into(),
        Failure::OutcomeUnknown => "no answer (it may or may not have run)".into(),
        Failure::Transport(t) => t.clone(),
        other => format!("{other:?}"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisionEvent {
    Step(Step),
    /// Waiting for the dpkg lock (`Busy`), retry `attempt`.
    Waiting {
        attempt: u32,
    },
    /// Auto-revert armed: confirm before this time.
    RevertArmed {
        deadline_ms: u64,
    },
    Modules {
        step: Step,
        modules: Vec<ModuleResult>,
    },
}

/// What the orchestration needs from the app; fakes in tests.
pub trait ProvisionBackend: Send + Sync {
    /// Signs and sends `op` (device key) as the human operator.
    fn request(
        &self,
        server: &ServerId,
        op: Op,
        opts: RequestOpts,
    ) -> BoxFut<Result<Payload, Failure>>;
    /// One root approval (Touch ID naming `what`).
    fn approve(&self, what: String, item: ApprovalItem) -> BoxFut<Result<RootApproval, String>>;
    /// The verified local roster chain (genesis first).
    fn roster_chain(&self) -> Result<Vec<SignedRoster>, String>;
    /// The server's sudo password (created if missing, Keychain + sync),
    /// hashed ([`sudo_password_hash`]).
    fn sudo_password_hash(&self, server: &ServerId) -> Result<SudoPasswordHash, String>;
    /// Proves the admin can log in (a new SSH connection as `admin`), or
    /// that its roster keys are in place where sshd can't read them yet.
    fn verify_admin_login(&self, server: &ServerId, admin: &str) -> BoxFut<Result<(), String>>;
    /// Future connections to `server` log in as `user`.
    fn set_ssh_user(&self, server: &ServerId, user: &str) -> Result<(), String>;
    /// `change.confirm` over a fresh connection, within the change's own
    /// deadline (`deadline_ms`, agent clock; `autorevert::confirm_window`).
    fn confirm_change(
        &self,
        server: &ServerId,
        change: ChangeId,
        deadline_ms: u64,
    ) -> BoxFut<Result<(), ConfirmFailure>>;
    /// Agent clock minus ours (advisory `Hello` time), for countdowns.
    fn clock_skew_ms(&self, _server: &ServerId) -> Option<i64> {
        None
    }
    fn add_to_fleet(
        &self,
        server: &ServerId,
        name: &str,
        group: Option<&str>,
        tags: &[String],
    ) -> Result<(), String>;
    fn save(&self, state: &ProvisionState) -> Result<(), String>;
}

/// Why a confirm failed: `Reverted` when the agent no longer holds the
/// change (it reverted already).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmFailure {
    Reverted,
    Other(String),
}

#[derive(Debug, Clone)]
pub struct ProvisionConfig {
    /// `Busy` retries (dpkg lock) and the delay between them.
    pub busy_retries: u32,
    pub busy_delay: Duration,
}

impl Default for ProvisionConfig {
    fn default() -> Self {
        Self {
            busy_retries: 20,
            busy_delay: Duration::from_secs(30),
        }
    }
}

// ---- the flow ----

/// Runs steps from `st.step` until Review (operator), Done or an error.
/// The state is saved after every step and on failure (`last_error`).
pub async fn advance<B, E>(
    b: &B,
    st: &mut ProvisionState,
    cfg: &ProvisionConfig,
    mut emit: E,
) -> Result<Step, ProvisionError>
where
    B: ProvisionBackend + ?Sized,
    E: FnMut(ProvisionEvent) + Send,
{
    let server = st.server()?;
    let spec = st.choice.spec(&server)?;
    loop {
        if matches!(st.step, Step::Review | Step::Done) {
            st.last_error = None;
            save(b, st)?;
            return Ok(st.step);
        }
        emit(ProvisionEvent::Step(st.step));
        match run_step(b, st, &server, &spec, cfg, &mut emit).await {
            Ok(next) => {
                st.step = next;
                st.last_error = None;
                save(b, st)?;
            }
            Err(e) => {
                st.last_error = Some(e.to_string());
                save(b, st)?;
                return Err(e);
            }
        }
    }
}

fn save<B: ProvisionBackend + ?Sized>(
    b: &B,
    st: &mut ProvisionState,
) -> Result<(), ProvisionError> {
    st.updated_ms = crate::now_ms();
    b.save(st).map_err(ProvisionError::Backend)
}

async fn call<B: ProvisionBackend + ?Sized>(
    b: &B,
    server: &ServerId,
    op: Op,
    opts: RequestOpts,
) -> Result<Payload, ProvisionError> {
    let name = op.name();
    b.request(server, op, opts)
        .await
        .map_err(|f| ProvisionError::Request {
            op: name,
            why: describe_failure(&f),
        })
}

async fn run_step<B, E>(
    b: &B,
    st: &mut ProvisionState,
    server: &ServerId,
    spec: &ProfileSpec,
    cfg: &ProvisionConfig,
    emit: &mut E,
) -> Result<Step, ProvisionError>
where
    B: ProvisionBackend + ?Sized,
    E: FnMut(ProvisionEvent) + Send,
{
    match st.step {
        Step::PushRoster => {
            push_roster(b, server).await?;
            Ok(Step::AuditBefore)
        }
        Step::AuditBefore => {
            st.score_before = Some(audit(b, server, st.choice.level_proto()).await?);
            Ok(Step::Plan)
        }
        Step::Plan => {
            let p = plan(b, server, spec).await?;
            st.plan_hash = Some(p.plan_hash);
            st.plan = p.changes.iter().map(PlanChange::from).collect();
            Ok(Step::Review)
        }
        Step::Review | Step::Done => Err(ProvisionError::NeedsReview),
        Step::Accounts => {
            let hash = b
                .sudo_password_hash(server)
                .map_err(ProvisionError::Backend)?;
            phase(
                b,
                st,
                server,
                spec,
                cfg,
                emit,
                ProfilePhase::Accounts,
                Some(hash),
            )
            .await?;
            Ok(Step::VerifyAdmin)
        }
        Step::VerifyAdmin => {
            b.verify_admin_login(server, &st.choice.admin_user)
                .await
                .map_err(ProvisionError::AdminLogin)?;
            Ok(Step::Access)
        }
        Step::Access => {
            let applied = phase(b, st, server, spec, cfg, emit, ProfilePhase::Access, None).await?;
            // Nothing left to apply may mean an earlier run applied it and
            // stopped before saving: an unconfirmed change would then
            // revert silently. Ask the agent before skipping.
            let pending = match applied {
                Some(p) => Some(p),
                None => pending_access_change(b, server).await?,
            };
            match pending {
                Some((change, deadline_ms)) => {
                    st.pending_change = Some(change);
                    st.pending_deadline_ms = Some(deadline_ms);
                    let local =
                        crate::autorevert::local_deadline(deadline_ms, b.clock_skew_ms(server));
                    emit(ProvisionEvent::RevertArmed { deadline_ms: local });
                    Ok(Step::ConfirmAccess)
                }
                None => Ok(Step::System),
            }
        }
        Step::ConfirmAccess => {
            let pending = match (st.pending_change, st.pending_deadline_ms) {
                (Some(c), Some(d)) => Some((c, d)),
                _ => pending_access_change(b, server).await?,
            };
            let Some((change, deadline_ms)) = pending else {
                return Ok(Step::System);
            };
            // Root login is off now: the fresh connection is the admin's.
            b.set_ssh_user(server, &st.choice.admin_user)
                .map_err(ProvisionError::Backend)?;
            match b.confirm_change(server, change, deadline_ms).await {
                Ok(()) => {
                    st.pending_change = None;
                    st.pending_deadline_ms = None;
                    Ok(Step::System)
                }
                Err(f) => {
                    // The change reverts (or has): back to the provider user.
                    let _ = b.set_ssh_user(server, &st.install_user);
                    st.pending_change = None;
                    st.pending_deadline_ms = None;
                    st.step = Step::Access;
                    Err(match f {
                        ConfirmFailure::Reverted => ProvisionError::Reverted,
                        ConfirmFailure::Other(m) => ProvisionError::Confirm(m),
                    })
                }
            }
        }
        Step::System => {
            phase(b, st, server, spec, cfg, emit, ProfilePhase::System, None).await?;
            Ok(Step::AuditAfter)
        }
        Step::AuditAfter => {
            let report = audit_report(b, server, st.choice.level_proto()).await?;
            st.score_after = Some(report.score);
            // The SSH/firewall phase must have stuck (not reverted behind
            // our back): otherwise apply it again.
            let drifted = access_not_compliant(&report);
            if !drifted.is_empty() {
                st.step = Step::Access;
                return Err(ProvisionError::AccessNotCompliant(drifted.join(", ")));
            }
            Ok(Step::AddToFleet)
        }
        Step::AddToFleet => {
            let c = &st.choice;
            b.add_to_fleet(server, &c.name, c.group.as_deref(), &c.tags)
                .map_err(ProvisionError::Backend)?;
            Ok(Step::Done)
        }
    }
}

async fn push_roster<B: ProvisionBackend + ?Sized>(
    b: &B,
    server: &ServerId,
) -> Result<(), ProvisionError> {
    let chain = b.roster_chain().map_err(ProvisionError::Backend)?;
    let (epoch, version) = match call(b, server, Op::AgentHealth, RequestOpts::default()).await? {
        Payload::AgentHealth(h) => (h.roster_epoch, h.roster_version),
        _ => {
            return Err(ProvisionError::Request {
                op: "agent.health",
                why: "unexpected reply".into(),
            });
        }
    };
    for link in crate::roster_mgmt::links_after(&chain, epoch, version) {
        let v = link.roster.version;
        let op = Op::RosterUpdate {
            roster: Box::new(link),
        };
        b.request(server, op, RequestOpts::default())
            .await
            .map_err(|f| match f {
                Failure::Agent(code) => ProvisionError::Roster { version: v, code },
                f => ProvisionError::Request {
                    op: "roster.update",
                    why: describe_failure(&f),
                },
            })?;
    }
    Ok(())
}

async fn audit<B: ProvisionBackend + ?Sized>(
    b: &B,
    server: &ServerId,
    level: ProfileLevel,
) -> Result<u8, ProvisionError> {
    Ok(audit_report(b, server, level).await?.score)
}

async fn audit_report<B: ProvisionBackend + ?Sized>(
    b: &B,
    server: &ServerId,
    level: ProfileLevel,
) -> Result<AuditReport, ProvisionError> {
    match call(b, server, Op::AuditRun { level }, RequestOpts::default()).await? {
        Payload::AuditReport(r) => Ok(r),
        _ => Err(ProvisionError::Request {
            op: "audit.run",
            why: "unexpected reply".into(),
        }),
    }
}

/// Access modules (sshd, firewall) the audit doesn't report as in place.
fn access_not_compliant(r: &AuditReport) -> Vec<String> {
    r.findings
        .iter()
        .filter(|f| ProfilePhase::is_access_module(&f.module))
        .filter(|f| {
            !matches!(
                f.status,
                ModuleStatus::Compliant
                    | ModuleStatus::NotApplicable
                    | ModuleStatus::Skipped
                    | ModuleStatus::PendingReboot
            )
        })
        .map(|f| f.module.clone())
        .collect()
}

/// A `profile.apply` change still waiting for its confirm on the agent
/// (`changes.list`), with its deadline.
async fn pending_access_change<B: ProvisionBackend + ?Sized>(
    b: &B,
    server: &ServerId,
) -> Result<Option<(ChangeId, u64)>, ProvisionError> {
    match call(b, server, Op::ChangesList, RequestOpts::default()).await? {
        Payload::PendingChanges(p) => Ok(p
            .changes
            .iter()
            .filter(|c| c.kind == ChangeKind::Profile)
            .max_by_key(|c| c.created_ms)
            .map(|c| (c.change_id, c.deadline_ms))),
        _ => Err(ProvisionError::Request {
            op: "changes.list",
            why: "unexpected reply".into(),
        }),
    }
}

async fn plan<B: ProvisionBackend + ?Sized>(
    b: &B,
    server: &ServerId,
    spec: &ProfileSpec,
) -> Result<ProfilePlan, ProvisionError> {
    match call(
        b,
        server,
        Op::ProfilePlan(spec.clone()),
        RequestOpts::default(),
    )
    .await?
    {
        Payload::ProfilePlan(p) => Ok(p),
        _ => Err(ProvisionError::Request {
            op: "profile.plan",
            why: "unexpected reply".into(),
        }),
    }
}

fn in_phase(module: &str, phase: ProfilePhase) -> bool {
    let accounts = ACCOUNTS_MODULES.contains(&module);
    let access = ProfilePhase::is_access_module(module);
    match phase {
        ProfilePhase::Accounts => accounts,
        ProfilePhase::Access => access,
        ProfilePhase::System => !accounts && !access,
        ProfilePhase::All => true,
    }
}

/// Re-plans, checks the plan against the reviewed one, applies `phase`
/// (retrying `Busy`), records module results. Returns the pending change
/// when the phase armed auto-revert.
#[allow(clippy::too_many_arguments)]
async fn phase<B, E>(
    b: &B,
    st: &mut ProvisionState,
    server: &ServerId,
    spec: &ProfileSpec,
    cfg: &ProvisionConfig,
    emit: &mut E,
    phase: ProfilePhase,
    password_hash: Option<SudoPasswordHash>,
) -> Result<Option<(ChangeId, u64)>, ProvisionError>
where
    B: ProvisionBackend + ?Sized,
    E: FnMut(ProvisionEvent) + Send,
{
    let mut attempt = 0u32;
    loop {
        let fresh = plan(b, server, spec).await?;
        if fresh
            .changes
            .iter()
            .any(|c| !st.approved_modules.contains(&c.module))
        {
            st.plan_hash = Some(fresh.plan_hash);
            st.plan = fresh.changes.iter().map(PlanChange::from).collect();
            st.step = Step::Review;
            return Err(ProvisionError::PlanChanged);
        }
        // Nothing of this phase left (resumed after it applied): skip it,
        // except Accounts, which also sets the sudo password.
        if phase != ProfilePhase::Accounts
            && !fresh.changes.iter().any(|c| in_phase(&c.module, phase))
        {
            return Ok(None);
        }
        let op = Op::ProfileApply {
            spec: spec.clone(),
            plan_hash: fresh.plan_hash,
            phase,
            password_hash: password_hash.clone(),
        };
        let mut opts = RequestOpts::default();
        if crate::opspec::needs_approval(&op) {
            let item = ApprovalItem {
                server_id: server.clone(),
                op_digest: op_digest(&op, None),
            };
            let what = format!("profile.apply ({phase:?}) on {server}");
            opts.approval = Some(
                b.approve(what, item)
                    .await
                    .map_err(ProvisionError::Approval)?,
            );
        }
        match b.request(server, op, opts).await {
            Err(Failure::Agent(ErrorCode::Busy)) if attempt < cfg.busy_retries => {
                attempt += 1;
                emit(ProvisionEvent::Waiting { attempt });
                tokio::time::sleep(cfg.busy_delay).await;
            }
            // The server changed between plan and apply: plan again.
            Err(Failure::Agent(ErrorCode::VersionConflict { .. }))
                if attempt < cfg.busy_retries =>
            {
                attempt += 1;
            }
            Err(f) => {
                return Err(ProvisionError::Request {
                    op: "profile.apply",
                    why: describe_failure(&f),
                });
            }
            Ok(p) => {
                let pending = match &p {
                    Payload::ChangePending { change, .. } => {
                        Some((change.change_id, change.deadline_ms))
                    }
                    _ => None,
                };
                if let Payload::ProfileApplied(a) = p.result() {
                    record(st, a, emit);
                }
                return Ok(pending);
            }
        }
    }
}

fn record<E: FnMut(ProvisionEvent) + Send>(
    st: &mut ProvisionState,
    a: &ProfileApplied,
    emit: &mut E,
) {
    let step = st.step;
    st.modules.retain(|m| m.step != step);
    for m in &a.modules {
        st.modules.push(ModuleRecord {
            step,
            id: m.id.clone(),
            outcome: format!("{:?}", m.outcome),
            detail: m.detail.clone(),
        });
    }
    st.profile_score = Some(a.score_after);
    emit(ProvisionEvent::Modules {
        step,
        modules: a.modules.clone(),
    });
}

#[cfg(test)]
#[path = "provision_tests.rs"]
mod tests;
