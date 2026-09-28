//! Agent releases on the Mac (design §5.7, §10.2): import a build, check it
//! against an independent reproducible build, root-sign its manifest once
//! for the fleet (Touch ID), keep it in the cache, and roll it out through
//! a canary sequence (1 server, then 10%, then the rest).
//!
//! **Import.** The artifact is the static binary or a `.deb` from
//! `scripts/build-deb.sh`, whose `data.tar` is stored uncompressed so the
//! binary (`./usr/lib/fleet/fleet-agent`) can be read out here without a
//! decompressor. The manifest signs the **binary's** BLAKE3, never the
//! package's. **Attestation:** the operator pastes the BLAKE3 of a second,
//! independent reproducible build (CI, another machine: `b3sum
//! fleet-agent`); the app refuses to sign unless it equals the hash of the
//! imported file, so a root-key signature always covers two builds that
//! agree (the imported one and the attested one).
//!
//! **Rollout** per server ([`update_one`]): SFTP upload as the admin user
//! to `/var/lib/fleet/incoming/<hex>`, `agent.update.stage` (self-signed by
//! the manifest), `agent.update.commit` (root approval, Merkle batch over
//! the phase), then over **fresh** connections: `agent.health` until it
//! reports the new version, and `change.confirm`. A server that doesn't
//! come back healthy in the window is left unconfirmed: its timer restores
//! the previous build. Phases stop at the first failure.

use crate::bulk::{
    Approver, BoxFut, BulkEvent, BulkOptions, BulkReport, BulkSummary, CancelToken, Failure,
    Outcome, Output, SkipReason, StopReason,
};
use crate::cache::{Cache, CacheError};
use crate::manager::{ManagerHandle, RequestOpts};
use crate::signer::{DeviceSigner, KeyRole, RoleSigner};
use fleet_crypto::approval::op_digest;
use fleet_proto::payload::PendingChange;
use fleet_proto::{
    Actor, AgentHealth, AgentTarget, AgentVersion, ApprovalItem, DeviceId, Op, Payload,
    ReleaseManifest, RootApproval, ServerId, SignedReleaseManifest, decode, encode,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Largest agent binary (the agent's own limit).
pub const MAX_BINARY: usize = 64 << 20;
/// Largest `.deb` read.
pub const MAX_PACKAGE: usize = 96 << 20;
/// Path of the binary inside the package's `data.tar`.
pub const DEB_BINARY: &str = "usr/lib/fleet/fleet-agent";
/// SFTP drop directory on the server (`0700 <admin>`).
pub const INCOMING_DIR: &str = "/var/lib/fleet/incoming";
/// Cache setting holding every imported release.
const SETTING: &str = "agent_releases";

#[derive(Debug, thiserror::Error)]
pub enum ReleaseImportError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("file is too large")]
    TooLarge,
    #[error("not a Debian package")]
    NotDeb,
    #[error(
        "package data is compressed; build it with scripts/build-deb.sh (uncompressed data.tar)"
    )]
    CompressedDeb,
    #[error("package has no {DEB_BINARY}")]
    NoBinaryInDeb,
    #[error("attested hash is not 64 hex digits")]
    BadAttestation,
    #[error("the independent build's hash differs from this build: refusing to sign")]
    AttestationMismatch,
    #[error("version must be major.minor.patch")]
    BadVersion,
    #[error("unknown target {0}")]
    BadTarget(String),
    #[error("signing failed: {0}")]
    Sign(String),
    #[error("cache: {0}")]
    Cache(#[from] CacheError),
    #[error("release not found")]
    NotFound,
    #[error("artifact changed since it was signed")]
    Changed,
}

/// One imported, signed release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseRecord {
    pub signed: SignedReleaseManifest,
    /// Where the artifact was imported from; re-read (and re-hashed) at
    /// rollout.
    pub artifact: String,
    /// The independent build's hash the operator attested (equal to
    /// `signed.manifest.blake3`).
    pub attested: [u8; 32],
    pub imported_ms: u64,
}

impl ReleaseRecord {
    /// `v1.2.3 (x86_64)`.
    pub fn label(&self) -> String {
        let m = &self.signed.manifest;
        format!("{} ({})", version_string(m.version), m.target.as_str())
    }
}

pub fn version_string(v: AgentVersion) -> String {
    format!("{}.{}.{}", v.major, v.minor, v.patch)
}

/// Strict `major.minor.patch`.
pub fn parse_version(s: &str) -> Result<AgentVersion, ReleaseImportError> {
    let p: Vec<&str> = s.trim().split('.').collect();
    let [a, b, c] = p.as_slice() else {
        return Err(ReleaseImportError::BadVersion);
    };
    let n = |x: &str| x.parse::<u16>().map_err(|_| ReleaseImportError::BadVersion);
    Ok(AgentVersion {
        major: n(a)?,
        minor: n(b)?,
        patch: n(c)?,
    })
}

fn field(h: &[u8], r: std::ops::Range<usize>) -> &str {
    std::str::from_utf8(&h[r])
        .unwrap_or("")
        .trim_matches(|c: char| c == '\0' || c == ' ')
}

/// `path` in an uncompressed (ustar/GNU) tar.
fn tar_find<'a>(tar: &'a [u8], path: &str) -> Option<&'a [u8]> {
    let want = path.trim_start_matches("./");
    let mut off = 0usize;
    while off + 512 <= tar.len() {
        let h = &tar[off..off + 512];
        if h.iter().all(|b| *b == 0) {
            return None;
        }
        let name = field(h, 0..100);
        let prefix = if &h[257..262] == b"ustar" {
            field(h, 345..500)
        } else {
            ""
        };
        let full = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        let size = usize::from_str_radix(field(h, 124..136), 8).ok()?;
        let data = off + 512;
        let end = data.checked_add(size)?;
        if full.trim_start_matches("./") == want && matches!(h[156], b'0' | 0) {
            return tar.get(data..end);
        }
        off = data + size.div_ceil(512) * 512;
    }
    None
}

/// The agent binary inside a `.deb` (ar archive; `data.tar` uncompressed).
pub fn deb_binary(deb: &[u8]) -> Result<Vec<u8>, ReleaseImportError> {
    if !deb.starts_with(b"!<arch>\n") {
        return Err(ReleaseImportError::NotDeb);
    }
    let mut off = 8usize;
    while off + 60 <= deb.len() {
        let h = &deb[off..off + 60];
        let name = field(h, 0..16).trim_end_matches('/');
        let size: usize = field(h, 48..58)
            .parse()
            .map_err(|_| ReleaseImportError::NotDeb)?;
        let data = off + 60;
        let body = deb
            .get(data..data + size)
            .ok_or(ReleaseImportError::NotDeb)?;
        if name == "data.tar" {
            return tar_find(body, DEB_BINARY)
                .map(<[u8]>::to_vec)
                .ok_or(ReleaseImportError::NoBinaryInDeb);
        }
        if name.starts_with("data.tar.") {
            return Err(ReleaseImportError::CompressedDeb);
        }
        off = data + size + (size & 1);
    }
    Err(ReleaseImportError::NoBinaryInDeb)
}

/// The agent binary of an artifact (the binary itself, or read out of a
/// `.deb`).
pub fn read_agent_binary(path: &Path) -> Result<Vec<u8>, ReleaseImportError> {
    let len = std::fs::metadata(path)?.len();
    if len > MAX_PACKAGE as u64 {
        return Err(ReleaseImportError::TooLarge);
    }
    let bytes = std::fs::read(path)?;
    let bin = match crate::install::ArtifactKind::of(path) {
        crate::install::ArtifactKind::Deb => deb_binary(&bytes)?,
        crate::install::ArtifactKind::Binary => bytes,
    };
    if bin.len() > MAX_BINARY {
        return Err(ReleaseImportError::TooLarge);
    }
    Ok(bin)
}

/// BLAKE3 (hex) of an artifact's agent binary, shown before signing.
pub fn artifact_hash(path: &Path) -> Result<String, ReleaseImportError> {
    Ok(hex::encode(fleet_crypto::blake3(&read_agent_binary(path)?)))
}

/// Parses the attested hash (hex, whitespace and a trailing file name as
/// printed by `b3sum` tolerated).
pub fn parse_attestation(s: &str) -> Result<[u8; 32], ReleaseImportError> {
    let first = s.split_whitespace().next().unwrap_or("");
    let v = hex::decode(first).map_err(|_| ReleaseImportError::BadAttestation)?;
    v.try_into().map_err(|_| ReleaseImportError::BadAttestation)
}

/// What the operator gives at import.
#[derive(Debug, Clone)]
pub struct ImportRequest {
    pub artifact: PathBuf,
    pub version: AgentVersion,
    pub target: AgentTarget,
    /// The independent reproducible build's BLAKE3 (hex).
    pub attested: String,
}

/// Every imported release, newest version first.
pub fn releases(cache: &Cache) -> Result<Vec<ReleaseRecord>, CacheError> {
    Ok(cache
        .setting(SETTING)?
        .and_then(|b| decode::<Vec<ReleaseRecord>>(&b).ok())
        .unwrap_or_default())
}

/// Stores (or replaces, per version and target) an imported release.
pub fn remember(cache: &Cache, rec: ReleaseRecord) -> Result<(), CacheError> {
    let mut all = releases(cache)?;
    all.retain(|r| {
        (r.signed.manifest.version, r.signed.manifest.target)
            != (rec.signed.manifest.version, rec.signed.manifest.target)
    });
    all.push(rec);
    all.sort_by_key(|r| std::cmp::Reverse(r.signed.manifest.version));
    cache.set_setting(SETTING, &encode(&all))
}

/// The release of `version` for `target`.
pub fn find(
    cache: &Cache,
    version: AgentVersion,
    target: AgentTarget,
) -> Result<ReleaseRecord, ReleaseImportError> {
    releases(cache)?
        .into_iter()
        .find(|r| r.signed.manifest.version == version && r.signed.manifest.target == target)
        .ok_or(ReleaseImportError::NotFound)
}

/// Touch ID prompt text for signing a release.
pub fn sign_reason(v: AgentVersion, target: AgentTarget) -> String {
    format!(
        "sign agent release v{} ({})",
        version_string(v),
        target.as_str()
    )
}

/// Import (module docs): hash, attestation check, root signature (blocking,
/// Touch ID). The caller stores it with [`remember`] (a MAC'd setting),
/// without holding the cache across the Touch ID prompt.
pub fn import_release(
    keys: &dyn DeviceSigner,
    device_id: DeviceId,
    req: &ImportRequest,
) -> Result<ReleaseRecord, ReleaseImportError> {
    let bin = read_agent_binary(&req.artifact)?;
    let hash = fleet_crypto::blake3(&bin);
    let attested = parse_attestation(&req.attested)?;
    if attested != hash {
        return Err(ReleaseImportError::AttestationMismatch);
    }
    let manifest = ReleaseManifest {
        version: req.version,
        blake3: hash,
        min_proto: fleet_proto::PROTO_VERSION,
        target: req.target,
    };
    let signer = RoleSigner::with_reason(keys, KeyRole::Root, sign_reason(req.version, req.target))
        .map_err(|e| ReleaseImportError::Sign(e.to_string()))?;
    let signed = fleet_crypto::release::sign_release(manifest, device_id, &signer)
        .map_err(|e| ReleaseImportError::Sign(e.to_string()))?;
    let rec = ReleaseRecord {
        signed,
        artifact: req.artifact.to_string_lossy().into_owned(),
        attested,
        imported_ms: crate::now_ms(),
    };
    Ok(rec)
}

/// The binary of `rec`, re-read and checked against the signed hash.
pub fn load_binary(rec: &ReleaseRecord) -> Result<Vec<u8>, ReleaseImportError> {
    let bin = read_agent_binary(Path::new(&rec.artifact))?;
    if fleet_crypto::blake3(&bin) != rec.signed.manifest.blake3 {
        return Err(ReleaseImportError::Changed);
    }
    Ok(bin)
}

// ---- rollout ----

/// What one server's update needs from the outside world (production:
/// [`ManagerSteps`]; tests: fakes).
pub trait UpdateSteps: Send + Sync {
    /// SFTP upload of `bytes` to `remote` as the admin user.
    fn upload(
        &self,
        server: ServerId,
        bytes: Arc<Vec<u8>>,
        remote: String,
    ) -> BoxFut<Result<(), Failure>>;
    fn request(
        &self,
        server: ServerId,
        op: Op,
        approval: Option<RootApproval>,
    ) -> BoxFut<Result<Payload, Failure>>;
    /// `agent.health` over a newly opened connection.
    fn fresh_health(&self, server: ServerId) -> BoxFut<Result<AgentHealth, Failure>>;
    /// `change.confirm` over a fresh connection within the change's window.
    fn confirm(&self, server: ServerId, change: PendingChange) -> BoxFut<Result<(), Failure>>;
}

/// Timing of one server's update.
#[derive(Debug, Clone, Copy)]
pub struct RolloutTiming {
    /// How long the new build has to report healthy (the agent's window
    /// is 30 s after its restart, which comes 3 s after the commit).
    pub health_window: Duration,
    pub retry: Duration,
}

impl Default for RolloutTiming {
    fn default() -> Self {
        Self {
            health_window: Duration::from_secs(30),
            retry: Duration::from_secs(1),
        }
    }
}

/// `agent.update.commit` for `version`.
pub fn commit_op(version: AgentVersion) -> Op {
    Op::AgentUpdateCommit { version }
}

/// Stage → commit → healthy new build → confirm, on one server.
pub async fn update_one(
    steps: Arc<dyn UpdateSteps>,
    server: ServerId,
    signed: SignedReleaseManifest,
    bytes: Arc<Vec<u8>>,
    approval: RootApproval,
    timing: RolloutTiming,
) -> Result<Output, Failure> {
    let hash = signed.manifest.blake3;
    let want = signed.manifest.version;
    let remote = format!("{INCOMING_DIR}/{}", hex::encode(hash));
    steps.upload(server.clone(), bytes, remote).await?;
    let stage = Op::AgentUpdateStage {
        manifest: Box::new(signed),
        staged_path_hash: hash,
    };
    steps.request(server.clone(), stage, None).await?;
    let change = match steps
        .request(server.clone(), commit_op(want), Some(approval))
        .await?
    {
        Payload::ChangePending { change, .. } => change,
        _ => {
            return Err(Failure::Transport(
                "unexpected answer to agent.update.commit".into(),
            ));
        }
    };
    let until = Instant::now() + timing.health_window;
    let health = loop {
        tokio::time::sleep(timing.retry).await;
        match steps.fresh_health(server.clone()).await {
            Ok(h) if h.agent_version == want => break h,
            Ok(_) | Err(_) if Instant::now() < until => continue,
            Ok(h) => {
                return Err(Failure::Transport(format!(
                    "still running {} after the health window; the agent rolls back",
                    version_string(h.agent_version)
                )));
            }
            Err(e) => {
                return Err(Failure::Transport(format!(
                    "new build not reachable in the health window ({e:?}); the agent rolls back"
                )));
            }
        }
    };
    steps.confirm(server, change).await?;
    Ok(Output::Payload(Payload::AgentHealth(health)))
}

/// Canary phases over `n` servers: `[0,1)`, then 10% (at least one), then
/// the rest.
pub fn phases(n: usize) -> Vec<std::ops::Range<usize>> {
    let mut v = Vec::new();
    if n == 0 {
        return v;
    }
    v.push(0..1);
    let tenth = n.div_ceil(10).max(1);
    let second_end = (1 + tenth).min(n);
    if second_end > 1 {
        v.push(1..second_end);
    }
    if n > second_end {
        v.push(second_end..n);
    }
    v
}

/// Approvals older than this are renewed before a phase (they live 30 min).
const APPROVAL_REFRESH: Duration = Duration::from_secs(20 * 60);

/// Rolls `signed` out to `targets` in [`phases`], stopping at the first
/// failure. One root approval (Touch ID) covers every commit, renewed for
/// the remaining servers if a phase starts after [`APPROVAL_REFRESH`].
#[allow(clippy::too_many_arguments)]
pub async fn rollout<E: FnMut(BulkEvent) + Send>(
    steps: Arc<dyn UpdateSteps>,
    approver: Arc<dyn Approver>,
    targets: Vec<ServerId>,
    signed: SignedReleaseManifest,
    bytes: Arc<Vec<u8>>,
    concurrency: usize,
    timing: RolloutTiming,
    cancel: CancelToken,
    mut emit: E,
) -> BulkReport {
    let n = targets.len();
    emit(BulkEvent::Started {
        total: n,
        needs_approval: true,
    });
    let op = commit_op(signed.manifest.version);
    let what = format!(
        "agent update to v{}",
        version_string(signed.manifest.version)
    );
    let mut outcomes: Vec<Option<Outcome>> = vec![None; n];
    let mut approvals: Vec<Option<RootApproval>> = vec![None; n];
    let mut approved_at: Option<Instant> = None;
    let mut stop: Option<StopReason> = None;
    let ph = phases(n);
    for (pi, range) in ph.iter().enumerate() {
        if cancel.is_cancelled() {
            stop = Some(StopReason::Cancelled);
            break;
        }
        if approved_at.is_none_or(|t| t.elapsed() > APPROVAL_REFRESH) {
            let rest: Vec<usize> = (range.start..n).collect();
            let items: Vec<ApprovalItem> = rest
                .iter()
                .map(|&i| ApprovalItem {
                    server_id: targets[i].clone(),
                    op_digest: op_digest(&op, None),
                })
                .collect();
            let (a, w) = (approver.clone(), what.clone());
            let got = tokio::task::spawn_blocking(move || a.approve(&w, &items))
                .await
                .map_err(|_| crate::bulk::ApproveError::Failed)
                .and_then(|r| r);
            match got {
                Ok(list) => {
                    for (i, ap) in rest.into_iter().zip(list) {
                        approvals[i] = Some(ap);
                    }
                    approved_at = Some(Instant::now());
                    emit(BulkEvent::Approved {
                        servers: n - range.start,
                    });
                }
                Err(e) => {
                    stop = Some(StopReason::ApprovalDenied(e.to_string()));
                    break;
                }
            }
        }
        let opts = BulkOptions {
            concurrency,
            canary: false,
            health: None,
            stop_on_failure: true,
            per_server_timeout: None,
            dry_run: false,
        };
        let phase_targets: Vec<ServerId> = targets[range.clone()].to_vec();
        let base = range.start;
        let work = |i: usize| -> BoxFut<Result<Output, Failure>> {
            let idx = base + i;
            match approvals[idx].clone() {
                Some(ap) => Box::pin(update_one(
                    steps.clone(),
                    targets[idx].clone(),
                    signed.clone(),
                    bytes.clone(),
                    ap,
                    timing,
                )),
                None => Box::pin(async { Err(Failure::NotReady("no approval".into())) }),
            }
        };
        let rep = crate::bulk::run_with(phase_targets, &opts, &work, &cancel, |ev| match ev {
            BulkEvent::Started { .. } | BulkEvent::Done(_) => {}
            other => emit(other),
        })
        .await;
        let Ok(rep) = rep else {
            stop = Some(StopReason::Failure);
            break;
        };
        for (i, (_, o)) in rep.outcomes.into_iter().enumerate() {
            outcomes[base + i] = Some(o);
        }
        if let Some(s) = rep.summary.stop {
            stop = Some(if pi == 0 && s == StopReason::Failure {
                StopReason::CanaryFailed
            } else {
                s
            });
            break;
        }
        if pi + 1 < ph.len() {
            emit(BulkEvent::CanaryPassed {
                server: targets[range.end - 1].clone(),
            });
        }
    }
    let skip = match &stop {
        Some(StopReason::CanaryFailed) => SkipReason::CanaryFailed,
        Some(StopReason::Cancelled) => SkipReason::Cancelled,
        Some(StopReason::ApprovalDenied(_)) => SkipReason::ApprovalDenied,
        _ => SkipReason::StoppedAfterFailure,
    };
    let outcomes: Vec<(ServerId, Outcome)> = targets
        .into_iter()
        .zip(outcomes)
        .map(|(s, o)| (s, o.unwrap_or(Outcome::Skipped(skip))))
        .collect();
    let mut summary = BulkSummary {
        stop,
        ..Default::default()
    };
    for (_, o) in &outcomes {
        match o {
            Outcome::Succeeded(_) => summary.succeeded += 1,
            Outcome::Failed(_) => summary.failed += 1,
            Outcome::Skipped(_) => summary.skipped += 1,
            Outcome::Cancelled => summary.cancelled += 1,
            Outcome::Planned(_) => summary.planned += 1,
        }
    }
    emit(BulkEvent::Done(summary.clone()));
    BulkReport { outcomes, summary }
}

/// Production [`UpdateSteps`] over the connection manager.
pub struct ManagerSteps {
    pub handle: ManagerHandle,
}

impl UpdateSteps for ManagerSteps {
    fn upload(
        &self,
        server: ServerId,
        bytes: Arc<Vec<u8>>,
        remote: String,
    ) -> BoxFut<Result<(), Failure>> {
        let h = self.handle.clone();
        Box::pin(async move {
            let ssh = h
                .ssh(&server)
                .ok_or_else(|| Failure::NotReady("no SSH connection".into()))?;
            let sftp = crate::sftp::Sftp::open(&ssh)
                .await
                .map_err(|e| Failure::Transport(format!("sftp: {e}")))?;
            sftp.upload_bytes(&bytes, &remote, Some(0o600), false, &mut |_, _| {})
                .await
                .map_err(|e| Failure::Transport(format!("upload: {e}")))?;
            Ok(())
        })
    }

    fn request(
        &self,
        server: ServerId,
        op: Op,
        approval: Option<RootApproval>,
    ) -> BoxFut<Result<Payload, Failure>> {
        let h = self.handle.clone();
        Box::pin(async move {
            let opts = RequestOpts {
                approval,
                ..RequestOpts::default()
            };
            let reply = h.request_with(&server, op, Actor::Human, opts).await?;
            reply.result.map_err(Failure::Agent)
        })
    }

    fn fresh_health(&self, server: ServerId) -> BoxFut<Result<AgentHealth, Failure>> {
        let h = self.handle.clone();
        Box::pin(async move {
            crate::autorevert::reconnect_fresh(&h, &server, Duration::from_secs(10))
                .await
                .map_err(|e| Failure::Transport(format!("reconnect: {e:?}")))?;
            let reply = h
                .request(&server, Op::AgentHealth, Actor::Human, None)
                .await?;
            match reply.result.map_err(Failure::Agent)? {
                Payload::AgentHealth(a) => Ok(a),
                _ => Err(Failure::Transport("unexpected health answer".into())),
            }
        })
    }

    fn confirm(&self, server: ServerId, change: PendingChange) -> BoxFut<Result<(), Failure>> {
        let h = self.handle.clone();
        Box::pin(async move {
            crate::autorevert::confirm_pending(&h, &server, &change, Actor::Human)
                .await
                .map_err(|e| {
                    Failure::Transport(format!("not confirmed ({e}); the agent rolls back"))
                })
        })
    }
}

#[cfg(test)]
#[path = "release_tests.rs"]
mod tests;
