//! Vulnerability matching (design §2.4, §7.7).
//!
//! [`VulnService`] owns the feed database (`vulns.sqlite`, its own file)
//! and the latest per-server reports. Feed updates run on their own
//! thread with their own tokio runtime (downloads and a ~0.5 GB parse
//! must not stall the connection manager): [`VulnService::start_daily`]
//! checks every few minutes whether a feed is due (daily; an hour after a
//! failure), [`VulnService::update_now`] forces a check.
//!
//! [`FleetCore::vuln_scan`] reads `system.info` and `pkg.list` from a
//! server and matches them on the Mac. Package names and versions come
//! from the server and are escaped for display (rule 6).

use crate::api::{FleetCore, lock};
use crate::text;
use crate::types::FleetError;
use fleet_core::manager;
use fleet_core::vuln::Severity;
use fleet_core::vuln::db::{FeedMeta, VulnDb};
use fleet_core::vuln::feed::{self, Source};
use fleet_core::vuln::matcher::{self, Installed, Report};
use fleet_core::vuln::release;
use fleet_proto::{Op, Payload, ServerId};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

/// How often the daily loop looks at the feeds' due times.
const CHECK_EVERY: Duration = Duration::from_secs(10 * 60);

fn vuln_err(e: impl std::fmt::Display) -> FleetError {
    FleetError::VulnData {
        message: e.to_string(),
    }
}

fn now_ms() -> u64 {
    fleet_core::now_ms()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum VulnSeverity {
    Unknown,
    Negligible,
    Low,
    Medium,
    High,
    Critical,
}

impl From<Severity> for VulnSeverity {
    fn from(s: Severity) -> Self {
        match s {
            Severity::Unknown => Self::Unknown,
            Severity::Negligible => Self::Negligible,
            Severity::Low => Self::Low,
            Severity::Medium => Self::Medium,
            Severity::High => Self::High,
            Severity::Critical => Self::Critical,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VulnFindingRow {
    /// Installed binary package (server data, escaped).
    pub package: String,
    pub installed: String,
    /// `CVE-…`, `TEMP-…` or `USN-…`.
    pub id: String,
    /// CVEs of a USN.
    pub aliases: Vec<String>,
    /// `None`: no fix released yet.
    pub fixed: Option<String>,
    pub severity: VulnSeverity,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VulnReportRow {
    pub server_id: String,
    /// `debian` / `ubuntu` and the release codename, when supported.
    pub distro: Option<String>,
    pub release: Option<String>,
    /// `os-release` as reported (escaped), for unsupported systems.
    pub os: String,
    pub scanned_ms: u64,
    pub packages_scanned: u32,
    pub findings: Vec<VulnFindingRow>,
    /// Packages an upgrade would fix (fleet table column).
    pub vulnerable_packages: u32,
    /// Packages whose findings have no fix yet.
    pub unfixed_packages: u32,
    pub highest: Option<VulnSeverity>,
    /// The feed for this distribution has never loaded.
    pub no_data: bool,
    /// Set when the scan failed (the other fields are empty).
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VulnFeedRow {
    pub key: String,
    pub url: String,
    pub attempted_ms: Option<u64>,
    /// Last successful check (new data or unchanged).
    pub fetched_ms: Option<u64>,
    /// Last time new data loaded.
    pub updated_ms: Option<u64>,
    pub rows: u64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VulnStatusRow {
    pub feeds: Vec<VulnFeedRow>,
    pub updating: bool,
}

#[derive(uniffi::Object)]
pub struct VulnService {
    path: PathBuf,
    db: Mutex<VulnDb>,
    reports: Mutex<HashMap<String, VulnReportRow>>,
    updating: Arc<AtomicBool>,
    daily: AtomicBool,
}

/// One update pass on the calling thread: every feed that is due (or all,
/// with `force`). Errors are recorded per feed in the database.
fn update_pass(path: &Path, force: bool) -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let tmp = path
        .parent()
        .unwrap_or(Path::new("."))
        .join("vuln-downloads");
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    let mut db = VulnDb::open(path).map_err(|e| e.to_string())?;
    let client = fleet_core::vuln::fetch::client().map_err(|e| e.to_string())?;
    let mut errors = Vec::new();
    for source in Source::ALL {
        let meta = db.meta(source).map_err(|e| e.to_string())?;
        if !force && !feed::due(&meta, now_ms()) {
            continue;
        }
        let r = rt.block_on(fleet_core::vuln::fetch::update(
            &client,
            &mut db,
            source,
            &tmp,
            now_ms(),
        ));
        if let Err(e) = r {
            errors.push(format!("{}: {e}", source.key()));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// Clears the flag when the pass ends, however it ends.
struct Updating(Arc<AtomicBool>);

impl Drop for Updating {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl VulnService {
    fn feed_row(source: Source, m: FeedMeta) -> VulnFeedRow {
        VulnFeedRow {
            key: source.key().into(),
            url: source.url().into(),
            attempted_ms: m.attempted_ms,
            fetched_ms: m.fetched_ms,
            updated_ms: m.updated_ms,
            rows: m.rows,
            last_error: m.last_error.map(text::line),
        }
    }

    /// Starts a pass on a new thread unless one runs; `None` if busy.
    fn spawn_pass(
        &self,
        force: bool,
    ) -> Option<tokio::sync::oneshot::Receiver<Result<(), String>>> {
        if self.updating.swap(true, Ordering::SeqCst) {
            return None;
        }
        let guard = Updating(self.updating.clone());
        let path = self.path.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let spawned = std::thread::Builder::new()
            .name("fleet-vuln".into())
            .spawn(move || {
                let _guard = guard;
                let _ = tx.send(update_pass(&path, force));
            });
        // On spawn failure the closure (and the guard) was dropped.
        spawned.ok().map(|_| rx)
    }

    fn match_report(
        &self,
        server_id: &str,
        os_id: &str,
        os_version: &str,
        installed: &[Installed],
    ) -> Result<VulnReportRow, FleetError> {
        let mut row = VulnReportRow {
            server_id: server_id.to_string(),
            distro: None,
            release: None,
            os: text::line(format!("{os_id} {os_version}")),
            scanned_ms: now_ms(),
            packages_scanned: installed.len() as u32,
            findings: vec![],
            vulnerable_packages: 0,
            unfixed_packages: 0,
            highest: None,
            no_data: false,
            error: None,
        };
        let Some(target) = release::target(os_id, os_version) else {
            return Ok(row);
        };
        row.distro = Some(target.distro.as_str().into());
        row.release = Some(target.codename.into());
        let db = lock(&self.db);
        row.no_data = db.count(target.distro).map_err(vuln_err)? == 0;
        let report: Report = matcher::match_packages(&target, installed, |p| {
            db.lookup(target.distro, target.codename, p)
        })
        .map_err(vuln_err)?;
        row.findings = report
            .findings
            .into_iter()
            .map(|f| VulnFindingRow {
                package: text::line(f.package),
                installed: text::line(f.installed),
                id: f.id,
                aliases: f.aliases,
                fixed: f.fixed,
                severity: f.severity.into(),
            })
            .collect();
        row.vulnerable_packages = report.vulnerable_packages;
        row.unfixed_packages = report.unfixed_packages;
        row.highest = report.highest.map(Into::into);
        Ok(row)
    }

    fn remember(&self, row: &VulnReportRow) {
        lock(&self.reports).insert(row.server_id.clone(), row.clone());
    }
}

#[uniffi::export]
impl VulnService {
    /// Opens (or creates) the feed database at `path`.
    #[uniffi::constructor]
    pub fn open(path: String) -> Result<Arc<Self>, FleetError> {
        let path = PathBuf::from(path);
        let db = VulnDb::open(&path).map_err(vuln_err)?;
        Ok(Arc::new(Self {
            path,
            db: Mutex::new(db),
            reports: Mutex::new(HashMap::new()),
            updating: Arc::new(AtomicBool::new(false)),
            daily: AtomicBool::new(false),
        }))
    }

    pub fn status(&self) -> Result<VulnStatusRow, FleetError> {
        let db = lock(&self.db);
        let feeds = Source::ALL
            .into_iter()
            .map(|s| db.meta(s).map(|m| Self::feed_row(s, m)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(vuln_err)?;
        Ok(VulnStatusRow {
            feeds,
            updating: self.updating.load(Ordering::SeqCst),
        })
    }

    /// Checks every feed now (conditional GET), whatever their due times.
    /// If a pass is already running, returns at once with `updating` set
    /// (poll [`VulnService::status`]).
    pub async fn update_now(&self) -> Result<VulnStatusRow, FleetError> {
        if let Some(rx) = self.spawn_pass(true) {
            match rx.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(vuln_err(text::line(e))),
                Err(_) => return Err(vuln_err("update thread ended")),
            }
        }
        self.status()
    }

    /// Starts the daily update loop (once; later calls do nothing). It
    /// ends when the service is dropped.
    pub fn start_daily(self: Arc<Self>) {
        if self.daily.swap(true, Ordering::SeqCst) {
            return;
        }
        let weak: Weak<Self> = Arc::downgrade(&self);
        let _ = std::thread::Builder::new()
            .name("fleet-vuln-daily".into())
            .spawn(move || {
                loop {
                    let Some(svc) = weak.upgrade() else { return };
                    if let Some(rx) = svc.spawn_pass(false) {
                        drop(svc);
                        let _ = rx.blocking_recv();
                    } else {
                        drop(svc);
                    }
                    // Sleep in short steps so a dropped service ends the
                    // thread promptly.
                    let mut slept = Duration::ZERO;
                    while slept < CHECK_EVERY {
                        std::thread::sleep(Duration::from_secs(5));
                        slept += Duration::from_secs(5);
                        if weak.strong_count() == 0 {
                            return;
                        }
                    }
                }
            });
    }

    /// The latest report for a server, if it was scanned this run.
    pub fn report(&self, server_id: String) -> Option<VulnReportRow> {
        lock(&self.reports).get(&server_id).cloned()
    }

    pub fn reports(&self) -> Vec<VulnReportRow> {
        let mut v: Vec<_> = lock(&self.reports).values().cloned().collect();
        v.sort_by(|a, b| a.server_id.cmp(&b.server_id));
        v
    }
}

impl FleetCore {
    async fn scan_one(
        &self,
        vulns: &VulnService,
        id: &ServerId,
    ) -> Result<VulnReportRow, FleetError> {
        let sid = id.to_string();
        let info = match self.request(&sid, Op::SystemInfo).await? {
            Payload::SystemInfo(i) => i,
            _ => return Err(FleetError::UnexpectedReply),
        };
        let packages = match self.request(&sid, Op::PkgList { filter: None }).await? {
            Payload::Packages(p) => p.packages,
            _ => return Err(FleetError::UnexpectedReply),
        };
        // `pkg.list` has no source package yet: match by binary name
        // (see `vuln::matcher`).
        let installed: Vec<Installed> = packages
            .into_iter()
            .map(|p| Installed {
                name: p.name,
                version: p.version,
                source: None,
            })
            .collect();
        vulns.match_report(&sid, &info.os_id, &info.os_version, &installed)
    }
}

#[uniffi::export]
impl FleetCore {
    /// Scans one server: `system.info` + `pkg.list`, matched on the Mac.
    /// The report is also kept in `vulns` for the fleet table.
    pub async fn vuln_scan(
        &self,
        vulns: Arc<VulnService>,
        server_id: String,
    ) -> Result<VulnReportRow, FleetError> {
        let id = crate::validate::server_id(&server_id)?;
        let row = self.scan_one(&vulns, &id).await?;
        vulns.remember(&row);
        Ok(row)
    }

    /// Scans every connected server concurrently. Failures come back as
    /// rows with `error` set (and are not remembered).
    pub async fn vuln_scan_fleet(
        &self,
        vulns: Arc<VulnService>,
    ) -> Result<Vec<VulnReportRow>, FleetError> {
        let (handle, _) = self.running()?;
        let ready: Vec<ServerId> = handle
            .servers()
            .into_iter()
            .filter(|(_, s)| *s == manager::ConnState::Ready)
            .map(|(id, _)| id)
            .collect();
        let scans = ready.iter().map(|id| {
            let vulns = &vulns;
            async move {
                match self.scan_one(vulns, id).await {
                    Ok(row) => {
                        vulns.remember(&row);
                        row
                    }
                    Err(e) => VulnReportRow {
                        server_id: id.to_string(),
                        distro: None,
                        release: None,
                        os: String::new(),
                        scanned_ms: now_ms(),
                        packages_scanned: 0,
                        findings: vec![],
                        vulnerable_packages: 0,
                        unfixed_packages: 0,
                        highest: None,
                        no_data: false,
                        error: Some(text::line(e.to_string())),
                    },
                }
            }
        });
        let mut rows = futures_util::future::join_all(scans).await;
        rows.sort_by(|a, b| a.server_id.cmp(&b.server_id));
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEBIAN: &str = r#"{"curl":{"CVE-2023-38545":{"releases":{"bookworm":{"status":"resolved","fixed_version":"7.88.1-10+deb12u4","urgency":"high"}}}}}"#;

    #[test]
    fn report_for_supported_and_unsupported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vulns.sqlite");
        let svc = VulnService::open(path.to_string_lossy().into()).unwrap();
        {
            let mut db = lock(&svc.db);
            feed::ingest(&mut db, Source::DebianTracker, DEBIAN.as_bytes()).unwrap();
        }
        let installed = [Installed {
            name: "curl".into(),
            version: "7.88.1-10+deb12u3".into(),
            source: None,
        }];
        let r = svc
            .match_report("srv_aaaaaaaaaaaa", "debian", "12", &installed)
            .unwrap();
        assert_eq!(r.release.as_deref(), Some("bookworm"));
        assert_eq!(r.vulnerable_packages, 1);
        assert_eq!(r.highest, Some(VulnSeverity::High));
        assert!(!r.no_data);
        let r = svc
            .match_report("srv_aaaaaaaaaaaa", "ubuntu", "22.04", &installed)
            .unwrap();
        assert!(r.no_data && r.findings.is_empty());
        let r = svc
            .match_report("srv_aaaaaaaaaaaa", "fedora\u{202E}", "40", &installed)
            .unwrap();
        assert_eq!(
            (r.distro.as_deref(), r.os.as_str()),
            (None, "fedora\\u{202E} 40")
        );
        let st = svc.status().unwrap();
        assert_eq!(st.feeds.len(), 2);
        assert!(!st.updating);
        svc.remember(&r);
        assert_eq!(svc.reports().len(), 1);
        assert!(svc.report("srv_aaaaaaaaaaaa".into()).is_some());
    }
}
