//! Typed server operations for the detail tabs (design §4.2). Arguments are
//! validated here with the protocol's own types (`fleet_proto::args`)
//! before anything is signed; exec validates them again (rule 3).

use crate::api::FleetCore;
use crate::rows::*;
use crate::types::FleetError;
use fleet_proto::args::{GrepPattern, JournalCursor, JournalQuery, Priority, TimeRange, UnitName};
use fleet_proto::op::{ProcessSort, Resolution, UpgradeScope};
use fleet_proto::{Op, Payload};

fn invalid(field: &str) -> FleetError {
    FleetError::InvalidArgument {
        field: field.into(),
    }
}

fn unexpected<T>(_: Payload) -> Result<T, FleetError> {
    Err(FleetError::UnexpectedReply)
}

pub(crate) fn journal_query(a: &JournalQueryArgs) -> Result<JournalQuery, FleetError> {
    let units = a
        .units
        .iter()
        .map(|u| UnitName::new(u.as_str()).map_err(|_| invalid("units")))
        .collect::<Result<Vec<_>, _>>()?;
    let q = JournalQuery {
        units,
        priority: a.priority.map(|p| match p {
            LogPriority::Emerg => Priority::Emerg,
            LogPriority::Alert => Priority::Alert,
            LogPriority::Crit => Priority::Crit,
            LogPriority::Err => Priority::Err,
            LogPriority::Warning => Priority::Warning,
            LogPriority::Notice => Priority::Notice,
            LogPriority::Info => Priority::Info,
            LogPriority::Debug => Priority::Debug,
        }),
        range: TimeRange {
            since_ms: a.since_ms,
            until_ms: a.until_ms,
        },
        grep: a
            .grep
            .as_deref()
            .filter(|g| !g.is_empty())
            .map(|g| GrepPattern::new(g).map_err(|_| invalid("grep")))
            .transpose()?,
        after_cursor: a
            .after_cursor
            .as_deref()
            .map(|c| JournalCursor::new(c).map_err(|_| invalid("after_cursor")))
            .transpose()?,
        limit: a.limit,
    };
    q.validate().map_err(|_| invalid("journal query"))?;
    Ok(q)
}

fn unit(name: &str) -> Result<UnitName, FleetError> {
    let u = UnitName::new(name).map_err(|_| invalid("unit"))?;
    // Exec refuses these too; fail before signing.
    if u.is_fleet() {
        return Err(invalid("unit"));
    }
    Ok(u)
}

fn range(since_ms: Option<u64>, until_ms: Option<u64>) -> Result<TimeRange, FleetError> {
    let r = TimeRange { since_ms, until_ms };
    r.validate().map_err(|_| invalid("range"))?;
    Ok(r)
}

#[uniffi::export]
impl FleetCore {
    /// Rollups from the agent's 7-day store. `series` empty = all (≤ 256).
    pub async fn metrics_query(
        &self,
        server_id: String,
        since_ms: Option<u64>,
        until_ms: Option<u64>,
        minute_resolution: bool,
        series: Vec<u16>,
    ) -> Result<MetricsHistoryRow, FleetError> {
        if series.len() > 256 {
            return Err(invalid("series"));
        }
        let op = Op::MetricsQuery {
            range: range(since_ms, until_ms)?,
            resolution: if minute_resolution {
                Resolution::Minute
            } else {
                Resolution::Raw
            },
            series,
        };
        match self.request(&server_id, op).await? {
            Payload::MetricsHistory(h) => Ok(h.into()),
            p => unexpected(p),
        }
    }

    /// `limit` 1..=1000.
    pub async fn processes_list(
        &self,
        server_id: String,
        sort: ProcessSortRow,
        limit: u16,
    ) -> Result<ProcessListRow, FleetError> {
        if !(1..=1000).contains(&limit) {
            return Err(invalid("limit"));
        }
        let sort = match sort {
            ProcessSortRow::Cpu => ProcessSort::Cpu,
            ProcessSortRow::Memory => ProcessSort::Memory,
            ProcessSortRow::Io => ProcessSort::Io,
            ProcessSortRow::Pid => ProcessSort::Pid,
        };
        match self
            .request(&server_id, Op::ProcessesList { sort, limit })
            .await?
        {
            Payload::ProcessList(l) => Ok(ProcessListRow {
                total: l.total,
                processes: l.processes.into_iter().map(Into::into).collect(),
            }),
            p => unexpected(p),
        }
    }

    pub async fn journal_query(
        &self,
        server_id: String,
        query: JournalQueryArgs,
    ) -> Result<JournalPageRow, FleetError> {
        let q = journal_query(&query)?;
        match self.request(&server_id, Op::JournalQuery(q)).await? {
            Payload::JournalEntries(j) => Ok(j.into()),
            p => unexpected(p),
        }
    }

    pub async fn unit_list(&self, server_id: String) -> Result<Vec<UnitRow>, FleetError> {
        match self.request(&server_id, Op::UnitList).await? {
            Payload::Units(u) => Ok(u.units.into_iter().map(Into::into).collect()),
            p => unexpected(p),
        }
    }

    pub async fn unit_status(
        &self,
        server_id: String,
        unit_name: String,
    ) -> Result<UnitStatusRow, FleetError> {
        let unit = unit(&unit_name)?;
        match self.request(&server_id, Op::UnitStatus { unit }).await? {
            Payload::UnitStatus(s) => Ok(s.into()),
            p => unexpected(p),
        }
    }

    /// Start/stop/restart/reload/enable/disable. The app confirms first.
    pub async fn unit_action(
        &self,
        server_id: String,
        unit_name: String,
        action: UnitAction,
    ) -> Result<(), FleetError> {
        let unit = unit(&unit_name)?;
        let op = match action {
            UnitAction::Start => Op::UnitStart { unit },
            UnitAction::Stop => Op::UnitStop { unit },
            UnitAction::Restart => Op::UnitRestart { unit },
            UnitAction::Reload => Op::UnitReload { unit },
            UnitAction::Enable => Op::UnitEnable { unit },
            UnitAction::Disable => Op::UnitDisable { unit },
        };
        self.request(&server_id, op).await.map(|_| ())
    }

    pub async fn pkg_upgradable(&self, server_id: String) -> Result<UpgradableListRow, FleetError> {
        match self.request(&server_id, Op::PkgUpgradable).await? {
            Payload::Upgradable(u) => Ok(u.into()),
            p => unexpected(p),
        }
    }

    /// `apt-get update`.
    pub async fn pkg_refresh(&self, server_id: String) -> Result<(), FleetError> {
        self.request(&server_id, Op::PkgRefresh).await.map(|_| ())
    }

    /// Upgrades everything, or security updates only.
    pub async fn pkg_upgrade(
        &self,
        server_id: String,
        security_only: bool,
    ) -> Result<PackageChangesRow, FleetError> {
        let scope = if security_only {
            UpgradeScope::SecurityOnly
        } else {
            UpgradeScope::All
        };
        match self.request(&server_id, Op::PkgUpgrade { scope }).await? {
            Payload::PackageChanges(c) => Ok(c.into()),
            p => unexpected(p),
        }
    }

    pub async fn logins_query(
        &self,
        server_id: String,
        since_ms: Option<u64>,
        failed_only: bool,
        limit: u32,
    ) -> Result<LoginsRow, FleetError> {
        if !(1..=10_000).contains(&limit) {
            return Err(invalid("limit"));
        }
        let op = Op::LoginsQuery {
            range: range(since_ms, None)?,
            failed_only,
            limit,
        };
        match self.request(&server_id, op).await? {
            Payload::Logins(l) => Ok(LoginsRow {
                logins: l.logins.into_iter().map(Into::into).collect(),
                truncated: l.truncated,
            }),
            p => unexpected(p),
        }
    }

    pub async fn ports_list(&self, server_id: String) -> Result<Vec<PortRow>, FleetError> {
        match self.request(&server_id, Op::PortsList).await? {
            Payload::Ports(p) => Ok(p.ports.into_iter().map(Into::into).collect()),
            p => unexpected(p),
        }
    }

    pub async fn certs_list(&self, server_id: String) -> Result<Vec<CertRow>, FleetError> {
        match self.request(&server_id, Op::CertsList).await? {
            Payload::Certs(c) => Ok(c.certs.into_iter().map(Into::into).collect()),
            p => unexpected(p),
        }
    }

    pub async fn bans_list(&self, server_id: String) -> Result<BansRow, FleetError> {
        match self.request(&server_id, Op::BansList).await? {
            Payload::Bans(b) => Ok(BansRow {
                bans: b.bans.into_iter().map(Into::into).collect(),
                learned_exempt: b.learned_exempt.iter().map(|a| a.to_string()).collect(),
            }),
            p => unexpected(p),
        }
    }

    /// Read-only view; `firewall.apply` comes later.
    pub async fn firewall_get(&self, server_id: String) -> Result<FirewallRow, FleetError> {
        match self.request(&server_id, Op::FirewallGet).await? {
            Payload::Firewall(f) => Ok(f.into()),
            p => unexpected(p),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> JournalQueryArgs {
        JournalQueryArgs {
            units: vec!["nginx.service".into()],
            priority: Some(LogPriority::Warning),
            since_ms: Some(1),
            until_ms: Some(2),
            grep: Some("error".into()),
            after_cursor: None,
            limit: 100,
        }
    }

    #[test]
    fn journal_args_validated() {
        let q = journal_query(&args()).unwrap();
        assert_eq!(q.units.len(), 1);
        assert_eq!(q.priority, Some(Priority::Warning));
        let mut a = args();
        a.units = vec!["nginx; rm -rf /".into()];
        assert!(journal_query(&a).is_err());
        let mut a = args();
        a.limit = 0;
        assert!(journal_query(&a).is_err());
        let mut a = args();
        a.since_ms = Some(3);
        assert!(journal_query(&a).is_err());
        let mut a = args();
        a.grep = Some(String::new());
        assert_eq!(journal_query(&a).unwrap().grep, None);
    }

    #[test]
    fn fleet_units_refused() {
        assert!(unit("fleet-exec.service").is_err());
        assert!(unit("nginx").is_err());
        assert!(unit("nginx.service").is_ok());
    }
}
