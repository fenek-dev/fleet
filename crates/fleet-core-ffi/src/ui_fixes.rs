//! Bindings behind the P3 UI features: manual agent rollback (design
//! §10.2), group and server placement editing (§2.1), and the Logs tab's
//! log files and web access logs (§2.4). Server text is escaped (rule 6).

use crate::admin_ops::{invalid, unexpected};
use crate::api::{FleetCore, lock};
use crate::rows::StreamStatus;
use crate::streams::{StreamHandle, run_stream};
use crate::text;
use crate::types::FleetError;
use crate::validate;
use fleet_core::cache::GroupRecord;
use fleet_proto::args::{AbsPath, HttpPath, TimeRange};
use fleet_proto::op::StatusRange;
use fleet_proto::{Op, Payload};
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LogFileRow {
    /// The server's path exactly as reported, validated when used. Only
    /// for `tail_logfile`; never show it (rule 6).
    pub path: String,
    /// Escaped for display.
    pub label: String,
    pub size_bytes: u64,
    pub mtime_ms: u64,
}

#[uniffi::export(callback_interface)]
pub trait LogLinesSink: Send + Sync {
    fn on_lines(&self, lines: Vec<String>, rotated: bool);
    fn on_status(&self, status: StreamStatus);
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WebLogEntryRow {
    pub time_ms: u64,
    pub client: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub bytes: u64,
    pub user_agent: Option<String>,
    pub log: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WebLogRow {
    pub requests: u64,
    pub by_status: Vec<WebLogCount>,
    pub top_clients: Vec<WebLogCount>,
    pub top_paths: Vec<WebLogCount>,
    pub scanner_hits: u64,
    pub entries: Vec<WebLogEntryRow>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WebLogCount {
    pub label: String,
    pub count: u64,
}

/// Inputs of `weblog.query`, validated with the protocol types.
pub(crate) fn weblog_op(
    since_ms: Option<u64>,
    limit: u32,
    status_min: Option<u16>,
    status_max: Option<u16>,
    path_prefix: Option<String>,
    client: Option<String>,
) -> Result<Op, FleetError> {
    let status = match (status_min, status_max) {
        (None, None) => None,
        (Some(min), Some(max)) => Some(StatusRange { min, max }),
        _ => return Err(invalid("status")),
    };
    let path_prefix = path_prefix
        .filter(|p| !p.is_empty())
        .map(|p| HttpPath::new(p).map_err(|_| invalid("path_prefix")))
        .transpose()?;
    let client = client
        .filter(|c| !c.trim().is_empty())
        .map(|c| c.trim().parse::<IpAddr>().map_err(|_| invalid("client")))
        .transpose()?;
    let op = Op::WeblogQuery {
        range: TimeRange {
            since_ms,
            until_ms: None,
        },
        limit,
        status,
        path_prefix,
        client,
    };
    op.check_args().map_err(|_| invalid("weblog query"))?;
    Ok(op)
}

pub(crate) fn log_file_row(f: fleet_proto::payload::LogFile) -> LogFileRow {
    LogFileRow {
        label: text::line(f.path.clone()),
        path: f.path,
        size_bytes: f.size_bytes,
        mtime_ms: f.mtime_ms,
    }
}

/// `logfile.tail` for a raw path from [`LogFileRow::path`].
pub(crate) fn tail_op(path: String, lines: u16, follow: bool) -> Result<Op, FleetError> {
    let path = AbsPath::new(path).map_err(|_| invalid("path"))?;
    let op = Op::LogfileTail {
        path,
        lines,
        follow,
    };
    op.check_args().map_err(|_| invalid("lines"))?;
    Ok(op)
}

fn count(label: String, count: u64) -> WebLogCount {
    WebLogCount {
        label: text::line(label),
        count,
    }
}

/// One runbook step as it will run, after parameter substitution.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RunbookStepPreviewRow {
    pub name: String,
    pub op_name: String,
    pub elevated: bool,
    /// Exact command or arguments (escaped, clipped).
    pub command: String,
}

/// A runbook's target servers by name, for the confirmation sheet.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RunbookPreviewRow {
    pub steps: Vec<RunbookStepPreviewRow>,
    /// Target names (ids of removed servers are marked).
    pub targets: Vec<String>,
}

#[uniffi::export]
impl FleetCore {
    /// What `run_runbook` would run with `params`: every step's resolved
    /// operation and every target server by name. Fails like a run would
    /// (missing or invalid parameters).
    pub fn runbook_preview(
        &self,
        id: String,
        params: std::collections::HashMap<String, String>,
    ) -> Result<RunbookPreviewRow, FleetError> {
        let (rb, names) = {
            let c = lock(&self.cache);
            let rb = c.runbook(&id)?.ok_or_else(|| invalid("runbook"))?;
            let names: std::collections::HashMap<String, String> = c
                .servers()?
                .into_iter()
                .map(|s| (s.id.to_string(), s.name))
                .collect();
            (rb, names)
        };
        let given: std::collections::BTreeMap<String, String> = params.into_iter().collect();
        let values = rb
            .resolve_params(&given)
            .map_err(|e| invalid(&e.to_string()))?;
        let ops = rb.ops(&values).map_err(|e| invalid(&e.to_string()))?;
        Ok(RunbookPreviewRow {
            steps: rb
                .steps
                .iter()
                .zip(&ops)
                .map(|(s, op)| RunbookStepPreviewRow {
                    name: text::line(s.name.clone()),
                    op_name: op.name().to_string(),
                    elevated: fleet_core::opspec::needs_approval(op) || op.may_escalate(),
                    command: crate::bulk::clip(fleet_core::bulk::describe(op)),
                })
                .collect(),
            targets: rb
                .targets
                .iter()
                .map(|t| {
                    names
                        .get(t)
                        .map(|n| text::line(n.clone()))
                        .unwrap_or_else(|| format!("{} (removed)", text::line(t.clone())))
                })
                .collect(),
        })
    }
}

#[uniffi::export]
impl FleetCore {
    /// `agent.update.rollback` (Elevated: Touch ID): swaps the previous
    /// agent build back in and restarts. The agent refuses while an update
    /// is pending (its own timer owns that).
    pub async fn rollback_agent(&self, server_id: String) -> Result<(), FleetError> {
        match self
            .send_op(&server_id, Op::AgentUpdateRollback, None)
            .await?
        {
            Payload::Empty => Ok(()),
            p => unexpected(p),
        }
    }

    /// Renames a group.
    pub fn rename_group(&self, group_id: String, name: String) -> Result<(), FleetError> {
        let id = validate::group_id(&group_id)?;
        let name = validate::name(&name, "name")?;
        let cache = lock(&self.cache);
        let g = cache
            .groups()?
            .into_iter()
            .find(|g| g.id == id)
            .ok_or_else(|| invalid("group_id"))?;
        cache.upsert_group(&GroupRecord { name, ..g })?;
        Ok(())
    }

    /// Moves a server to `group_id` (none = ungrouped) and sets its tags.
    /// Pinned keys stay.
    pub fn set_server_placement(
        &self,
        server_id: String,
        group_id: Option<String>,
        tags: Vec<String>,
    ) -> Result<(), FleetError> {
        let id = validate::server_id(&server_id)?;
        let group = group_id.as_deref().map(validate::group_id).transpose()?;
        let tags = validate::tags(&tags)?;
        let mut cache = lock(&self.cache);
        if let Some(g) = &group
            && !cache.groups()?.iter().any(|x| &x.id == g)
        {
            return Err(invalid("group_id"));
        }
        let mut rec = cache.server(&id)?.ok_or_else(|| invalid("server_id"))?;
        rec.group = group;
        rec.tags = tags;
        cache.upsert_server(&rec)?;
        Ok(())
    }

    /// `logfiles.list`: readable log files on the agent's allow-list.
    pub async fn logfiles_list(&self, server_id: String) -> Result<Vec<LogFileRow>, FleetError> {
        match self.request(&server_id, Op::LogfilesList).await? {
            Payload::LogFiles(l) => Ok(l
                .files
                .into_iter()
                .map(log_file_row)
                .collect()),
            p => unexpected(p),
        }
    }

    /// `logfile.tail`: the last `lines` (<= 10000) lines of `path`, then
    /// new ones while `follow`. The agent checks its allow-list.
    pub fn tail_logfile(
        &self,
        server_id: String,
        path: String,
        lines: u16,
        follow: bool,
        sink: Box<dyn LogLinesSink>,
    ) -> Result<Arc<StreamHandle>, FleetError> {
        let id = validate::server_id(&server_id)?;
        let op = tail_op(path, lines, follow)?;
        let (handle, rt) = self.running()?;
        let (h, cancel) = StreamHandle::new();
        let sink: Arc<dyn LogLinesSink> = Arc::from(sink);
        let s1 = sink.clone();
        rt.spawn(run_stream(
            handle,
            id,
            move || op.clone(),
            move |p| {
                if let Payload::LogLines(l) = p {
                    s1.on_lines(text::lines(l.lines), l.rotated);
                }
            },
            move |st| sink.on_status(st),
            cancel,
        ));
        Ok(h)
    }

    /// `weblog.query` (Caddy/nginx JSON access logs), newest first.
    pub async fn weblog_query(
        &self,
        server_id: String,
        since_ms: Option<u64>,
        limit: u32,
        status_min: Option<u16>,
        status_max: Option<u16>,
        path_prefix: Option<String>,
        client: Option<String>,
    ) -> Result<WebLogRow, FleetError> {
        let op = weblog_op(since_ms, limit, status_min, status_max, path_prefix, client)?;
        match self.request(&server_id, op).await? {
            Payload::WebLogSummary(s) => Ok(WebLogRow {
                requests: s.requests,
                by_status: s
                    .by_status
                    .into_iter()
                    .map(|(c, n)| count(c.to_string(), n))
                    .collect(),
                top_clients: s
                    .top_clients
                    .into_iter()
                    .map(|(a, n)| count(a.to_string(), n))
                    .collect(),
                top_paths: s.top_paths.into_iter().map(|(p, n)| count(p, n)).collect(),
                scanner_hits: s.scanner_hits,
                entries: s
                    .entries
                    .into_iter()
                    .map(|e| WebLogEntryRow {
                        time_ms: e.time_ms,
                        client: e.client.to_string(),
                        method: text::line(e.method),
                        path: text::line(e.path),
                        status: e.status,
                        bytes: e.bytes,
                        user_agent: text::opt(e.user_agent),
                        log: text::line(e.log),
                    })
                    .collect(),
                truncated: s.truncated,
            }),
            p => unexpected(p),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_uses_raw_path_not_display_label() {
        let raw = "/var/log/evil\u{202E}txt\u{200B}.log";
        let row = log_file_row(fleet_proto::payload::LogFile {
            path: raw.into(),
            size_bytes: 1,
            mtime_ms: 2,
        });
        assert_eq!(row.path, raw);
        assert!(!row.label.contains('\u{202E}') && !row.label.contains('\u{200B}'));
        assert!(row.label.contains("\\u{202E}") && row.label.contains("\\u{200B}"));
        let want = |p: &str| match tail_op(p.into(), 10, false).unwrap() {
            Op::LogfileTail { path, .. } => path.as_str().to_owned(),
            _ => unreachable!(),
        };
        assert_eq!(want(&row.path), raw);
        // The escaped label would name a different file.
        assert_ne!(want(&row.label), raw);
        // Control characters are still refused.
        assert!(tail_op("/var/log/a\nb".into(), 10, false).is_err());
    }

    #[test]
    fn weblog_args_validated() {
        let op = weblog_op(Some(1), 100, Some(400), Some(499), Some("/api/".into()), None);
        assert!(op.is_ok());
        assert!(weblog_op(None, 0, None, None, None, None).is_err());
        assert!(weblog_op(None, 1001, None, None, None, None).is_err());
        assert!(weblog_op(None, 10, Some(400), None, None, None).is_err());
        assert!(weblog_op(None, 10, Some(500), Some(400), None, None).is_err());
        assert!(weblog_op(None, 10, None, None, Some("nope".into()), None).is_err());
        assert!(weblog_op(None, 10, None, None, None, Some("not-an-ip".into())).is_err());
        assert!(weblog_op(None, 10, None, None, Some(String::new()), Some(" ".into())).is_ok());
    }
}
