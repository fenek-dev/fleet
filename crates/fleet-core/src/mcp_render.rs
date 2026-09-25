//! Server payloads as plain text for MCP tool results (design §8).
//!
//! Each payload type is rendered by its fields, YAML-like (`key: value`,
//! `- item`, multi-line strings as indented blocks), never with `Debug`
//! (which would quote strings and hide `password: …` behind escapes, so
//! redaction couldn't see it). Byte fields (`ShellResult` output) are
//! lossy UTF-8. The result then goes through `untrusted::prepare`
//! (escape, redact, cut).

use fleet_proto::Payload;
use fleet_proto::payload::ShellResult;
use serde::Serialize;
use serde_json::Value;

/// `p` as text ("" for `Empty`).
pub fn payload_text(p: &Payload) -> String {
    let mut out = String::new();
    render(p, &mut out, 0);
    out
}

fn render(p: &Payload, out: &mut String, indent: usize) {
    macro_rules! fields {
        ($v:expr) => {
            fields(p.name(), $v, out, indent)
        };
    }
    match p {
        Payload::Empty => {}
        Payload::ShellResult(r) => shell(r, out, indent),
        Payload::RconOutput { text } => block(text, out, indent),
        Payload::ChangePending { change, inner } => {
            fields!(change);
            if let Some(inner) = inner {
                line(out, indent, "result:");
                render(inner, out, indent + 1);
            }
        }
        Payload::Unknown { tag } => line(out, indent, &format!("unknown payload (tag {tag})")),
        Payload::SystemInfo(v) => fields!(v),
        Payload::AgentHealth(v) => fields!(v),
        Payload::RosterPending(v) => fields!(v),
        Payload::RosterState(v) => fields!(v),
        Payload::MetricsCatalog(v) => fields!(v),
        Payload::MetricsSample(v) => fields!(v),
        Payload::MetricsHistory(v) => fields!(v),
        Payload::ProcessList(v) => fields!(v),
        Payload::ProcessHistory(v) => fields!(v),
        Payload::Connections(v) => fields!(v),
        Payload::Timeline(v) => fields!(v),
        Payload::HealthChecks(v) => fields!(v),
        Payload::SignedEvents(v) => fields!(v),
        Payload::JournalEntries(v) => fields!(v),
        Payload::LogLines(v) => fields!(v),
        Payload::LogFiles(v) => fields!(v),
        Payload::WebLogSummary(v) => fields!(v),
        Payload::Logins(v) => fields!(v),
        Payload::Bans(v) => fields!(v),
        Payload::BanConfig(v) => fields!(v),
        Payload::Ports(v) => fields!(v),
        Payload::Certs(v) => fields!(v),
        Payload::AuditReport(v) => fields!(v),
        Payload::IntegrityStatus(v) => fields!(v),
        Payload::Units(v) => fields!(v),
        Payload::UnitStatus(v) => fields!(v),
        Payload::Firewall(v) => fields!(v),
        Payload::PendingChanges(v) => fields!(v),
        Payload::Packages(v) => fields!(v),
        Payload::Upgradable(v) => fields!(v),
        Payload::PackageHistory(v) => fields!(v),
        Payload::PackageChanges(v) => fields!(v),
        Payload::Containers(v) => fields!(v),
        Payload::ContainerDetail(v) => fields!(v),
        Payload::Images(v) => fields!(v),
        Payload::Volumes(v) => fields!(v),
        Payload::Networks(v) => fields!(v),
        Payload::DockerStats(v) => fields!(v),
        Payload::DockerLogChunk(v) => fields!(v),
        Payload::ComposeProjects(v) => fields!(v),
        Payload::Pruned(v) => fields!(v),
        Payload::CronTabs(v) => fields!(v),
        Payload::Timers(v) => fields!(v),
        Payload::Users(v) => fields!(v),
        Payload::AuthorizedKeys(v) => fields!(v),
        Payload::DiskUsage(v) => fields!(v),
        Payload::LargeFiles(v) => fields!(v),
        Payload::ConfigHistory(v) => fields!(v),
        Payload::ConfigDiff(v) => fields!(v),
        Payload::ConfigPaths(v) => fields!(v),
        Payload::ProfileCheck(v) => fields!(v),
        Payload::ProfilePlan(v) => fields!(v),
        Payload::ProfileApplied(v) => fields!(v),
        Payload::SearchResults(v) => fields!(v),
        Payload::MeshStatus(v) => fields!(v),
        Payload::Games(v) => fields!(v),
        Payload::GameBackups(v) => fields!(v),
        Payload::AlertRules(v) => fields!(v),
    }
}

fn shell(r: &ShellResult, out: &mut String, indent: usize) {
    let status = match r.exit_code {
        Some(c) => c.to_string(),
        None => "none (signal or timeout)".into(),
    };
    line(out, indent, &format!("exit_code: {status}"));
    if r.timed_out {
        line(out, indent, "timed_out: true");
    }
    if r.truncated {
        line(out, indent, "output_truncated: true");
    }
    for (name, bytes) in [("stdout", &r.stdout), ("stderr", &r.stderr)] {
        if bytes.is_empty() {
            continue;
        }
        line(out, indent, &format!("{name}:"));
        block(&String::from_utf8_lossy(bytes), out, indent + 1);
    }
}

fn fields<T: Serialize>(name: &str, v: &T, out: &mut String, indent: usize) {
    match serde_json::to_value(v) {
        Ok(v) => value(&v, out, indent),
        // Only for a map keyed by a non-string type; nothing to show.
        Err(_) => line(out, indent, &format!("({name}: not renderable)")),
    }
}

fn line(out: &mut String, indent: usize, s: &str) {
    for _ in 0..indent {
        out.push_str("  ");
    }
    out.push_str(s);
    out.push('\n');
}

fn block(s: &str, out: &mut String, indent: usize) {
    for l in s.lines() {
        line(out, indent, l);
    }
}

/// Fixed-size byte arrays (ids, hashes) as hex.
fn as_hex(items: &[Value]) -> Option<String> {
    if !matches!(items.len(), 16 | 32 | 64) {
        return None;
    }
    let bytes: Option<Vec<u8>> = items
        .iter()
        .map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()))
        .collect();
    bytes.map(hex::encode)
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::Null => Some("null".into()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) if !s.contains('\n') => Some(s.clone()),
        Value::Array(a) if a.is_empty() => Some("[]".into()),
        Value::Array(a) => as_hex(a),
        Value::Object(o) if o.is_empty() => Some("{}".into()),
        _ => None,
    }
}

fn value(v: &Value, out: &mut String, indent: usize) {
    match v {
        Value::Object(o) => {
            for (k, v) in o {
                entry(&format!("{k}:"), v, out, indent);
            }
        }
        Value::Array(a) if scalar(v).is_none() => {
            for v in a {
                entry("-", v, out, indent);
            }
        }
        Value::String(s) if s.contains('\n') => block(s, out, indent),
        v => line(out, indent, &scalar(v).unwrap_or_default()),
    }
}

fn entry(head: &str, v: &Value, out: &mut String, indent: usize) {
    match scalar(v) {
        Some(s) => line(out, indent, &format!("{head} {s}")),
        None => {
            line(out, indent, head);
            value(v, out, indent + 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_proto::payload::ConfigPaths;

    #[test]
    fn shell_output_is_lossy_text_not_debug() {
        let p = Payload::ShellResult(ShellResult {
            exit_code: Some(1),
            stdout: b"line one\nDB_PASSWORD=\"a b\"\n\xff\xfeend".to_vec(),
            stderr: vec![],
            truncated: false,
            timed_out: false,
        });
        let t = payload_text(&p);
        assert!(t.contains("exit_code: 1\n"), "{t}");
        assert!(
            t.contains("stdout:\n  line one\n  DB_PASSWORD=\"a b\"\n"),
            "{t}"
        );
        assert!(t.contains('\u{FFFD}'));
        // Not a byte array or Debug quoting.
        assert!(!t.contains("[108"));
        assert!(!t.contains("\\n"));
        assert!(!t.contains("stderr"));
    }

    #[test]
    fn struct_fields_as_key_value_lines() {
        let p = Payload::ConfigPaths(ConfigPaths {
            builtin_tracked: vec!["/etc/app.conf".into()],
            builtin_secret: vec![],
            tracked: vec!["password: two words".into()],
            secret: vec![],
            version: 3,
        });
        let t = payload_text(&p);
        assert!(t.contains("builtin_tracked:\n  - /etc/app.conf\n"), "{t}");
        assert!(t.contains("builtin_secret: []\n"), "{t}");
        assert!(t.contains("tracked:\n  - password: two words\n"), "{t}");
        assert!(t.contains("version: 3\n"), "{t}");
        assert!(!t.contains("ConfigPaths {"));
        assert_eq!(payload_text(&Payload::Empty), "");
    }
}
