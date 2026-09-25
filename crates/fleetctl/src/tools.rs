//! The MCP tool list: names, descriptions, input schemas, hints.

use fleetctl_proto::msg::*;
use rmcp::model::{JsonObject, Tool, ToolAnnotations};
use schemars::JsonSchema;
use std::sync::Arc;

fn schema<T: JsonSchema>() -> Arc<JsonObject> {
    let generator = schemars::generate::SchemaSettings::draft2020_12().into_generator();
    let schema = generator.into_root_schema_for::<T>();
    match serde_json::to_value(schema) {
        Ok(serde_json::Value::Object(o)) => Arc::new(o),
        _ => Arc::new(JsonObject::new()),
    }
}

const UNTRUSTED: &str = " Server-derived text in the result is marked as untrusted content.";

fn tool<T: JsonSchema>(name: &'static str, desc: &str, read_only: bool) -> Tool {
    let mut d = desc.to_string();
    if !matches!(name, "fleet_list_servers") {
        d.push_str(UNTRUSTED);
    }
    Tool::new(name, d, schema::<T>()).with_annotations(
        ToolAnnotations::new()
            .read_only(read_only)
            .destructive(!read_only),
    )
}

/// Every tool, in [`TOOL_NAMES`] order.
pub fn all() -> Vec<Tool> {
    let tools = vec![
        tool::<ListServersArgs>(
            "fleet_list_servers",
            "List managed servers with id, name, tags and connection state.",
            true,
        ),
        tool::<SearchArgs>(
            "fleet_search",
            "Search packages, ports, processes, files, journal or users across servers.",
            true,
        ),
        tool::<MetricsQueryArgs>(
            "metrics_query",
            "Query stored metrics (7 days) of one server.",
            true,
        ),
        tool::<ProcessesListArgs>("processes_list", "List processes on a server.", true),
        tool::<LogsQueryArgs>("logs_query", "Query the systemd journal of a server.", true),
        tool::<LoginsQueryArgs>(
            "logins_query",
            "Query SSH/console logins (optionally failed only) of a server.",
            true,
        ),
        tool::<ServiceActionArgs>(
            "service_action",
            "Start, stop, restart, reload, enable or disable a systemd unit on one or more \
             servers. More servers than the operator's threshold need their approval.",
            false,
        ),
        tool::<ServerArgs>(
            "firewall_get",
            "Get the Fleet-managed firewall ruleset and its version.",
            true,
        ),
        tool::<FirewallApplyArgs>(
            "firewall_apply",
            "Replace the Fleet-managed firewall ruleset (auto-reverts unless confirmed).",
            false,
        ),
        tool::<PackagesUpgradeArgs>(
            "packages_upgrade",
            "Upgrade packages (all or security only) on one or more servers.",
            false,
        ),
        tool::<DockerActionArgs>(
            "docker_action",
            "Start, stop or restart a Docker container.",
            false,
        ),
        tool::<ComposeDeployArgs>(
            "compose_deploy",
            "Deploy a Docker Compose project. Privileged features need the operator's approval.",
            false,
        ),
        tool::<ConfigDiffArgs>(
            "config_diff",
            "Diff two versions of a tracked config file. Secret files are never returned.",
            true,
        ),
        tool::<ConfigRollbackArgs>(
            "config_rollback",
            "Roll a tracked config file back to an earlier version.",
            false,
        ),
        tool::<BulkRunArgs>(
            "bulk_run",
            "Run one typed operation on many servers. Canary mode is enforced: the first \
             server runs alone and must pass a health check before the rest.",
            false,
        ),
        tool::<ShellExecArgs>(
            "shell_exec",
            "Run a shell command where the server policy allows shell.exec (off by default). \
             Always needs the operator's Touch ID.",
            false,
        ),
        tool::<ProfileCheckArgs>(
            "profile_check",
            "Check a server against a hardening profile (read-only).",
            true,
        ),
        tool::<ExplainEventArgs>(
            "explain_event",
            "Fetch an event and the events around it, for explaining what happened.",
            true,
        ),
    ];
    debug_assert!(tools.iter().map(|t| t.name.as_ref()).eq(TOOL_NAMES));
    tools
}

#[cfg(test)]
mod tests {
    use super::*;

    const FORBIDDEN: &[&str] = &[
        "roster",
        "policy",
        "key",
        "recovery",
        "sync",
        "agent_update",
        "enroll",
    ];

    #[test]
    fn names_match_protocol_and_nothing_privileged() {
        let tools = all();
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert_eq!(names, TOOL_NAMES);
        for n in names {
            for f in FORBIDDEN {
                assert!(!n.contains(f), "{n} looks like a forbidden tool");
            }
        }
    }

    /// Snapshot of names, descriptions and input schemas. Regenerate with
    /// `UPDATE_SNAPSHOTS=1 cargo test -p fleetctl`.
    #[test]
    fn schema_snapshot() {
        let tools = all();
        let v = serde_json::to_value(&tools).unwrap();
        let text = serde_json::to_string_pretty(&v).unwrap() + "\n";
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/tools.snapshot.json");
        if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
            std::fs::write(&path, &text).unwrap();
        }
        let want =
            std::fs::read_to_string(&path).expect("snapshot missing; run with UPDATE_SNAPSHOTS=1");
        assert_eq!(
            text, want,
            "tool schemas changed; review and regenerate the snapshot"
        );
    }

    #[test]
    fn schemas_forbid_unknown_fields() {
        for t in all() {
            let s = serde_json::Value::Object((*t.input_schema).clone());
            assert_eq!(s["type"], "object", "{}", t.name);
            assert_eq!(s["additionalProperties"], false, "{}", t.name);
        }
    }
}
