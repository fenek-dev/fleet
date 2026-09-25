//! Requests, responses and tool arguments.
//!
//! Every request carries the protocol version `v` and an id the response
//! echoes. The first request on a connection must be [`RequestBody::Hello`];
//! the app answers [`ResponseBody::Welcome`] once the client is paired
//! (which may wait for the operator's Touch ID), and refuses calls before.
//!
//! [`Call`] is one variant per MCP tool (`#[serde(tag = "tool")]`, snake
//! case names equal the tool names), so a tool call is forwarded as
//! `{"tool": "<name>", "args": {…}}` and parsed with the argument struct's
//! `deny_unknown_fields`. There are deliberately no calls for keys, roster,
//! policy, agent updates, recovery or sync (design §8).

use crate::opspec::OpSpec;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub v: u16,
    pub id: u64,
    pub body: RequestBody,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestBody {
    Hello(Hello),
    Call(Call),
}

/// First message: who the MCP client says it is. The app combines
/// `client_name` with the code signature of `fleetctl`'s parent process to
/// form the pairing identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// `clientInfo.name` from the MCP `initialize` request (≤ 64 bytes).
    pub client_name: String,
    pub client_version: String,
    /// 16 random bytes, hex; `Actor::Ai { session }`.
    pub session: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub v: u16,
    pub id: u64,
    pub body: Result<ResponseBody, ProtoError>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseBody {
    Welcome(Welcome),
    Tool(ToolOutput),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Welcome {
    pub app_version: String,
    /// Operator-visible name of this pairing.
    pub client_label: String,
}

/// A tool result. `summary` is produced by the app from Mac-side state and
/// fixed codes; everything a server sent is in `untrusted`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ToolOutput {
    pub summary: serde_json::Value,
    pub untrusted: Vec<UntrustedItem>,
}

/// Server-derived text, already redacted and truncated by the app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UntrustedItem {
    pub server: String,
    /// What produced it (`journal.query`, `docker.logs`, …).
    pub source: String,
    pub text: String,
    pub truncated: bool,
    /// Number of secrets replaced by `[REDACTED]`.
    pub redactions: u32,
}

/// Fixed errors; `fleetctl` words them for the AI. `NotRunning` is only
/// produced by `fleetctl` itself (no app on the socket).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case", tag = "error")]
pub enum ProtoError {
    #[error("the Fleet app is not running")]
    NotRunning,
    #[error("the Fleet app is locked; ask the operator to unlock it")]
    Locked,
    #[error("AI access is paused by the operator")]
    Paused,
    #[error("this MCP client is not paired with the Fleet app")]
    PairingRequired,
    #[error("the operator declined to pair this MCP client")]
    PairingDenied,
    #[error("this action needs the operator's approval in the Fleet app")]
    ApprovalRequired,
    #[error("the operator declined this action")]
    ApprovalDenied,
    #[error("rate limit reached; retry after {retry_after_ms} ms")]
    RateLimited { retry_after_ms: u64 },
    #[error("invalid argument: {field}")]
    InvalidArgument { field: String },
    #[error("unknown server: {server}")]
    UnknownServer { server: String },
    #[error("not supported: {what}")]
    Unsupported { what: String },
    #[error("protocol version mismatch (app {app}, client {client})")]
    Version { app: u16, client: u16 },
    #[error("server {server}: {code}")]
    Agent { server: String, code: String },
    #[error("internal error")]
    Internal,
}

// ---- tool arguments ----

macro_rules! args {
    ($(#[$m:meta])* $name:ident { $($body:tt)* }) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        #[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
        #[serde(deny_unknown_fields)]
        pub struct $name { $($body)* }
    };
}

macro_rules! choice {
    ($(#[$m:meta])* $name:ident { $($v:ident),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($v),+ }
    };
}

fn t() -> bool {
    true
}
fn d50() -> u16 {
    50
}
fn d200() -> u32 {
    200
}
fn d60() -> u32 {
    60
}

args!(
    /// Lists servers known to the app (Mac-side data only).
    ListServersArgs {
        /// Only servers with this tag.
        #[serde(default)]
        pub tag: Option<String>,
    }
);

choice!(SearchKind {
    Packages,
    Ports,
    Processes,
    Files,
    Journal,
    Users
});

args!(
    /// Fleet-wide search; each server searches locally.
    SearchArgs {
        pub kind: SearchKind,
        /// Literal text (no regex), 1–256 bytes.
        pub term: String,
        /// Server ids; empty = every server.
        #[serde(default)]
        pub servers: Vec<String>,
        #[serde(default)]
        pub case_sensitive: bool,
    }
);

args!(
    MetricsQueryArgs {
        pub server: String,
        #[serde(default)]
        pub since_ms: Option<u64>,
        #[serde(default)]
        pub until_ms: Option<u64>,
        /// Series ids; empty = all (≤ 256).
        #[serde(default)]
        pub series: Vec<u16>,
        /// Minute rollups (default) or raw samples.
        #[serde(default = "t")]
        pub minute_resolution: bool,
    }
);

choice!(ProcessSortArg {
    Cpu,
    Memory,
    Io,
    Pid
});

args!(
    ProcessesListArgs {
        pub server: String,
        pub sort: ProcessSortArg,
        /// 1–1000, default 50.
        #[serde(default = "d50")]
        pub limit: u16,
    }
);

choice!(LogPriorityArg {
    Emerg,
    Alert,
    Crit,
    Err,
    Warning,
    Notice,
    Info,
    Debug
});

args!(
    LogsQueryArgs {
        pub server: String,
        /// systemd units (`nginx.service`); empty = all.
        #[serde(default)]
        pub units: Vec<String>,
        #[serde(default)]
        pub priority: Option<LogPriorityArg>,
        /// Literal substring filter.
        #[serde(default)]
        pub grep: Option<String>,
        #[serde(default)]
        pub since_ms: Option<u64>,
        #[serde(default)]
        pub until_ms: Option<u64>,
        /// 1–1000, default 200.
        #[serde(default = "d200")]
        pub limit: u32,
    }
);

args!(
    LoginsQueryArgs {
        pub server: String,
        #[serde(default)]
        pub since_ms: Option<u64>,
        #[serde(default)]
        pub until_ms: Option<u64>,
        #[serde(default)]
        pub failed_only: bool,
        #[serde(default = "d200")]
        pub limit: u32,
    }
);

choice!(ServiceActionKind {
    Start,
    Stop,
    Restart,
    Reload,
    Enable,
    Disable
});

args!(
    ServiceActionArgs {
        pub servers: Vec<String>,
        /// `name.service`, `.timer` or `.socket`; never `fleet-*`.
        pub unit: String,
        pub action: ServiceActionKind,
    }
);

args!(
    ServerArgs {
        pub server: String,
    }
);

args!(
    FirewallApplyArgs {
        pub server: String,
        /// The ruleset as `firewall_get` returned it, edited.
        pub ruleset: serde_json::Value,
        /// The version `firewall_get` reported.
        pub expected_version: u64,
    }
);

args!(
    PackagesUpgradeArgs {
        pub servers: Vec<String>,
        #[serde(default)]
        pub security_only: bool,
    }
);

choice!(ContainerActionKind {
    Start,
    Stop,
    Restart
});

args!(
    DockerActionArgs {
        pub server: String,
        /// Container name or id.
        pub container: String,
        pub action: ContainerActionKind,
    }
);

args!(
    ComposeDeployArgs {
        pub server: String,
        /// `^[a-z0-9][a-z0-9_-]{0,62}$`; lives in `/srv/<project>/`.
        pub project: String,
        /// Full `compose.yaml` text (≤ 256 KiB).
        pub compose_yaml: String,
        #[serde(default = "t")]
        pub pull: bool,
    }
);

args!(
    ConfigDiffArgs {
        pub server: String,
        /// Absolute path of a tracked config file.
        pub path: String,
        pub from: u64,
        /// Default: the current version.
        #[serde(default)]
        pub to: Option<u64>,
    }
);

args!(
    ConfigRollbackArgs {
        pub server: String,
        pub path: String,
        pub version: u64,
    }
);

args!(
    /// Runs one typed operation on many servers. Canary mode is always on:
    /// the first server runs alone and must pass a health check.
    BulkRunArgs {
        pub servers: Vec<String>,
        pub op: OpSpec,
        #[serde(default = "t")]
        pub stop_on_failure: bool,
        /// 1–16, default 16.
        #[serde(default)]
        pub concurrency: Option<u16>,
    }
);

args!(
    /// Policy-gated (`shell.exec`, off by default); always needs approval.
    ShellExecArgs {
        pub servers: Vec<String>,
        /// Local user to run as (must be allowed by the server policy).
        pub user: String,
        pub command: String,
        /// 1–3600, default 60.
        #[serde(default = "d60")]
        pub timeout_s: u32,
    }
);

choice!(ProfileLevelArg { Baseline, Strict });
choice!(ProfileRoleArg { Docker, Web, Game });

args!(
    ProfileCheckArgs {
        pub server: String,
        pub level: ProfileLevelArg,
        #[serde(default)]
        pub roles: Vec<ProfileRoleArg>,
    }
);

args!(
    /// Returns an event and its surrounding events for explanation.
    ExplainEventArgs {
        pub server: String,
        /// Event sequence number from the server's event log.
        pub seq: u64,
    }
);

/// One variant per MCP tool; the snake-case variant name is the tool name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "tool", content = "args", rename_all = "snake_case")]
pub enum Call {
    FleetListServers(ListServersArgs),
    FleetSearch(SearchArgs),
    MetricsQuery(MetricsQueryArgs),
    ProcessesList(ProcessesListArgs),
    LogsQuery(LogsQueryArgs),
    LoginsQuery(LoginsQueryArgs),
    ServiceAction(ServiceActionArgs),
    FirewallGet(ServerArgs),
    FirewallApply(FirewallApplyArgs),
    PackagesUpgrade(PackagesUpgradeArgs),
    DockerAction(DockerActionArgs),
    ComposeDeploy(ComposeDeployArgs),
    ConfigDiff(ConfigDiffArgs),
    ConfigRollback(ConfigRollbackArgs),
    BulkRun(BulkRunArgs),
    ShellExec(ShellExecArgs),
    ProfileCheck(ProfileCheckArgs),
    ExplainEvent(ExplainEventArgs),
}

/// Tool names in listing order (design §8).
pub const TOOL_NAMES: [&str; 18] = [
    "fleet_list_servers",
    "fleet_search",
    "metrics_query",
    "processes_list",
    "logs_query",
    "logins_query",
    "service_action",
    "firewall_get",
    "firewall_apply",
    "packages_upgrade",
    "docker_action",
    "compose_deploy",
    "config_diff",
    "config_rollback",
    "bulk_run",
    "shell_exec",
    "profile_check",
    "explain_event",
];

impl Call {
    /// Parses a tool call; unknown tools and unknown fields are errors.
    pub fn from_tool(name: &str, args: serde_json::Value) -> Result<Self, String> {
        if !TOOL_NAMES.contains(&name) {
            return Err(format!("unknown tool {name}"));
        }
        let args = if args.is_null() {
            serde_json::Value::Object(Default::default())
        } else {
            args
        };
        serde_json::from_value(serde_json::json!({ "tool": name, "args": args }))
            .map_err(|e| e.to_string())
    }

    pub fn tool_name(&self) -> &'static str {
        match self {
            Call::FleetListServers(_) => TOOL_NAMES[0],
            Call::FleetSearch(_) => TOOL_NAMES[1],
            Call::MetricsQuery(_) => TOOL_NAMES[2],
            Call::ProcessesList(_) => TOOL_NAMES[3],
            Call::LogsQuery(_) => TOOL_NAMES[4],
            Call::LoginsQuery(_) => TOOL_NAMES[5],
            Call::ServiceAction(_) => TOOL_NAMES[6],
            Call::FirewallGet(_) => TOOL_NAMES[7],
            Call::FirewallApply(_) => TOOL_NAMES[8],
            Call::PackagesUpgrade(_) => TOOL_NAMES[9],
            Call::DockerAction(_) => TOOL_NAMES[10],
            Call::ComposeDeploy(_) => TOOL_NAMES[11],
            Call::ConfigDiff(_) => TOOL_NAMES[12],
            Call::ConfigRollback(_) => TOOL_NAMES[13],
            Call::BulkRun(_) => TOOL_NAMES[14],
            Call::ShellExec(_) => TOOL_NAMES[15],
            Call::ProfileCheck(_) => TOOL_NAMES[16],
            Call::ExplainEvent(_) => TOOL_NAMES[17],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_names_match_serde_tags() {
        let samples = [
            Call::FleetListServers(ListServersArgs { tag: None }),
            Call::FirewallGet(ServerArgs { server: "s".into() }),
            Call::ExplainEvent(ExplainEventArgs {
                server: "s".into(),
                seq: 1,
            }),
        ];
        for c in samples {
            let v = serde_json::to_value(&c).unwrap();
            assert_eq!(v["tool"], c.tool_name());
            let back = Call::from_tool(c.tool_name(), v["args"].clone()).unwrap();
            assert_eq!(back, c);
        }
    }

    #[test]
    fn rejects_unknown_tools_and_fields() {
        assert!(Call::from_tool("roster_update", serde_json::json!({})).is_err());
        assert!(
            Call::from_tool(
                "firewall_get",
                serde_json::json!({"server": "a", "sudo": true})
            )
            .is_err()
        );
        let c = Call::from_tool("fleet_list_servers", serde_json::Value::Null).unwrap();
        assert_eq!(c, Call::FleetListServers(ListServersArgs { tag: None }));
    }

    #[test]
    fn defaults_apply() {
        let c = Call::from_tool("logs_query", serde_json::json!({"server": "srv_a"})).unwrap();
        let Call::LogsQuery(a) = c else { panic!() };
        assert_eq!(a.limit, 200);
        assert!(a.units.is_empty());
    }

    #[test]
    fn errors_serialize_with_code() {
        let e = ProtoError::RateLimited { retry_after_ms: 5 };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["error"], "rate_limited");
        let back: ProtoError = serde_json::from_value(v).unwrap();
        assert_eq!(back, e);
    }
}
