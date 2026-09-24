//! [`SystemdApi`] over the system bus with `zbus` (pure Rust, tokio
//! executor). Only `org.freedesktop.systemd1` is ever addressed.

use super::{JobKind, JobResult, RawUnit, SdError, SystemdApi, UnitProps, UnitSignal, UnitWatch};
use crate::handler::LocalBoxFuture;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::time::Duration;
use zbus::message::Type as MsgType;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};
use zbus::{Connection, MatchRule, MessageStream, Proxy};

const DEST: &str = "org.freedesktop.systemd1";
const PATH: &str = "/org/freedesktop/systemd1";
const MANAGER: &str = "org.freedesktop.systemd1.Manager";
const UNIT_IFACE: &str = "org.freedesktop.systemd1.Unit";
const SERVICE_IFACE: &str = "org.freedesktop.systemd1.Service";
const PROPS_IFACE: &str = "org.freedesktop.DBus.Properties";
const UNIT_PATH_NS: &str = "/org/freedesktop/systemd1/unit";
/// Signals buffered per watch before the oldest are dropped.
const WATCH_QUEUE: usize = 1024;

type ListUnitsRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    OwnedObjectPath,
    u32,
    String,
    OwnedObjectPath,
);

fn bus(e: zbus::Error) -> SdError {
    if let zbus::Error::MethodError(name, _, _) = &e {
        let n = name.as_str();
        if n == "org.freedesktop.systemd1.NoSuchUnit" || n.ends_with(".LoadFailed") {
            return SdError::NoSuchUnit;
        }
    }
    SdError::Bus(e.to_string())
}

/// Real client. One connection, `Subscribe`d so systemd emits signals.
pub struct ZbusSystemd {
    conn: Connection,
}

impl ZbusSystemd {
    /// Connects to the system bus and calls `Manager.Subscribe`.
    pub async fn connect() -> Result<Self, SdError> {
        let conn = Connection::system().await.map_err(bus)?;
        let s = Self { conn };
        s.manager()
            .await?
            .call::<_, _, ()>("Subscribe", &())
            .await
            .map_err(bus)?;
        Ok(s)
    }

    async fn manager(&self) -> Result<Proxy<'static>, SdError> {
        Proxy::new(&self.conn, DEST, PATH, MANAGER)
            .await
            .map_err(bus)
    }

    async fn get_all(
        &self,
        path: &OwnedObjectPath,
        iface: &str,
    ) -> Result<HashMap<String, OwnedValue>, SdError> {
        let p = Proxy::new(&self.conn, DEST, path.as_str().to_owned(), PROPS_IFACE)
            .await
            .map_err(bus)?;
        p.call("GetAll", &(iface,)).await.map_err(bus)
    }

    async fn props(&self, unit: &str) -> Result<UnitProps, SdError> {
        // LoadUnit also answers for installed units that aren't loaded
        // (disabled); unknown names come back with LoadState "not-found".
        let path: OwnedObjectPath = self
            .manager()
            .await?
            .call("LoadUnit", &(unit,))
            .await
            .map_err(bus)?;
        let u = self.get_all(&path, UNIT_IFACE).await?;
        let mut p = UnitProps {
            description: str_prop(&u, "Description"),
            load_state: str_prop(&u, "LoadState"),
            active_state: str_prop(&u, "ActiveState"),
            sub_state: str_prop(&u, "SubState"),
            unit_file_state: str_prop(&u, "UnitFileState"),
            active_enter_us: u64_prop(&u, "ActiveEnterTimestamp"),
            ..UnitProps::default()
        };
        if unit.ends_with(".service") && p.load_state == "loaded" {
            // Resource accounting may be off; every field is optional.
            if let Ok(s) = self.get_all(&path, SERVICE_IFACE).await {
                p.main_pid = s.get("MainPID").and_then(|v| u32::try_from(v).ok());
                p.memory_bytes = u64_prop(&s, "MemoryCurrent");
                p.cpu_ns = u64_prop(&s, "CPUUsageNSec");
                p.tasks = u64_prop(&s, "TasksCurrent");
                p.restarts = s.get("NRestarts").and_then(|v| u32::try_from(v).ok());
            }
        }
        Ok(p)
    }

    async fn job(
        &self,
        kind: JobKind,
        unit: &str,
        timeout: Duration,
    ) -> Result<JobResult, SdError> {
        let mgr = self.manager().await?;
        // Subscribe before queuing so the JobRemoved can't be missed.
        let mut removed = mgr.receive_signal("JobRemoved").await.map_err(bus)?;
        let job: OwnedObjectPath = mgr
            .call(kind.method(), &(unit, "replace"))
            .await
            .map_err(bus)?;
        let wait = async {
            while let Some(msg) = removed.next().await {
                let Ok((_id, path, _unit, result)) =
                    msg.body()
                        .deserialize::<(u32, OwnedObjectPath, String, String)>()
                else {
                    continue;
                };
                if path == job {
                    return Some(result);
                }
            }
            None
        };
        match tokio::time::timeout(timeout, wait).await {
            Err(_) => Err(SdError::Timeout),
            Ok(None) => Err(SdError::Bus("signal stream ended".into())),
            Ok(Some(r)) => Ok(JobResult::parse(&r)),
        }
    }

    async fn enable(&self, unit: &str, enabled: bool) -> Result<(), SdError> {
        let mgr = self.manager().await?;
        let files = [unit];
        if enabled {
            // (carries_install_info, changes); `force` false.
            let _: (bool, Vec<(String, String, String)>) = mgr
                .call("EnableUnitFiles", &(&files[..], false, false))
                .await
                .map_err(bus)?;
        } else {
            let _: Vec<(String, String, String)> = mgr
                .call("DisableUnitFiles", &(&files[..], false))
                .await
                .map_err(bus)?;
        }
        mgr.call::<_, _, ()>("Reload", &()).await.map_err(bus)
    }

    async fn watch_impl(&self) -> Result<Box<dyn UnitWatch>, SdError> {
        let rule = MatchRule::builder()
            .msg_type(MsgType::Signal)
            .sender(DEST)
            .and_then(|b| b.interface(PROPS_IFACE))
            .and_then(|b| b.member("PropertiesChanged"))
            .and_then(|b| b.path_namespace(UNIT_PATH_NS))
            .and_then(|b| b.arg(0, UNIT_IFACE))
            .map_err(bus)?
            .build();
        let stream = MessageStream::for_match_rule(rule, &self.conn, Some(WATCH_QUEUE))
            .await
            .map_err(bus)?;
        Ok(Box::new(ZbusWatch(stream)))
    }
}

fn str_prop(m: &HashMap<String, OwnedValue>, k: &str) -> String {
    m.get(k)
        .and_then(|v| <&str>::try_from(v).ok())
        .map(str::to_owned)
        .unwrap_or_default()
}

/// systemd reports "unset" counters as `u64::MAX`.
fn u64_prop(m: &HashMap<String, OwnedValue>, k: &str) -> Option<u64> {
    m.get(k)
        .and_then(|v| u64::try_from(v).ok())
        .filter(|&v| v != u64::MAX)
}

struct ZbusWatch(MessageStream);

impl UnitWatch for ZbusWatch {
    fn next(&mut self) -> LocalBoxFuture<'_, Option<UnitSignal>> {
        Box::pin(async move {
            loop {
                let msg = match self.0.next().await? {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let header = msg.header();
                let Some(path) = header.path() else { continue };
                let Some(label) = path
                    .as_str()
                    .strip_prefix("/org/freedesktop/systemd1/unit/")
                else {
                    continue;
                };
                let Some(unit) = unescape_bus_label(label) else {
                    continue;
                };
                let Ok((_iface, changed, _invalidated)) =
                    msg.body()
                        .deserialize::<(String, HashMap<String, OwnedValue>, Vec<String>)>()
                else {
                    continue;
                };
                let active = str_prop(&changed, "ActiveState");
                if !active.is_empty() {
                    return Some(UnitSignal {
                        unit,
                        active_state: active,
                    });
                }
            }
        })
    }
}

/// Reverses systemd's object path escaping (`_xx` = byte `0xxx`), e.g.
/// `ssh_2eservice` → `ssh.service`. `None` on malformed input or non-UTF-8.
pub fn unescape_bus_label(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'_' {
            let hex = b.get(i + 1..i + 3)?;
            let hex = std::str::from_utf8(hex).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

impl SystemdApi for ZbusSystemd {
    fn list_units(&self) -> LocalBoxFuture<'_, Result<Vec<RawUnit>, SdError>> {
        Box::pin(async move {
            let rows: Vec<ListUnitsRow> = self
                .manager()
                .await?
                .call("ListUnits", &())
                .await
                .map_err(bus)?;
            Ok(rows
                .into_iter()
                .map(|r| RawUnit {
                    name: r.0,
                    description: r.1,
                    load_state: r.2,
                    active_state: r.3,
                    sub_state: r.4,
                })
                .collect())
        })
    }

    fn list_unit_files(&self) -> LocalBoxFuture<'_, Result<Vec<(String, String)>, SdError>> {
        Box::pin(async move {
            self.manager()
                .await?
                .call("ListUnitFiles", &())
                .await
                .map_err(bus)
        })
    }

    fn unit_props<'a>(&'a self, unit: &'a str) -> LocalBoxFuture<'a, Result<UnitProps, SdError>> {
        Box::pin(self.props(unit))
    }

    fn run_job<'a>(
        &'a self,
        kind: JobKind,
        unit: &'a str,
        timeout: Duration,
    ) -> LocalBoxFuture<'a, Result<JobResult, SdError>> {
        Box::pin(self.job(kind, unit, timeout))
    }

    fn set_enabled<'a>(
        &'a self,
        unit: &'a str,
        enabled: bool,
    ) -> LocalBoxFuture<'a, Result<(), SdError>> {
        Box::pin(self.enable(unit, enabled))
    }

    fn watch(&self) -> LocalBoxFuture<'_, Result<Box<dyn UnitWatch>, SdError>> {
        Box::pin(self.watch_impl())
    }
}
