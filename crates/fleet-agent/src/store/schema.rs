//! Database schema versions and copy-on-migrate (design §10.2 step 4).
//!
//! Schema version 1 lives in `state.redb`; version `N > 1` in
//! `state.redb.v<N>`. A build whose [`SCHEMA_VERSION`] has no file yet
//! copies the newest older file and migrates the **copy**, leaving the old
//! file untouched, so an agent update's rollback (the previous build opens
//! its own file again) loses at most what was written during the health
//! window. A build finding files of a *newer* schema removes them: they
//! belong to a build that was rolled back, and a later update must migrate
//! from current data, not resume that stale copy.
//!
//! No migration exists yet ([`MIGRATIONS`] is empty); the hook is here so
//! the first one needs no new plumbing.

use super::{Store, StoreError};
use redb::{ReadableDatabase, TableDefinition};
use std::path::{Path, PathBuf};

/// Schema this build reads and writes.
pub const SCHEMA_VERSION: u32 = 1;

/// `"version" → u32`: the schema a file holds (absent in files written
/// before versioning: version 1).
const SCHEMA: TableDefinition<&str, u32> = TableDefinition::new("schema");

/// Migrates an open copy from `to - 1` to `to`.
pub type Migration = fn(&Store) -> Result<(), StoreError>;

/// `(to_version, migration)`, ascending.
pub const MIGRATIONS: &[(u32, Migration)] = &[];

#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("database holds schema {found}, this build reads {want}")]
    Newer { found: u32, want: u32 },
}

impl From<SchemaError> for crate::exec::ExecError {
    fn from(e: SchemaError) -> Self {
        match e {
            SchemaError::Io(e) => Self::Io(e),
            SchemaError::Store(e) => Self::Store(e),
            SchemaError::Newer { .. } => Self::Corrupt("database schema is newer than this build"),
        }
    }
}

impl From<SchemaError> for crate::install::InstallError {
    fn from(e: SchemaError) -> Self {
        match e {
            SchemaError::Io(e) => Self::Io(e),
            SchemaError::Store(e) => Self::Store(e),
            SchemaError::Newer { .. } => Self::Io(std::io::Error::other(
                "database schema is newer than this build",
            )),
        }
    }
}

/// File holding schema `v` for the base path `state.redb`.
pub fn file_for(base: &Path, v: u32) -> PathBuf {
    if v <= 1 {
        return base.to_path_buf();
    }
    let mut name = base.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".v{v}"));
    base.with_file_name(name)
}

/// Schema versions of `state.redb.v<N>` files next to `base`.
fn versioned_files(base: &Path) -> std::io::Result<Vec<(u32, PathBuf)>> {
    let Some(dir) = base.parent() else {
        return Ok(Vec::new());
    };
    let prefix = format!(
        "{}.v",
        base.file_name().unwrap_or_default().to_string_lossy()
    );
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for e in entries {
        let e = e?;
        let name = e.file_name();
        let Some(v) = name
            .to_str()
            .and_then(|n| n.strip_prefix(&prefix))
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        out.push((v, e.path()));
    }
    out.sort();
    Ok(out)
}

fn stored_version(s: &Store) -> Result<Option<u32>, StoreError> {
    let db = super::read(&s.db);
    let tx = db.begin_read()?;
    let t = match tx.open_table(SCHEMA) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    Ok(t.get("version")?.map(|v| v.value()))
}

fn set_version(s: &Store, v: u32) -> Result<(), StoreError> {
    let db = super::read(&s.db);
    let tx = db.begin_write()?;
    {
        let mut t = tx.open_table(SCHEMA)?;
        t.insert("version", v)?;
    }
    tx.commit()?;
    Ok(())
}

/// Opens this build's database ([`SCHEMA_VERSION`]) for base path `base`.
pub fn open_versioned(base: &Path) -> Result<Store, SchemaError> {
    open_at(base, SCHEMA_VERSION, MIGRATIONS)
}

/// [`open_versioned`] for schema `target` with `migrations` (tests).
pub fn open_at(
    base: &Path,
    target: u32,
    migrations: &[(u32, Migration)],
) -> Result<Store, SchemaError> {
    for (v, p) in versioned_files(base)? {
        if v > target {
            // A rolled-back newer build's copy.
            std::fs::remove_file(&p)?;
        }
    }
    let path = file_for(base, target);
    if !path.exists() {
        let older = (1..target)
            .rev()
            .map(|v| (v, file_for(base, v)))
            .find(|(_, p)| p.exists());
        if let Some((from, src)) = older {
            let mut tmp = path.clone().into_os_string();
            tmp.push(".migrating");
            let tmp = PathBuf::from(tmp);
            let _ = std::fs::remove_file(&tmp);
            std::fs::copy(&src, &tmp)?;
            {
                let s = Store::open(&tmp)?;
                for (to, m) in migrations {
                    if *to > from && *to <= target {
                        m(&s)?;
                    }
                }
                set_version(&s, target)?;
            }
            std::fs::rename(&tmp, &path)?;
        }
    }
    let s = Store::open(&path)?;
    match stored_version(&s)? {
        Some(found) if found > target => {
            return Err(SchemaError::Newer {
                found,
                want: target,
            });
        }
        Some(found) if found == target => {}
        _ => set_version(&s, target)?,
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MetaKey;

    fn mark(s: &Store) -> Result<(), StoreError> {
        s.meta().update(&[(MetaKey::ServerId, Some(b"migrated"))])
    }

    #[test]
    fn migrates_into_a_copy_and_drops_newer_files_on_rollback() {
        let d = tempfile::tempdir().unwrap();
        let base = d.path().join("state.redb");
        {
            let s = open_at(&base, 1, &[]).unwrap();
            s.meta()
                .update(&[(MetaKey::ServerId, Some(b"v1"))])
                .unwrap();
        }
        // The update's first start: v2 migrates a copy.
        {
            let s = open_at(&base, 2, &[(2, mark)]).unwrap();
            assert_eq!(
                s.meta().get(MetaKey::ServerId).unwrap().as_deref(),
                Some(&b"migrated"[..])
            );
        }
        assert!(file_for(&base, 2).exists());
        // The old file is untouched.
        {
            let s = open_at(&base, 1, &[]).unwrap();
            assert_eq!(
                s.meta().get(MetaKey::ServerId).unwrap().as_deref(),
                Some(&b"v1"[..])
            );
        }
        // Rolled back: the v2 copy is gone, so the next update migrates
        // current data again.
        assert!(!file_for(&base, 2).exists());
        assert_eq!(
            file_for(&base, 3).file_name().unwrap().to_str(),
            Some("state.redb.v3")
        );
    }

    #[test]
    fn fresh_database_gets_the_target_file() {
        let d = tempfile::tempdir().unwrap();
        let base = d.path().join("state.redb");
        drop(open_at(&base, 2, &[]).unwrap());
        assert!(!base.exists());
        assert!(file_for(&base, 2).exists());
    }
}
