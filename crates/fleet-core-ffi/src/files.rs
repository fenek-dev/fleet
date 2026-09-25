//! SFTP file browser (design §2.3) over the server's SSH connection; see
//! `fleet_core::sftp`. One SFTP channel per server is cached and reopened
//! when the connection changes. Local paths come from the operator's own
//! file pickers and drags.

use crate::api::{FleetCore, lock};
use crate::rows::{FileContents, RemoteFileRow};
use crate::types::{ConnState, FleetError};
use crate::validate;
use fleet_core::sftp::{MAX_EDIT_BYTES, Sftp, join, remote_path};
use fleet_proto::ServerId;
use std::sync::Arc;

/// Transfer progress; called on the core thread.
#[uniffi::export(callback_interface)]
pub trait TransferListener: Send + Sync {
    fn on_progress(&self, done_bytes: u64, total_bytes: u64);
}

impl FleetCore {
    /// The cached SFTP channel for `id`, reopened if the SSH connection
    /// changed. Runs `f` with it on the core runtime; a failure drops the
    /// cached channel so the next call reopens it.
    async fn with_sftp<T, F, Fut>(&self, server_id: &str, f: F) -> Result<T, FleetError>
    where
        T: Send + 'static,
        F: FnOnce(Arc<Sftp>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<T, FleetError>> + Send + 'static,
    {
        let id = validate::server_id(server_id)?;
        let (handle, _) = self.running()?;
        let conn = handle.ssh(&id).ok_or(FleetError::NotReady {
            state: handle
                .state(&id)
                .map(Into::into)
                .unwrap_or(ConnState::Disconnected),
        })?;
        let cached = lock(&self.sftp)
            .get(&id)
            .filter(|(c, _)| Arc::ptr_eq(c, &conn))
            .map(|(_, s)| s.clone());
        let sftp = match cached {
            Some(s) => s,
            None => {
                let c = conn.clone();
                let s = Arc::new(
                    self.on_core(async move { Sftp::open(&c).await.map_err(FleetError::from) })
                        .await?,
                );
                lock(&self.sftp).insert(id.clone(), (conn, s.clone()));
                s
            }
        };
        let r = self.on_core(f(sftp)).await;
        if matches!(r, Err(FleetError::File { .. })) {
            self.drop_sftp(&id);
        }
        r
    }

    fn drop_sftp(&self, id: &ServerId) {
        lock(&self.sftp).remove(id);
    }
}

#[uniffi::export]
impl FleetCore {
    /// The SSH user's home directory.
    pub async fn file_home(&self, server_id: String) -> Result<String, FleetError> {
        self.with_sftp(&server_id, |s| async move { Ok(s.home().await?) })
            .await
    }

    /// Directory entries, directories first.
    pub async fn file_list(
        &self,
        server_id: String,
        dir: String,
    ) -> Result<Vec<RemoteFileRow>, FleetError> {
        let dir = remote_path(&dir)?;
        self.with_sftp(&server_id, |s| async move {
            Ok(s.list(&dir).await?.into_iter().map(Into::into).collect())
        })
        .await
    }

    pub async fn file_stat(
        &self,
        server_id: String,
        path: String,
    ) -> Result<RemoteFileRow, FleetError> {
        let path = remote_path(&path)?;
        self.with_sftp(
            &server_id,
            |s| async move { Ok(s.stat(&path).await?.into()) },
        )
        .await
    }

    /// Loads a file for the editor (at most 4 MiB).
    pub async fn file_read(
        &self,
        server_id: String,
        path: String,
    ) -> Result<FileContents, FleetError> {
        let path = remote_path(&path)?;
        self.with_sftp(&server_id, |s| async move {
            let st = s.stat(&path).await?;
            let data = s.read_file(&path, MAX_EDIT_BYTES).await?;
            Ok(FileContents {
                size: data.len() as u64,
                data,
                mtime_s: st.mtime_s,
            })
        })
        .await
    }

    /// Saves an edited file. Refused with `FileChanged` when the file's
    /// size or mtime differs from `expected_size` / `expected_mtime_s`
    /// (someone changed it since it was loaded).
    pub async fn file_write(
        &self,
        server_id: String,
        path: String,
        data: Vec<u8>,
        expected_size: u64,
        expected_mtime_s: Option<u32>,
    ) -> Result<(), FleetError> {
        let path = remote_path(&path)?;
        if data.len() as u64 > MAX_EDIT_BYTES {
            return Err(FleetError::FileTooLarge {
                size: data.len() as u64,
            });
        }
        self.with_sftp(&server_id, move |s| async move {
            Ok(
                s.write_file(&path, &data, Some((expected_size, expected_mtime_s)))
                    .await?,
            )
        })
        .await
    }

    pub async fn file_rename(
        &self,
        server_id: String,
        from: String,
        to: String,
    ) -> Result<(), FleetError> {
        let (from, to) = (remote_path(&from)?, remote_path(&to)?);
        self.with_sftp(
            &server_id,
            |s| async move { Ok(s.rename(&from, &to).await?) },
        )
        .await
    }

    /// Creates `name` inside `parent`.
    pub async fn file_mkdir(
        &self,
        server_id: String,
        parent: String,
        name: String,
    ) -> Result<(), FleetError> {
        let path = join(&parent, &name)?;
        self.with_sftp(&server_id, |s| async move { Ok(s.mkdir(&path).await?) })
            .await
    }

    /// Removes a file, symlink or empty directory.
    pub async fn file_remove(&self, server_id: String, path: String) -> Result<(), FleetError> {
        let path = remote_path(&path)?;
        self.with_sftp(&server_id, |s| async move { Ok(s.remove(&path).await?) })
            .await
    }

    /// Sets permission bits (e.g. `0o644`).
    pub async fn file_chmod(
        &self,
        server_id: String,
        path: String,
        mode: u32,
    ) -> Result<(), FleetError> {
        let path = remote_path(&path)?;
        if mode > 0o7777 {
            return Err(FleetError::InvalidArgument {
                field: "mode".into(),
            });
        }
        self.with_sftp(&server_id, move |s| async move {
            Ok(s.chmod(&path, mode).await?)
        })
        .await
    }

    /// Copies a remote file to `local_path` (created or replaced).
    pub async fn file_download(
        &self,
        server_id: String,
        remote: String,
        local_path: String,
        listener: Option<Box<dyn TransferListener>>,
    ) -> Result<u64, FleetError> {
        let remote = remote_path(&remote)?;
        let local = validate::local_path(&local_path)?;
        self.with_sftp(&server_id, move |s| async move {
            Ok(s.download(&remote, &local, |d, t| {
                if let Some(l) = &listener {
                    l.on_progress(d, t)
                }
            })
            .await?)
        })
        .await
    }

    /// Uploads `local_path` into directory `remote_dir` under `name`,
    /// replacing an existing file of that name.
    pub async fn file_upload(
        &self,
        server_id: String,
        local_path: String,
        remote_dir: String,
        name: String,
        listener: Option<Box<dyn TransferListener>>,
    ) -> Result<u64, FleetError> {
        let local = validate::local_path(&local_path)?;
        let remote = join(&remote_dir, &name)?;
        self.with_sftp(&server_id, move |s| async move {
            Ok(s.upload(&local, &remote, None, false, |d, t| {
                if let Some(l) = &listener {
                    l.on_progress(d, t)
                }
            })
            .await?)
        })
        .await
    }
}
