//! Terminal sessions (design §2.3): a PTY channel on the server's SSH
//! connection, backed by tmux so sessions survive disconnects.
//!
//! The PTY runs [`tmux_command`]: a **fixed** template whose only variable
//! part is the slot number (an integer), so no operator or server text is
//! ever interpolated into the command line (rule 4). Without tmux on the
//! server it falls back to the login shell. Data path: a task on the core
//! runtime reads the channel and hands each chunk to the Swift
//! [`TerminalSink`]; keystrokes and resizes come back through an unbounded
//! queue into the same task, so the channel has one owner.

use crate::api::FleetCore;
use crate::types::FleetError;
use crate::validate;
use fleet_core::ssh::PtyOutput;
use std::sync::Arc;
use tokio::sync::mpsc;

/// `TERM` for SwiftTerm.
const TERM: &str = "xterm-256color";

/// Receives terminal output on the core thread; return quickly.
#[uniffi::export(callback_interface)]
pub trait TerminalSink: Send + Sync {
    fn on_output(&self, data: Vec<u8>);
    /// The session ended; `exit_status` if the server sent one, `error`
    /// if the channel failed.
    fn on_closed(&self, exit_status: Option<u32>, error: Option<String>);
}

enum Cmd {
    Data(Vec<u8>),
    Resize(u32, u32),
    Close,
}

/// A live terminal. Dropping it closes the channel (the tmux session keeps
/// running on the server).
#[derive(uniffi::Object)]
pub struct TerminalSession {
    tx: mpsc::UnboundedSender<Cmd>,
}

#[uniffi::export]
impl TerminalSession {
    /// Keystrokes / pasted bytes.
    pub fn write(&self, data: Vec<u8>) {
        let _ = self.tx.send(Cmd::Data(data));
    }

    pub fn resize(&self, cols: u32, rows: u32) {
        let _ = self
            .tx
            .send(Cmd::Resize(cols.clamp(1, 1000), rows.clamp(1, 1000)));
    }

    /// Detaches (closes the channel). The tmux session stays.
    pub fn close(&self) {
        let _ = self.tx.send(Cmd::Close);
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = self.tx.send(Cmd::Close);
    }
}

/// `tmux new-session -A` attaches to `fleet-<slot>` or creates it; the
/// shell fallback runs when tmux is missing. Only `slot` varies. The status
/// bar is restyled per session (tmux's default bright green clashes with the
/// app); the user's global tmux options are left alone.
pub fn tmux_command(slot: u32) -> String {
    format!(
        "command -v tmux >/dev/null 2>&1 && exec tmux new-session -A -s fleet-{slot} \
         \\; set-option status-style bg=colour236,fg=colour250 \
         || exec \"${{SHELL:-/bin/sh}}\" -l"
    )
}

#[uniffi::export]
impl FleetCore {
    /// Opens a terminal on `server_id`'s SSH connection (the server must
    /// be Ready). `slot` names the tmux session (`fleet-<slot>`); with
    /// `tmux == false` it is a plain login shell.
    pub async fn open_terminal(
        &self,
        server_id: String,
        slot: u32,
        tmux: bool,
        cols: u32,
        rows: u32,
        sink: Box<dyn TerminalSink>,
    ) -> Result<Arc<TerminalSession>, FleetError> {
        let id = validate::server_id(&server_id)?;
        let (handle, _) = self.running()?;
        let conn = handle.ssh(&id).ok_or(FleetError::NotReady {
            state: handle
                .state(&id)
                .map(Into::into)
                .unwrap_or(crate::types::ConnState::Disconnected),
        })?;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let command = tmux.then(|| tmux_command(slot));
        let (cols, rows) = (cols.clamp(1, 1000), rows.clamp(1, 1000));
        let mut pty = self
            .on_core(async move {
                conn.open_pty_with(TERM, cols, rows, command.as_deref())
                    .await
                    .map_err(FleetError::from)
            })
            .await?;
        let (_, rt) = self.running()?;
        rt.spawn(async move {
            let mut status = None;
            let error = loop {
                tokio::select! {
                    out = pty.read() => match out {
                        Some(PtyOutput::Data(d)) => sink.on_output(d),
                        Some(PtyOutput::Exit(s)) => status = Some(s),
                        None => break None,
                    },
                    cmd = rx.recv() => {
                        let r = match cmd {
                            Some(Cmd::Data(d)) => pty.write(&d).await,
                            Some(Cmd::Resize(c, r)) => pty.resize(c, r).await,
                            Some(Cmd::Close) | None => {
                                let _ = pty.close().await;
                                break None;
                            }
                        };
                        if let Err(e) = r {
                            break Some(e.to_string());
                        }
                    }
                }
            };
            sink.on_closed(status, error);
        });
        Ok(Arc::new(TerminalSession { tx }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_template_is_fixed() {
        let c = tmux_command(3);
        assert!(c.contains("tmux new-session -A -s fleet-3 "));
        assert!(c.ends_with("exec \"${SHELL:-/bin/sh}\" -l"));
        assert_eq!(tmux_command(3), c);
    }
}
