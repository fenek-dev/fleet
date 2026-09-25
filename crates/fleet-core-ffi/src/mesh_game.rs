//! WireGuard mesh (fleet-level, `fleet_core::mesh_orch`) and game servers
//! (design §2.5, §9.x roles). Game start/stop go through the instance's
//! systemd unit `game-<name>.service` (`fleet_ops::game::template::unit`).

use crate::admin_ops::{invalid, unexpected};
use crate::admin_rows::*;
use crate::api::FleetCore;
use crate::text;
use crate::types::FleetError;
use crate::validate;
use fleet_core::mesh_orch::{self, MeshMember};
use fleet_proto::args::{Cidr, GameName, GameTemplateId, Port, RconCommand, UnitName};
use fleet_proto::{Actor, Op, Payload};
use std::sync::{Arc, Mutex};

fn game(name: &str) -> Result<GameName, FleetError> {
    GameName::new(name).map_err(|_| invalid("game"))
}

fn game_unit(name: &GameName) -> Result<UnitName, FleetError> {
    UnitName::new(format!("game-{}.service", name.as_str())).map_err(|_| invalid("game"))
}

#[uniffi::export]
impl FleetCore {
    // ---- mesh ----

    pub async fn mesh_status(&self, server_id: String) -> Result<MeshStatusRow, FleetError> {
        match self.send_op(&server_id, Op::MeshStatus, None).await? {
            Payload::MeshStatus(s) => Ok(s.into()),
            p => unexpected(p),
        }
    }

    /// Leaves the mesh (auto-revert: confirm with `confirm_change`).
    pub async fn mesh_leave(&self, server_id: String) -> Result<PendingChangeRow, FleetError> {
        match self.send_op(&server_id, Op::MeshLeave, None).await? {
            Payload::ChangePending(c) => Ok(c.into()),
            p => unexpected(p),
        }
    }

    /// Builds (or extends) a mesh over `members`: firewall port, joins,
    /// key distribution, each change confirmed from a fresh connection.
    /// Stops at the first failure; `steps` lists what was done.
    pub async fn mesh_create(
        &self,
        network: String,
        listen_port: u16,
        members: Vec<MeshMemberArgs>,
    ) -> Result<MeshRunRow, FleetError> {
        let network: Cidr = network.trim().parse().map_err(|_| invalid("network"))?;
        let port = Port::new(listen_port).map_err(|_| invalid("listen port"))?;
        let members = members
            .iter()
            .map(|m| {
                Ok(MeshMember {
                    server: validate::server_id(&m.server_id)?,
                    endpoint: match m.endpoint.as_deref().map(str::trim) {
                        None | Some("") => None,
                        Some(e) => Some(e.parse().map_err(|_| invalid("endpoint"))?),
                    },
                })
            })
            .collect::<Result<Vec<_>, FleetError>>()?;
        let (handle, _) = self.running()?;
        self.on_core(async move {
            let steps = Arc::new(Mutex::new(Vec::new()));
            let s1 = steps.clone();
            let res = mesh_orch::run(&handle, Actor::Human, network, port, &members, |p| {
                crate::api::lock(&s1).push(MeshStepRow {
                    server_id: p.server.to_string(),
                    step: p.step.into(),
                    detail: p.detail,
                });
            })
            .await;
            let steps = std::mem::take(&mut *crate::api::lock(&steps));
            Ok(MeshRunRow {
                steps,
                error: res.err().map(|e| text::line(e.to_string())),
            })
        })
        .await
    }

    // ---- game servers ----

    pub async fn game_status(&self, server_id: String) -> Result<Vec<GameRow>, FleetError> {
        match self
            .send_op(&server_id, Op::GameStatus { name: None }, None)
            .await?
        {
            Payload::Games(g) => Ok(g.games.into_iter().map(Into::into).collect()),
            p => unexpected(p),
        }
    }

    /// `template`: a built-in template id (`minecraft-paper`, `valheim`).
    pub async fn game_install(
        &self,
        server_id: String,
        name: String,
        template: String,
    ) -> Result<(), FleetError> {
        let op = Op::GameInstall {
            name: game(&name)?,
            template: GameTemplateId::new(template).map_err(|_| invalid("template"))?,
        };
        self.send_op(&server_id, op, None).await.map(|_| ())
    }

    pub async fn game_action(
        &self,
        server_id: String,
        name: String,
        action: GameAction,
    ) -> Result<(), FleetError> {
        let name = game(&name)?;
        let op = match action {
            GameAction::Start => Op::UnitStart {
                unit: game_unit(&name)?,
            },
            GameAction::Stop => Op::UnitStop {
                unit: game_unit(&name)?,
            },
            GameAction::Restart => Op::UnitRestart {
                unit: game_unit(&name)?,
            },
            GameAction::Update => Op::GameUpdate { name },
            GameAction::Backup => Op::GameBackup { name },
        };
        self.send_op(&server_id, op, None).await.map(|_| ())
    }

    pub async fn game_backups(
        &self,
        server_id: String,
        name: String,
    ) -> Result<Vec<GameBackupRow>, FleetError> {
        let op = Op::GameBackupsList { name: game(&name)? };
        match self.send_op(&server_id, op, None).await? {
            Payload::GameBackups(b) => Ok(b.backups.into_iter().map(Into::into).collect()),
            p => unexpected(p),
        }
    }

    pub async fn game_restore(
        &self,
        server_id: String,
        name: String,
        backup_id: u64,
    ) -> Result<(), FleetError> {
        let op = Op::GameRestore {
            name: game(&name)?,
            backup_id,
        };
        self.send_op(&server_id, op, None).await.map(|_| ())
    }

    pub async fn game_remove(
        &self,
        server_id: String,
        name: String,
        keep_data: bool,
    ) -> Result<(), FleetError> {
        let op = Op::GameRemove {
            name: game(&name)?,
            keep_data,
        };
        self.send_op(&server_id, op, None).await.map(|_| ())
    }

    /// One RCON console command; the server's answer (display text).
    pub async fn game_rcon(
        &self,
        server_id: String,
        name: String,
        command: String,
    ) -> Result<String, FleetError> {
        let op = Op::GameRcon {
            name: game(&name)?,
            command: RconCommand::new(command).map_err(|_| invalid("command"))?,
        };
        match self.send_op(&server_id, op, None).await? {
            Payload::RconOutput { text } => Ok(text::text(text)),
            p => unexpected(p),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn game_units() {
        let n = game("survival").unwrap();
        assert_eq!(game_unit(&n).unwrap().as_str(), "game-survival.service");
        assert!(game("../x").is_err());
    }
}
