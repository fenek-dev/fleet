//! Server overview extras: the profile a server was provisioned with
//! (Profile card, ui-design.md §Screens 2).

use crate::api::{FleetCore, lock};
use crate::bulk::ProfileLevelRow;
use crate::provision::{ProfileRoleRow, provisioned_profile, role_row};
use crate::types::FleetError;
use crate::validate;
use fleet_core::provision::{Level, ProvisionChoice};

/// Level and roles chosen when the server was provisioned.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ServerProfileRow {
    pub level: ProfileLevelRow,
    pub roles: Vec<ProfileRoleRow>,
}

fn summarize(c: &ProvisionChoice) -> ServerProfileRow {
    ServerProfileRow {
        level: match c.level {
            Level::Baseline => ProfileLevelRow::Baseline,
            Level::Strict => ProfileLevelRow::Strict,
        },
        roles: c.roles.iter().copied().map(role_row).collect(),
    }
}

#[uniffi::export]
impl FleetCore {
    /// `None` when the server was not provisioned from this Mac.
    pub fn server_profile(
        &self,
        server_id: String,
    ) -> Result<Option<ServerProfileRow>, FleetError> {
        let id = validate::server_id(&server_id)?;
        Ok(provisioned_profile(&lock(&self.cache), &id)
            .as_ref()
            .map(summarize))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_core::provision::Role;

    #[test]
    fn summarizes_level_and_roles() {
        let c = ProvisionChoice {
            level: Level::Strict,
            roles: vec![Role::Docker, Role::Web],
            admin_user: "ops".into(),
            allow_from: vec![],
            reboot_window: None,
            name: "web-04".into(),
            group: None,
            tags: vec![],
        };
        let s = summarize(&c);
        assert_eq!(s.level, ProfileLevelRow::Strict);
        assert_eq!(s.roles, vec![ProfileRoleRow::Docker, ProfileRoleRow::Web]);
    }
}
