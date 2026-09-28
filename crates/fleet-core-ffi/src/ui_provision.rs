//! Provisioning wizard helpers for the app's Provision screen: the address
//! this Mac reaches a server from (for "only my Macs' IPs") and a small
//! library of saved profiles (design §9.2). The library is local to this
//! Mac (a MAC'd cache setting); it only fills the wizard form, and the
//! plan is validated and approved as usual.

use crate::api::{FleetCore, lock};
use crate::provision::{ProvisionChoiceRow, choice_row, to_choice};
use crate::types::FleetError;
use crate::validate;
use fleet_core::provision::ProvisionChoice;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

const LIBRARY_KEY: &str = "provision-profiles";
const MAX_PROFILES: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SavedProvisionProfileRow {
    /// `[a-z0-9-]{1,48}`; shown as `<name>.toml`.
    pub name: String,
    pub choice: ProvisionChoiceRow,
}

fn valid_profile_name(n: &str) -> bool {
    (1..=48).contains(&n.len())
        && !n.starts_with('-')
        && n.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The client address from `SSH_CONNECTION` (`client_ip client_port
/// server_ip server_port`), as the server saw it.
pub(crate) fn parse_ssh_connection(out: &str) -> Option<IpAddr> {
    let first = out.split_whitespace().next()?;
    let ip: IpAddr = first.parse().ok()?;
    let usable = match ip {
        IpAddr::V4(v) => !(v.is_unspecified() || v.is_loopback() || v.is_multicast()),
        IpAddr::V6(v) => !(v.is_unspecified() || v.is_loopback() || v.is_multicast()),
    };
    usable.then_some(ip)
}

fn load_library(cache: &fleet_core::cache::Cache) -> BTreeMap<String, ProvisionChoice> {
    cache
        .setting(LIBRARY_KEY)
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        .unwrap_or_default()
}

#[uniffi::export]
impl FleetCore {
    /// The address the server sees this Mac's SSH connection from
    /// (`SSH_CONNECTION` on a fixed `printenv` exec, no user data in the
    /// command). Behind a jump host that is the jump host's address, not
    /// this Mac's, so servers reached through one are refused.
    pub async fn provision_mac_source(&self, server_id: String) -> Result<String, FleetError> {
        let id = validate::server_id(&server_id)?;
        {
            let cache = lock(&self.cache);
            let rec = cache.server(&id)?.ok_or(FleetError::UnknownServer)?;
            if rec.target.proxy_jump.is_some() {
                return Err(FleetError::Provision {
                    reason: "this server is reached through a jump host, so its view of your \
                             address is the jump host's"
                        .into(),
                });
            }
        }
        let (handle, _) = self.running()?;
        let conn = handle.ssh(&id).ok_or(FleetError::NotStarted)?;
        let out = self
            .on_core(async move {
                conn.exec_capture("printenv SSH_CONNECTION", 512, Duration::from_secs(15))
                    .await
                    .map_err(FleetError::from)
            })
            .await?;
        let text = String::from_utf8_lossy(&out.stdout);
        parse_ssh_connection(&text)
            .map(|ip| ip.to_string())
            .ok_or(FleetError::Provision {
                reason: "the server didn't report this Mac's address".into(),
            })
    }

    pub fn provision_saved_profiles(&self) -> Vec<SavedProvisionProfileRow> {
        load_library(&lock(&self.cache))
            .into_iter()
            .map(|(name, c)| SavedProvisionProfileRow {
                name,
                choice: choice_row(&c),
            })
            .collect()
    }

    /// Saves (or replaces) `name`; the choice is validated like a wizard
    /// submit.
    pub fn provision_save_profile(
        &self,
        name: String,
        choice: ProvisionChoiceRow,
    ) -> Result<(), FleetError> {
        if !valid_profile_name(&name) {
            return Err(FleetError::Provision {
                reason: "profile name: lowercase letters, digits and dashes".into(),
            });
        }
        let ch = to_choice(choice)?;
        let cache = lock(&self.cache);
        let mut lib = load_library(&cache);
        if !lib.contains_key(&name) && lib.len() >= MAX_PROFILES {
            return Err(FleetError::Provision {
                reason: "too many saved profiles".into(),
            });
        }
        lib.insert(name, ch);
        let raw = serde_json::to_vec(&lib).map_err(|e| FleetError::Provision {
            reason: e.to_string(),
        })?;
        cache.set_setting(LIBRARY_KEY, &raw)?;
        Ok(())
    }

    pub fn provision_delete_profile(&self, name: String) -> Result<(), FleetError> {
        let cache = lock(&self.cache);
        let mut lib = load_library(&cache);
        if lib.remove(&name).is_some() {
            let raw = serde_json::to_vec(&lib).map_err(|e| FleetError::Provision {
                reason: e.to_string(),
            })?;
            cache.set_setting(LIBRARY_KEY, &raw)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_connection_client_address() {
        let ip = parse_ssh_connection("203.0.113.9 51022 198.51.100.4 22\n");
        assert_eq!(ip, Some("203.0.113.9".parse().unwrap()));
        assert_eq!(
            parse_ssh_connection("2001:db8::7 5 2001:db8::1 22"),
            Some("2001:db8::7".parse().unwrap())
        );
        for bad in ["", "\n", "not-an-ip 1 2 3", "127.0.0.1 1 2 3", "0.0.0.0 1 2 3", "::1 1 2 3",
                    "224.0.0.1 1 2 3", "203.0.113.9; rm -rf / 1 2 3"] {
            assert_eq!(parse_ssh_connection(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn profile_names() {
        assert!(valid_profile_name("web-docker-prod"));
        for bad in ["", "-a", "A", "a b", "a/b", "a.toml", &"a".repeat(49)] {
            assert!(!valid_profile_name(bad), "{bad:?}");
        }
    }
}
