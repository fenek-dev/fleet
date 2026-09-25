//! Agent events and fleet alerts: roster changes, pending recoveries,
//! "removed from the fleet", catch-up and roster pushes on connect.

use super::*;

impl FleetCore {
    /// Delivers one verified agent event: the existing listener plus the
    /// roster/recovery alerts (design §5.10).
    fn deliver(&self, listener: &dyn CoreListener, server: &ServerId, seq: u64, event: &Event) {
        listener.on_event(AgentEventRow::new(server.to_string(), seq, event));
        match event {
            Event::RosterChanged { epoch, version } => {
                let (chain, me) = {
                    let cache = lock(&self.cache);
                    let _ = rm::set_seen(&cache, server, (*epoch, *version));
                    (
                        rm::chain(&cache).unwrap_or_default(),
                        id16(&cache, SETTING_DEVICE_ID).ok(),
                    )
                };
                match rm::describe_version(&chain, *epoch, *version) {
                    Some(ch) if ch.by.as_ref().map(|b| b.0 .0) == me => {}
                    Some(ch) => {
                        let by = ch.by.as_ref().map_or("the recovery key".to_string(), |b| crate::text::line(b.1.clone()));
                        for (id, name) in &ch.added {
                            self.alert(FleetAlertRow {
                                kind: FleetAlertKind::MacAdded,
                                server_id: Some(server.to_string()),
                                device_id: Some(device_hex(id)),
                                title: format!("Mac added by {by}"),
                                detail: format!("{} joined the fleet (roster v{version}).", crate::text::line(name.clone())),
                                pending_hash: None,
                                activates_at_ms: None,
                                signed: true,
                            });
                        }
                        for (id, name) in &ch.removed {
                            self.alert(FleetAlertRow {
                                kind: FleetAlertKind::MacRevoked,
                                server_id: Some(server.to_string()),
                                device_id: Some(device_hex(id)),
                                title: format!("Mac revoked by {by}"),
                                detail: format!("{} was removed (roster v{version}).", crate::text::line(name.clone())),
                                pending_hash: None,
                                activates_at_ms: None,
                                signed: true,
                            });
                        }
                        if ch.added.is_empty() && ch.removed.is_empty() {
                            self.alert(FleetAlertRow {
                                kind: FleetAlertKind::RosterChanged,
                                server_id: Some(server.to_string()),
                                device_id: ch.by.as_ref().map(|b| device_hex(&b.0)),
                                title: format!("Roster changed by {by}"),
                                detail: if ch.recovery_changed {
                                    format!("The recovery code was replaced (roster v{version}).")
                                } else {
                                    format!("Roster v{version}.")
                                },
                                pending_hash: None,
                                activates_at_ms: None,
                                signed: true,
                            });
                        }
                    }
                    None => self.alert(FleetAlertRow {
                        kind: FleetAlertKind::RosterChanged,
                        server_id: Some(server.to_string()),
                        device_id: None,
                        title: "Roster changed on a server".into(),
                        detail: format!(
                            "{server} now holds roster epoch {epoch} v{version}, which this Mac hasn't seen. Details follow once it syncs."
                        ),
                        pending_hash: None,
                        activates_at_ms: None,
                        signed: true,
                    }),
                }
            }
            Event::RecoveryPending(p) => {
                lock(&self.fleet.pending_recoveries).insert(server.clone(), *p);
                self.alert(FleetAlertRow {
                    kind: FleetAlertKind::RecoveryPending,
                    server_id: Some(server.to_string()),
                    device_id: None,
                    title: "Fleet recovery pending".into(),
                    detail: format!(
                        "Someone used the recovery code on {server}. Veto it unless it was you."
                    ),
                    pending_hash: Some(hex::encode(p.hash)),
                    activates_at_ms: Some(p.activates_at_ms),
                    signed: true,
                });
            }
            Event::RecoveryVetoed { hash } => {
                lock(&self.fleet.pending_recoveries).remove(server);
                self.alert(FleetAlertRow {
                    kind: FleetAlertKind::RecoveryVetoed,
                    server_id: Some(server.to_string()),
                    device_id: None,
                    title: "Recovery vetoed".into(),
                    detail: format!(
                        "The pending recovery {} on {server} was vetoed.",
                        &hex::encode(hash)[..12]
                    ),
                    pending_hash: Some(hex::encode(hash)),
                    activates_at_ms: None,
                    signed: true,
                });
            }
            _ => {}
        }
    }

    fn removed_alert(&self, server: &ServerId, signed: bool) {
        // A server installed or added before its roster listed this Mac
        // refuses it until another Mac pushes the chain: not an attack.
        let waiting = {
            let cache = lock(&self.cache);
            let me = id16(&cache, SETTING_DEVICE_ID).ok().map(DeviceId);
            let chain = rm::chain(&cache).unwrap_or_default();
            let added = me.and_then(|me| {
                chain
                    .iter()
                    .find(|r| r.roster.device(&me).is_some())
                    .map(|r| (r.roster.epoch, r.roster.version))
            });
            let seen = rm::seen(&cache, server).ok().flatten();
            added.is_some_and(|a| seen.is_none_or(|s| s < a))
        };
        let (kind, title, detail) = if waiting {
            (
                FleetAlertKind::WaitingForRoster,
                "Waiting for a roster update".to_string(),
                format!(
                    "{server} doesn't list this Mac yet. It will once another Mac in the fleet connects to it."
                ),
            )
        } else {
            (
                FleetAlertKind::RemovedFromFleet,
                "This Mac may have been removed from the fleet".to_string(),
                format!(
                    "{server} refused this Mac{}. If no one revoked it, another Mac or the recovery code may have been used against you.",
                    if signed { " (signed by the agent)" } else { "" }
                ),
            )
        };
        self.alert(FleetAlertRow {
            kind,
            server_id: Some(server.to_string()),
            device_id: None,
            title,
            detail,
            pending_hash: None,
            activates_at_ms: None,
            signed,
        });
    }
}

/// Fleet-level handling of manager output: catch-up on Ready, deduped
/// live events, roster pushes to servers that are behind, alerts.
pub(crate) async fn fleet_events(
    core: Weak<FleetCore>,
    handle: ManagerHandle,
    listener: Arc<dyn CoreListener>,
) {
    let mut rx = handle.subscribe();
    loop {
        let ev = match rx.recv().await {
            Ok(ev) => ev,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
        };
        let Some(c) = core.upgrade() else { return };
        match ev {
            ManagerEvent::State {
                server,
                state,
                kind,
                ..
            } => {
                if state == ConnState::Ready {
                    let (core, handle, listener) = (core.clone(), handle.clone(), listener.clone());
                    tokio::spawn(on_ready(core, handle, listener, server, kind));
                } else {
                    lock(&c.fleet.tracker).forget(&server);
                }
            }
            ManagerEvent::Event { server, seq, event } => {
                let deliver = lock(&c.fleet.tracker).live(&server, seq);
                if let Some(cursor) = deliver {
                    if let Some(cur) = cursor {
                        let _ = catchup::store_cursor(&lock(&c.cache), &server, &cur);
                    }
                    c.deliver(&*listener, &server, seq, &event);
                }
            }
            ManagerEvent::RemovedFromFleet { server, signed } => c.removed_alert(&server, signed),
            ManagerEvent::HostKeyFirstUse { .. } => {}
        }
    }
}

async fn on_ready(
    core: Weak<FleetCore>,
    handle: ManagerHandle,
    listener: Arc<dyn CoreListener>,
    server: ServerId,
    kind: Option<SessionKind>,
) {
    let Some((pin, from)) = core.upgrade().and_then(|c| {
        let cache = lock(&c.cache);
        let pin = cache.pins(&server).ok().flatten()?.agent_signing?;
        Some((pin, catchup::load_cursor(&cache, &server).ok().flatten()))
    }) else {
        return;
    };
    if let Ok(up) = catchup::catch_up(&handle, &server, &pin, from).await
        && let Some(c) = core.upgrade()
    {
        for e in &up.events {
            c.deliver(&*listener, &server, e.seq, &e.event);
        }
        if let Some(cur) = up.cursor {
            let _ = catchup::store_cursor(&lock(&c.cache), &server, &cur);
        }
        lock(&c.fleet.tracker).caught_up(&server, &up);
    }
    // Servers behind on the roster catch up (rule 2) — needs a device
    // session; while locked they stay queued.
    if kind == Some(SessionKind::Device) {
        let behind = core.upgrade().is_some_and(|c| {
            rm::pending_servers(&lock(&c.cache), std::slice::from_ref(&server))
                .is_ok_and(|p| !p.is_empty())
        });
        if behind {
            let r = FleetCore::push_to(&handle, &core, vec![server.clone()]).await;
            if let (Some(c), Some(f)) = (core.upgrade(), r.failed.first()) {
                c.alert(FleetAlertRow {
                    kind: FleetAlertKind::RosterPushFailed,
                    server_id: Some(server.to_string()),
                    device_id: None,
                    title: "Roster update refused".into(),
                    detail: f.clone(),
                    pending_hash: None,
                    activates_at_ms: None,
                    signed: true,
                });
            }
        }
    }
}
