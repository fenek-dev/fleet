//! End-to-end encrypted sync (design §7.6): the engine, reconciliation
//! with the cache, key boxes and escrow (sealed and signed by this Mac,
//! checked against the roster), key rotation, sudo passwords.

use super::*;

impl FleetCore {
    /// Opens the engine with `key` over the local store.
    pub(crate) fn install_engine(&self, key: SyncKey) -> Result<(), FleetError> {
        let me = self.me()?;
        let store = self.fleet.open_store()?;
        let engine = SyncEngine::new(store, key, me).map_err(sync_err)?;
        *lock(&self.fleet.sync) = Some(engine);
        Ok(())
    }

    /// Writes local cache state the sync store doesn't have yet (and
    /// tombstones for items deleted locally). Needs the device key
    /// (unlocked); silently does nothing while locked.
    pub(super) fn reconcile(&self) -> Result<(), FleetError> {
        let Ok(signer) = RoleSigner::new(&*self.keys, KeyRole::Device) else {
            return Ok(());
        };
        let me = self.me()?;
        let agreement = lock(&self.fleet.secrets)
            .clone()
            .and_then(|s| s.agreement_public_key().ok());
        let now = fleet_core::now_ms();
        let mut sync = lock(&self.fleet.sync);
        let Some(engine) = sync.as_mut() else {
            return Ok(());
        };
        let cache = lock(&self.cache);
        let mut wants: Vec<(Collection, String, Option<Vec<u8>>)> = Vec::new();
        let servers = cache.servers()?;
        for s in &servers {
            wants.push((
                Collection::Servers,
                s.id.to_string(),
                Some(encode(&ServerDoc::from_record(s))),
            ));
            if let Some(p) = cache.pins(&s.id)? {
                wants.push((
                    Collection::PinnedKeys,
                    s.id.to_string(),
                    Some(encode(&PinsDoc::from_pins(&p))),
                ));
            }
        }
        for g in cache.groups()? {
            wants.push((
                Collection::Groups,
                g.id.clone(),
                Some(encode(&GroupDoc {
                    name: g.name,
                    sort: g.sort,
                })),
            ));
        }
        for r in rm::chain(&cache)? {
            wants.push((
                Collection::RosterChain,
                bridge::roster_key(&r),
                Some(bridge::roster_body(&r)),
            ));
        }
        // This Mac's key-agreement key, self-signed with its device key
        // (re-signed only when the key changes: signatures are randomized).
        if let Some(a) = agreement {
            let have = engine
                .get(Collection::DeviceKeys, &device_hex(&me))
                .map_err(sync_err)?
                .filter(|r| decode::<keys::DeviceKeysDoc>(&r.body).is_ok_and(|d| d.agreement == a))
                .map(|r| r.body);
            let body = match have {
                Some(b) => b,
                None => encode(&keys::DeviceKeysDoc::sign(&me, a, &signer).map_err(sync_err)?),
            };
            wants.push((Collection::DeviceKeys, device_hex(&me), Some(body)));
        }
        // Local deletions (servers and groups only; pins go with servers).
        for c in [Collection::Servers, Collection::Groups] {
            for r in engine.list(c).map_err(sync_err)? {
                if !wants.iter().any(|(wc, k, _)| *wc == c && *k == r.key) {
                    wants.push((c, r.key, None));
                }
            }
        }
        let pending_pins: Vec<String> = engine
            .pending_pin_changes()
            .map_err(sync_err)?
            .into_iter()
            .map(|r| r.key)
            .collect();
        drop(cache);
        for (c, k, body) in wants {
            let have = engine.get(c, &k).map_err(sync_err)?;
            match body {
                Some(b) => {
                    // Roster copies never change; pins under review wait.
                    let same = have.as_ref().is_some_and(|h| h.body == b);
                    let skip = (c == Collection::RosterChain && have.is_some())
                        || (c == Collection::PinnedKeys && pending_pins.contains(&k));
                    if !same && !skip {
                        engine.put(&signer, c, &k, b, now).map_err(sync_err)?;
                    }
                }
                None => {
                    if have.is_some() {
                        engine.delete(&signer, c, &k, now).map_err(sync_err)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Applies merged records to the cache, the manager and the Keychain.
    fn bridge_applied(&self, applied: &[fleet_core::sync::SyncRecord]) -> Result<bool, FleetError> {
        let mut order: Vec<&fleet_core::sync::SyncRecord> = applied.iter().collect();
        let rank = |c: Collection| match c {
            Collection::RosterChain => 0,
            Collection::Groups => 1,
            Collection::Servers => 2,
            Collection::PinnedKeys => 3,
            _ => 4,
        };
        order.sort_by_key(|r| rank(r.collection));
        let mut roster_added = false;
        let handle = self.running().ok().map(|(h, _)| h);
        for r in order {
            if r.collection == Collection::SudoPasswords {
                if let Ok(s) = self.secrets() {
                    if r.deleted {
                        let _ = s.delete_sudo_password(r.key.clone());
                    } else if let Ok(pw) = std::str::from_utf8(&r.body)
                        && fleet_core::sudo::is_valid(pw)
                    {
                        let _ = s.store_sudo_password(r.key.clone(), pw.to_string());
                    }
                }
                continue;
            }
            let res = bridge::apply_to_cache(&mut lock(&self.cache), r);
            match res {
                Ok(Bridged::Server(id) | Bridged::Pins(id)) => {
                    let _ = self.connect_pinned(&id);
                }
                Ok(Bridged::ServerRemoved(id)) => {
                    if let Some(h) = &handle {
                        h.remove_server(&id);
                    }
                }
                Ok(Bridged::Roster { .. }) => roster_added = true,
                Ok(_) => {}
                Err(fleet_core::sync::SyncError::RosterFork { epoch, version }) => {
                    self.alert(FleetAlertRow {
                        kind: FleetAlertKind::RosterFork,
                        server_id: None,
                        device_id: Some(device_hex(&r.author)),
                        title: "Conflicting rosters".into(),
                        detail: format!(
                            "Two different rosters claim epoch {epoch} version {version} (the synced one via {}). Someone signed conflicting roster updates: check which Macs are enrolled and revoke any you don't recognize.",
                            self.device_name(&r.author)
                        ),
                        pending_hash: None,
                        activates_at_ms: None,
                        signed: false,
                    })
                }
                Err(_) => self.alert(FleetAlertRow {
                    kind: FleetAlertKind::SyncRejected,
                    server_id: None,
                    device_id: Some(device_hex(&r.author)),
                    title: "A synced record was refused".into(),
                    detail: format!(
                        "{:?} {} from {}",
                        r.collection,
                        crate::text::line(r.key.clone()),
                        self.device_name(&r.author)
                    ),
                    pending_hash: None,
                    activates_at_ms: None,
                    signed: false,
                }),
            }
        }
        Ok(roster_added)
    }
}

#[uniffi::export]
impl FleetCore {
    // ---- sync ----

    /// Opens sync after enrollment. With no sync key in the Keychain, a
    /// single-Mac fleet creates one and escrows it to the recovery escrow
    /// key; a Mac in a multi-Mac fleet waits for its key box instead.
    /// Returns whether a new key was created.
    pub fn sync_setup(&self) -> Result<bool, FleetError> {
        if lock(&self.fleet.sync).is_some() {
            return Ok(false);
        }
        let secrets = self.secrets()?;
        if let Some(raw) = secrets.load_sync_key().map_err(keys_err)? {
            let raw = Zeroizing::new(raw);
            self.install_engine(SyncKey::from_bytes(&raw).map_err(sync_err)?)?;
            return Ok(false);
        }
        let (latest, fleet_id, me) = {
            let cache = lock(&self.cache);
            (
                rm::latest(&cache)?,
                FleetId(id16(&cache, SETTING_FLEET_ID)?),
                DeviceId(id16(&cache, SETTING_DEVICE_ID)?),
            )
        };
        if latest.roster.devices.len() != 1 || latest.roster.device(&me).is_none() {
            return Err(sync_err("waiting for the sync key from another Mac"));
        }
        let key = SyncKey::generate().map_err(sync_err)?;
        let signer =
            RoleSigner::new(&*self.keys, KeyRole::Device).map_err(|e| keys_err(e.into()))?;
        let escrow = keys::seal_escrow(
            &key,
            fleet_id,
            &latest.roster.recovery_escrow_key,
            &keys::Sealer {
                id: me,
                device: &signer,
            },
        )
        .map_err(sync_err)?;
        secrets
            .store_sync_key(key.to_bytes().to_vec())
            .map_err(keys_err)?;
        self.install_engine(key)?;
        lock(&self.fleet.extra_uploads).push(escrow);
        Ok(true)
    }

    pub fn sync_ready(&self) -> bool {
        lock(&self.fleet.sync).is_some()
    }

    /// Records to upload: local changes (reconciled from the cache) plus
    /// key boxes and escrow.
    pub fn sync_outgoing(&self) -> Result<Vec<CloudRecordRow>, FleetError> {
        self.reconcile()?;
        self.retire_old_escrow()?;
        let mut out: Vec<CloudRecordRow> = match lock(&self.fleet.sync).as_ref() {
            Some(e) => e
                .outgoing()
                .map_err(sync_err)?
                .into_iter()
                .map(Into::into)
                .collect(),
            None => Vec::new(),
        };
        out.extend(
            lock(&self.fleet.extra_uploads)
                .iter()
                .cloned()
                .map(Into::into),
        );
        Ok(out)
    }

    pub fn sync_mark_pushed(&self, names: Vec<String>) -> Result<(), FleetError> {
        lock(&self.fleet.extra_uploads).retain(|r| !names.contains(&r.name));
        if let Some(e) = lock(&self.fleet.sync).as_mut() {
            e.mark_pushed(&names).map_err(sync_err)?;
        }
        Ok(())
    }

    /// Record names to delete from the zone (old names after a rotation).
    pub fn sync_deletions(&self) -> Vec<String> {
        lock(&self.fleet.deletions).clone()
    }

    pub fn sync_mark_deleted(&self, names: Vec<String>) {
        lock(&self.fleet.deletions).retain(|n| !names.contains(n));
    }

    /// Merges fetched records and applies them to the cache.
    pub fn sync_ingest(&self, records: Vec<CloudRecordRow>) -> Result<SyncReportRow, FleetError> {
        let records: Vec<CloudRecord> = records.into_iter().map(Into::into).collect();
        self.ingest(&records)
    }

    /// This Mac's key-box record name (fetch it when `needs_key`).
    pub fn sync_keybox_record_name(&self) -> Result<String, FleetError> {
        let a = self.secrets()?.agreement_public_key().map_err(keys_err)?;
        Ok(keys::keybox_record_name(&self.me()?, &a))
    }

    /// Switches to the sync key in this Mac's key box (after a rotation):
    /// only one sealed by a Mac in the latest roster.
    pub fn sync_accept_keybox(&self, keybox: CloudRecordRow) -> Result<(), FleetError> {
        let secrets = self.secrets()?;
        let agreement = EnclaveAgreement::new(&*secrets)?;
        let (fid, key, sealed_by) =
            keys::open_keybox(&keybox.into(), self.me()?, &agreement).map_err(sync_err)?;
        if fid != self.fleet_id()? {
            return Err(sync_err("key box is for another fleet"));
        }
        let latest = rm::latest(&lock(&self.cache))?;
        sealed_by.verify(&latest.roster).map_err(sync_err)?;
        secrets
            .store_sync_key(key.to_bytes().to_vec())
            .map_err(keys_err)?;
        lock(&self.fleet.sync).take();
        self.install_engine(key)
    }

    pub fn sync_conflicts(&self) -> Result<Vec<SyncConflictRow>, FleetError> {
        let sync = lock(&self.fleet.sync);
        let Some(e) = sync.as_ref() else {
            return Ok(Vec::new());
        };
        let cs = e.conflicts().map_err(sync_err)?;
        drop(sync);
        Ok(cs
            .into_iter()
            .map(|c| SyncConflictRow {
                collection: format!("{:?}", c.local.collection),
                key: crate::text::line(c.local.key.clone()),
                local: crate::text::text(String::from_utf8_lossy(&c.local.body).into_owned()),
                remote: crate::text::text(String::from_utf8_lossy(&c.remote.body).into_owned()),
                remote_author: self.device_name(&c.remote.author),
            })
            .collect())
    }

    pub fn sync_resolve(
        &self,
        collection: String,
        key: String,
        choice: ConflictChoice,
        merged: Option<String>,
    ) -> Result<(), FleetError> {
        let c = Collection::ALL
            .into_iter()
            .find(|c| format!("{c:?}") == collection)
            .ok_or(FleetError::InvalidArgument {
                field: "collection".into(),
            })?;
        let res = match choice {
            ConflictChoice::KeepLocal => Resolution::KeepLocal,
            ConflictChoice::TakeRemote => Resolution::TakeRemote,
            ConflictChoice::Merged => Resolution::Merged(merged.unwrap_or_default().into_bytes()),
        };
        let signer =
            RoleSigner::new(&*self.keys, KeyRole::Device).map_err(|e| keys_err(e.into()))?;
        let mut sync = lock(&self.fleet.sync);
        let e = sync.as_mut().ok_or_else(|| sync_err("sync not set up"))?;
        e.resolve(&signer, c, &key, res, fleet_core::now_ms())
            .map_err(sync_err)?;
        Ok(())
    }

    pub fn pin_changes(&self) -> Result<Vec<PinChangeRow>, FleetError> {
        let changes = match lock(&self.fleet.sync).as_ref() {
            Some(e) => e.pending_pin_changes().map_err(sync_err)?,
            None => return Ok(Vec::new()),
        };
        Ok(changes
            .into_iter()
            .map(|r| PinChangeRow {
                server_name: ServerId::new(r.key.clone())
                    .ok()
                    .and_then(|id| lock(&self.cache).server(&id).ok().flatten())
                    .map(|s| s.name)
                    .unwrap_or_default(),
                server_id: r.key,
                changed_by: self.device_name(&r.author),
            })
            .collect())
    }

    /// The operator confirmed another Mac's change to a server's pins.
    pub fn confirm_pin_change(&self, server_id: String) -> Result<(), FleetError> {
        let rec = {
            let mut sync = lock(&self.fleet.sync);
            let e = sync.as_mut().ok_or_else(|| sync_err("sync not set up"))?;
            e.confirm_pin_change(&server_id).map_err(sync_err)?
        };
        self.bridge_applied(&[rec])?;
        let id = crate::validate::server_id(&server_id)?;
        if let Ok((h, _)) = self.running() {
            h.reconnect(&id);
        }
        Ok(())
    }

    pub fn reject_pin_change(&self, server_id: String) -> Result<(), FleetError> {
        let signer =
            RoleSigner::new(&*self.keys, KeyRole::Device).map_err(|e| keys_err(e.into()))?;
        let mut sync = lock(&self.fleet.sync);
        let e = sync.as_mut().ok_or_else(|| sync_err("sync not set up"))?;
        e.reject_pin_change(&signer, &server_id, fleet_core::now_ms())
            .map_err(sync_err)
    }

    /// A synced app setting (not a security setting: those never sync).
    pub fn synced_setting(&self, key: String) -> Option<Vec<u8>> {
        lock(&self.fleet.sync)
            .as_ref()
            .and_then(|e| e.get(Collection::Settings, &key).ok().flatten())
            .map(|r| r.body)
    }

    pub fn set_synced_setting(&self, key: String, value: Vec<u8>) -> Result<(), FleetError> {
        let signer =
            RoleSigner::new(&*self.keys, KeyRole::Device).map_err(|e| keys_err(e.into()))?;
        let mut sync = lock(&self.fleet.sync);
        let e = sync.as_mut().ok_or_else(|| sync_err("sync not set up"))?;
        e.put(
            &signer,
            Collection::Settings,
            &key,
            value,
            fleet_core::now_ms(),
        )
        .map_err(sync_err)?;
        Ok(())
    }

    // ---- sudo passwords ----

    /// Generates `server_id`'s sudo password if it has none (design §5.9):
    /// stored in the Keychain (via `SyncSecrets`) and synced. Returns
    /// whether one was created. The password is never returned here.
    pub fn ensure_sudo_password(&self, server_id: String) -> Result<bool, FleetError> {
        let id = crate::validate::server_id(&server_id)?;
        let signer =
            RoleSigner::new(&*self.keys, KeyRole::Device).map_err(|e| keys_err(e.into()))?;
        let secrets = self.secrets()?;
        let mut sync = lock(&self.fleet.sync);
        let e = sync.as_mut().ok_or_else(|| sync_err("sync not set up"))?;
        if e.get(Collection::SudoPasswords, id.as_str())
            .map_err(sync_err)?
            .is_some()
        {
            return Ok(false);
        }
        let pw = fleet_core::sudo::generate().map_err(|_| FleetError::Internal {
            message: "rng".into(),
        })?;
        e.put(
            &signer,
            Collection::SudoPasswords,
            id.as_str(),
            pw.as_bytes().to_vec(),
            fleet_core::now_ms(),
        )
        .map_err(sync_err)?;
        secrets
            .store_sudo_password(id.to_string(), pw.to_string())
            .map_err(keys_err)?;
        Ok(true)
    }

    /// Puts a synced sudo password back into the Keychain (e.g. the item
    /// was removed). Does not reveal it; the app reads the Keychain item
    /// behind Touch ID.
    pub fn restore_sudo_password(&self, server_id: String) -> Result<bool, FleetError> {
        let id = crate::validate::server_id(&server_id)?;
        let pw = lock(&self.fleet.sync)
            .as_ref()
            .and_then(|e| e.get(Collection::SudoPasswords, id.as_str()).ok().flatten())
            .map(|r| Zeroizing::new(r.body));
        let Some(pw) = pw else { return Ok(false) };
        let s = std::str::from_utf8(&pw).map_err(|_| sync_err("bad sudo password record"))?;
        self.secrets()?
            .store_sudo_password(id.to_string(), s.to_string())
            .map_err(keys_err)?;
        Ok(true)
    }
}

impl FleetCore {
    /// Records `pw` as `id`'s sudo password: synced when sync is set up
    /// and the device key is available (skipped if the record already
    /// holds it), and in the Keychain (add-or-update on the Swift side).
    pub(crate) fn put_sudo_password(&self, id: &ServerId, pw: &str) -> Result<(), FleetError> {
        if let Ok(signer) = RoleSigner::new(&*self.keys, KeyRole::Device)
            && let Some(e) = lock(&self.fleet.sync).as_mut()
        {
            let same = e
                .get(Collection::SudoPasswords, id.as_str())
                .map_err(sync_err)?
                .is_some_and(|r| Zeroizing::new(r.body).as_slice() == pw.as_bytes());
            if !same {
                e.put(
                    &signer,
                    Collection::SudoPasswords,
                    id.as_str(),
                    pw.as_bytes().to_vec(),
                    fleet_core::now_ms(),
                )
                .map_err(sync_err)?;
            }
        }
        self.secrets()?
            .store_sudo_password(id.to_string(), pw.to_string())
            .map_err(keys_err)
    }

    pub(crate) fn ingest(&self, records: &[CloudRecord]) -> Result<SyncReportRow, FleetError> {
        let now = fleet_core::now_ms();
        let mut total = SyncReportRow {
            applied: 0,
            conflicts: 0,
            pin_changes: 0,
            rejected: 0,
            needs_key: false,
        };
        // Two passes: records signed by a Mac whose roster arrives in the
        // same batch verify once that roster is in the chain.
        for pass in 0..2 {
            let chain = rm::chain(&lock(&self.cache))?;
            let rep = {
                let mut sync = lock(&self.fleet.sync);
                let e = sync.as_mut().ok_or_else(|| sync_err("sync not set up"))?;
                e.apply_remote(records, &chain, now).map_err(sync_err)?
            };
            let roster_added = self.bridge_applied(&rep.applied)?;
            total.applied += rep.applied.len() as u32;
            total.conflicts += rep.conflicts.len() as u32;
            total.pin_changes += rep.pin_changes.len() as u32;
            total.needs_key |= rep.other_key > 0;
            for (c, k) in &rep.conflicts {
                self.alert(FleetAlertRow {
                    kind: FleetAlertKind::SyncConflict,
                    server_id: None,
                    device_id: None,
                    title: "Edited on two Macs".into(),
                    detail: format!(
                        "{c:?} “{}” changed on another Mac too. Choose a version.",
                        crate::text::line(k.clone())
                    ),
                    pending_hash: None,
                    activates_at_ms: None,
                    signed: false,
                });
            }
            for k in &rep.pin_changes {
                self.alert(FleetAlertRow {
                    kind: FleetAlertKind::PinChange,
                    server_id: Some(k.clone()),
                    device_id: None,
                    title: "Another Mac changed pinned keys".into(),
                    detail: format!(
                        "Confirm the new host/agent keys for {} on this Mac before they are used.",
                        crate::text::line(k.clone())
                    ),
                    pending_hash: None,
                    activates_at_ms: None,
                    signed: false,
                });
            }
            if rep.future > 0 || rep.removed_author > 0 {
                self.alert(FleetAlertRow {
                    kind: FleetAlertKind::SyncRejected,
                    server_id: None,
                    device_id: None,
                    title: "Synced records were refused".into(),
                    detail: format!(
                        "{} stamped in the future, {} from a Mac no longer in the fleet.",
                        rep.future, rep.removed_author
                    ),
                    pending_hash: None,
                    activates_at_ms: None,
                    signed: false,
                });
            }
            if roster_added {
                self.reverify_store()?;
            }
            if !roster_added || pass == 1 {
                total.rejected = rep.rejected;
                break;
            }
        }
        if total.applied > 0 {
            self.sync_changed();
        }
        Ok(total)
    }

    /// After a roster change: stored rows that no longer verify against the
    /// chain (a removed Mac's rows stamped after its removal, future
    /// stamps) are dropped and reported.
    pub(super) fn reverify_store(&self) -> Result<(), FleetError> {
        let chain = rm::chain(&lock(&self.cache))?;
        let dropped = match lock(&self.fleet.sync).as_mut() {
            Some(e) => e.reverify(&chain, fleet_core::now_ms()).map_err(sync_err)?,
            None => return Ok(()),
        };
        if !dropped.is_empty() {
            self.alert(FleetAlertRow {
                kind: FleetAlertKind::SyncRejected,
                server_id: None,
                device_id: None,
                title: "Synced records dropped after a roster change".into(),
                detail: format!(
                    "{} record(s) no longer verify against the roster (e.g. written by a removed Mac after its removal).",
                    dropped.len()
                ),
                pending_hash: None,
                activates_at_ms: None,
                signed: false,
            });
        }
        Ok(())
    }

    /// New sync key after a revocation: re-seals every record, key boxes
    /// for the remaining Macs (their enclave keys from the `DeviceKeys`
    /// records), escrow to the roster's recovery escrow key(s).
    pub(super) fn rotate_sync_key(
        &self,
        roster: &SignedRoster,
    ) -> Result<(Vec<CloudRecord>, Vec<String>), FleetError> {
        let fleet_id = self.fleet_id()?;
        let me = self.me()?;
        let secrets = self.secrets()?;
        let signer =
            RoleSigner::new(&*self.keys, KeyRole::Device).map_err(|e| keys_err(e.into()))?;
        let sealer = keys::Sealer {
            id: me,
            device: &signer,
        };
        let now = fleet_core::now_ms();
        let mut sync = lock(&self.fleet.sync);
        let Some(engine) = sync.as_mut() else {
            return Ok((Vec::new(), Vec::new()));
        };
        // Rows written by Macs no longer in the roster are re-signed by
        // this Mac, so Macs joining later (which accept only current
        // members' records) still get them.
        let r = &roster.roster;
        engine
            .readopt(&signer, |a| r.device(a).is_some(), now)
            .map_err(sync_err)?;
        let new = SyncKey::generate().map_err(sync_err)?;
        secrets
            .store_sync_key(new.to_bytes().to_vec())
            .map_err(keys_err)?;
        let dev_keys = engine.list(Collection::DeviceKeys).map_err(sync_err)?;
        let (mut upload, delete) = engine.rotate(new).map_err(sync_err)?;
        for d in &r.devices {
            if d.id == me {
                continue;
            }
            // Only a key the roster device signed itself.
            let Some(agreement) = dev_keys
                .iter()
                .find(|rec| rec.key == device_hex(&d.id))
                .and_then(|rec| decode::<keys::DeviceKeysDoc>(&rec.body).ok())
                .and_then(|doc| doc.verified(d).ok().map(<[u8]>::to_vec))
            else {
                continue;
            };
            let name = keys::keybox_record_name(&d.id, &agreement);
            upload.push(
                keys::seal_keybox(engine.key(), fleet_id, d.id, &agreement, name, &sealer)
                    .map_err(sync_err)?,
            );
        }
        upload.push(
            keys::seal_escrow(engine.key(), fleet_id, &r.recovery_escrow_key, &sealer)
                .map_err(sync_err)?,
        );
        if let Some(p) = r.prev_recovery.filter(|p| p.active_at(now)) {
            upload.push(
                keys::seal_escrow(engine.key(), fleet_id, &p.recovery_escrow_key, &sealer)
                    .map_err(sync_err)?,
            );
        }
        lock(&self.fleet.deletions).extend(delete.iter().cloned());
        Ok((upload, delete))
    }

    /// Recovery-code rotation, finished: once the old code's grace window
    /// has closed, the old escrow must stop opening anything. Rotates the
    /// sync key (the old escrow held the current one), re-seals for the
    /// current Macs and code only, and deletes the old escrow record.
    /// Runs from `sync_outgoing`; needs the device key (skipped while
    /// locked) and does nothing until the window closes.
    fn retire_old_escrow(&self) -> Result<(), FleetError> {
        let due = {
            let cache = lock(&self.cache);
            match cache.setting(ESCROW_RETIRE)? {
                Some(b) if !b.is_empty() => decode::<(X25519Public, u64)>(&b)
                    .ok()
                    .filter(|(_, until)| *until <= fleet_core::now_ms()),
                _ => None,
            }
        };
        let Some((old_pub, _)) = due else {
            return Ok(());
        };
        if RoleSigner::new(&*self.keys, KeyRole::Device).is_err()
            || lock(&self.fleet.sync).is_none()
        {
            return Ok(());
        }
        let latest = rm::latest(&lock(&self.cache))?;
        let (upload, _) = self.rotate_sync_key(&latest)?;
        lock(&self.fleet.extra_uploads).extend(upload);
        let old = keys::escrow_record_name(&old_pub);
        if keys::escrow_record_name(&latest.roster.recovery_escrow_key) != old {
            lock(&self.fleet.deletions).push(old);
        }
        lock(&self.cache).set_setting(ESCROW_RETIRE, &[])?;
        Ok(())
    }

    /// Remembers to retire `old` (the replaced code's escrow key) once its
    /// grace window (`until_ms`) closes ([`FleetCore::retire_old_escrow`]).
    pub(crate) fn schedule_escrow_retirement(
        &self,
        old: X25519Public,
        until_ms: u64,
    ) -> Result<(), FleetError> {
        lock(&self.cache).set_setting(ESCROW_RETIRE, &encode(&(old, until_ms)))?;
        Ok(())
    }
}
