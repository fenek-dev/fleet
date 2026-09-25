//! The roster from an enrolled Mac (design §5.12): status, adding a Mac
//! (commit-reveal SAS), revoking one, pushing the chain to servers.

use super::*;

impl FleetCore {
    /// Pushes the local chain to `servers`; records what each confirmed.
    pub(super) async fn push_to(
        handle: &ManagerHandle,
        core: &Weak<FleetCore>,
        servers: Vec<ServerId>,
    ) -> RosterChangeResult {
        let mut res = RosterChangeResult {
            version: 0,
            current: 0,
            queued: 0,
            failed: Vec::new(),
            upload: Vec::new(),
            delete: Vec::new(),
        };
        let Some(chain) = core.upgrade().and_then(|c| rm::chain(&lock(&c.cache)).ok()) else {
            return res;
        };
        res.version = chain.last().map_or(0, |r| r.roster.version);
        for s in servers {
            match rm::push_chain(handle, &s, &chain).await {
                PushOutcome::Current { epoch, version } => {
                    res.current += 1;
                    if let Some(c) = core.upgrade() {
                        let _ = rm::set_seen(&lock(&c.cache), &s, (epoch, version));
                    }
                }
                PushOutcome::Queued => res.queued += 1,
                PushOutcome::Rejected { at_version, code } => res
                    .failed
                    .push(format!("{s}: v{at_version} refused ({code:?})")),
                PushOutcome::Unknown(m) => res.failed.push(format!("{s}: {m}")),
            }
        }
        res
    }

    fn managed_servers(&self) -> Result<Vec<ServerId>, FleetError> {
        let cache = lock(&self.cache);
        let mut out = Vec::new();
        for rec in cache.servers()? {
            if spec_for(&cache, &rec)?.is_some() {
                out.push(rec.id);
            }
        }
        Ok(out)
    }

    /// Accepts the cached genesis for an agent install when it isn't this
    /// Mac's own (a Mac that joined later): it must be the first link of
    /// the verified local chain, and the latest roster must list this Mac
    /// with its current keys. The new server then learns the rest of the
    /// chain from any connected Mac already in its roster.
    pub(crate) fn genesis_is_anchor(
        &self,
        genesis: &SignedRoster,
        device_id: DeviceId,
    ) -> Result<(), FleetError> {
        let chain = rm::chain(&lock(&self.cache))?;
        let first_ok = chain.first() == Some(genesis);
        let noise = self.noise_key()?.public();
        let me_ok = chain
            .last()
            .and_then(|l| l.roster.device(&device_id))
            .is_some_and(|d| {
                d.noise_static == noise
                    && self
                        .keys
                        .public_key(KeyRole::Device)
                        .is_ok_and(|k| k == d.device_key)
                    && self
                        .keys
                        .public_key(KeyRole::Ssh)
                        .is_ok_and(|k| k == d.ssh_key)
            });
        if first_ok && me_ok {
            Ok(())
        } else {
            Err(roster_err("genesis roster is not part of this Mac's fleet"))
        }
    }
}

#[uniffi::export]
impl FleetCore {
    // ---- devices ----

    pub fn roster_status(&self) -> Result<RosterStatusRow, FleetError> {
        let servers = self.managed_servers()?;
        let cache = lock(&self.cache);
        let me = id16(&cache, SETTING_DEVICE_ID).ok().map(DeviceId);
        let latest = rm::latest(&cache)?;
        let name_of = |id: &DeviceId| {
            rm::chain(&cache)
                .ok()
                .and_then(|c| {
                    c.iter()
                        .rev()
                        .find_map(|r| r.roster.device(id).map(|d| d.name.as_str().to_string()))
                })
                .unwrap_or_else(|| device_hex(id))
        };
        let devices = latest
            .roster
            .devices
            .iter()
            .map(|d| DeviceRow {
                id: device_hex(&d.id),
                name: crate::text::line(d.name.as_str().to_string()),
                added_at_ms: d.added_at,
                added_by: crate::text::line(name_of(&d.added_by)),
                this_mac: Some(d.id) == me,
            })
            .collect();
        let pending = rm::pending_servers(&cache, &servers)?
            .into_iter()
            .map(|(id, seen)| PendingServerRow {
                name: cache
                    .server(&id)
                    .ok()
                    .flatten()
                    .map(|s| s.name)
                    .unwrap_or_default(),
                server_id: id.to_string(),
                seen_version: seen.map(|s| s.1),
            })
            .collect();
        let fleet_fingerprint = rm::chain(&cache)?
            .first()
            .map(fleet_core::recovery_flow::roster_fingerprint)
            .unwrap_or_default();
        Ok(RosterStatusRow {
            epoch: latest.roster.epoch,
            version: latest.roster.version,
            devices,
            pending,
            recovery_delay_s: latest.roster.recovery_delay_s,
            fleet_fingerprint,
        })
    }

    /// Enrolled Mac, step 2: parse a scanned or pasted pairing code, create
    /// the answer (upload `response`) and the verification code to compare.
    pub fn begin_add_mac(&self, code: String) -> Result<AddMacPrompt, FleetError> {
        let offer = PairingOffer::parse(&code, fleet_core::now_ms())?;
        let me = self.me()?;
        let (fleet_id, fleet_name, my_name, latest) = {
            let cache = lock(&self.cache);
            (
                FleetId(id16(&cache, SETTING_FLEET_ID)?),
                setting_str(&cache, SETTING_FLEET_NAME),
                setting_str(&cache, SETTING_DEVICE_NAME),
                rm::latest(&cache)?,
            )
        };
        if latest.roster.device(&offer.device_id).is_some() {
            return Err(roster_err("that Mac is already in the roster"));
        }
        let root = self
            .keys
            .public_key(KeyRole::Root)
            .map_err(|e| keys_err(e.into()))?;
        let resp = PairingResponse::new(&offer, fleet_id, &fleet_name, me, &my_name, root)?;
        let response = CloudRecord {
            name: rm::pairing_record_name(&offer.nonce, "response"),
            data: encode(&Blob::Pairing(resp.clone())),
        };
        let prompt = AddMacPrompt {
            name: crate::text::line(offer.name.clone()),
            device_id: device_hex(&offer.device_id),
            response: response.into(),
            reveal_record: rm::pairing_record_name(&offer.nonce, "reveal"),
        };
        lock(&self.fleet.requests).insert(
            offer.device_id,
            AddRequest {
                offer,
                response: resp,
                reveal: None,
            },
        );
        Ok(prompt)
    }

    /// Enrolled Mac: the new Mac's revealed secret (fetched by
    /// `reveal_record`) must open the offer's commitment; then the code to
    /// compare with the one the new Mac shows.
    pub fn add_mac_verification_code(
        &self,
        device_id: String,
        reveal: CloudRecordRow,
    ) -> Result<String, FleetError> {
        let id = parse_device(&device_id)?;
        let mut reqs = lock(&self.fleet.requests);
        let req = reqs
            .get_mut(&id)
            .ok_or_else(|| roster_err("no pairing request for that Mac"))?;
        if reveal.name != rm::pairing_record_name(&req.offer.nonce, "reveal") {
            return Err(roster_err("not the reveal for this pairing"));
        }
        let Ok(Blob::PairingReveal {
            offer_nonce,
            reveal: secret,
        }) = decode::<Blob>(&reveal.data)
        else {
            return Err(roster_err("malformed pairing reveal"));
        };
        if offer_nonce != req.offer.nonce || !req.offer.check_reveal(&secret) {
            return Err(roster_err(
                "the new Mac's reveal doesn't match its pairing code; start over",
            ));
        }
        req.reveal = Some(secret);
        Ok(rm::sas(&req.offer, &req.response, &secret))
    }

    /// Enrolled Mac, step 3–4 after the codes matched: roster v+1 (Touch
    /// ID: "add Mac <name>"), pushed to every server (offline ones are
    /// queued), the sync key sealed to the new Mac (upload `upload`).
    pub async fn approve_add_mac(
        self: Arc<Self>,
        device_id: String,
    ) -> Result<RosterChangeResult, FleetError> {
        let id = parse_device(&device_id)?;
        let offer = {
            let mut reqs = lock(&self.fleet.requests);
            match reqs.get(&id) {
                None => return Err(roster_err("no pairing request for that Mac")),
                // No code was shown yet: nothing to have compared.
                Some(r) if r.reveal.is_none() => {
                    return Err(roster_err("compare the verification codes first"));
                }
                Some(_) => {}
            }
            reqs.remove(&id)
                .map(|r| r.offer)
                .ok_or_else(|| roster_err("no pairing request for that Mac"))?
        };
        let servers = self.managed_servers()?;
        let core = self.clone();
        let offer2 = offer.clone();
        let n = servers.len();
        blocking("fleet-add-mac", move || {
            let me = core.me()?;
            let latest = rm::latest(&lock(&core.cache))?;
            let now = fleet_core::now_ms();
            let roster = rm::add_mac_roster(&latest, &offer2, me, now)?;
            let what = format!("add Mac {}", offer2.name);
            let signed = rm::sign_next(&*core.keys, me, &latest, roster, &what, n, now)?;
            rm::store_own(&lock(&core.cache), &signed)?;
            Ok(())
        })
        .await?;
        // The key box: the sync key sealed to the new Mac's enclave key,
        // after checking the new roster's device key signed that key.
        let mut upload = Vec::new();
        {
            let fleet_id = self.fleet_id()?;
            let me = self.me()?;
            let latest = rm::latest(&lock(&self.cache))?;
            let dev = latest
                .roster
                .device(&offer.device_id)
                .ok_or_else(|| roster_err("the new Mac is not in the roster"))?;
            let doc = offer.device_keys_doc();
            let agreement = doc.verified(dev).map_err(sync_err)?.to_vec();
            let signer =
                RoleSigner::new(&*self.keys, KeyRole::Device).map_err(|e| keys_err(e.into()))?;
            let mut sync = lock(&self.fleet.sync);
            if let Some(engine) = sync.as_mut() {
                let name = keys::keybox_record_name(&offer.device_id, &agreement);
                let kb = keys::seal_keybox(
                    engine.key(),
                    fleet_id,
                    offer.device_id,
                    &agreement,
                    name,
                    &keys::Sealer {
                        id: me,
                        device: &signer,
                    },
                )
                .map_err(sync_err)?;
                upload.push(kb.into());
                // Its self-signed key-agreement key, for key boxes after a
                // rotation.
                engine
                    .put(
                        &signer,
                        Collection::DeviceKeys,
                        &device_hex(&offer.device_id),
                        encode(&doc),
                        fleet_core::now_ms(),
                    )
                    .map_err(sync_err)?;
            }
        }
        let _ = self.reconcile();
        let (handle, _) = self.running()?;
        let weak = Arc::downgrade(&self);
        let mut res = self
            .on_core(async move { Ok(FleetCore::push_to(&handle, &weak, servers).await) })
            .await?;
        res.upload.extend(upload);
        self.sync_changed();
        Ok(res)
    }

    /// Revokes another Mac (Touch ID: "revoke Mac <name>"): roster v+1
    /// without it, pushed to every server; then the sync key is rotated,
    /// sealed to the remaining Macs and re-escrowed (upload/delete).
    pub async fn revoke_mac(
        self: Arc<Self>,
        device_id: String,
    ) -> Result<RosterChangeResult, FleetError> {
        let target = parse_device(&device_id)?;
        let name = self.device_name(&target);
        let servers = self.managed_servers()?;
        let core = self.clone();
        let signed = blocking("fleet-revoke-mac", move || {
            let me = core.me()?;
            let latest = rm::latest(&lock(&core.cache))?;
            let now = fleet_core::now_ms();
            let roster = rm::revoke_mac_roster(&latest, target, me, now)?;
            let what = format!("revoke Mac {name}");
            let signed =
                rm::sign_next(&*core.keys, me, &latest, roster, &what, servers.len(), now)?;
            rm::store_own(&lock(&core.cache), &signed)?;
            Ok(signed)
        })
        .await?;
        let (upload, delete) = self.rotate_sync_key(&signed)?;
        self.reverify_store()?;
        let _ = self.reconcile();
        let (handle, _) = self.running()?;
        let weak = Arc::downgrade(&self);
        let servers = self.managed_servers()?;
        let mut res = self
            .on_core(async move { Ok(FleetCore::push_to(&handle, &weak, servers).await) })
            .await?;
        res.upload.extend(upload.into_iter().map(Into::into));
        res.delete.extend(delete);
        self.sync_changed();
        Ok(res)
    }

    /// Retries roster pushes to every server still behind.
    pub async fn push_pending_rosters(self: Arc<Self>) -> Result<RosterChangeResult, FleetError> {
        let servers = self.managed_servers()?;
        let pending: Vec<ServerId> = rm::pending_servers(&lock(&self.cache), &servers)?
            .into_iter()
            .map(|(s, _)| s)
            .collect();
        let (handle, _) = self.running()?;
        let weak = Arc::downgrade(&self);
        self.on_core(async move { Ok(FleetCore::push_to(&handle, &weak, pending).await) })
            .await
    }
}
