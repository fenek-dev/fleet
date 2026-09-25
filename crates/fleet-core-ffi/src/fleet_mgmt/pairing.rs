//! Joining a fleet, on the new Mac (design §5.12): the pairing offer
//! (committing to a secret), the code shown once the answer is fixed,
//! the operator's "codes match", and the verified chain and key box.

use super::*;

#[uniffi::export]
impl FleetCore {
    /// New Mac, step 1: its keys (the app must allow key creation) and the
    /// pairing code to show as a QR code or copy.
    pub fn create_pairing_offer(&self, device_name: String) -> Result<PairingOfferRow, FleetError> {
        if self.is_enrolled() {
            return Err(roster_err("already enrolled"));
        }
        let name = crate::validate::name(&device_name, "device_name")?;
        let secrets = self.secrets()?;
        let agreement = secrets.agreement_public_key().map_err(keys_err)?;
        let id = DeviceId(
            fleet_core::enroll::random_id16().map_err(|_| FleetError::Internal {
                message: "rng".into(),
            })?,
        );
        let noise = self.noise_key()?.public();
        let (offer, reveal) = PairingOffer::build(
            &*self.keys,
            agreement.clone(),
            noise,
            id,
            &name,
            fleet_core::now_ms(),
        )?;
        let row = PairingOfferRow {
            code: offer.to_code(),
            device_id: device_hex(&id),
            response_record: rm::pairing_record_name(&offer.nonce, "response"),
            keybox_record: keys::keybox_record_name(&id, &agreement),
        };
        *lock(&self.fleet.offer) = Some(OfferDraft {
            offer,
            reveal,
            response: None,
            confirmed: false,
        });
        Ok(row)
    }

    /// New Mac, step 2: the enrolled Mac's answer (fetched by
    /// `response_record`) is now fixed, so the committed secret is revealed
    /// (upload `reveal`); the verification code to compare. The answer
    /// can't change afterwards.
    pub fn pairing_verification_code(
        &self,
        response: CloudRecordRow,
    ) -> Result<PairingCodeRow, FleetError> {
        let mut g = lock(&self.fleet.offer);
        let d = g
            .as_mut()
            .ok_or_else(|| roster_err("no pairing in progress"))?;
        if response.name != rm::pairing_record_name(&d.offer.nonce, "response") {
            return Err(roster_err("not the answer to this pairing"));
        }
        let Ok(Blob::Pairing(resp)) = decode::<Blob>(&response.data) else {
            return Err(roster_err("malformed pairing answer"));
        };
        if resp.offer_nonce != d.offer.nonce {
            return Err(roster_err("not the answer to this pairing"));
        }
        if d.response.as_ref().is_some_and(|r| *r != resp) {
            return Err(roster_err("the pairing answer changed; start over"));
        }
        let sas = rm::sas(&d.offer, &resp, &d.reveal);
        d.response = Some(resp);
        let reveal = CloudRecord {
            name: rm::pairing_record_name(&d.offer.nonce, "reveal"),
            data: encode(&Blob::PairingReveal {
                offer_nonce: d.offer.nonce,
                reveal: d.reveal,
            }),
        };
        Ok(PairingCodeRow {
            verification_code: sas,
            reveal: reveal.into(),
        })
    }

    /// New Mac: the operator confirmed both screens show the same code.
    /// Required before `complete_pairing`.
    pub fn confirm_pairing_codes(&self) -> Result<(), FleetError> {
        let mut g = lock(&self.fleet.offer);
        let d = g
            .as_mut()
            .ok_or_else(|| roster_err("no pairing in progress"))?;
        if d.response.is_none() {
            return Err(roster_err("no verification code shown yet"));
        }
        d.confirmed = true;
        Ok(())
    }

    /// New Mac, final step after the operator confirmed the codes and the
    /// enrolled Mac approved: opens the key box with the enclave key,
    /// verifies the synced roster chain (the roster adding this Mac must be
    /// signed by the root key the verified answer named), stores it, and
    /// becomes enrolled. `records`: the whole zone.
    pub fn complete_pairing(
        &self,
        keybox: CloudRecordRow,
        records: Vec<CloudRecordRow>,
    ) -> Result<(), FleetError> {
        let (offer, resp) = {
            let g = lock(&self.fleet.offer);
            let d = g
                .as_ref()
                .ok_or_else(|| roster_err("no pairing in progress"))?;
            let r = d
                .response
                .clone()
                .ok_or_else(|| roster_err("codes not compared yet"))?;
            if !d.confirmed {
                return Err(roster_err("confirm that the codes match first"));
            }
            (d.offer.clone(), r)
        };
        let secrets = self.secrets()?;
        let agreement = EnclaveAgreement::new(&*secrets)?;
        let (fleet_id, key, sealed_by) =
            keys::open_keybox(&keybox.into(), offer.device_id, &agreement).map_err(sync_err)?;
        if fleet_id != resp.fleet_id {
            return Err(roster_err("key box is for another fleet"));
        }
        let records: Vec<CloudRecord> = records.into_iter().map(Into::into).collect();
        let chain = verified_chain(&key, &records, &resp, &offer)?;
        // The key box must come from the Mac we paired with, a member of
        // the verified roster.
        let latest = chain.last().ok_or_else(|| roster_err("empty chain"))?;
        if sealed_by.verify(&latest.roster).map_err(sync_err)? != resp.by {
            return Err(roster_err(
                "the key box wasn't sealed by the Mac you paired with",
            ));
        }
        {
            let cache = lock(&self.cache);
            for r in &chain {
                rm::store_own(&cache, r)?;
            }
            cache.set_setting(SETTING_FLEET_NAME, resp.fleet_name.as_bytes())?;
            cache.set_setting(SETTING_DEVICE_NAME, offer.name.as_bytes())?;
            cache.set_setting(SETTING_DEVICE_ID, &offer.device_id.0)?;
            cache.set_setting(SETTING_FLEET_ID, &fleet_id.0)?;
        }
        secrets
            .store_sync_key(key.to_bytes().to_vec())
            .map_err(keys_err)?;
        self.install_engine(key)?;
        lock(&self.fleet.offer).take();
        self.ingest(&records)?;
        Ok(())
    }
}

/// The roster chain from synced copies, checked for a joining Mac: a valid
/// genesis, every link valid, this Mac in the latest roster with the keys
/// it offered, and the roster that added it signed by the root key the
/// SAS-verified answer named.
fn verified_chain(
    key: &SyncKey,
    records: &[CloudRecord],
    resp: &PairingResponse,
    offer: &PairingOffer,
) -> Result<Vec<SignedRoster>, FleetError> {
    let rosters = rm::order_copies(
        records
            .iter()
            .filter_map(|r| key.open_record(r).ok())
            .filter(|s| s.record.collection == Collection::RosterChain && !s.record.deleted)
            .filter_map(|s| decode::<SignedRoster>(&s.record.body).ok())
            .collect(),
    )?;
    let genesis = rosters
        .first()
        .ok_or_else(|| roster_err("no roster copies in iCloud yet"))?;
    verify_genesis(genesis, genesis.roster.issued_at_ms).map_err(roster_err)?;
    if genesis.roster.fleet_id != resp.fleet_id {
        return Err(roster_err("roster copies are for another fleet"));
    }
    let tmp = Cache::open_in_memory()?;
    rm::store_own(&tmp, genesis)?;
    for r in &rosters[1..] {
        rm::store_chain_link(&tmp, r)?;
    }
    let chain = rm::chain(&tmp)?;
    let latest = chain.last().ok_or_else(|| roster_err("empty chain"))?;
    let mine = latest.roster.device(&offer.device_id).is_some_and(|d| {
        d.device_key == offer.device_key
            && d.noise_static == offer.noise_static
            && d.ssh_key == offer.ssh_key
    });
    let added_by_them = chain.iter().any(|r| {
        r.roster.device(&offer.device_id).is_some()
            && r.signer == KeyRef::Root(resp.by)
            && chain.iter().any(|p| {
                p.roster
                    .device(&resp.by)
                    .is_some_and(|d| d.root_key == resp.by_root_key)
            })
    });
    if !mine || !added_by_them {
        return Err(roster_err(
            "the roster doesn't list this Mac as approved by the Mac you paired with",
        ));
    }
    Ok(chain)
}
