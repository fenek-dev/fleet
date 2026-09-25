//! Merging and the push queue (design §7.6 "Merging").
//!
//! A sync cycle, driven by the app's transport (CloudKit in Swift):
//! fetch changed [`CloudRecord`]s → [`SyncEngine::apply_remote`] →
//! [`SyncEngine::outgoing`] → upload → [`SyncEngine::mark_pushed`].
//!
//! Rules for a verified remote version `R` of an item whose local version
//! is `L`:
//!
//! - no `L`, or `R` newer and descending from `L`: take `R`;
//! - same stamp: already have it; `R` older: keep `L` and re-push it;
//! - text documents (snippets, runbooks, profiles): `R` newer but based on
//!   another version than `L` (both edited since they last agreed), with
//!   different content → **conflict**: `L` stays, `R` is parked for the
//!   operator ([`SyncEngine::resolve`]);
//! - pinned keys: `R` would *change* an existing pin set → parked until the
//!   operator confirms on this Mac ([`SyncEngine::confirm_pin_change`]);
//!   new pins (a server another Mac added) apply directly;
//! - everything else: newest stamp wins (the HLC order is total).
//!
//! Local edits record as `base` the stamp of the version last synced, so a
//! Mac that edits the same document several times offline doesn't conflict
//! with itself.

use super::keys::SyncKey;
use super::store::{Row, SyncStore};
use super::{
    CloudRecord, Collection, Hlc, HlcClock, MAX_HLC_DRIFT_MS, SignedRecord, SyncError, SyncRecord,
    author_current, sign_record, verify_record,
};
use fleet_crypto::sig::Signer;
use fleet_proto::{DeviceId, SignedRoster, decode, encode};

const META_CLOCK: &str = "hlc";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyReport {
    /// Items that changed locally (the app reloads them / bridges them).
    pub applied: Vec<SyncRecord>,
    pub conflicts: Vec<(Collection, String)>,
    /// Server ids whose pin sets another Mac changed (need confirmation).
    pub pin_changes: Vec<String>,
    /// Undecryptable, malformed, or signed by no roster device.
    pub rejected: u32,
    /// Sealed with a sync key this Mac doesn't hold (rotated: fetch the key box).
    pub other_key: u32,
    /// Of `rejected`: stamped more than `MAX_HLC_DRIFT_MS` ahead.
    pub future: u32,
    /// Of `rejected`: new records by a Mac no longer in the roster.
    pub removed_author: u32,
}

/// A parked text-document conflict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    pub local: SyncRecord,
    pub remote: SyncRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    KeepLocal,
    TakeRemote,
    Merged(Vec<u8>),
}

pub struct SyncEngine {
    store: SyncStore,
    key: SyncKey,
    me: DeviceId,
    clock: HlcClock,
}

impl SyncEngine {
    pub fn new(store: SyncStore, key: SyncKey, me: DeviceId) -> Result<Self, SyncError> {
        let clock = match store.meta(META_CLOCK)? {
            Some(b) => HlcClock::restore(decode(&b).map_err(|_| SyncError::Malformed)?),
            None => HlcClock::new(me),
        };
        let mut clock = clock;
        // Always stamp as this Mac.
        let mut last = clock.last();
        last.node = me;
        clock = HlcClock::restore(last);
        Ok(Self {
            store,
            key,
            me,
            clock,
        })
    }

    pub fn key(&self) -> &SyncKey {
        &self.key
    }

    pub fn store(&self) -> &SyncStore {
        &self.store
    }

    fn tick(&mut self, wall_ms: u64) -> Result<Hlc, SyncError> {
        let h = self.clock.now(wall_ms);
        self.store.set_meta(META_CLOCK, &encode(&h))?;
        Ok(h)
    }

    fn write_local(
        &mut self,
        device: &dyn Signer,
        collection: Collection,
        key: &str,
        body: Vec<u8>,
        deleted: bool,
        wall_ms: u64,
    ) -> Result<SignedRecord, SyncError> {
        let old = self.store.get(collection, key)?;
        let synced = old.as_ref().and_then(|r| r.synced);
        let hlc = self.tick(wall_ms)?;
        let record = SyncRecord {
            collection,
            key: key.to_string(),
            hlc,
            base: synced,
            author: self.me,
            deleted,
            body,
        };
        let signed = sign_record(record, device)?;
        self.store.put(&Row {
            signed: signed.clone(),
            dirty: true,
            synced,
        })?;
        Ok(signed)
    }

    /// Creates or changes an item (queued for upload).
    pub fn put(
        &mut self,
        device: &dyn Signer,
        collection: Collection,
        key: &str,
        body: Vec<u8>,
        wall_ms: u64,
    ) -> Result<SignedRecord, SyncError> {
        self.write_local(device, collection, key, body, false, wall_ms)
    }

    /// Deletes an item (a tombstone syncs, so other Macs delete it too).
    pub fn delete(
        &mut self,
        device: &dyn Signer,
        collection: Collection,
        key: &str,
        wall_ms: u64,
    ) -> Result<SignedRecord, SyncError> {
        self.write_local(device, collection, key, Vec::new(), true, wall_ms)
    }

    /// The live (not deleted) item.
    pub fn get(&self, collection: Collection, key: &str) -> Result<Option<SyncRecord>, SyncError> {
        Ok(self
            .store
            .get(collection, key)?
            .map(|r| r.signed.record)
            .filter(|r| !r.deleted))
    }

    pub fn list(&self, collection: Collection) -> Result<Vec<SyncRecord>, SyncError> {
        Ok(self
            .store
            .rows(Some(collection))?
            .into_iter()
            .map(|r| r.signed.record)
            .filter(|r| !r.deleted)
            .collect())
    }

    /// Merges fetched records. `chain`: the roster chain (oldest first)
    /// that record signatures are checked against.
    pub fn apply_remote(
        &mut self,
        records: &[CloudRecord],
        chain: &[SignedRoster],
        wall_ms: u64,
    ) -> Result<ApplyReport, SyncError> {
        let mut rep = ApplyReport::default();
        for cr in records {
            let sr = match self.key.open_record(cr) {
                Ok(sr) => sr,
                Err(SyncError::OtherKey) => {
                    rep.other_key += 1;
                    continue;
                }
                Err(SyncError::Malformed)
                    if !matches!(
                        decode::<super::Blob>(&cr.data),
                        Ok(super::Blob::Record { .. })
                    ) =>
                {
                    // Escrow, key boxes and pairing records share the zone.
                    continue;
                }
                Err(_) => {
                    rep.rejected += 1;
                    continue;
                }
            };
            if verify_record(&sr, chain).is_err() {
                rep.rejected += 1;
                continue;
            }
            // Stamped too far ahead: quarantined, never merged (it would
            // win every later merge).
            if sr.record.hlc.wall_ms > wall_ms.saturating_add(MAX_HLC_DRIFT_MS) {
                rep.rejected += 1;
                rep.future += 1;
                continue;
            }
            // A removed Mac's records: only what this Mac already held
            // before the removal was known (the exact signed record); its
            // stamps are its own, so "written before removal" can't be
            // trusted for anything new.
            if !author_current(&sr.record.author, chain) {
                let held = self
                    .store
                    .get(sr.record.collection, &sr.record.key)?
                    .is_some_and(|l| l.signed == sr);
                if !held {
                    rep.rejected += 1;
                    rep.removed_author += 1;
                }
                continue;
            }
            self.clock.observe(&sr.record.hlc, wall_ms);
            self.merge(sr, &mut rep)?;
        }
        self.store
            .set_meta(META_CLOCK, &encode(&self.clock.last()))?;
        Ok(rep)
    }

    fn merge(&mut self, remote: SignedRecord, rep: &mut ApplyReport) -> Result<(), SyncError> {
        let r = &remote.record;
        let local = self.store.get(r.collection, &r.key)?;
        let take = |store: &SyncStore, rep: &mut ApplyReport| -> Result<(), SyncError> {
            store.put(&Row {
                signed: remote.clone(),
                dirty: false,
                synced: Some(remote.record.hlc),
            })?;
            rep.applied.push(remote.record.clone());
            Ok(())
        };
        let Some(local) = local else {
            return take(&self.store, rep);
        };
        let l = &local.signed.record;
        if r.hlc == l.hlc {
            if local.synced != Some(r.hlc) {
                self.store.put(&Row {
                    synced: Some(r.hlc),
                    dirty: false,
                    ..local
                })?;
            }
            return Ok(());
        }
        if r.hlc < l.hlc {
            // The cloud is behind us: make sure ours goes up.
            if !local.dirty {
                self.store.put(&Row {
                    dirty: true,
                    ..local
                })?;
            }
            return Ok(());
        }
        let differs = l.deleted != r.deleted || l.body != r.body;
        if r.collection.is_text_doc()
            && differs
            && !l.deleted
            && !r.deleted
            && r.base != Some(l.hlc)
        {
            self.store.put_conflict(&remote)?;
            rep.conflicts.push((r.collection, r.key.clone()));
            return Ok(());
        }
        if r.collection == Collection::PinnedKeys && differs && !l.deleted {
            self.store.put_pin_change(&remote)?;
            rep.pin_changes.push(r.key.clone());
            return Ok(());
        }
        take(&self.store, rep)
    }

    /// Local changes to upload, sealed with the current sync key.
    pub fn outgoing(&self) -> Result<Vec<CloudRecord>, SyncError> {
        self.store
            .rows(None)?
            .into_iter()
            .filter(|r| r.dirty)
            .map(|r| self.key.seal_record(&r.signed))
            .collect()
    }

    /// The upload of `names` succeeded.
    pub fn mark_pushed(&mut self, names: &[String]) -> Result<(), SyncError> {
        for row in self.store.rows(None)? {
            if !row.dirty {
                continue;
            }
            let r = &row.signed.record;
            if names.contains(&self.key.record_name(r.collection, &r.key)) {
                let hlc = r.hlc;
                self.store.put(&Row {
                    dirty: false,
                    synced: Some(hlc),
                    ..row
                })?;
            }
        }
        Ok(())
    }

    pub fn conflicts(&self) -> Result<Vec<Conflict>, SyncError> {
        let mut out = Vec::new();
        for remote in self.store.conflicts()? {
            let r = remote.record;
            if let Some(l) = self.store.get(r.collection, &r.key)? {
                out.push(Conflict {
                    local: l.signed.record,
                    remote: r,
                });
            }
        }
        Ok(out)
    }

    /// Settles a conflict with a new version stamped after both, based on
    /// the remote one (so every other Mac takes it without a new conflict).
    pub fn resolve(
        &mut self,
        device: &dyn Signer,
        collection: Collection,
        key: &str,
        choice: Resolution,
        wall_ms: u64,
    ) -> Result<SignedRecord, SyncError> {
        let remote = self
            .store
            .take_conflict(collection, key)?
            .ok_or(SyncError::NotFound)?;
        let local = self
            .store
            .get(collection, key)?
            .ok_or(SyncError::NotFound)?;
        let body = match choice {
            Resolution::KeepLocal => local.signed.record.body.clone(),
            Resolution::TakeRemote => remote.record.body.clone(),
            Resolution::Merged(b) => b,
        };
        self.clock.observe(&remote.record.hlc, wall_ms);
        // Base the resolution on the remote version.
        self.store.put(&Row {
            synced: Some(remote.record.hlc),
            ..local
        })?;
        self.put(device, collection, key, body, wall_ms)
    }

    pub fn pending_pin_changes(&self) -> Result<Vec<SyncRecord>, SyncError> {
        Ok(self
            .store
            .pin_changes()?
            .into_iter()
            .map(|s| s.record)
            .collect())
    }

    /// The operator confirmed another Mac's pin change: apply it. Returns
    /// the record for the cache bridge.
    pub fn confirm_pin_change(&mut self, key: &str) -> Result<SyncRecord, SyncError> {
        let remote = self
            .store
            .take_pin_change(key)?
            .ok_or(SyncError::NotFound)?;
        self.store.put(&Row {
            signed: remote.clone(),
            dirty: false,
            synced: Some(remote.record.hlc),
        })?;
        Ok(remote.record)
    }

    /// The operator refused it: keep ours and push it again (newer stamp).
    pub fn reject_pin_change(
        &mut self,
        device: &dyn Signer,
        key: &str,
        wall_ms: u64,
    ) -> Result<(), SyncError> {
        let remote = self
            .store
            .take_pin_change(key)?
            .ok_or(SyncError::NotFound)?;
        let local = self
            .store
            .get(Collection::PinnedKeys, key)?
            .ok_or(SyncError::NotFound)?;
        self.clock.observe(&remote.record.hlc, wall_ms);
        let body = local.signed.record.body.clone();
        self.store.put(&Row {
            synced: Some(remote.record.hlc),
            ..local
        })?;
        self.put(device, Collection::PinnedKeys, key, body, wall_ms)?;
        Ok(())
    }

    /// Re-checks every stored row against `chain` (after a roster change):
    /// rows that no longer verify (author removed before the row's stamp,
    /// never listed) or stamped more than `MAX_HLC_DRIFT_MS` ahead of
    /// `wall_ms` are dropped. Returns what was dropped.
    pub fn reverify(
        &mut self,
        chain: &[SignedRoster],
        wall_ms: u64,
    ) -> Result<Vec<(Collection, String)>, SyncError> {
        let mut dropped = Vec::new();
        for row in self.store.rows(None)? {
            let r = &row.signed.record;
            let future = r.hlc.wall_ms > wall_ms.saturating_add(MAX_HLC_DRIFT_MS);
            if future || verify_record(&row.signed, chain).is_err() {
                self.store.remove(r.collection, &r.key)?;
                dropped.push((r.collection, r.key.clone()));
            }
        }
        Ok(dropped)
    }

    /// Re-signs, as this Mac, every row whose author `keep` rejects (a Mac
    /// being revoked or lost), so Macs that join later — which accept only
    /// current roster members' records — still receive the data. Content
    /// is unchanged; the new stamp makes other Macs take it.
    pub fn readopt(
        &mut self,
        device: &dyn Signer,
        keep: impl Fn(&DeviceId) -> bool,
        wall_ms: u64,
    ) -> Result<u32, SyncError> {
        let mut n = 0;
        for row in self.store.rows(None)? {
            let r = row.signed.record;
            if keep(&r.author) {
                continue;
            }
            self.write_local(device, r.collection, &r.key, r.body, r.deleted, wall_ms)?;
            n += 1;
        }
        Ok(n)
    }

    /// Switches to `new` (revocation, design §5.12): every record is
    /// re-sealed under it. Returns `(uploads, names to delete)`; old names
    /// die with the old key. Key boxes and escrow are the caller's job.
    pub fn rotate(&mut self, new: SyncKey) -> Result<(Vec<CloudRecord>, Vec<String>), SyncError> {
        let rows = self.store.rows(None)?;
        let old_names: Vec<String> = rows
            .iter()
            .map(|r| {
                self.key
                    .record_name(r.signed.record.collection, &r.signed.record.key)
            })
            .collect();
        let uploads = rows
            .iter()
            .map(|r| new.seal_record(&r.signed))
            .collect::<Result<Vec<_>, _>>()?;
        self.key = new;
        Ok((uploads, old_names))
    }
}
