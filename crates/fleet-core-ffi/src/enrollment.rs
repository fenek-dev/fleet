//! Fleet bootstrap on the first Mac (design §5.3, §5.11); the core logic
//! is `fleet_core::enroll`.
//!
//! ```text
//! let e = core.create_fleet(fleet_name, device_name)   // ids + recovery code
//! e.recovery_words()                                    // once
//! e.challenge() / e.confirm_words(answers)              // 4 random words
//! await e.finish(passphrase)                            // Argon2id, Touch ID, persist
//! core.start(listener)
//! ```
//!
//! The words cross to Swift exactly once, for display (Swift strings can't
//! be wiped; the view drops them as soon as the check passes). The entropy
//! stays in Rust in a zeroizing buffer and is dropped by `finish` or
//! `cancel`.

use crate::api::{FleetCore, lock};
use crate::rows::EnrollmentResult;
use crate::types::FleetError;
use fleet_core::enroll::{self, EnrollError, GenesisInput};
use fleet_crypto::Zeroizing;
use fleet_crypto::recovery::{KdfParams, RecoveryCode, delay_for};
use fleet_proto::{DeviceId, FleetId};
use std::sync::{Arc, Mutex};

struct Draft {
    fleet_name: String,
    device_name: String,
    fleet_id: FleetId,
    device_id: DeviceId,
    code: RecoveryCode,
    words_shown: bool,
    challenge: Vec<u32>,
    confirmed: bool,
}

#[derive(uniffi::Object)]
pub struct Enrollment {
    core: Arc<FleetCore>,
    draft: Mutex<Option<Draft>>,
}

fn step(reason: &str) -> FleetError {
    FleetError::Enrollment {
        reason: reason.into(),
    }
}

impl From<EnrollError> for FleetError {
    fn from(e: EnrollError) -> Self {
        match e {
            EnrollError::Signer(fleet_core::signer::SignerError::Cancelled) => Self::Cancelled,
            EnrollError::Signer(s) => Self::Keys { error: s.into() },
            EnrollError::Name => Self::InvalidArgument {
                field: "device_name".into(),
            },
            EnrollError::Cache(c) => c.into(),
            other => step(&other.to_string()),
        }
    }
}

impl From<fleet_core::signer::SignerError> for crate::types::SignerError {
    fn from(e: fleet_core::signer::SignerError) -> Self {
        match e {
            fleet_core::signer::SignerError::Unavailable => Self::Unavailable,
            fleet_core::signer::SignerError::Cancelled => Self::Cancelled,
            fleet_core::signer::SignerError::Failed => Self::Failed,
        }
    }
}

#[uniffi::export]
impl FleetCore {
    /// Starts creating a new fleet with this Mac as its first device.
    pub fn create_fleet(
        self: Arc<Self>,
        fleet_name: String,
        device_name: String,
    ) -> Result<Arc<Enrollment>, FleetError> {
        if self.is_enrolled() {
            return Err(step("already enrolled"));
        }
        let fleet_name = crate::validate::name(&fleet_name, "fleet_name")?;
        let device_name = crate::validate::name(&device_name, "device_name")?;
        let rng = |_| FleetError::Internal {
            message: "rng".into(),
        };
        let draft = Draft {
            fleet_name,
            device_name,
            fleet_id: FleetId(enroll::random_id16().map_err(rng)?),
            device_id: DeviceId(enroll::random_id16().map_err(rng)?),
            code: RecoveryCode::generate().map_err(rng)?,
            words_shown: false,
            challenge: Vec::new(),
            confirmed: false,
        };
        Ok(Arc::new(Enrollment {
            core: self,
            draft: Mutex::new(Some(draft)),
        }))
    }
}

#[uniffi::export]
impl Enrollment {
    /// The 24 recovery words. Returned once; later calls fail.
    pub fn recovery_words(&self) -> Result<Vec<String>, FleetError> {
        let mut g = lock(&self.draft);
        let d = g.as_mut().ok_or_else(|| step("finished"))?;
        if d.words_shown {
            return Err(step("words already shown"));
        }
        d.words_shown = true;
        let phrase = d.code.phrase();
        Ok(phrase.split_whitespace().map(str::to_owned).collect())
    }

    /// Four distinct 0-based word positions to re-type (new ones per call).
    pub fn challenge(&self) -> Result<Vec<u32>, FleetError> {
        let mut g = lock(&self.draft);
        let d = g.as_mut().ok_or_else(|| step("finished"))?;
        if !d.words_shown {
            return Err(step("words not shown yet"));
        }
        d.challenge = enroll::challenge().map_err(|_| FleetError::Internal {
            message: "rng".into(),
        })?;
        d.confirmed = false;
        Ok(d.challenge.clone())
    }

    /// Checks the re-typed words against the last `challenge`.
    pub fn confirm_words(&self, answers: Vec<String>) -> Result<bool, FleetError> {
        let mut g = lock(&self.draft);
        let d = g.as_mut().ok_or_else(|| step("finished"))?;
        let ok = enroll::check_words(&d.code.phrase(), &d.challenge, &answers);
        // Wipe the typed words.
        answers.into_iter().for_each(|a| drop(Zeroizing::new(a)));
        d.confirmed = ok;
        Ok(ok)
    }

    /// Derives the recovery keys (Argon2id, 256 MiB), builds the genesis
    /// roster and signs it with the root key (Touch ID), stores it and the
    /// ids, then wipes the recovery code. An empty passphrase means none
    /// (72 h recovery delay). On failure the enrollment stays usable, so
    /// `finish` can be retried with the same words.
    pub async fn finish(&self, passphrase: String) -> Result<EnrollmentResult, FleetError> {
        let passphrase = Zeroizing::new(passphrase);
        let draft = {
            let mut g = lock(&self.draft);
            match g.as_ref() {
                None => return Err(step("finished")),
                Some(d) if !d.confirmed => return Err(step("recovery words not confirmed")),
                Some(_) => {}
            }
            g.take().expect("checked above")
        };
        let core = self.core.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        // Argon2 and Touch ID block: off the caller's executor.
        std::thread::Builder::new()
            .name("fleet-enroll".into())
            .spawn(move || {
                let r = finish_blocking(&core, &draft, &passphrase);
                // On failure (e.g. Touch ID cancelled) hand the draft back
                // so the operator can retry with the same written words.
                let back = r.is_err().then_some(draft);
                let _ = tx.send((r, back));
            })
            .map_err(|e| FleetError::Internal {
                message: e.to_string(),
            })?;
        let (r, back) = rx.await.map_err(|_| FleetError::Stopped)?;
        if let Some(d) = back {
            *lock(&self.draft) = Some(d);
        }
        r
    }

    /// Abandons the enrollment and wipes the recovery code.
    pub fn cancel(&self) {
        lock(&self.draft).take();
    }
}

fn finish_blocking(
    core: &FleetCore,
    d: &Draft,
    passphrase: &str,
) -> Result<EnrollmentResult, FleetError> {
    let keys = d
        .code
        .derive(passphrase, KdfParams::PRODUCTION)
        .map_err(|e| FleetError::Internal {
            message: e.to_string(),
        })?;
    let delay = delay_for(passphrase);
    let noise = core.noise_key()?;
    let genesis = enroll::build_genesis(
        &*core.keys,
        GenesisInput {
            fleet_id: d.fleet_id,
            device_id: d.device_id,
            device_name: d.device_name.clone(),
            noise_static: noise.public(),
            recovery: keys.publics(),
            recovery_delay_s: delay,
            now_ms: fleet_core::now_ms(),
        },
    )?;
    drop(keys);
    enroll::persist(&lock(&core.cache), &d.fleet_name, &d.device_name, &genesis)?;
    Ok(EnrollmentResult {
        fleet_id: d.fleet_id.to_string(),
        device_id_hex: hex::encode(d.device_id.0),
        recovery_delay_s: delay,
    })
}
