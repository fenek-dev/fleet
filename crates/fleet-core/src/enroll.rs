//! Fleet bootstrap on the first Mac (design §5.3 genesis roster, §5.11
//! recovery code).
//!
//! 1. The app generates `fleet_id`, `device_id` and a [`RecoveryCode`]; the
//!    24 words are shown once and the operator re-types
//!    [`CHALLENGE_WORDS`] randomly chosen ones ([`challenge`], [`check_words`]).
//! 2. With the (optional) passphrase, the code derives the recovery public
//!    keys (Argon2id, slow) and the delay (`0` with a strong passphrase,
//!    72 h otherwise).
//! 3. [`build_genesis`] lists this Mac with its enclave public keys and
//!    Noise key, and signs epoch 0 / version 1 with the **root key** (Touch
//!    ID), then checks it with the agent's own `verify_genesis`.
//! 4. [`persist`] stores the signed roster in `roster_chain` and the ids in
//!    `settings` (the ids last: they are what "enrolled" means).
//!
//! The recovery entropy and derived secrets are zeroized on drop
//! (`fleet_crypto::recovery`); only public keys leave this module.

use crate::cache::{Cache, CacheError, RosterRow};
use crate::signer::{DeviceSigner, KeyRole, RoleSigner, SignerError, root_reason};
use fleet_crypto::recovery::RecoveryPublics;
use fleet_crypto::roster::{RosterError, roster_hash, sign_root, verify_genesis};
use fleet_proto::{
    BoundedString, Device, DeviceId, FleetId, KeyRef, Role, Roster, SignedRoster, X25519Public,
    decode, encode,
};

/// `settings` keys (raw bytes / UTF-8).
pub const SETTING_FLEET_ID: &str = "fleet_id";
pub const SETTING_DEVICE_ID: &str = "device_id";
pub const SETTING_FLEET_NAME: &str = "fleet_name";
pub const SETTING_DEVICE_NAME: &str = "device_name";

/// Words the operator must re-type (design §5.11 step 4).
pub const CHALLENGE_WORDS: usize = 4;
pub const RECOVERY_WORDS: usize = 24;

#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    #[error("signer: {0}")]
    Signer(#[from] SignerError),
    #[error("crypto: {0}")]
    Crypto(#[from] fleet_crypto::Error),
    #[error("genesis roster rejected: {0:?}")]
    Roster(RosterError),
    #[error("invalid name")]
    Name,
    #[error(transparent)]
    Cache(#[from] CacheError),
    #[error("already enrolled")]
    AlreadyEnrolled,
    #[error("no genesis roster in the cache")]
    NoGenesis,
    /// The cached genesis doesn't list this Mac's keys (`what` differs).
    #[error("genesis roster is not this Mac's ({0} differs)")]
    NotOurs(&'static str),
}

pub struct GenesisInput {
    pub fleet_id: FleetId,
    pub device_id: DeviceId,
    pub device_name: String,
    pub noise_static: X25519Public,
    pub recovery: RecoveryPublics,
    pub recovery_delay_s: u32,
    pub now_ms: u64,
}

pub fn random_id16() -> Result<[u8; 16], fleet_crypto::Error> {
    let mut b = [0u8; 16];
    fleet_crypto::random_bytes(&mut b)?;
    Ok(b)
}

/// Builds and root-signs the genesis roster. Blocks on Touch ID.
pub fn build_genesis(
    keys: &dyn DeviceSigner,
    input: GenesisInput,
) -> Result<SignedRoster, EnrollError> {
    let name = BoundedString::new(input.device_name.trim()).map_err(|_| EnrollError::Name)?;
    if name.as_str().is_empty() {
        return Err(EnrollError::Name);
    }
    let device = Device {
        id: input.device_id,
        name,
        role: Role::Admin,
        root_key: keys.public_key(KeyRole::Root)?,
        device_key: keys.public_key(KeyRole::Device)?,
        monitor_key: keys.public_key(KeyRole::Monitor)?,
        ssh_key: keys.public_key(KeyRole::Ssh)?,
        // Placeholder until the Mac generates a monitor SSH key (the agent
        // skips a monitor line identical to the device SSH key).
        monitor_ssh_key: keys.public_key(KeyRole::Ssh)?,
        noise_static: input.noise_static,
        added_at: input.now_ms,
        added_by: input.device_id,
    };
    let roster = Roster {
        fleet_id: input.fleet_id,
        epoch: 0,
        version: 1,
        prev_hash: [0; 32],
        issued_at_ms: input.now_ms,
        devices: vec![device],
        recovery_key: input.recovery.recovery_key,
        recovery_ssh_key: input.recovery.recovery_ssh_key,
        recovery_escrow_key: input.recovery.recovery_escrow_key,
        recovery_delay_s: input.recovery_delay_s,
        prev_recovery: None,
    };
    let root = RoleSigner::with_reason(
        keys,
        KeyRole::Root,
        root_reason("the new fleet's first roster (v1)", 0),
    )?;
    let signed = sign_root(roster, input.device_id, &root)?;
    // The agent runs exactly this check at install; fail here instead.
    verify_genesis(&signed, input.now_ms).map_err(EnrollError::Roster)?;
    Ok(signed)
}

/// Before a genesis roster from the cache goes to a server: it must be a
/// valid genesis whose only device is **this** Mac — every key equal to
/// the enclave's and the Keychain Noise key — self-signed by our root key.
/// A tampered cache could otherwise make an install trust someone else's
/// keys.
pub fn check_genesis_is_ours(
    genesis: &SignedRoster,
    keys: &dyn DeviceSigner,
    noise_static: X25519Public,
    device_id: DeviceId,
    now_ms: u64,
) -> Result<(), EnrollError> {
    verify_genesis(genesis, now_ms).map_err(EnrollError::Roster)?;
    let r = &genesis.roster;
    let [d] = r.devices.as_slice() else {
        return Err(EnrollError::NotOurs("device count"));
    };
    let checks = [
        (d.id == device_id, "device id"),
        (d.root_key == keys.public_key(KeyRole::Root)?, "root key"),
        (
            d.device_key == keys.public_key(KeyRole::Device)?,
            "device key",
        ),
        (
            d.monitor_key == keys.public_key(KeyRole::Monitor)?,
            "monitor key",
        ),
        (d.ssh_key == keys.public_key(KeyRole::Ssh)?, "ssh key"),
        (d.noise_static == noise_static, "noise key"),
        (genesis.signer == KeyRef::Root(device_id), "signer"),
    ];
    match checks.iter().find(|(ok, _)| !ok) {
        Some((_, what)) => Err(EnrollError::NotOurs(what)),
        None => Ok(()),
    }
}

/// Stores the genesis roster and the enrollment settings.
pub fn persist(
    cache: &Cache,
    fleet_name: &str,
    device_name: &str,
    genesis: &SignedRoster,
) -> Result<(), EnrollError> {
    if cache.setting(SETTING_FLEET_ID)?.is_some() {
        return Err(EnrollError::AlreadyEnrolled);
    }
    let r = &genesis.roster;
    let device = r.devices.first().ok_or(EnrollError::NoGenesis)?;
    cache.put_roster(&RosterRow {
        epoch: r.epoch,
        version: r.version,
        hash: roster_hash(genesis),
        signed: encode(genesis),
    })?;
    cache.set_setting(SETTING_FLEET_NAME, fleet_name.as_bytes())?;
    cache.set_setting(SETTING_DEVICE_NAME, device_name.as_bytes())?;
    cache.set_setting(SETTING_DEVICE_ID, &device.id.0)?;
    cache.set_setting(SETTING_FLEET_ID, &r.fleet_id.0)?;
    Ok(())
}

/// The genesis roster (epoch 0, version 1) for `fleet-agent install`.
pub fn genesis(cache: &Cache) -> Result<SignedRoster, EnrollError> {
    let row = cache
        .roster_chain()?
        .into_iter()
        .find(|r| r.epoch == 0 && r.version == 1)
        .ok_or(EnrollError::NoGenesis)?;
    decode(&row.signed).map_err(|_| EnrollError::NoGenesis)
}

/// [`CHALLENGE_WORDS`] distinct word positions (0-based), ascending.
pub fn challenge() -> Result<Vec<u32>, fleet_crypto::Error> {
    let mut picked: Vec<u32> = Vec::with_capacity(CHALLENGE_WORDS);
    while picked.len() < CHALLENGE_WORDS {
        let mut b = [0u8; 1];
        fleet_crypto::random_bytes(&mut b)?;
        // Rejection sampling: 240 is the largest multiple of 24 below 256.
        if b[0] >= 240 {
            continue;
        }
        let i = u32::from(b[0]) % RECOVERY_WORDS as u32;
        if !picked.contains(&i) {
            picked.push(i);
        }
    }
    picked.sort_unstable();
    Ok(picked)
}

/// Whether `answers[k]` is word `positions[k]` of `phrase` (trimmed,
/// case-insensitive). Constant work per word; no early exit on a mismatch.
pub fn check_words<A: AsRef<str>>(phrase: &str, positions: &[u32], answers: &[A]) -> bool {
    if positions.len() != answers.len() || positions.is_empty() {
        return false;
    }
    let words: Vec<&str> = phrase.split_whitespace().collect();
    let mut ok = true;
    for (p, a) in positions.iter().zip(answers) {
        let want = words.get(*p as usize).copied().unwrap_or("");
        ok &= !want.is_empty() && a.as_ref().trim().eq_ignore_ascii_case(want);
    }
    ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::SoftwareDeviceSigner;
    use fleet_crypto::recovery::{KdfParams, RecoveryCode, delay_for};
    use fleet_crypto::sig::Signer;
    use fleet_proto::KeyRef;

    const TINY: KdfParams = KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    };
    const STRONG: &str = "correct horse battery staple zebra";

    #[test]
    fn genesis_ownership_check() {
        let keys = SoftwareDeviceSigner::generate().unwrap();
        let g = genesis_for(&keys);
        let now = crate::now_ms();
        let noise = X25519Public([3; 32]);
        let me = DeviceId([2; 16]);
        check_genesis_is_ours(&g, &keys, noise, me, now).unwrap();
        let other = SoftwareDeviceSigner::generate().unwrap();
        assert!(matches!(
            check_genesis_is_ours(&g, &other, noise, me, now),
            Err(EnrollError::NotOurs("root key"))
        ));
        assert!(matches!(
            check_genesis_is_ours(&g, &keys, X25519Public([4; 32]), me, now),
            Err(EnrollError::NotOurs("noise key"))
        ));
        assert!(matches!(
            check_genesis_is_ours(&g, &keys, noise, DeviceId([9; 16]), now),
            Err(EnrollError::NotOurs("device id"))
        ));
        // A genesis signed by someone else's root key doesn't verify.
        let foreign = genesis_for(&other);
        assert!(check_genesis_is_ours(&foreign, &keys, noise, me, now).is_err());
    }

    fn genesis_for(keys: &SoftwareDeviceSigner) -> SignedRoster {
        let code = RecoveryCode::generate().unwrap();
        let rk = code.derive(STRONG, TINY).unwrap();
        build_genesis(
            keys,
            GenesisInput {
                fleet_id: FleetId([1; 16]),
                device_id: DeviceId([2; 16]),
                device_name: "MacBook Pro".into(),
                noise_static: X25519Public([3; 32]),
                recovery: rk.publics(),
                recovery_delay_s: delay_for(STRONG),
                now_ms: crate::now_ms(),
            },
        )
        .unwrap()
    }

    #[test]
    fn genesis_is_valid_and_persists() {
        let keys = SoftwareDeviceSigner::generate().unwrap();
        let g = genesis_for(&keys);
        assert_eq!(g.signer, KeyRef::Root(DeviceId([2; 16])));
        assert_eq!(g.roster.recovery_delay_s, 0);
        assert_eq!(g.roster.devices[0].root_key, keys.root.public());
        verify_genesis(&g, crate::now_ms()).unwrap();

        let cache = Cache::open_in_memory().unwrap();
        persist(&cache, "Prod", "MacBook Pro", &g).unwrap();
        assert_eq!(genesis(&cache).unwrap(), g);
        assert_eq!(
            cache.setting(SETTING_FLEET_ID).unwrap().unwrap(),
            vec![1; 16]
        );
        assert!(matches!(
            persist(&cache, "Prod", "MacBook Pro", &g),
            Err(EnrollError::AlreadyEnrolled)
        ));
    }

    #[test]
    fn rejects_blank_name() {
        let keys = SoftwareDeviceSigner::generate().unwrap();
        let code = RecoveryCode::generate().unwrap();
        let rk = code.derive("", TINY).unwrap();
        let r = build_genesis(
            &keys,
            GenesisInput {
                fleet_id: FleetId([1; 16]),
                device_id: DeviceId([2; 16]),
                device_name: "   ".into(),
                noise_static: X25519Public([3; 32]),
                recovery: rk.publics(),
                recovery_delay_s: delay_for(""),
                now_ms: 1,
            },
        );
        assert!(matches!(r, Err(EnrollError::Name)));
    }

    #[test]
    fn challenge_and_check() {
        let code = RecoveryCode::generate().unwrap();
        let phrase = code.phrase();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), RECOVERY_WORDS);
        let pos = challenge().unwrap();
        assert_eq!(pos.len(), CHALLENGE_WORDS);
        assert!(pos.windows(2).all(|w| w[0] < w[1]));
        assert!(pos.iter().all(|&p| (p as usize) < RECOVERY_WORDS));
        let answers: Vec<String> = pos
            .iter()
            .map(|&p| format!(" {} ", words[p as usize].to_uppercase()))
            .collect();
        assert!(check_words(&phrase, &pos, &answers));
        let mut wrong = answers.clone();
        wrong[2] = "zzz".into();
        assert!(!check_words(&phrase, &pos, &wrong));
        assert!(!check_words(&phrase, &pos, &answers[..3]));
        assert!(!check_words::<String>(&phrase, &[], &[]));
    }
}
