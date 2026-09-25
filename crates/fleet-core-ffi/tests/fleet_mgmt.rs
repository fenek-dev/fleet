//! Two cores through the public FFI surface: pairing (commit-reveal SAS,
//! confirmation on both Macs, authenticated key box), sync, sudo
//! passwords and revocation with key rotation.

use fleet_core::signer::{DeviceSigner as _, KeyRole as CoreRole, SoftwareDeviceSigner};
use fleet_core_ffi::{
    AgentEventRow, CloudRecordRow, CoreListener, DeviceSigner, FleetCore, HostKeyPrompt, KeyRole,
    KeyStore, NewServer, ServerMetricsRow, SignerError, StateChange, SyncSecrets,
};
use fleet_crypto::hpke::{P256Recipient, SoftwareP256Recipient};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

struct Soft(SoftwareDeviceSigner);

fn role(r: KeyRole) -> CoreRole {
    match r {
        KeyRole::Root => CoreRole::Root,
        KeyRole::Device => CoreRole::Device,
        KeyRole::Monitor => CoreRole::Monitor,
        KeyRole::Ssh => CoreRole::Ssh,
        KeyRole::MonitorSsh => CoreRole::MonitorSsh,
    }
}

impl DeviceSigner for Soft {
    fn public_key(&self, r: KeyRole) -> Result<Vec<u8>, SignerError> {
        Ok(self.0.public_key(role(r)).unwrap().0.to_vec())
    }
    fn sign(&self, r: KeyRole, msg: Vec<u8>, _: String) -> Result<Vec<u8>, SignerError> {
        Ok(self.0.sign(role(r), &msg, "").unwrap().0.to_vec())
    }
}

#[derive(Default)]
struct Store {
    noise: Mutex<Option<Vec<u8>>>,
    cache: Mutex<Option<Vec<u8>>>,
}

impl KeyStore for Store {
    fn load_noise_key(&self) -> Result<Option<Vec<u8>>, SignerError> {
        Ok(self.noise.lock().unwrap().clone())
    }
    fn store_noise_key(&self, s: Vec<u8>) -> Result<(), SignerError> {
        *self.noise.lock().unwrap() = Some(s);
        Ok(())
    }
    fn load_cache_key(&self) -> Result<Option<Vec<u8>>, SignerError> {
        Ok(self.cache.lock().unwrap().clone())
    }
    fn store_cache_key(&self, s: Vec<u8>) -> Result<(), SignerError> {
        *self.cache.lock().unwrap() = Some(s);
        Ok(())
    }
}

type Sudo = Arc<Mutex<HashMap<String, String>>>;

struct Secrets {
    key: Mutex<Option<Vec<u8>>>,
    agree: SoftwareP256Recipient,
    sudo: Sudo,
}

impl SyncSecrets for Secrets {
    fn load_sync_key(&self) -> Result<Option<Vec<u8>>, SignerError> {
        Ok(self.key.lock().unwrap().clone())
    }
    fn store_sync_key(&self, k: Vec<u8>) -> Result<(), SignerError> {
        *self.key.lock().unwrap() = Some(k);
        Ok(())
    }
    fn agreement_public_key(&self) -> Result<Vec<u8>, SignerError> {
        Ok(self.agree.public().to_vec())
    }
    fn agree(&self, peer: Vec<u8>) -> Result<Vec<u8>, SignerError> {
        let p: [u8; 65] = peer.try_into().map_err(|_| SignerError::Failed)?;
        Ok(self.agree.agree(&p).unwrap().to_vec())
    }
    fn store_sudo_password(&self, s: String, p: String) -> Result<(), SignerError> {
        self.sudo.lock().unwrap().insert(s, p);
        Ok(())
    }
    fn delete_sudo_password(&self, s: String) -> Result<(), SignerError> {
        self.sudo.lock().unwrap().remove(&s);
        Ok(())
    }
}

struct Quiet;

impl CoreListener for Quiet {
    fn on_state(&self, _: StateChange) {}
    fn on_host_key(&self, _: HostKeyPrompt) {}
    fn on_event(&self, _: AgentEventRow) {}
    fn on_resync(&self) {}
    fn on_metrics(&self, _: ServerMetricsRow) {}
}

fn mac(dir: &tempfile::TempDir, name: &str) -> (Arc<FleetCore>, Sudo) {
    let path = dir.path().join(format!("{name}.sqlite"));
    let c = FleetCore::open(
        path.to_string_lossy().into_owned(),
        Box::new(Soft(SoftwareDeviceSigner::generate().unwrap())),
        Box::new(Store::default()),
    )
    .unwrap();
    let sudo = Sudo::default();
    c.set_sync_secrets(Box::new(Secrets {
        key: Mutex::default(),
        agree: SoftwareP256Recipient::generate().unwrap(),
        sudo: sudo.clone(),
    }));
    (c, sudo)
}

/// A new fleet through the enrollment flow (words shown, re-typed).
fn enroll(rt: &tokio::runtime::Runtime, c: &Arc<FleetCore>) {
    let e = c
        .clone()
        .create_fleet("Prod".into(), "Studio".into())
        .unwrap();
    let words = e.recovery_words().unwrap();
    let ask = e.challenge().unwrap();
    let answers = ask.iter().map(|i| words[*i as usize].clone()).collect();
    assert!(e.confirm_words(answers).unwrap());
    rt.block_on(e.finish(String::new())).unwrap();
}

fn by_name(rs: &[CloudRecordRow], name: &str) -> CloudRecordRow {
    rs.iter().find(|r| r.name == name).cloned().unwrap()
}

#[test]
fn pairing_sync_sudo_and_revocation_between_two_cores() {
    let dir = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (a, _) = mac(&dir, "a");
    enroll(&rt, &a);
    assert!(a.sync_setup().unwrap(), "single Mac creates the sync key");
    a.clone().start(Box::new(Quiet)).unwrap();
    let mut cloud: Vec<CloudRecordRow> = a.sync_outgoing().unwrap();
    a.sync_mark_pushed(cloud.iter().map(|r| r.name.clone()).collect())
        .unwrap();

    // New Mac B shows its code; A scans it and answers.
    let (b, b_sudo) = mac(&dir, "b");
    let offer = b.create_pairing_offer("Laptop".into()).unwrap();
    let prompt = a.begin_add_mac(offer.code.clone()).unwrap();
    assert_eq!(prompt.name, "Laptop");
    assert_eq!(prompt.response.name, offer.response_record);
    // A can't approve before the new Mac revealed its secret.
    assert!(
        rt.block_on(a.clone().approve_add_mac(prompt.device_id.clone()))
            .is_err()
    );
    let prompt = a.begin_add_mac(offer.code.clone()).unwrap();
    // B reveals only now that the answer is fixed; both show one code.
    let code = b
        .pairing_verification_code(prompt.response.clone())
        .unwrap();
    assert_eq!(code.reveal.name, prompt.reveal_record);
    let mut bad = code.reveal.clone();
    let n = bad.data.len();
    bad.data[n - 1] ^= 1;
    assert!(
        a.add_mac_verification_code(prompt.device_id.clone(), bad)
            .is_err(),
        "a reveal that doesn't open the commitment"
    );
    let sas = a
        .add_mac_verification_code(prompt.device_id.clone(), code.reveal.clone())
        .unwrap();
    assert_eq!(sas, code.verification_code);

    let res = rt
        .block_on(a.clone().approve_add_mac(prompt.device_id.clone()))
        .unwrap();
    assert_eq!(res.version, 2);
    cloud.extend(res.upload.clone());
    cloud.extend(a.sync_outgoing().unwrap());
    let keybox = by_name(&cloud, &offer.keybox_record);
    // B completes only after the operator confirmed the codes there too.
    assert!(b.complete_pairing(keybox.clone(), cloud.clone()).is_err());
    b.confirm_pairing_codes().unwrap();
    b.complete_pairing(keybox, cloud.clone()).unwrap();
    assert!(b.is_enrolled());
    let st = b.roster_status().unwrap();
    assert_eq!(st.version, 2);
    assert_eq!(st.devices.len(), 2);
    assert!(st.devices.iter().any(|d| d.this_mac && d.name == "Laptop"));
    assert_eq!(
        st.fleet_fingerprint,
        a.roster_status().unwrap().fleet_fingerprint
    );

    // A adds a group, a server and its sudo password; B receives them.
    a.add_group("Web".into()).unwrap();
    let srv = a
        .add_server(NewServer {
            name: "web".into(),
            host: "web.example.com".into(),
            port: 22,
            user: "admin".into(),
            group_id: None,
            tags: vec![],
            proxy_jump: None,
        })
        .unwrap();
    assert!(a.ensure_sudo_password(srv.id.clone()).unwrap());
    assert!(
        !a.ensure_sudo_password(srv.id.clone()).unwrap(),
        "only once"
    );
    let out = a.sync_outgoing().unwrap();
    a.sync_mark_pushed(out.iter().map(|r| r.name.clone()).collect())
        .unwrap();
    let rep = b.sync_ingest(out).unwrap();
    assert_eq!(rep.rejected, 0);
    assert!(b.list_groups().unwrap().iter().any(|g| g.name == "Web"));
    assert_eq!(b.list_servers().unwrap().len(), 1);
    let pw = b_sudo.lock().unwrap().get(&srv.id).cloned().unwrap();
    assert!(fleet_core::sudo::is_valid(&pw));

    // A revokes B: v3, new sync key sealed to nobody else, escrowed.
    let res = rt
        .block_on(a.clone().revoke_mac(prompt.device_id.clone()))
        .unwrap();
    assert_eq!(res.version, 3);
    assert!(!res.delete.is_empty(), "old record names go");
    assert_eq!(a.roster_status().unwrap().devices.len(), 1);
    // B can't read what A writes now.
    a.add_group("Db".into()).unwrap();
    let rep = b.sync_ingest(a.sync_outgoing().unwrap()).unwrap();
    assert!(rep.needs_key);
}
