//! SSH transport against in-process russh servers on localhost.

use fleet_core::ssh::{
    AGENT_BRIDGE, AGENT_BRIDGE_RECOVERY, HostKey, HostKeyStatus, P256SshSigner, PtyOutput,
    SshConnection, SshError, SshSigner, SshTarget,
};
use fleet_crypto::sig::{Ed25519Signer, SoftwareP256Signer};
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::{PrivateKey, PublicKey};
use russh::server::{self, Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const T: Duration = Duration::from_secs(10);

#[derive(Default)]
struct Log {
    execs: Vec<String>,
    resizes: Vec<(u32, u32)>,
    direct: Vec<(String, u32)>,
}

#[derive(Clone)]
struct TestServer {
    allowed: Vec<PublicKey>,
    log: Arc<Mutex<Log>>,
    channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
}

fn echo(ch: Channel<Msg>) {
    tokio::spawn(async move {
        let (mut r, mut w) = tokio::io::split(ch.into_stream());
        let _ = tokio::io::copy(&mut r, &mut w).await;
        let _ = w.shutdown().await;
    });
}

impl server::Handler for TestServer {
    type Error = russh::Error;

    async fn auth_publickey_offered(
        &mut self,
        _: &str,
        pk: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(if self.allowed.contains(pk) {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_publickey(&mut self, _: &str, pk: &PublicKey) -> Result<Auth, Self::Error> {
        self.auth_publickey_offered("", pk).await
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.lock().unwrap().insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.log
            .lock()
            .unwrap()
            .execs
            .push(String::from_utf8_lossy(data).into_owned());
        session.channel_success(id)?;
        if let Some(ch) = self.channels.lock().unwrap().remove(&id) {
            echo(ch);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        id: ChannelId,
        _: &str,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(id)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        id: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(id)?;
        if let Some(ch) = self.channels.lock().unwrap().remove(&id) {
            echo(ch);
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        _: ChannelId,
        cols: u32,
        rows: u32,
        _: u32,
        _: u32,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.log.lock().unwrap().resizes.push((cols, rows));
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _: &str,
        _: u32,
        reply: ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.log
            .lock()
            .unwrap()
            .direct
            .push((host.to_owned(), port));
        let Ok(mut tcp) = TcpStream::connect((host, port as u16)).await else {
            return Ok(()); // dropped handle rejects
        };
        reply.accept().await;
        tokio::spawn(async move {
            let mut s = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut s, &mut tcp).await;
        });
        Ok(())
    }
}

struct Running {
    port: u16,
    host_key: HostKey,
    log: Arc<Mutex<Log>>,
}

async fn start_server(seed: u8, allowed: &[&dyn SshSigner]) -> Running {
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]));
    let host_key = HostKey::from_blob(&key.public_key().to_bytes().unwrap()).unwrap();
    let config = Arc::new(server::Config {
        keys: vec![key],
        auth_rejection_time: Duration::from_millis(1),
        auth_rejection_time_initial: Some(Duration::ZERO),
        inactivity_timeout: Some(Duration::from_secs(30)),
        ..Default::default()
    });
    let handler = TestServer {
        allowed: allowed
            .iter()
            .map(|s| PublicKey::from_bytes(&s.public_key().blob().unwrap()).unwrap())
            .collect(),
        log: Arc::default(),
        channels: Arc::default(),
    };
    let log = handler.log.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let (cfg, h) = (config.clone(), handler.clone());
            tokio::spawn(async move {
                if let Ok(s) = server::run_stream(cfg, sock, h).await {
                    let _ = s.await;
                }
            });
        }
    });
    Running {
        port,
        host_key,
        log,
    }
}

fn target(port: u16) -> SshTarget {
    SshTarget::new("127.0.0.1", port, "admin")
}

async fn roundtrip<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(s: &mut S, msg: &[u8]) {
    s.write_all(msg).await.unwrap();
    let mut buf = vec![0u8; msg.len()];
    timeout(T, s.read_exact(&mut buf)).await.unwrap().unwrap();
    assert_eq!(buf, msg);
}

#[tokio::test]
async fn host_key_pinning_first_use_match_mismatch() {
    let key = P256SshSigner(SoftwareP256Signer::generate().unwrap());
    let srv = start_server(1, &[&key]).await;

    let (c, obs) = SshConnection::connect(&target(srv.port), &key, None)
        .await
        .unwrap();
    assert_eq!(obs.status, HostKeyStatus::FirstUse);
    assert!(obs.needs_confirmation());
    assert_eq!(obs.key, srv.host_key);
    c.disconnect().await;

    let (_c, obs) = SshConnection::connect(&target(srv.port), &key, Some(srv.host_key.clone()))
        .await
        .unwrap();
    assert_eq!(obs.status, HostKeyStatus::Matched);
    assert!(!obs.needs_confirmation());

    let other = start_server(2, &[]).await.host_key;
    let e = SshConnection::connect(&target(srv.port), &key, Some(other.clone()))
        .await
        .err()
        .unwrap();
    match e {
        SshError::HostKeyChanged { expected, got } => {
            assert_eq!(expected, other);
            assert_eq!(got, srv.host_key);
        }
        e => panic!("expected HostKeyChanged, got {e}"),
    }
}

#[tokio::test]
async fn external_p256_signer_auth_and_agent_channel() {
    let key = P256SshSigner(SoftwareP256Signer::generate().unwrap());
    let stranger = P256SshSigner(SoftwareP256Signer::generate().unwrap());
    let srv = start_server(3, &[&key]).await;

    let e = SshConnection::connect(&target(srv.port), &stranger, None)
        .await
        .err()
        .unwrap();
    assert!(matches!(e, SshError::AuthRejected), "{e}");

    let (c, _) = SshConnection::connect(&target(srv.port), &key, Some(srv.host_key.clone()))
        .await
        .unwrap();
    let mut s = c.open_agent_channel(false).await.unwrap();
    // Nothing is prepended: the bridge, not the client, sends the mode byte.
    roundtrip(&mut s, b"\x00\x00\x00\x05hello").await;
    let mut r = c.open_agent_channel(true).await.unwrap();
    roundtrip(&mut r, &[7u8; 70_000]).await;
    assert_eq!(
        srv.log.lock().unwrap().execs,
        vec![AGENT_BRIDGE.to_owned(), AGENT_BRIDGE_RECOVERY.to_owned()]
    );
}

/// The locked app's connection: the monitor SSH key (a separate enclave
/// key) and the monitor bridge command.
#[tokio::test]
async fn monitor_ssh_key_opens_the_monitor_bridge() {
    use fleet_core::SessionMode;
    use fleet_core::signer::{KeyRole, RoleSigner, SoftwareDeviceSigner};
    let keys = SoftwareDeviceSigner::generate().unwrap();
    let monitor = P256SshSigner(RoleSigner::new(&keys, KeyRole::MonitorSsh).unwrap());
    let device = P256SshSigner(RoleSigner::new(&keys, KeyRole::Ssh).unwrap());
    assert_ne!(monitor.public_key(), device.public_key());
    let srv = start_server(5, &[&monitor]).await;
    let (c, _) = SshConnection::connect(&target(srv.port), &monitor, Some(srv.host_key.clone()))
        .await
        .unwrap();
    let mut s = c
        .open_agent_channel_mode(SessionMode::Monitor)
        .await
        .unwrap();
    roundtrip(&mut s, b"monitor").await;
    assert_eq!(
        srv.log.lock().unwrap().execs,
        vec![fleet_core::ssh::AGENT_BRIDGE_MONITOR.to_owned()]
    );
    // The device SSH key isn't the monitor key.
    let e = SshConnection::connect(&target(srv.port), &device, Some(srv.host_key.clone()))
        .await
        .err()
        .unwrap();
    assert!(matches!(e, SshError::AuthRejected), "{e}");
}

#[tokio::test]
async fn recovery_ed25519_key_auth() {
    let rec = Ed25519Signer::from_seed(&[9; 32]);
    let srv = start_server(4, &[&rec]).await;
    let (c, _) = SshConnection::connect(&target(srv.port), &rec, Some(srv.host_key.clone()))
        .await
        .unwrap();
    let mut s = c.open_agent_channel(true).await.unwrap();
    roundtrip(&mut s, b"recovery").await;
}

#[tokio::test]
async fn pty_echo_and_resize() {
    let key = P256SshSigner(SoftwareP256Signer::generate().unwrap());
    let srv = start_server(5, &[&key]).await;
    let (c, _) = SshConnection::connect(&target(srv.port), &key, Some(srv.host_key.clone()))
        .await
        .unwrap();
    let mut pty = c.open_pty("xterm-256color", 80, 24).await.unwrap();
    pty.write(b"ls\n").await.unwrap();
    let mut got = Vec::new();
    while got.len() < 3 {
        match timeout(T, pty.read()).await.unwrap() {
            Some(PtyOutput::Data(d)) => got.extend(d),
            o => panic!("unexpected {o:?}"),
        }
    }
    assert_eq!(got, b"ls\n");
    pty.resize(120, 40).await.unwrap();
    timeout(T, async {
        while srv.log.lock().unwrap().resizes.is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(srv.log.lock().unwrap().resizes, vec![(120, 40)]);
}

#[tokio::test]
async fn proxy_jump_through_bastion() {
    let key = P256SshSigner(SoftwareP256Signer::generate().unwrap());
    let bastion = start_server(6, &[&key]).await;
    let inner = start_server(7, &[&key]).await;

    let mut jump = target(bastion.port);
    jump.host_key = Some(bastion.host_key.clone());
    let t = target(inner.port).via(jump);
    let (c, obs) = SshConnection::connect(&t, &key, Some(inner.host_key.clone()))
        .await
        .unwrap();
    assert_eq!(obs.key, inner.host_key);
    let via = obs.via.as_ref().unwrap();
    assert_eq!(via.key, bastion.host_key);
    assert_eq!(via.status, HostKeyStatus::Matched);
    assert_eq!(
        bastion.log.lock().unwrap().direct,
        vec![("127.0.0.1".to_owned(), u32::from(inner.port))]
    );
    let mut s = c.open_agent_channel(false).await.unwrap();
    roundtrip(&mut s, b"through the bastion").await;

    // A changed bastion key blocks too.
    let mut jump = target(bastion.port);
    jump.host_key = Some(inner.host_key.clone());
    let t = target(inner.port).via(jump);
    let e = SshConnection::connect(&t, &key, Some(inner.host_key.clone()))
        .await
        .err()
        .unwrap();
    assert!(matches!(e, SshError::HostKeyChanged { .. }), "{e}");
}
