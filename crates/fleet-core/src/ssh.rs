//! SSH transport (design §3.2, §5.5 step 1, §5.9) on `russh`.
//!
//! One [`SshConnection`] per server. Client auth is public-key only, and the
//! private key never enters russh: russh hands us the exact bytes to sign
//! (`authenticate_publickey_with`, the ssh-agent path) and an [`SshSigner`]
//! signs them — the Secure Enclave on a Mac, [`Ed25519Signer`] for the
//! recovery SSH key. Host keys are pinned: a mismatch is a hard
//! [`SshError::HostKeyChanged`]; with no pin the connection proceeds and
//! the [`HostKeyObservation`] says `FirstUse` so the app can show the
//! fingerprint and store the pin.

use crate::signer::SignerError;
use fleet_crypto::sig::{self, Ed25519Signer, Signer};
use fleet_proto::{Ed25519Public, P256Public, Signature};
use russh::client::{self, Handle, Msg};
use russh::keys::agent::AgentIdentity;
use russh::keys::{HashAlg, PublicKey, PublicKeyOrCertificate};
use russh::{Channel, ChannelMsg, ChannelReadHalf, ChannelStream, ChannelWriteHalf};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::timeout;

/// Agent channel command (design §5.5 step 2). A fixed string: nothing is
/// ever interpolated into it.
pub const AGENT_BRIDGE: &str = "/usr/lib/fleet/fleet-agent bridge";
/// Recovery variant; the recovery key's forced command runs this anyway.
pub const AGENT_BRIDGE_RECOVERY: &str = "/usr/lib/fleet/fleet-agent bridge --recovery";

/// Byte stream of the agent exec channel, for
/// [`crate::Session::connect_bridged`].
pub type AgentStream = ChannelStream<Msg>;

/// Where to connect. `proxy_jump` chains like OpenSSH `-J` (the innermost
/// `proxy_jump` is the first hop).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshTarget {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub proxy_jump: Option<Box<SshTarget>>,
    /// Pin for this hop **when it is a jump host**. The final target's pin
    /// is the `pinned_host_key` argument of [`SshConnection::connect`].
    pub host_key: Option<HostKey>,
}

impl SshTarget {
    pub fn new(host: impl Into<String>, port: u16, user: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port,
            user: user.into(),
            proxy_jump: None,
            host_key: None,
        }
    }

    pub fn via(mut self, jump: SshTarget) -> Self {
        self.proxy_jump = Some(Box::new(jump));
        self
    }
}

/// An SSH host public key in OpenSSH wire format (the `string`-encoded key
/// blob, as in `known_hosts` after base64 decoding).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct HostKey(Vec<u8>);

impl HostKey {
    pub fn from_blob(blob: &[u8]) -> Result<Self, SshError> {
        PublicKey::from_bytes(blob).map_err(|e| SshError::BadKey(e.to_string()))?;
        Ok(Self(blob.to_vec()))
    }

    /// From `"<algorithm> <base64> [comment]"`.
    pub fn from_openssh(line: &str) -> Result<Self, SshError> {
        let pk = PublicKey::from_openssh(line).map_err(|e| SshError::BadKey(e.to_string()))?;
        Self::from_public(&pk)
    }

    fn from_public(pk: &PublicKey) -> Result<Self, SshError> {
        pk.to_bytes()
            .map(Self)
            .map_err(|e| SshError::BadKey(e.to_string()))
    }

    fn public(&self) -> PublicKey {
        // Validated at construction.
        PublicKey::from_bytes(&self.0).expect("validated host key blob")
    }

    pub fn blob(&self) -> &[u8] {
        &self.0
    }

    /// E.g. `ssh-ed25519`, `ecdsa-sha2-nistp256`.
    pub fn algorithm(&self) -> String {
        self.public().algorithm().as_str().to_owned()
    }

    /// `SHA256:<base64>`, as `ssh-keygen -lf` and provider consoles show it.
    pub fn fingerprint(&self) -> String {
        self.public().fingerprint(HashAlg::Sha256).to_string()
    }
}

impl std::fmt::Debug for HostKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HostKey({} {})", self.algorithm(), self.fingerprint())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyStatus {
    /// Equal to the pin.
    Matched,
    /// No pin: trust on first use. The app shows the fingerprint and pins it.
    FirstUse,
}

/// Host keys seen while connecting, final target first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyObservation {
    pub key: HostKey,
    pub status: HostKeyStatus,
    /// The jump host's observation, if connected through one.
    pub via: Option<Box<HostKeyObservation>>,
}

impl HostKeyObservation {
    /// Any hop was trust-on-first-use.
    pub fn needs_confirmation(&self) -> bool {
        self.status == HostKeyStatus::FirstUse
            || self.via.as_ref().is_some_and(|v| v.needs_confirmation())
    }
}

/// SSH client public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshPublicKey {
    /// Mac SSH key (Secure Enclave), `ecdsa-sha2-nistp256`.
    EcdsaP256(P256Public),
    /// Recovery SSH key, `ssh-ed25519`.
    Ed25519(Ed25519Public),
}

impl SshPublicKey {
    pub fn algorithm(&self) -> &'static str {
        match self {
            Self::EcdsaP256(_) => "ecdsa-sha2-nistp256",
            Self::Ed25519(_) => "ssh-ed25519",
        }
    }

    /// OpenSSH wire-format key blob.
    pub fn blob(&self) -> Result<Vec<u8>, SshError> {
        let mut out = Vec::new();
        put_string(&mut out, self.algorithm().as_bytes());
        match self {
            Self::EcdsaP256(pk) => {
                let q = sig::p256_uncompressed(pk).map_err(|e| SshError::BadKey(e.to_string()))?;
                put_string(&mut out, b"nistp256");
                put_string(&mut out, &q);
            }
            Self::Ed25519(pk) => put_string(&mut out, &pk.0),
        }
        Ok(out)
    }

    /// `authorized_keys` form: `"<algorithm> <base64>"`.
    pub fn to_openssh(&self) -> Result<String, SshError> {
        let pk = self.to_russh()?;
        pk.to_openssh().map_err(|e| SshError::BadKey(e.to_string()))
    }

    fn to_russh(self) -> Result<PublicKey, SshError> {
        PublicKey::from_bytes(&self.blob()?).map_err(|e| SshError::BadKey(e.to_string()))
    }
}

/// Signs SSH user-auth requests without exposing the key. `sign` gets the
/// full RFC 4252 §7 to-be-signed data and returns the raw signature: P-256
/// `r ‖ s` over SHA-256(data) (high-S allowed), or Ed25519 over data.
pub trait SshSigner: Send + Sync {
    fn public_key(&self) -> SshPublicKey;
    fn sign(&self, data: &[u8]) -> Result<Signature, SignerError>;
}

/// Any `fleet_crypto` P-256 signer as an SSH key, e.g.
/// `P256SshSigner(RoleSigner::new(keys, KeyRole::Ssh)?)` or a
/// `SoftwareP256Signer`.
pub struct P256SshSigner<S>(pub S);

impl<S: Signer + Send + Sync> SshSigner for P256SshSigner<S> {
    fn public_key(&self) -> SshPublicKey {
        SshPublicKey::EcdsaP256(self.0.public())
    }

    fn sign(&self, data: &[u8]) -> Result<Signature, SignerError> {
        self.0.sign(data).map_err(|_| SignerError::Failed)
    }
}

/// The recovery SSH key (derived from the recovery code, memory only).
impl SshSigner for Ed25519Signer {
    fn public_key(&self) -> SshPublicKey {
        SshPublicKey::Ed25519(self.public())
    }

    fn sign(&self, data: &[u8]) -> Result<Signature, SignerError> {
        Ok(Ed25519Signer::sign(self, data))
    }
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// SSH `mpint` body of an unsigned big-endian integer.
fn mpint(be: &[u8]) -> Vec<u8> {
    let start = be.iter().position(|&b| b != 0).unwrap_or(be.len());
    let mut v = Vec::with_capacity(be.len() - start + 1);
    if be.get(start).is_some_and(|b| b & 0x80 != 0) {
        v.push(0);
    }
    v.extend_from_slice(&be[start..]);
    v
}

/// Appends the SSH signature blob to `data`, the format russh expects back
/// from an agent-style signer.
fn sign_request(signer: &dyn SshSigner, mut data: Vec<u8>) -> Result<Vec<u8>, SignerError> {
    let public = signer.public_key();
    let raw = signer.sign(&data)?;
    let inner = match public {
        SshPublicKey::EcdsaP256(_) => {
            let s = sig::p256_normalize(&raw).map_err(|_| SignerError::Failed)?;
            let mut v = Vec::with_capacity(72);
            put_string(&mut v, &mpint(&s.0[..32]));
            put_string(&mut v, &mpint(&s.0[32..]));
            v
        }
        SshPublicKey::Ed25519(_) => raw.0.to_vec(),
    };
    let alg = public.algorithm().as_bytes();
    data.extend_from_slice(&((8 + alg.len() + inner.len()) as u32).to_be_bytes());
    put_string(&mut data, alg);
    put_string(&mut data, &inner);
    Ok(data)
}

#[derive(Debug, thiserror::Error)]
enum AuthSignError {
    #[error("ssh session gone")]
    Send(#[from] russh::SendError),
    #[error(transparent)]
    Signer(#[from] SignerError),
}

struct AuthSigner<'a>(&'a dyn SshSigner);

impl russh::Signer for AuthSigner<'_> {
    type Error = AuthSignError;

    fn auth_sign(
        &mut self,
        _key: &AgentIdentity,
        _hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        std::future::ready(sign_request(self.0, to_sign).map_err(AuthSignError::from))
    }
}

/// Host key check; records what the server presented.
struct HostKeyCheck {
    pinned: Option<HostKey>,
    seen: Arc<Mutex<Option<HostKey>>>,
}

impl client::Handler for HostKeyCheck {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // Plain keys only; Fleet never uses host certificates.
        let PublicKeyOrCertificate::PublicKey { key, .. } = key else {
            return Ok(false);
        };
        let Ok(got) = HostKey::from_public(key) else {
            return Ok(false);
        };
        let ok = self.pinned.as_ref().is_none_or(|p| *p == got);
        *self.seen.lock().unwrap_or_else(|e| e.into_inner()) = Some(got);
        Ok(ok)
    }
}

#[derive(Debug, Clone)]
pub struct SshOptions {
    /// TCP connect + key exchange + auth, per hop.
    pub connect_timeout: Duration,
    /// Keepalive when idle (design §3.2: 15 s).
    pub keepalive_interval: Duration,
    /// Unanswered keepalives before the connection is dropped.
    pub keepalive_max: usize,
    /// Opening a channel and its exec/pty/shell request.
    pub channel_timeout: Duration,
}

impl Default for SshOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(15),
            keepalive_interval: Duration::from_secs(15),
            keepalive_max: 3,
            channel_timeout: Duration::from_secs(15),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SshError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("ssh: {0}")]
    Ssh(#[from] russh::Error),
    #[error("timed out")]
    Timeout,
    /// The server presented a different host key than the pinned one.
    #[error("host key changed: expected {expected:?}, got {got:?}")]
    HostKeyChanged { expected: HostKey, got: HostKey },
    #[error("server refused our key")]
    AuthRejected,
    #[error("signer: {0}")]
    Signer(SignerError),
    #[error("channel request refused")]
    ChannelRejected,
    #[error("bad key: {0}")]
    BadKey(String),
}

impl From<AuthSignError> for SshError {
    fn from(e: AuthSignError) -> Self {
        match e {
            AuthSignError::Signer(s) => SshError::Signer(s),
            AuthSignError::Send(_) => SshError::Ssh(russh::Error::SendError),
        }
    }
}

type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One authenticated SSH connection (plus the jump connection it rides on).
pub struct SshConnection {
    handle: Handle<HostKeyCheck>,
    opts: SshOptions,
    /// Keeps the jump host's connection alive as long as this one.
    _jump: Option<Box<SshConnection>>,
}

impl SshConnection {
    /// Connects with default [`SshOptions`].
    pub async fn connect(
        target: &SshTarget,
        auth: &dyn SshSigner,
        pinned_host_key: Option<HostKey>,
    ) -> Result<(SshConnection, HostKeyObservation), SshError> {
        Self::connect_with(target, auth, pinned_host_key, &SshOptions::default()).await
    }

    pub async fn connect_with(
        target: &SshTarget,
        auth: &dyn SshSigner,
        pinned_host_key: Option<HostKey>,
        opts: &SshOptions,
    ) -> Result<(SshConnection, HostKeyObservation), SshError> {
        Self::hop(target, auth, pinned_host_key, opts).await
    }

    fn hop<'a>(
        target: &'a SshTarget,
        auth: &'a dyn SshSigner,
        pinned: Option<HostKey>,
        opts: &'a SshOptions,
    ) -> BoxFut<'a, Result<(SshConnection, HostKeyObservation), SshError>> {
        Box::pin(async move {
            // The jump host has its own timeout; this one covers our hop.
            let (jump, via) = match &target.proxy_jump {
                Some(j) => {
                    let (c, o) = Self::hop(j, auth, j.host_key.clone(), opts).await?;
                    (Some(Box::new(c)), Some(Box::new(o)))
                }
                None => (None, None),
            };
            timeout(
                opts.connect_timeout,
                Self::handshake(target, auth, pinned, opts, jump, via),
            )
            .await
            .map_err(|_| SshError::Timeout)?
        })
    }

    async fn handshake(
        target: &SshTarget,
        auth: &dyn SshSigner,
        pinned: Option<HostKey>,
        opts: &SshOptions,
        jump: Option<Box<SshConnection>>,
        via: Option<Box<HostKeyObservation>>,
    ) -> Result<(SshConnection, HostKeyObservation), SshError> {
        let config = Arc::new(client::Config {
            keepalive_interval: Some(opts.keepalive_interval),
            keepalive_max: opts.keepalive_max,
            inactivity_timeout: None,
            nodelay: true,
            ..Default::default()
        });
        let seen = Arc::new(Mutex::new(None));
        let handler = HostKeyCheck {
            pinned: pinned.clone(),
            seen: seen.clone(),
        };
        let result = match &jump {
            Some(j) => {
                let ch = j
                    .handle
                    .channel_open_direct_tcpip(
                        target.host.clone(),
                        target.port.into(),
                        "127.0.0.1",
                        0,
                    )
                    .await?;
                client::connect_stream(config, ch.into_stream(), handler).await
            }
            None => {
                let tcp =
                    tokio::net::TcpStream::connect((target.host.as_str(), target.port)).await?;
                tcp.set_nodelay(true)?;
                client::connect_stream(config, tcp, handler).await
            }
        };
        let seen = seen.lock().unwrap_or_else(|e| e.into_inner()).take();
        let mut handle = match result {
            Ok(h) => h,
            Err(e) => {
                return Err(match (pinned, seen) {
                    (Some(expected), Some(got)) if expected != got => {
                        SshError::HostKeyChanged { expected, got }
                    }
                    _ => e.into(),
                });
            }
        };
        let key = seen.ok_or(SshError::Ssh(russh::Error::UnknownKey))?;
        let status = if pinned.is_some() {
            HostKeyStatus::Matched
        } else {
            HostKeyStatus::FirstUse
        };
        let public = auth.public_key().to_russh()?;
        let res = handle
            .authenticate_publickey_with(target.user.clone(), public, None, &mut AuthSigner(auth))
            .await?;
        if !res.success() {
            return Err(SshError::AuthRejected);
        }
        Ok((
            SshConnection {
                handle,
                opts: opts.clone(),
                _jump: jump,
            },
            HostKeyObservation { key, status, via },
        ))
    }

    async fn open_session(&self) -> Result<Channel<Msg>, SshError> {
        timeout(
            self.opts.channel_timeout,
            self.handle.channel_open_session(),
        )
        .await
        .map_err(|_| SshError::Timeout)?
        .map_err(Into::into)
    }

    /// Waits for the reply to a `want_reply` channel request.
    async fn wait_reply(&self, ch: &mut Channel<Msg>) -> Result<(), SshError> {
        let wait = async {
            loop {
                match ch.wait().await {
                    Some(ChannelMsg::Success) => return Ok(()),
                    Some(ChannelMsg::Failure) | Some(ChannelMsg::Close) | None => {
                        return Err(SshError::ChannelRejected);
                    }
                    // Window adjustments and the like.
                    Some(_) => {}
                }
            }
        };
        timeout(self.opts.channel_timeout, wait)
            .await
            .map_err(|_| SshError::Timeout)?
    }

    /// Exec channel running `fleet-agent bridge [--recovery]` (design §5.5).
    /// The bridge sends the mode byte to the gate itself, so use
    /// [`crate::Session::connect_bridged`] on the returned stream.
    pub async fn open_agent_channel(&self, recovery: bool) -> Result<AgentStream, SshError> {
        let mut ch = self.open_session().await?;
        let cmd = if recovery {
            AGENT_BRIDGE_RECOVERY
        } else {
            AGENT_BRIDGE
        };
        ch.exec(true, cmd).await?;
        // The gate never speaks first (the Noise initiator does), so no
        // data can be skipped while waiting for the reply.
        self.wait_reply(&mut ch).await?;
        Ok(ch.into_stream())
    }

    /// Interactive shell on a PTY (terminal, Phase 2).
    pub async fn open_pty(&self, term: &str, cols: u32, rows: u32) -> Result<PtyChannel, SshError> {
        let mut ch = self.open_session().await?;
        ch.request_pty(true, term, cols, rows, 0, 0, &[]).await?;
        self.wait_reply(&mut ch).await?;
        ch.request_shell(true).await?;
        self.wait_reply(&mut ch).await?;
        let (read, write) = ch.split();
        Ok(PtyChannel { read, write })
    }

    /// Sends a keepalive and waits for the answer.
    pub async fn ping(&self) -> Result<(), SshError> {
        timeout(self.opts.keepalive_interval, self.handle.send_ping())
            .await
            .map_err(|_| SshError::Timeout)?
            .map_err(Into::into)
    }

    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    pub async fn disconnect(&self) {
        let _ = self
            .handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
    }
}

/// Output of a PTY channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PtyOutput {
    Data(Vec<u8>),
    Exit(u32),
}

/// A shell on a PTY. Minimal until the terminal lands (Phase 2).
pub struct PtyChannel {
    read: ChannelReadHalf,
    write: ChannelWriteHalf<Msg>,
}

impl PtyChannel {
    pub async fn write(&self, data: &[u8]) -> Result<(), SshError> {
        self.write.data_bytes(data.to_vec()).await?;
        Ok(())
    }

    pub async fn resize(&self, cols: u32, rows: u32) -> Result<(), SshError> {
        self.write.window_change(cols, rows, 0, 0).await?;
        Ok(())
    }

    /// Next output; `None` once the channel is closed.
    pub async fn read(&mut self) -> Option<PtyOutput> {
        loop {
            match self.read.wait().await? {
                ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                    return Some(PtyOutput::Data(data.to_vec()));
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    return Some(PtyOutput::Exit(exit_status));
                }
                ChannelMsg::Eof | ChannelMsg::Close => return None,
                _ => {}
            }
        }
    }

    pub async fn close(&self) -> Result<(), SshError> {
        self.write.close().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mpint_encoding() {
        assert_eq!(mpint(&[0, 0, 1]), vec![1]);
        assert_eq!(mpint(&[0x80, 1]), vec![0, 0x80, 1]);
        assert_eq!(mpint(&[0, 0]), Vec::<u8>::new());
    }

    #[test]
    fn client_key_blobs_parse() {
        let p = fleet_crypto::sig::SoftwareP256Signer::generate().unwrap();
        let k = P256SshSigner(p).public_key();
        assert!(k.to_openssh().unwrap().starts_with("ecdsa-sha2-nistp256 "));
        let e = Ed25519Signer::from_seed(&[3; 32]);
        let k = SshSigner::public_key(&e);
        assert!(k.to_openssh().unwrap().starts_with("ssh-ed25519 "));
        let hk = HostKey::from_blob(&k.blob().unwrap()).unwrap();
        assert!(hk.fingerprint().starts_with("SHA256:"));
        assert_eq!(hk.algorithm(), "ssh-ed25519");
    }
}
