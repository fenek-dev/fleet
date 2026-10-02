//! SSH transport (design §3.2, §5.5 step 1, §5.9) on `russh`.
//!
//! One [`SshConnection`] per server. Client auth is public-key, and the
//! private key never enters russh: russh hands us the exact bytes to sign
//! (`authenticate_publickey_with`, the ssh-agent path) and an [`SshSigner`]
//! signs them — the Secure Enclave on a Mac, [`Ed25519Signer`] for the
//! recovery SSH key. The one exception is the operator's one-time password
//! ([`SshAuth::Password`], design §10.1): it is only sent to a **pinned**
//! host key, answers a single `password` or one password-style
//! keyboard-interactive prompt, and is never stored. Host keys are pinned:
//! a mismatch is a hard [`SshError::HostKeyChanged`]; with no pin the
//! connection proceeds (key auth, or [`SshConnection::probe_host_key_only`])
//! and the [`HostKeyObservation`] says `FirstUse` so the app can show the
//! fingerprint and store the pin.

use crate::secret::SecretString;
use crate::signer::SignerError;
use fleet_crypto::sig::{self, Ed25519Signer, Signer};
use fleet_proto::{Ed25519Public, P256Public, Signature};
use russh::client::{self, Handle, KeyboardInteractiveAuthResponse, Msg};
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
/// Monitor variant; the monitor SSH key's forced command runs this anyway.
pub const AGENT_BRIDGE_MONITOR: &str = "/usr/lib/fleet/fleet-agent bridge --monitor";

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
    /// The hop this key is from.
    pub host: String,
    pub port: u16,
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

    /// Every hop matched its pin: the only state in which a connection may
    /// be used for anything but showing the fingerprint.
    pub fn all_matched(&self) -> bool {
        !self.needs_confirmation()
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
    /// A hop has no pinned host key: the operator must compare the
    /// fingerprint and pin it before the connection is used.
    #[error("host key needs confirmation")]
    HostKeyUnconfirmed,
    #[error("server refused our key")]
    AuthRejected,
    /// The server refused the one-time password.
    #[error("the server refused the password")]
    WrongPassword,
    /// The server offers neither `password` nor keyboard-interactive.
    #[error(
        "the server does not accept password login (PasswordAuthentication is off); add this \
         Mac's SSH key to the user's authorized_keys manually"
    )]
    PasswordAuthDisabled,
    /// Keyboard-interactive asked for more than one password (OTP, 2FA…).
    #[error("password login needs more than a password: {0}; add this Mac's SSH key manually")]
    KeyboardInteractiveUnsupported(String),
    #[error("signer: {0}")]
    Signer(SignerError),
    #[error("channel request refused")]
    ChannelRejected,
    #[error("bad key: {0}")]
    BadKey(String),
    #[error("sftp: {0}")]
    Sftp(String),
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

/// How the final hop authenticates. Jump hops always use `jump_key`.
pub enum SshAuth<'a> {
    /// This Mac's SSH key (or the recovery key).
    Key(&'a dyn SshSigner),
    /// The one-time password; needs a pinned host key.
    Password {
        secret: &'a SecretString,
        jump_key: &'a dyn SshSigner,
    },
}

impl SshAuth<'_> {
    fn jump_key(&self) -> &dyn SshSigner {
        match self {
            Self::Key(k) => *k,
            Self::Password { jump_key, .. } => *jump_key,
        }
    }
}

/// What the final hop does after the key exchange.
enum Mode<'a> {
    Auth(&'a SshAuth<'a>),
    /// Stop after the host key: nothing is authenticated or sent.
    HostKeyOnly,
}

/// Phrases that mark a prompt as a second factor, not the password.
const OTP_WORDS: [&str; 10] = [
    "verification",
    "code",
    "otp",
    "token",
    "one-time",
    "one time",
    "duo",
    "2fa",
    "authenticator",
    "passcode",
];

/// What to do with one keyboard-interactive round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KiAction {
    /// No prompts (a banner round): answer with nothing.
    Empty,
    /// Exactly one password-style prompt: answer with the password.
    Password,
    /// The password was sent and PAM asks again: it was wrong.
    WrongPassword,
    /// Anything else (multi-prompt, OTP, expired password): stop.
    Refuse(String),
}

/// Classifies a keyboard-interactive round (`prompts` = text and echo flag).
/// Only a single non-echoing password prompt is ever answered.
/// `answered`: the password was already sent in an earlier round.
pub fn classify_ki(prompts: &[(String, bool)], answered: bool) -> KiAction {
    match prompts {
        [] => KiAction::Empty,
        [(text, echo)] => {
            let lower = text.to_ascii_lowercase();
            if answered {
                if lower.contains("new password")
                    || lower.contains("retype")
                    || lower.contains("expired")
                {
                    return KiAction::Refuse(
                        "the password has expired; change it on the server first".into(),
                    );
                }
                if lower.contains("password") && !*echo {
                    return KiAction::WrongPassword;
                }
            } else if *echo {
                return KiAction::Refuse("the prompt is not a password prompt".into());
            } else if lower.contains("password")
                && !OTP_WORDS.iter().any(|w| lower.contains(w))
            {
                return KiAction::Password;
            }
            KiAction::Refuse("the server asks for something other than a password".into())
        }
        many => KiAction::Refuse(format!(
            "the server asks {} questions (one-time code or multi-factor login)",
            many.len()
        )),
    }
}

/// Password auth on a handle with a pinned host key. Prefers plain
/// `password`; falls back to keyboard-interactive (PAM setups with
/// `PasswordAuthentication no`) answering one password prompt.
async fn password_auth(
    handle: &mut Handle<HostKeyCheck>,
    user: &str,
    secret: &SecretString,
) -> Result<(), SshError> {
    let methods = match handle.authenticate_none(user.to_string()).await? {
        client::AuthResult::Success => return Ok(()),
        client::AuthResult::Failure {
            remaining_methods, ..
        } => remaining_methods,
    };
    // `MethodKind` isn't exported by russh; its wire names are.
    let offers = |name: &str| methods.iter().any(|m| <&str>::from(m) == name);
    if offers("password") {
        return match handle
            .authenticate_password(user.to_string(), secret.expose())
            .await?
        {
            client::AuthResult::Success => Ok(()),
            client::AuthResult::Failure {
                partial_success: true,
                ..
            } => Err(SshError::KeyboardInteractiveUnsupported(
                "the server wants a second factor after the password".into(),
            )),
            client::AuthResult::Failure { .. } => Err(SshError::WrongPassword),
        };
    }
    if !offers("keyboard-interactive") {
        return Err(SshError::PasswordAuthDisabled);
    }
    let mut resp = handle
        .authenticate_keyboard_interactive_start(user.to_string(), None)
        .await?;
    let mut answered = false;
    for _ in 0..4 {
        match resp {
            KeyboardInteractiveAuthResponse::Success => return Ok(()),
            KeyboardInteractiveAuthResponse::Failure {
                partial_success, ..
            } => {
                return Err(if partial_success {
                    SshError::KeyboardInteractiveUnsupported(
                        "the server wants a second factor after the password".into(),
                    )
                } else if answered {
                    SshError::WrongPassword
                } else {
                    SshError::PasswordAuthDisabled
                });
            }
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                let ps: Vec<(String, bool)> =
                    prompts.into_iter().map(|p| (p.prompt, p.echo)).collect();
                resp = match classify_ki(&ps, answered) {
                    KiAction::Empty => {
                        handle
                            .authenticate_keyboard_interactive_respond(Vec::new())
                            .await?
                    }
                    KiAction::Password => {
                        answered = true;
                        handle
                            .authenticate_keyboard_interactive_respond(vec![
                                secret.expose().to_string(),
                            ])
                            .await?
                    }
                    KiAction::WrongPassword => return Err(SshError::WrongPassword),
                    KiAction::Refuse(why) => {
                        return Err(SshError::KeyboardInteractiveUnsupported(why));
                    }
                };
            }
        }
    }
    Err(SshError::KeyboardInteractiveUnsupported(
        "too many prompts".into(),
    ))
}

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
        Self::connect_auth(target, &SshAuth::Key(auth), pinned_host_key, opts).await
    }

    /// Connects with `auth` for the final hop. [`SshAuth::Password`] is
    /// refused with [`SshError::HostKeyUnconfirmed`] unless `pinned_host_key`
    /// is set: the password only ever goes to a pinned key.
    pub async fn connect_auth(
        target: &SshTarget,
        auth: &SshAuth<'_>,
        pinned_host_key: Option<HostKey>,
        opts: &SshOptions,
    ) -> Result<(SshConnection, HostKeyObservation), SshError> {
        Self::hop(target, auth.jump_key(), &Mode::Auth(auth), pinned_host_key, opts).await
    }

    /// Reads the host keys (jump hops authenticate with `jump_key`, the
    /// final hop is not authenticated at all) and disconnects. For servers
    /// that don't accept this Mac's key yet, so the operator can confirm the
    /// fingerprint before a password is ever sent.
    pub async fn probe_host_key_only(
        target: &SshTarget,
        jump_key: &dyn SshSigner,
        opts: &SshOptions,
    ) -> Result<HostKeyObservation, SshError> {
        let (conn, obs) =
            Self::hop(target, jump_key, &Mode::HostKeyOnly, None, opts).await?;
        conn.disconnect().await;
        Ok(obs)
    }

    fn hop<'a>(
        target: &'a SshTarget,
        jump_key: &'a dyn SshSigner,
        mode: &'a Mode<'a>,
        pinned: Option<HostKey>,
        opts: &'a SshOptions,
    ) -> BoxFut<'a, Result<(SshConnection, HostKeyObservation), SshError>> {
        Box::pin(async move {
            // The jump host has its own timeout; this one covers our hop.
            let (jump, via) = match &target.proxy_jump {
                Some(j) => {
                    let key_auth = SshAuth::Key(jump_key);
                    let (c, o) = Self::hop(
                        j,
                        jump_key,
                        &Mode::Auth(&key_auth),
                        j.host_key.clone(),
                        opts,
                    )
                    .await?;
                    (Some(Box::new(c)), Some(Box::new(o)))
                }
                None => (None, None),
            };
            timeout(
                opts.connect_timeout,
                Self::handshake(target, mode, pinned, opts, jump, via),
            )
            .await
            .map_err(|_| SshError::Timeout)?
        })
    }

    async fn handshake(
        target: &SshTarget,
        mode: &Mode<'_>,
        pinned: Option<HostKey>,
        opts: &SshOptions,
        jump: Option<Box<SshConnection>>,
        via: Option<Box<HostKeyObservation>>,
    ) -> Result<(SshConnection, HostKeyObservation), SshError> {
        // A password is only ever sent to a host key the operator pinned.
        if matches!(mode, Mode::Auth(SshAuth::Password { .. })) && pinned.is_none() {
            return Err(SshError::HostKeyUnconfirmed);
        }
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
        match mode {
            Mode::HostKeyOnly => {}
            Mode::Auth(SshAuth::Key(auth)) => {
                let public = auth.public_key().to_russh()?;
                let res = handle
                    .authenticate_publickey_with(
                        target.user.clone(),
                        public,
                        None,
                        &mut AuthSigner(*auth),
                    )
                    .await?;
                if !res.success() {
                    return Err(SshError::AuthRejected);
                }
            }
            Mode::Auth(SshAuth::Password { secret, .. }) => {
                password_auth(&mut handle, &target.user, secret).await?;
            }
        }
        Ok((
            SshConnection {
                handle,
                opts: opts.clone(),
                _jump: jump,
            },
            HostKeyObservation {
                host: target.host.clone(),
                port: target.port,
                key,
                status,
                via,
            },
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
        self.open_agent_channel_mode(if recovery {
            crate::SessionMode::Recovery
        } else {
            crate::SessionMode::Normal
        })
        .await
    }

    /// Agent channel for `mode` (`bridge`, `bridge --recovery`,
    /// `bridge --monitor`); restricted keys force their own flag anyway.
    pub async fn open_agent_channel_mode(
        &self,
        mode: crate::SessionMode,
    ) -> Result<AgentStream, SshError> {
        let mut ch = self.open_session().await?;
        let cmd = match mode {
            crate::SessionMode::Normal => AGENT_BRIDGE,
            crate::SessionMode::Recovery => AGENT_BRIDGE_RECOVERY,
            crate::SessionMode::Monitor => AGENT_BRIDGE_MONITOR,
        };
        ch.exec(true, cmd).await?;
        // The gate never speaks first (the Noise initiator does), so no
        // data can be skipped while waiting for the reply.
        self.wait_reply(&mut ch).await?;
        Ok(ch.into_stream())
    }

    /// Interactive shell on a PTY (terminal, Phase 2).
    pub async fn open_pty(&self, term: &str, cols: u32, rows: u32) -> Result<PtyChannel, SshError> {
        self.open_pty_with(term, cols, rows, None).await
    }

    /// A PTY running `command` (a fixed string built by the caller from
    /// validated tokens only; the server's shell parses it) or, with
    /// `None`, the login shell.
    pub async fn open_pty_with(
        &self,
        term: &str,
        cols: u32,
        rows: u32,
        command: Option<&str>,
    ) -> Result<PtyChannel, SshError> {
        let mut ch = self.open_session().await?;
        ch.request_pty(true, term, cols, rows, 0, 0, &[]).await?;
        self.wait_reply(&mut ch).await?;
        match command {
            Some(c) => ch.exec(true, c).await?,
            None => ch.request_shell(true).await?,
        }
        self.wait_reply(&mut ch).await?;
        let (read, write) = ch.split();
        Ok(PtyChannel { read, write })
    }

    /// SFTP subsystem channel on this connection (file browser, uploads).
    pub async fn open_sftp(&self) -> Result<russh_sftp::client::SftpSession, SshError> {
        let mut ch = self.open_session().await?;
        ch.request_subsystem(true, "sftp").await?;
        self.wait_reply(&mut ch).await?;
        timeout(
            self.opts.channel_timeout,
            russh_sftp::client::SftpSession::new(ch.into_stream()),
        )
        .await
        .map_err(|_| SshError::Timeout)?
        .map_err(|e| SshError::Sftp(e.to_string()))
    }

    /// A second, raw SFTP channel (protocol extensions such as
    /// `posix-rename@openssh.com`). The caller runs `init`.
    pub async fn open_raw_sftp(&self) -> Result<russh_sftp::client::RawSftpSession, SshError> {
        let mut ch = self.open_session().await?;
        ch.request_subsystem(true, "sftp").await?;
        self.wait_reply(&mut ch).await?;
        Ok(russh_sftp::client::RawSftpSession::new(ch.into_stream()))
    }

    /// Runs `command` on an exec channel (no PTY) and collects its output,
    /// each stream capped at `max_output` bytes (the rest is dropped), until
    /// the channel closes or `limit` passes. `command` is parsed by the
    /// remote shell: callers build it from validated tokens only.
    pub async fn exec_capture(
        &self,
        command: &str,
        max_output: usize,
        limit: Duration,
    ) -> Result<ExecOutput, SshError> {
        self.exec_capture_prompted(command, None, max_output, limit)
            .await
    }

    /// Like [`Self::exec_capture`] for `sudo -S -p <marker>`: `answer`
    /// (the password line) is written **only after** `marker` shows up on
    /// stderr, i.e. after sudo itself asked for it, and stdin is closed right
    /// after. If the command finishes, or writes to stdout, without the
    /// marker (sudo needed no password), nothing is ever sent, so the
    /// secret can't reach the command sudo runs. The marker is removed from
    /// the returned stderr. Bounded by `limit` like any exec. The caller
    /// keeps `answer` in a zeroizing buffer.
    pub async fn exec_capture_prompted(
        &self,
        command: &str,
        prompt: Option<(&str, &[u8])>,
        max_output: usize,
        limit: Duration,
    ) -> Result<ExecOutput, SshError> {
        let mut ch = self.open_session().await?;
        ch.exec(true, command).await?;
        let run = async {
            let mut out = ExecOutput::default();
            let mut replied = false;
            // Rolling window so a marker split across packets is found even
            // once the capture cap is reached.
            let mut window: Vec<u8> = Vec::new();
            let mut done = prompt.is_none();
            loop {
                match ch.wait().await {
                    Some(ChannelMsg::Success) => replied = true,
                    Some(ChannelMsg::Failure) if !replied => return Err(SshError::ChannelRejected),
                    Some(ChannelMsg::Data { data }) => {
                        if !done {
                            // The command is already running: sudo needed no
                            // password. Send nothing; just close stdin.
                            done = true;
                            let _ = ch.eof().await;
                        }
                        cap_extend(&mut out.stdout, &data, max_output)
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        if !done && let Some((marker, answer)) = prompt {
                            window.extend_from_slice(&data);
                            if window
                                .windows(marker.len())
                                .any(|w| w == marker.as_bytes())
                            {
                                done = true;
                                // The command may have exited already; its
                                // status still tells the story.
                                let _ = ch.data(answer).await;
                                let _ = ch.eof().await;
                            } else {
                                let keep = marker.len().saturating_sub(1);
                                let drop = window.len().saturating_sub(keep);
                                window.drain(..drop);
                            }
                        }
                        cap_extend(&mut out.stderr, &data, max_output);
                        if out.stderr.len() >= max_output {
                            out.stderr_truncated = true;
                        }
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => out.status = Some(exit_status),
                    Some(ChannelMsg::Close) | None => {
                        if let Some((marker, _)) = prompt {
                            out.stderr = remove_all(&out.stderr, marker.as_bytes());
                        }
                        return Ok(out);
                    }
                    Some(_) => {}
                }
            }
        };
        timeout(limit, run).await.map_err(|_| SshError::Timeout)?
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

/// Result of [`SshConnection::exec_capture`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// `None` when the server sent no exit status (killed by a signal).
    pub status: Option<u32>,
    /// stderr hit the capture cap: bytes were dropped after it.
    pub stderr_truncated: bool,
}

/// `hay` without any occurrence of `needle`.
fn remove_all(hay: &[u8], needle: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return hay.to_vec();
    }
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0;
    while i < hay.len() {
        if hay[i..].starts_with(needle) {
            i += needle.len();
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out
}

fn cap_extend(buf: &mut Vec<u8>, data: &[u8], max: usize) {
    let room = max.saturating_sub(buf.len());
    buf.extend_from_slice(&data[..data.len().min(room)]);
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

    /// Next output; `None` once the channel is closed. `Eof` only ends the
    /// server's data: sshd sends `exit-status` after it, so reading goes on
    /// until `Close` to surface [`PtyOutput::Exit`].
    pub async fn read(&mut self) -> Option<PtyOutput> {
        loop {
            match self.read.wait().await? {
                ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                    return Some(PtyOutput::Data(data.to_vec()));
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    return Some(PtyOutput::Exit(exit_status));
                }
                ChannelMsg::Close => return None,
                // Eof, window adjustments, exit signals…
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

    fn p(text: &str, echo: bool) -> (String, bool) {
        (text.to_string(), echo)
    }

    #[test]
    fn ki_answers_only_one_password_prompt() {
        assert_eq!(classify_ki(&[], false), KiAction::Empty);
        for ok in ["Password: ", "alice@host's password:", "Password:"] {
            assert_eq!(classify_ki(&[p(ok, false)], false), KiAction::Password, "{ok}");
        }
        // Echoed prompt, OTP wording, or no "password" at all: refused.
        for bad in [
            p("Password: ", true),
            p("Verification code: ", false),
            p("Password + OTP token: ", false),
            p("Duo passcode or option (1-3): ", false),
            p("Enter PIN: ", false),
        ] {
            assert!(
                matches!(classify_ki(std::slice::from_ref(&bad), false), KiAction::Refuse(_)),
                "{bad:?}"
            );
        }
        // Several questions: refused, with the count in the message.
        match classify_ki(&[p("Password: ", false), p("Code: ", false)], false) {
            KiAction::Refuse(m) => assert!(m.contains('2')),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn ki_second_round_means_wrong_or_expired() {
        assert_eq!(
            classify_ki(&[p("Password: ", false)], true),
            KiAction::WrongPassword
        );
        assert!(matches!(
            classify_ki(&[p("New password: ", false)], true),
            KiAction::Refuse(m) if m.contains("expired")
        ));
        assert!(matches!(
            classify_ki(&[p("Verification code: ", false)], true),
            KiAction::Refuse(_)
        ));
    }

    #[test]
    fn password_error_texts_name_the_fix() {
        let e = SshError::PasswordAuthDisabled.to_string();
        assert!(e.contains("authorized_keys") && e.contains("manually"));
        assert!(
            SshError::KeyboardInteractiveUnsupported("x".into())
                .to_string()
                .contains("manually")
        );
    }

    #[tokio::test]
    async fn password_needs_a_pinned_host_key() {
        let secret = SecretString::from_string("pw-pw-pw".into()).unwrap();
        let key = P256SshSigner(fleet_crypto::sig::SoftwareP256Signer::generate().unwrap());
        let target = SshTarget::new("127.0.0.1", 1, "ops");
        // Refused before any connection is attempted (port 1 is closed).
        let err = SshConnection::connect_auth(
            &target,
            &SshAuth::Password {
                secret: &secret,
                jump_key: &key,
            },
            None,
            &SshOptions::default(),
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(err, SshError::HostKeyUnconfirmed), "{err}");
    }

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
