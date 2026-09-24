use fleet_proto::DecodeError;

/// Low-level cryptographic failures. Protocol-level verification has its own
/// error types (`verify::VerifyError`, `approval::ApprovalError`,
/// `roster::RosterError`) that map to wire `ErrorCode`s.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid public key")]
    BadKey,
    #[error("invalid signature")]
    BadSignature,
    #[error("signer failed")]
    Signer,
    #[error("malformed encoding: {0}")]
    Decode(#[from] DecodeError),
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),
    #[error("message of {0} bytes is too large")]
    TooLarge(usize),
    #[error("malformed frame stream")]
    Framing,
    #[error("invalid recovery code")]
    Mnemonic,
    #[error("key derivation failed")]
    Kdf,
    #[error("OS random number generator failed")]
    Rng,
}
