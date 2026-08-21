//! Error type for the primitive layer.

use thiserror::Error;

/// Errors that can occur in the primitive wrappers.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PrimitiveError {
    /// Invalid or malformed public key.
    #[error("invalid public key")]
    InvalidPublicKey,

    /// Invalid or malformed private / secret key.
    #[error("invalid secret key")]
    InvalidSecretKey,

    /// Malformed or rejected KEM ciphertext.
    #[error("malformed or rejected KEM ciphertext")]
    InvalidKemCiphertext,

    /// AEAD decryption failed (tag mismatch, wrong key, wrong AD, etc.).
    #[error("AEAD decryption failed")]
    AeadDecryptionFailed,

    /// AEAD authentication failed (header or message).
    #[error("AEAD authentication failed")]
    AeadAuthFailed,

    /// Nonce misuse or invalid nonce length.
    #[error("invalid or reused nonce")]
    InvalidNonce,

    /// Input length is invalid for the primitive.
    #[error("invalid length")]
    InvalidLength,

    /// HKDF expansion requested an output longer than permitted.
    #[error("HKDF output length too large")]
    HkdfLength,

    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// RNG failure.
    #[error("random number generation failed")]
    Rng,

    /// Internal / unexpected error.
    #[error("internal primitive error")]
    Internal,

    /// A security-sensitive counter would overflow or exceed a bound.
    #[error("counter or resource limit exceeded")]
    LimitExceeded,
}
