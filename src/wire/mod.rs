//! Wire formats and authenticated application envelopes.
//!
//! All security-sensitive metadata is cryptographically bound either as
//! associated data or inside the encrypted payload. Ciphertext cannot be
//! moved across conversations or devices and still authenticate.

pub mod envelope;

pub use envelope::{
    Envelope, EnvelopeError, MessageType, PayloadType, ProtocolVersion, CryptoSuite,
};
