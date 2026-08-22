//! VoiceChat Crypto — clean-room Signal Protocol family implementation.
//!
//! Application code should depend only on `engine::CryptoEngineApi` and
//! `engine::VoiceChatCryptoEngine`. Internal modules are not part of the
//! stable application contract.

#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod engine;
pub mod envelope;
pub mod fingerprint;
pub mod identity;
pub mod padding;
pub mod policy;
pub mod pqxdh;
pub mod prekeys;
pub mod primitives;
pub mod ratchet;
pub mod replay;
pub mod session;
pub mod storage;

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(test)]
pub mod testing;

pub use engine::{
    CryptoEngineApi, CryptoError, DeviceConfig, InboundSessionMessage, InitiationPacket,
    SealedMessage, SessionId, VoiceChatCryptoEngine,
};
pub use fingerprint::{
    compute_fingerprint, IdentityChangeReason, IdentityMaterial, IdentityState, IdentityTracker,
    SafetyFingerprint, TrustStore, VerificationMethod,
};
pub use identity::{PeerIdentityStore, PeerTrustRecord};
pub use policy::{
    available_profiles, enforce_profile, select_profile, CryptoProfile, PROFILE_PREFERENCE,
    PROTOCOL_VERSION,
};
pub use primitives::kdf::LABELS;
pub use session::SessionManager;
pub use storage::{RollbackGuard, StorageEpoch};
