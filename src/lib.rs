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

// Compatibility module aliases for integrations that adopted the earlier P02
// names before storage submodules became first-class.
pub use storage::encrypted_file as encrypted_storage;
pub use storage::trusted_anchor;

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(test)]
pub mod testing;

pub use engine::{
    CryptoEngineApi, CryptoError, DeviceConfig, InboundSessionMessage, InitiationPacket,
    SealedMessage, SessionId, SessionTag, VoiceChatCryptoEngine,
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
pub use storage::coordinated::{
    coordinated_backends_for_initialize, coordinated_backends_for_restore, AnchoredStorage,
    PreparedMonotonicCounter, RestoreRejection,
};
pub use storage::encrypted_file::EncryptedFileStorage;
pub use storage::trusted_anchor::{AnchoredMonotonicCounter, RollbackAnchor};
pub use storage::{RollbackGuard, StorageEpoch};

/// Debug representation intentionally summarizes the public bundle instead of
/// dumping the full ML-KEM public key into logs/test failures.
impl std::fmt::Debug for prekeys::PublicPrekeyBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicPrekeyBundle")
            .field("identity_key", &self.identity_key)
            .field("signed_prekey_id", &self.signed_prekey_id)
            .field("signed_prekey", &self.signed_prekey)
            .field("has_one_time_ec", &self.one_time_ec.is_some())
            .field("pq_prekey_id", &self.pq_prekey_id)
            .field("pq_prekey_public_len", &self.pq_prekey_public.len())
            .field("is_pq_one_time", &self.is_pq_one_time)
            .finish()
    }
}
