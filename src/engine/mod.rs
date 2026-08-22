//! Application-facing CryptoEngine.
//!
//! This is the **only** surface VoiceChat UI / domain code should use.
//! Internal ratchet state, chain keys, and private keys never leave this
//! boundary. Implementation is VoiceChat Crypto only — no libsignal.
//!
//! Integration path:
//!   UI → CryptoEngine trait → VoiceChatCryptoEngine → voicechat-crypto modules
//!
//! Privacy invariant:
//!   VOICE PROFILE NEVER LEAVES OWNER DEVICE.
//!   Only sender-generated encrypted voice-message payloads cross the network.

use std::collections::HashMap;

use crate::fingerprint::{
    compute_fingerprint, IdentityMaterial, IdentityState, IdentityTracker, SafetyFingerprint,
    TrustStore, VerificationMethod,
};
use crate::policy::CryptoProfile;
use crate::pqxdh::{alice_initiate, bob_process, BobPrivateMaterial};
use crate::prekeys::{IdentityKeyPair, PrekeyStore, PublicPrekeyBundle};
use crate::primitives::error::PrimitiveError;
#[cfg(feature = "header-encrypt")]
use crate::primitives::kdf::{hkdf_extract_expand, LABELS};
use crate::primitives::x25519::{X25519Public, X25519Secret};
#[cfg(feature = "header-encrypt")]
use crate::ratchet::header_encrypt::HeaderEncryptState;
#[cfg(feature = "hybrid")]
use crate::ratchet::triple::TripleRatchetState;
use crate::ratchet::{DoubleRatchetState, Header, DEFAULT_MAX_SKIP};
use crate::replay::{ReplayCache, ReplayKey};
use crate::storage::monotonic::{MemoryCounter, MonotonicCounter};
use crate::storage::{
    MemoryStorage, RollbackGuard, StateBlob, StorageEpoch, TransactionalStorage,
};

// ---------------------------------------------------------------------------
// Domain types visible to the application (opaque / minimal)
// ---------------------------------------------------------------------------

/// Opaque session identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; 16]);

/// Opaque device configuration at initialization.
#[derive(Clone, Debug)]
pub struct DeviceConfig {
    pub device_id: Vec<u8>,
    pub profile: CryptoProfile,
}

impl DeviceConfig {
    /// Strongest profile this build advertises (`PROFILE_PREFERENCE[0]`).
    pub fn recommended(device_id: Vec<u8>) -> Self {
        Self {
            device_id,
            profile: crate::policy::PROFILE_PREFERENCE[0],
        }
    }
}

/// Sealed message for network transport (no secrets).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedMessage {
    pub header: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub session_hint: SessionId,
}

/// PQXDH initiation packet Alice delivers to Bob.
///
/// Contains identity/ephemeral public keys, ML-KEM ciphertext, the prekey
/// identifiers Alice used, and the first authenticated Double Ratchet
/// ciphertext (PQXDH initial message).
#[derive(Clone, Debug)]
pub struct InitiationPacket {
    pub sender_identity_public: [u8; 32],
    pub sender_ephemeral_public: [u8; 32],
    pub kem_ciphertext: Vec<u8>,
    pub used_spk_id: u32,
    pub used_ec_opk_id: Option<u32>,
    pub pq_prekey_id: u32,
    pub first_message: SealedMessage,
}

/// Backward-compatible name for [`InitiationPacket`].
pub type InboundSessionMessage = InitiationPacket;

impl SealedMessage {
    /// Public-only encoding for the network / FFI. No secrets.
    pub fn encode(&self) -> Vec<u8> {
        let mut o = b"VCSEAL01".to_vec();
        o.extend_from_slice(&self.session_hint.0);
        o.extend_from_slice(&(self.header.len() as u32).to_le_bytes());
        o.extend_from_slice(&self.header);
        o.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        o.extend_from_slice(&self.ciphertext);
        o
    }

    /// Decode a sealed message. Rejects trailing garbage.
    pub fn decode(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < 8 + 16 + 8 || &data[0..8] != b"VCSEAL01" {
            return Err(CryptoError::InvalidArgument);
        }
        let mut i = 8;
        let mut hint = [0u8; 16];
        hint.copy_from_slice(&data[i..i + 16]);
        i += 16;
        if i + 4 > data.len() {
            return Err(CryptoError::InvalidArgument);
        }
        let hlen = u32::from_le_bytes(data[i..i + 4].try_into().unwrap()) as usize;
        i += 4;
        if i + hlen + 4 > data.len() {
            return Err(CryptoError::InvalidArgument);
        }
        let header = data[i..i + hlen].to_vec();
        i += hlen;
        let clen = u32::from_le_bytes(data[i..i + 4].try_into().unwrap()) as usize;
        i += 4;
        if i + clen != data.len() {
            return Err(CryptoError::InvalidArgument);
        }
        Ok(Self {
            header,
            ciphertext: data[i..].to_vec(),
            session_hint: SessionId(hint),
        })
    }
}

impl InitiationPacket {
    /// Public-only encoding for the network / FFI. No secrets.
    pub fn encode(&self) -> Vec<u8> {
        let mut o = b"VCINIT01".to_vec();
        o.extend_from_slice(&self.sender_identity_public);
        o.extend_from_slice(&self.sender_ephemeral_public);
        o.extend_from_slice(&(self.kem_ciphertext.len() as u16).to_le_bytes());
        o.extend_from_slice(&self.kem_ciphertext);
        o.extend_from_slice(&self.used_spk_id.to_le_bytes());
        match self.used_ec_opk_id {
            None => o.push(0),
            Some(id) => {
                o.push(1);
                o.extend_from_slice(&id.to_le_bytes());
            }
        }
        o.extend_from_slice(&self.pq_prekey_id.to_le_bytes());
        let first = self.first_message.encode();
        o.extend_from_slice(&(first.len() as u32).to_le_bytes());
        o.extend_from_slice(&first);
        o
    }

    /// Decode an initiation packet. Rejects trailing garbage.
    pub fn decode(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < 8 + 32 + 32 + 2 + 4 + 1 + 4 + 4 || &data[0..8] != b"VCINIT01" {
            return Err(CryptoError::InvalidArgument);
        }
        let mut i = 8;
        let take = |i: &mut usize, n: usize| -> Result<&[u8], CryptoError> {
            if *i + n > data.len() {
                return Err(CryptoError::InvalidArgument);
            }
            let s = &data[*i..*i + n];
            *i += n;
            Ok(s)
        };
        let mut ik = [0u8; 32];
        ik.copy_from_slice(take(&mut i, 32)?);
        let mut ek = [0u8; 32];
        ek.copy_from_slice(take(&mut i, 32)?);
        let ct_len = u16::from_le_bytes(take(&mut i, 2)?.try_into().unwrap()) as usize;
        let kem_ciphertext = take(&mut i, ct_len)?.to_vec();
        let used_spk_id = u32::from_le_bytes(take(&mut i, 4)?.try_into().unwrap());
        let has_opk = take(&mut i, 1)?[0];
        let used_ec_opk_id = match has_opk {
            0 => None,
            1 => Some(u32::from_le_bytes(take(&mut i, 4)?.try_into().unwrap())),
            _ => return Err(CryptoError::InvalidArgument),
        };
        let pq_prekey_id = u32::from_le_bytes(take(&mut i, 4)?.try_into().unwrap());
        let first_len = u32::from_le_bytes(take(&mut i, 4)?.try_into().unwrap()) as usize;
        let first = take(&mut i, first_len)?;
        if i != data.len() {
            return Err(CryptoError::InvalidArgument);
        }
        Ok(Self {
            sender_identity_public: ik,
            sender_ephemeral_public: ek,
            kem_ciphertext,
            used_spk_id,
            used_ec_opk_id,
            pq_prekey_id,
            first_message: SealedMessage::decode(first)?,
        })
    }
}

/// Application-level crypto errors (no internal protocol detail leakage).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CryptoError {
    InvalidArgument,
    CryptoFailure,
    NoSession,
    IdentityChanged,
    Replay,
    Storage,
    LimitExceeded,
    VoiceProfileForbidden,
    Internal,
}

impl From<PrimitiveError> for CryptoError {
    fn from(e: PrimitiveError) -> Self {
        match e {
            PrimitiveError::Internal => CryptoError::Internal,
            PrimitiveError::LimitExceeded => CryptoError::LimitExceeded,
            PrimitiveError::InvalidLength | PrimitiveError::InvalidPublicKey => {
                CryptoError::InvalidArgument
            }
            _ => CryptoError::CryptoFailure,
        }
    }
}

/// Trait matching the application-defined CryptoEngine abstraction.
/// VoiceChat application code depends on this trait only.
pub trait CryptoEngineApi {
    fn generate_public_prekey_bundle(
        &mut self,
        one_time_count: usize,
    ) -> Result<PublicPrekeyBundle, CryptoError>;

    fn replenish_prekeys(
        &mut self,
        one_time_count: usize,
    ) -> Result<PublicPrekeyBundle, CryptoError>;

    fn establish_outbound_session(
        &mut self,
        remote_bundle: &PublicPrekeyBundle,
        conversation_context: &[u8],
        first_plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(SessionId, InitiationPacket), CryptoError>;

    fn process_inbound_session(
        &mut self,
        message: &InitiationPacket,
        conversation_context: &[u8],
        associated_data: &[u8],
    ) -> Result<(SessionId, Vec<u8>), CryptoError>;

    fn encrypt(
        &mut self,
        session_id: &SessionId,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<SealedMessage, CryptoError>;

    /// Encrypt a voice message payload.
    ///
    /// **Privacy:** `voice_profile` bytes must never be supplied here and must
    /// never appear in associated data or envelope metadata. Only the
    /// sender-generated encrypted payload may leave the device.
    fn encrypt_voice_payload(
        &mut self,
        session_id: &SessionId,
        voice_payload: &[u8],
        associated_data: &[u8],
    ) -> Result<SealedMessage, CryptoError>;

    fn decrypt(
        &mut self,
        session_id: &SessionId,
        sealed: &SealedMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    fn safety_fingerprint(
        &self,
        remote_identity_public: &[u8; 32],
        remote_device_id: Option<&[u8]>,
    ) -> Result<SafetyFingerprint, CryptoError>;

    fn acknowledge_identity_change(
        &mut self,
        remote_identity_public: &[u8; 32],
        remote_device_id: Option<&[u8]>,
    ) -> Result<(), CryptoError>;

    fn has_session(&self, session_id: &SessionId) -> bool;
    fn delete_session(&mut self, session_id: &SessionId) -> Result<(), CryptoError>;
    fn delete_all_sessions(&mut self) -> Result<(), CryptoError>;

    fn local_identity_public(&self) -> [u8; 32];
}

// ---------------------------------------------------------------------------
// VoiceChatCryptoEngine — concrete implementation
// ---------------------------------------------------------------------------

#[allow(clippy::large_enum_variant)]
enum LiveRatchet {
    Classical(DoubleRatchetState),
    #[cfg(feature = "header-encrypt")]
    HeaderEncrypt(HeaderEncryptState),
    #[cfg(feature = "hybrid")]
    Hybrid(TripleRatchetState),
}

impl LiveRatchet {
    fn clone_for_trial(&self) -> Self {
        match self {
            LiveRatchet::Classical(r) => LiveRatchet::Classical(r.clone_for_trial()),
            #[cfg(feature = "header-encrypt")]
            LiveRatchet::HeaderEncrypt(r) => LiveRatchet::HeaderEncrypt(r.clone_for_trial()),
            #[cfg(feature = "hybrid")]
            LiveRatchet::Hybrid(r) => LiveRatchet::Hybrid(r.clone_for_trial()),
        }
    }

    fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        match self {
            LiveRatchet::Classical(r) => {
                let (h, ct) = r.encrypt(plaintext, ad).map_err(CryptoError::from)?;
                Ok((h.encode(), ct))
            }
            #[cfg(feature = "header-encrypt")]
            LiveRatchet::HeaderEncrypt(r) => r.encrypt(plaintext, ad).map_err(CryptoError::from),
            #[cfg(feature = "hybrid")]
            LiveRatchet::Hybrid(r) => {
                let (h, ct) = r.encrypt(plaintext, ad).map_err(CryptoError::from)?;
                Ok((h.encode(), ct))
            }
        }
    }

    fn decrypt(
        &mut self,
        header: &[u8],
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        match self {
            LiveRatchet::Classical(r) => {
                let h = Header::decode(header).map_err(CryptoError::from)?;
                r.decrypt(&h, ciphertext, ad).map_err(CryptoError::from)
            }
            #[cfg(feature = "header-encrypt")]
            LiveRatchet::HeaderEncrypt(r) => {
                r.decrypt(header, ciphertext, ad).map_err(CryptoError::from)
            }
            #[cfg(feature = "hybrid")]
            LiveRatchet::Hybrid(r) => {
                let h = crate::ratchet::triple::TripleHeader::decode(header)
                    .map_err(CryptoError::from)?;
                r.decrypt(&h, ciphertext, ad).map_err(CryptoError::from)
            }
        }
    }

    fn persist_blob(&self) -> Vec<u8> {
        match self {
            LiveRatchet::Classical(r) => {
                let mut out = vec![1u8];
                out.extend_from_slice(&r.serialize());
                out
            }
            #[cfg(feature = "hybrid")]
            LiveRatchet::Hybrid(r) => {
                let mut out = vec![2u8];
                out.extend_from_slice(&r.serialize());
                out
            }
            #[cfg(feature = "header-encrypt")]
            LiveRatchet::HeaderEncrypt(r) => {
                let mut out = vec![3u8];
                out.extend_from_slice(&r.serialize());
                out
            }
        }
    }

    fn restore(data: &[u8]) -> Result<Self, CryptoError> {
        if data.is_empty() {
            return Err(CryptoError::Storage);
        }
        match data[0] {
            1 => Ok(LiveRatchet::Classical(
                DoubleRatchetState::deserialize(&data[1..], DEFAULT_MAX_SKIP)
                    .map_err(CryptoError::from)?,
            )),
            #[cfg(feature = "hybrid")]
            2 => Ok(LiveRatchet::Hybrid(
                TripleRatchetState::deserialize(&data[1..], DEFAULT_MAX_SKIP)
                    .map_err(CryptoError::from)?,
            )),
            #[cfg(feature = "header-encrypt")]
            3 => Ok(LiveRatchet::HeaderEncrypt(
                HeaderEncryptState::deserialize(&data[1..], DEFAULT_MAX_SKIP)
                    .map_err(CryptoError::from)?,
            )),
            _ => Err(CryptoError::Storage),
        }
    }
}

fn encode_session(sid: &SessionId, sess: &LiveSession) -> Vec<u8> {
    let ratchet = sess.ratchet.persist_blob();
    let mut out = Vec::new();
    out.extend_from_slice(b"VCSESS01");
    out.extend_from_slice(&sid.0);
    out.extend_from_slice(&sess.remote_identity.to_bytes());
    out.extend_from_slice(&(sess.conversation.len() as u32).to_le_bytes());
    out.extend_from_slice(&sess.conversation);
    out.extend_from_slice(&(sess.handshake_ad.len() as u32).to_le_bytes());
    out.extend_from_slice(&sess.handshake_ad);
    out.extend_from_slice(&(ratchet.len() as u32).to_le_bytes());
    out.extend_from_slice(&ratchet);
    out
}

fn decode_session(data: &[u8]) -> Result<(SessionId, LiveSession), CryptoError> {
    if data.len() < 8 + 16 + 32 + 12 || &data[0..8] != b"VCSESS01" {
        return Err(CryptoError::Storage);
    }
    let mut i = 8;
    let mut sid_b = [0u8; 16];
    sid_b.copy_from_slice(&data[i..i + 16]);
    i += 16;
    let mut ik = [0u8; 32];
    ik.copy_from_slice(&data[i..i + 32]);
    i += 32;
    let take_len = |i: &mut usize| -> Result<usize, CryptoError> {
        if *i + 4 > data.len() {
            return Err(CryptoError::Storage);
        }
        let n = u32::from_le_bytes(data[*i..*i + 4].try_into().unwrap()) as usize;
        *i += 4;
        Ok(n)
    };
    let clen = take_len(&mut i)?;
    if i + clen > data.len() {
        return Err(CryptoError::Storage);
    }
    let conversation = data[i..i + clen].to_vec();
    i += clen;
    let alen = take_len(&mut i)?;
    if i + alen > data.len() {
        return Err(CryptoError::Storage);
    }
    let handshake_ad = data[i..i + alen].to_vec();
    i += alen;
    let rlen = take_len(&mut i)?;
    if i + rlen != data.len() {
        return Err(CryptoError::Storage);
    }
    let ratchet = LiveRatchet::restore(&data[i..])?;
    let remote_identity = X25519Public::from_bytes(ik).map_err(CryptoError::from)?;
    Ok((
        SessionId(sid_b),
        LiveSession {
            ratchet,
            remote_identity,
            conversation,
            identity_tracker: IdentityTracker::new(),
            handshake_ad,
        },
    ))
}

#[cfg(feature = "header-encrypt")]
fn he_keys_from_sk(sk: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let mut okm = [0u8; 64];
    hkdf_extract_expand(None, sk, LABELS::DR_HEADER, &mut okm).map_err(CryptoError::from)?;
    let mut hka = [0u8; 32];
    let mut nhkb = [0u8; 32];
    hka.copy_from_slice(&okm[..32]);
    nhkb.copy_from_slice(&okm[32..]);
    Ok((hka, nhkb))
}

fn init_alice_ratchet(
    profile: CryptoProfile,
    sk: &[u8; 32],
    bob_spk: &X25519Public,
) -> Result<LiveRatchet, CryptoError> {
    match profile {
        CryptoProfile::ClassicalV1 => Ok(LiveRatchet::Classical(
            DoubleRatchetState::init_alice(sk, bob_spk, DEFAULT_MAX_SKIP)
                .map_err(CryptoError::from)?,
        )),
        #[cfg(feature = "header-encrypt")]
        CryptoProfile::ClassicalHeV1 => {
            let (hka, nhkb) = he_keys_from_sk(sk)?;
            Ok(LiveRatchet::HeaderEncrypt(
                HeaderEncryptState::init_alice(sk, bob_spk, &hka, &nhkb, DEFAULT_MAX_SKIP)
                    .map_err(CryptoError::from)?,
            ))
        }
        #[cfg(feature = "hybrid")]
        CryptoProfile::HybridPqV1 => Ok(LiveRatchet::Hybrid(
            TripleRatchetState::init_alice(sk, bob_spk).map_err(CryptoError::from)?,
        )),
    }
}

fn init_bob_ratchet(
    profile: CryptoProfile,
    sk: &[u8; 32],
    bob_dh: X25519Secret,
) -> Result<LiveRatchet, CryptoError> {
    match profile {
        CryptoProfile::ClassicalV1 => Ok(LiveRatchet::Classical(DoubleRatchetState::init_bob(
            sk,
            bob_dh,
            DEFAULT_MAX_SKIP,
        ))),
        #[cfg(feature = "header-encrypt")]
        CryptoProfile::ClassicalHeV1 => {
            let (hka, nhkb) = he_keys_from_sk(sk)?;
            Ok(LiveRatchet::HeaderEncrypt(HeaderEncryptState::init_bob(
                sk,
                bob_dh,
                &hka,
                &nhkb,
                DEFAULT_MAX_SKIP,
            )))
        }
        #[cfg(feature = "hybrid")]
        CryptoProfile::HybridPqV1 => Ok(LiveRatchet::Hybrid(
            TripleRatchetState::init_bob(sk, bob_dh).map_err(CryptoError::from)?,
        )),
    }
}

struct LiveSession {
    ratchet: LiveRatchet,
    remote_identity: X25519Public,
    conversation: Vec<u8>,
    identity_tracker: IdentityTracker,
    handshake_ad: Vec<u8>,
}

/// Concrete engine: implements CryptoEngineApi using voicechat-crypto only.
pub struct VoiceChatCryptoEngine {
    identity: IdentityKeyPair,
    device_id: Vec<u8>,
    profile: CryptoProfile,
    prekeys: PrekeyStore,
    sessions: HashMap<SessionId, LiveSession>,
    replay: ReplayCache,
    trust: TrustStore,
    storage: Box<dyn TransactionalStorage>,
    monotonic: Box<dyn MonotonicCounter>,
    rollback_guard: RollbackGuard,
    /// True after an external counter advanced but durable commit outcome was
    /// not proven. Continuing could reuse a message key after rollback.
    storage_poisoned: bool,
}

impl VoiceChatCryptoEngine {
    /// Initialize a new local device identity using process-local test storage.
    /// Production integrations should call `initialize_device_with_backends`.
    pub fn initialize_device(config: DeviceConfig) -> Result<Self, CryptoError> {
        Self::initialize_device_with_backends(
            config,
            Box::new(MemoryStorage::default()),
            Box::new(MemoryCounter::default()),
        )
    }

    /// Initialize a brand-new identity using caller-provided storage and
    /// rollback counter backends.
    pub fn initialize_device_with_backends(
        config: DeviceConfig,
        storage: Box<dyn TransactionalStorage>,
        monotonic: Box<dyn MonotonicCounter>,
    ) -> Result<Self, CryptoError> {
        if storage
            .get(Self::KEY_IDENTITY)
            .map_err(|_| CryptoError::Storage)?
            .is_some()
        {
            return Err(CryptoError::Storage);
        }
        let identity = IdentityKeyPair::generate().map_err(CryptoError::from)?;
        let prekeys = PrekeyStore::new(&identity).map_err(CryptoError::from)?;
        let mut engine = Self {
            identity,
            device_id: config.device_id,
            profile: config.profile,
            prekeys,
            sessions: HashMap::new(),
            replay: ReplayCache::new(4096),
            trust: TrustStore::new(),
            storage,
            monotonic,
            rollback_guard: RollbackGuard::default(),
            storage_poisoned: false,
        };
        engine.persist_device_state()?;
        Ok(engine)
    }

    /// Restore a previously initialized identity from durable storage.
    ///
    /// The durable transaction epoch must exactly equal the caller-provided
    /// monotonic counter. A stale backup, cloned database, or uncertain partial
    /// commit therefore fails before ratchet keys are loaded into service.
    pub fn restore_device_with_backends(
        config: DeviceConfig,
        storage: Box<dyn TransactionalStorage>,
        monotonic: Box<dyn MonotonicCounter>,
    ) -> Result<Self, CryptoError> {
        let epoch_blob = storage
            .get(Self::KEY_STORAGE_EPOCH)
            .map_err(|_| CryptoError::Storage)?
            .ok_or(CryptoError::Storage)?;
        if epoch_blob.0.len() != 8 {
            return Err(CryptoError::Storage);
        }
        let persisted_epoch = u64::from_le_bytes(
            epoch_blob
                .0
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::Storage)?,
        );
        let counter_epoch = monotonic.current().map_err(|_| CryptoError::Storage)?;
        if persisted_epoch != counter_epoch {
            return Err(CryptoError::Storage);
        }

        let identity_blob = storage
            .get(Self::KEY_IDENTITY)
            .map_err(|_| CryptoError::Storage)?
            .ok_or(CryptoError::Storage)?;
        let prekeys_blob = storage
            .get(Self::KEY_PREKEYS)
            .map_err(|_| CryptoError::Storage)?
            .ok_or(CryptoError::Storage)?;
        let identity = IdentityKeyPair::deserialize(&identity_blob.0).map_err(CryptoError::from)?;
        let prekeys = PrekeyStore::deserialize(&prekeys_blob.0).map_err(CryptoError::from)?;
        let replay = match storage
            .get(Self::KEY_REPLAY)
            .map_err(|_| CryptoError::Storage)?
        {
            Some(blob) => ReplayCache::deserialize(&blob.0).map_err(CryptoError::from)?,
            None => ReplayCache::new(4096),
        };
        let trust = match storage
            .get(Self::KEY_TRUST)
            .map_err(|_| CryptoError::Storage)?
        {
            Some(blob) => TrustStore::deserialize(&blob.0).map_err(CryptoError::from)?,
            None => TrustStore::new(),
        };

        let mut sessions = HashMap::new();
        for key in storage.keys().map_err(|_| CryptoError::Storage)? {
            let Some(blob) = storage.get(&key).map_err(|_| CryptoError::Storage)? else {
                continue;
            };
            if blob.0.len() >= 8 && &blob.0[..8] == b"VCSESS01" {
                let (sid, sess) = decode_session(&blob.0)?;
                sessions.insert(sid, sess);
            }
        }

        let mut rollback_guard = RollbackGuard::default();
        rollback_guard
            .observe(StorageEpoch(persisted_epoch))
            .map_err(|_| CryptoError::Storage)?;
        let mut engine = Self {
            identity,
            device_id: config.device_id,
            profile: config.profile,
            prekeys,
            sessions,
            replay,
            trust,
            storage,
            monotonic,
            rollback_guard,
            storage_poisoned: false,
        };
        for sess in engine.sessions.values_mut() {
            sess.identity_tracker = engine.trust.tracker_for(&sess.remote_identity);
        }
        Ok(engine)
    }

    const KEY_IDENTITY: &'static [u8] = b"identity";
    const KEY_PREKEYS: &'static [u8] = b"prekeys";
    const KEY_REPLAY: &'static [u8] = b"replay";
    const KEY_TRUST: &'static [u8] = b"trust";
    const KEY_STORAGE_EPOCH: &'static [u8] = b"storage-epoch-v1";

    fn persist_device_state(&mut self) -> Result<(), CryptoError> {
        let identity = self.identity.serialize();
        let prekeys = self.prekeys.serialize();
        let replay = self.replay.serialize();
        let trust = self.trust.serialize();
        self.commit_pairs(&[
            (Self::KEY_IDENTITY, identity),
            (Self::KEY_PREKEYS, prekeys),
            (Self::KEY_REPLAY, replay),
            (Self::KEY_TRUST, trust),
        ])
    }

    fn persist_session_aux(&mut self, session_id: &SessionId) -> Result<(), CryptoError> {
        let blob = {
            let sess = self
                .sessions
                .get(session_id)
                .ok_or(CryptoError::NoSession)?;
            encode_session(session_id, sess)
        };
        let replay = self.replay.serialize();
        let trust = self.trust.serialize();
        self.commit_pairs(&[
            (session_id.0.as_slice(), blob),
            (Self::KEY_REPLAY, replay),
            (Self::KEY_TRUST, trust),
        ])
    }

    /// One transaction: session + consumed prekeys + identity + replay + trust.
    fn persist_handshake(&mut self, session_id: &SessionId) -> Result<(), CryptoError> {
        let blob = {
            let sess = self
                .sessions
                .get(session_id)
                .ok_or(CryptoError::NoSession)?;
            encode_session(session_id, sess)
        };
        let identity = self.identity.serialize();
        let prekeys = self.prekeys.serialize();
        let replay = self.replay.serialize();
        let trust = self.trust.serialize();
        self.commit_pairs(&[
            (Self::KEY_IDENTITY, identity),
            (Self::KEY_PREKEYS, prekeys),
            (session_id.0.as_slice(), blob),
            (Self::KEY_REPLAY, replay),
            (Self::KEY_TRUST, trust),
        ])
    }

    fn ensure_storage_healthy(&self) -> Result<(), CryptoError> {
        if self.storage_poisoned {
            Err(CryptoError::Storage)
        } else {
            Ok(())
        }
    }

    /// Atomically apply durable state and bind it to a monotonic counter value.
    ///
    /// Counter advancement happens before commit. If anything after that point
    /// fails, the engine becomes unusable. This prevents a caller from
    /// continuing after an ambiguous commit and accidentally reusing a ratchet
    /// message key / AES-GCM nonce after rollback.
    fn commit_changes(
        &mut self,
        pairs: &[(&[u8], Vec<u8>)],
        deletes: &[&[u8]],
    ) -> Result<(), CryptoError> {
        self.ensure_storage_healthy()?;
        let epoch = self
            .monotonic
            .increment()
            .map_err(|_| CryptoError::Storage)?;

        let tx = match self.storage.begin() {
            Ok(tx) => tx,
            Err(_) => {
                self.storage_poisoned = true;
                return Err(CryptoError::Storage);
            }
        };

        for (k, v) in pairs {
            if self.storage.put(tx, k, &StateBlob(v.clone())).is_err() {
                let _ = self.storage.abort(tx);
                self.storage_poisoned = true;
                return Err(CryptoError::Storage);
            }
        }
        for key in deletes {
            if self.storage.delete(tx, key).is_err() {
                let _ = self.storage.abort(tx);
                self.storage_poisoned = true;
                return Err(CryptoError::Storage);
            }
        }
        if self
            .storage
            .put(
                tx,
                Self::KEY_STORAGE_EPOCH,
                &StateBlob(epoch.to_le_bytes().to_vec()),
            )
            .is_err()
        {
            let _ = self.storage.abort(tx);
            self.storage_poisoned = true;
            return Err(CryptoError::Storage);
        }

        if self.storage.commit(tx).is_err() {
            self.storage_poisoned = true;
            return Err(CryptoError::Storage);
        }
        self.rollback_guard
            .observe(StorageEpoch(epoch))
            .map_err(|_| CryptoError::Storage)?;
        Ok(())
    }

    fn commit_pairs(&mut self, pairs: &[(&[u8], Vec<u8>)]) -> Result<(), CryptoError> {
        self.commit_changes(pairs, &[])
    }

    fn verify_storage_epoch(&mut self) -> Result<(), CryptoError> {
        self.ensure_storage_healthy()?;
        let blob = self
            .storage
            .get(Self::KEY_STORAGE_EPOCH)
            .map_err(|_| CryptoError::Storage)?
            .ok_or(CryptoError::Storage)?;
        if blob.0.len() != 8 {
            self.storage_poisoned = true;
            return Err(CryptoError::Storage);
        }
        let persisted = u64::from_le_bytes(
            blob.0
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::Storage)?,
        );
        let current = self
            .monotonic
            .current()
            .map_err(|_| CryptoError::Storage)?;
        if persisted != current {
            self.storage_poisoned = true;
            return Err(CryptoError::Storage);
        }
        if self
            .rollback_guard
            .observe(StorageEpoch(persisted))
            .is_err()
        {
            self.storage_poisoned = true;
            return Err(CryptoError::Storage);
        }
        Ok(())
    }

    fn next_session_id(&self) -> Result<SessionId, CryptoError> {
        let mut id = [0u8; 16];
        crate::primitives::random::fill_random(&mut id).map_err(CryptoError::from)?;
        Ok(SessionId(id))
    }

    fn apply_decrypt(
        &mut self,
        session_id: &SessionId,
        sealed: &SealedMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let conversation = self
            .sessions
            .get(session_id)
            .ok_or(CryptoError::NoSession)?
            .conversation
            .clone();
        let rkey = Self::replay_key(session_id, sealed, &conversation, &self.device_id);
        if self.replay.contains(&rkey) {
            return Err(CryptoError::Replay);
        }

        let sess = self
            .sessions
            .get_mut(session_id)
            .ok_or(CryptoError::NoSession)?;
        let ad = Self::bound_ad(sess, associated_data);
        let mut trial = sess.ratchet.clone_for_trial();
        let plaintext = trial.decrypt(&sealed.header, &sealed.ciphertext, &ad)?;
        sess.ratchet = trial;
        let replayed = self
            .replay
            .check_and_insert(rkey)
            .map_err(|_| CryptoError::Internal)?;
        if replayed {
            return Err(CryptoError::Replay);
        }
        Ok(plaintext)
    }

    fn bound_ad(sess: &LiveSession, associated_data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            sess.handshake_ad.len() + sess.conversation.len() + associated_data.len() + 8,
        );
        out.extend_from_slice(&(sess.handshake_ad.len() as u32).to_le_bytes());
        out.extend_from_slice(&sess.handshake_ad);
        out.extend_from_slice(&(sess.conversation.len() as u32).to_le_bytes());
        out.extend_from_slice(&sess.conversation);
        out.extend_from_slice(associated_data);
        out
    }

    /// Drop in-memory sessions and reload every committed session blob.
    /// Models process restart after a clean commit (crash-safe persist).
    pub fn simulate_crash_reload(&mut self) -> Result<(), CryptoError> {
        self.verify_storage_epoch()?;

        let identity_blob = self
            .storage
            .get(Self::KEY_IDENTITY)
            .map_err(|_| CryptoError::Storage)?
            .ok_or(CryptoError::Storage)?;
        self.identity = IdentityKeyPair::deserialize(&identity_blob.0).map_err(CryptoError::from)?;

        let prekeys_blob = self
            .storage
            .get(Self::KEY_PREKEYS)
            .map_err(|_| CryptoError::Storage)?
            .ok_or(CryptoError::Storage)?;
        self.prekeys = PrekeyStore::deserialize(&prekeys_blob.0).map_err(CryptoError::from)?;

        let keys = self.storage.keys().map_err(|_| CryptoError::Storage)?;
        let mut restored = HashMap::new();
        for key in keys {
            let blob = self
                .storage
                .get(&key)
                .map_err(|_| CryptoError::Storage)?
                .ok_or(CryptoError::Storage)?;
            if blob.0.len() < 8 || &blob.0[0..8] != b"VCSESS01" {
                continue;
            }
            let (sid, sess) = decode_session(&blob.0)?;
            restored.insert(sid, sess);
        }
        self.sessions = restored;

        if let Some(blob) = self
            .storage
            .get(Self::KEY_REPLAY)
            .map_err(|_| CryptoError::Storage)?
        {
            self.replay = ReplayCache::deserialize(&blob.0).map_err(CryptoError::from)?;
        }
        if let Some(blob) = self
            .storage
            .get(Self::KEY_TRUST)
            .map_err(|_| CryptoError::Storage)?
        {
            self.trust = TrustStore::deserialize(&blob.0).map_err(CryptoError::from)?;
        }
        for sess in self.sessions.values_mut() {
            sess.identity_tracker = self.trust.tracker_for(&sess.remote_identity);
        }
        Ok(())
    }

    fn replay_key(
        session_id: &SessionId,
        sealed: &SealedMessage,
        conversation: &[u8],
        sender_device: &[u8],
    ) -> ReplayKey {
        let mut mid = Vec::new();
        mid.extend_from_slice(&crate::policy::PROTOCOL_VERSION.to_le_bytes());
        mid.extend_from_slice(&session_id.0);
        mid.extend_from_slice(&sealed.header);
        mid.extend_from_slice(&sealed.ciphertext[..sealed.ciphertext.len().min(32)]);
        ReplayKey {
            conversation_id: conversation.to_vec(),
            sender_device_id: sender_device.to_vec(),
            message_id: mid,
        }
    }

    /// Stable replay identity for the *whole* PQXDH initiation packet.
    ///
    /// It deliberately does not contain Bob's newly generated local session
    /// id. Otherwise the exact same initiation could be replayed against
    /// reusable signed/last-resort prekeys and obtain a new replay identity.
    fn initiation_replay_key(
        &self,
        message: &InitiationPacket,
        conversation: &[u8],
    ) -> ReplayKey {
        let mut transcript = Vec::new();
        transcript.extend_from_slice(&crate::policy::PROTOCOL_VERSION.to_le_bytes());
        transcript.push(self.profile.as_u8());
        transcript.extend_from_slice(&(conversation.len() as u64).to_le_bytes());
        transcript.extend_from_slice(conversation);
        transcript.extend_from_slice(&message.encode());
        let digest = crate::primitives::kdf::sha256(&transcript);
        ReplayKey {
            conversation_id: conversation.to_vec(),
            sender_device_id: message.sender_identity_public.to_vec(),
            message_id: digest.to_vec(),
        }
    }

    /// Trust state for a remote identity (independent of whether a session exists).
    pub fn remote_identity_state(
        &self,
        remote_identity_public: &[u8; 32],
        remote_device_id: Option<&[u8]>,
    ) -> Result<IdentityState, CryptoError> {
        let remote =
            X25519Public::from_bytes(*remote_identity_public).map_err(CryptoError::from)?;
        let mat = IdentityMaterial {
            identity_key: remote,
            device_id: remote_device_id.map(|d| d.to_vec()),
        };
        Ok(self.trust.tracker_for(&remote).observe(&mat))
    }
}

fn contains_seq(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

impl CryptoEngineApi for VoiceChatCryptoEngine {
    fn generate_public_prekey_bundle(
        &mut self,
        one_time_count: usize,
    ) -> Result<PublicPrekeyBundle, CryptoError> {
        self.ensure_storage_healthy()?;
        self.prekeys
            .replenish(&self.identity, one_time_count, one_time_count)
            .map_err(CryptoError::from)?;
        self.persist_device_state()?;
        self.prekeys
            .public_bundle(&self.identity)
            .map_err(CryptoError::from)
    }

    fn replenish_prekeys(
        &mut self,
        one_time_count: usize,
    ) -> Result<PublicPrekeyBundle, CryptoError> {
        self.generate_public_prekey_bundle(one_time_count)
    }

    fn establish_outbound_session(
        &mut self,
        remote_bundle: &PublicPrekeyBundle,
        conversation_context: &[u8],
        first_plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(SessionId, InitiationPacket), CryptoError> {
        self.ensure_storage_healthy()?;
        remote_bundle.validate().map_err(CryptoError::from)?;
        let initiation =
            alice_initiate(&self.identity, remote_bundle).map_err(CryptoError::from)?;
        let sk = initiation.shared.sk;
        let handshake_ad = initiation.shared.ad.clone();
        let ratchet = init_alice_ratchet(self.profile, &sk, &remote_bundle.signed_prekey)?;

        let sid = self.next_session_id()?;
        let remote_mat = IdentityMaterial {
            identity_key: remote_bundle.identity_key,
            device_id: None,
        };
        self.trust.record_seen(remote_mat.clone());
        self.sessions.insert(
            sid.clone(),
            LiveSession {
                ratchet,
                remote_identity: remote_bundle.identity_key,
                conversation: conversation_context.to_vec(),
                identity_tracker: self.trust.tracker_for(&remote_bundle.identity_key),
                handshake_ad,
            },
        );
        let first_message = self.encrypt(&sid, first_plaintext, associated_data)?;
        let packet = InitiationPacket {
            sender_identity_public: self.identity.public().to_bytes(),
            sender_ephemeral_public: initiation.ephemeral_public.to_bytes(),
            kem_ciphertext: initiation.kem_ciphertext.clone(),
            used_spk_id: remote_bundle.signed_prekey_id,
            used_ec_opk_id: initiation.used_ec_opk_id,
            pq_prekey_id: initiation.used_pq_prekey_id,
            first_message,
        };
        Ok((sid, packet))
    }

    fn process_inbound_session(
        &mut self,
        message: &InitiationPacket,
        conversation_context: &[u8],
        associated_data: &[u8],
    ) -> Result<(SessionId, Vec<u8>), CryptoError> {
        self.ensure_storage_healthy()?;
        let initiation_replay = self.initiation_replay_key(message, conversation_context);
        if self.replay.contains(&initiation_replay) {
            return Err(CryptoError::Replay);
        }

        let alice_ik =
            X25519Public::from_bytes(message.sender_identity_public).map_err(CryptoError::from)?;
        let alice_ek =
            X25519Public::from_bytes(message.sender_ephemeral_public).map_err(CryptoError::from)?;

        if message.used_spk_id != self.prekeys.signed.id {
            return Err(CryptoError::CryptoFailure);
        }

        let peeked_ec = match message.used_ec_opk_id {
            Some(id) => Some(self.prekeys.peek_ec(id).map_err(CryptoError::from)?.clone()),
            None => None,
        };

        let last_resort = message.pq_prekey_id == self.prekeys.last_resort_pq.id;
        let peeked_pq = if last_resort {
            None
        } else {
            Some(
                self.prekeys
                    .peek_pq(message.pq_prekey_id)
                    .map_err(CryptoError::from)?
                    .clone(),
            )
        };

        let shared = {
            let pq_secret = if let Some(ref opk) = peeked_pq {
                &opk.secret
            } else {
                &self.prekeys.last_resort_pq.secret
            };
            let pq_public = pq_secret.public_key().map_err(CryptoError::from)?;
            let bob_mat = BobPrivateMaterial {
                identity: &self.identity,
                signed_prekey: &self.prekeys.signed,
                one_time_ec: peeked_ec.as_ref(),
                pq_secret,
                pq_public: &pq_public,
                pq_prekey_id: message.pq_prekey_id,
            };
            bob_process(
                &bob_mat,
                &alice_ik,
                &alice_ek,
                &message.kem_ciphertext,
                message.used_ec_opk_id,
            )
            .map_err(CryptoError::from)?
        };

        // Bob's initial DH key pair is the exact signed prekey advertised to Alice.
        let bob_dh = X25519Secret::from_bytes(self.prekeys.signed.secret.to_bytes());
        let ratchet = init_bob_ratchet(self.profile, &shared.sk, bob_dh)?;

        let sid = self.next_session_id()?;
        let remote_mat = IdentityMaterial {
            identity_key: alice_ik,
            device_id: None,
        };
        self.trust.record_seen(remote_mat.clone());
        self.sessions.insert(
            sid.clone(),
            LiveSession {
                ratchet,
                remote_identity: alice_ik,
                conversation: conversation_context.to_vec(),
                identity_tracker: self.trust.tracker_for(&alice_ik),
                handshake_ad: shared.ad.clone(),
            },
        );

        let plaintext = match self.apply_decrypt(&sid, &message.first_message, associated_data) {
            Ok(pt) => pt,
            Err(e) => {
                self.sessions.remove(&sid);
                return Err(e);
            }
        };

        // Insert only after authentication so forged initiation packets cannot
        // poison the replay cache.
        if self
            .replay
            .check_and_insert(initiation_replay)
            .map_err(|_| CryptoError::Internal)?
        {
            self.sessions.remove(&sid);
            return Err(CryptoError::Replay);
        }

        if let Some(id) = message.used_ec_opk_id {
            let _consumed = self.prekeys.consume_ec(id).map_err(CryptoError::from)?;
        }
        if !last_resort {
            let _consumed = self
                .prekeys
                .consume_pq(message.pq_prekey_id)
                .map_err(CryptoError::from)?;
        }
        if let Err(e) = self.persist_handshake(&sid) {
            self.sessions.remove(&sid);
            return Err(e);
        }
        Ok((sid, plaintext))
    }

    fn encrypt(
        &mut self,
        session_id: &SessionId,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<SealedMessage, CryptoError> {
        self.ensure_storage_healthy()?;
        let sess = self
            .sessions
            .get_mut(session_id)
            .ok_or(CryptoError::NoSession)?;
        let ad = Self::bound_ad(sess, associated_data);
        let mut trial = sess.ratchet.clone_for_trial();
        let (header, ct) = trial.encrypt(plaintext, &ad)?;
        sess.ratchet = trial;
        self.persist_session_aux(session_id)?;
        Ok(SealedMessage {
            header,
            ciphertext: ct,
            session_hint: session_id.clone(),
        })
    }

    fn encrypt_voice_payload(
        &mut self,
        session_id: &SessionId,
        voice_payload: &[u8],
        associated_data: &[u8],
    ) -> Result<SealedMessage, CryptoError> {
        if contains_seq(associated_data, b"voice_profile")
            || contains_seq(associated_data, b"voice-profile")
        {
            return Err(CryptoError::VoiceProfileForbidden);
        }
        self.encrypt(session_id, voice_payload, associated_data)
    }

    fn decrypt(
        &mut self,
        session_id: &SessionId,
        sealed: &SealedMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.ensure_storage_healthy()?;
        let plaintext = self.apply_decrypt(session_id, sealed, associated_data)?;
        self.persist_session_aux(session_id)?;
        Ok(plaintext)
    }

    fn safety_fingerprint(
        &self,
        remote_identity_public: &[u8; 32],
        remote_device_id: Option<&[u8]>,
    ) -> Result<SafetyFingerprint, CryptoError> {
        let remote =
            X25519Public::from_bytes(*remote_identity_public).map_err(CryptoError::from)?;
        let local = IdentityMaterial {
            identity_key: self.identity.public(),
            device_id: Some(self.device_id.clone()),
        };
        let remote_m = IdentityMaterial {
            identity_key: remote,
            device_id: remote_device_id.map(|d| d.to_vec()),
        };
        compute_fingerprint(&local, &remote_m).map_err(CryptoError::from)
    }

    fn acknowledge_identity_change(
        &mut self,
        remote_identity_public: &[u8; 32],
        remote_device_id: Option<&[u8]>,
    ) -> Result<(), CryptoError> {
        self.ensure_storage_healthy()?;
        let remote =
            X25519Public::from_bytes(*remote_identity_public).map_err(CryptoError::from)?;
        let mat = IdentityMaterial {
            identity_key: remote,
            device_id: remote_device_id.map(|d| d.to_vec()),
        };
        for sess in self.sessions.values_mut() {
            if sess.remote_identity.to_bytes() == *remote_identity_public
                || matches!(
                    sess.identity_tracker.observe(&mat),
                    IdentityState::IdentityChanged { .. }
                )
            {
                sess.identity_tracker.acknowledge(mat.clone());
            }
        }
        self.trust
            .acknowledge(mat, 0, VerificationMethod::SafetyNumber);
        self.persist_device_state()?;
        Ok(())
    }

    fn has_session(&self, session_id: &SessionId) -> bool {
        self.sessions.contains_key(session_id)
    }

    fn delete_session(&mut self, session_id: &SessionId) -> Result<(), CryptoError> {
        self.ensure_storage_healthy()?;
        if !self.sessions.contains_key(session_id) {
            return Err(CryptoError::NoSession);
        }
        // Durable delete first; never report success while the old state can
        // still resurrect after restart.
        self.commit_changes(&[], &[session_id.0.as_slice()])?;
        self.sessions.remove(session_id);
        Ok(())
    }

    fn delete_all_sessions(&mut self) -> Result<(), CryptoError> {
        self.ensure_storage_healthy()?;
        let mut session_keys = Vec::new();
        for key in self.storage.keys().map_err(|_| CryptoError::Storage)? {
            let Some(blob) = self.storage.get(&key).map_err(|_| CryptoError::Storage)? else {
                continue;
            };
            if blob.0.len() >= 8 && &blob.0[..8] == b"VCSESS01" {
                session_keys.push(key);
            }
        }
        let refs: Vec<&[u8]> = session_keys.iter().map(Vec::as_slice).collect();
        self.commit_changes(&[], &refs)?;
        self.sessions.clear();
        Ok(())
    }

    fn local_identity_public(&self) -> [u8; 32] {
        self.identity.public().to_bytes()
    }
}

// ---------------------------------------------------------------------------
// Behavioral tests (application-level)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::CryptoProfile;

    fn cfg() -> DeviceConfig {
        DeviceConfig {
            device_id: b"device-1".to_vec(),
            profile: CryptoProfile::ClassicalV1,
        }
    }

    fn handshake(
        alice: &mut VoiceChatCryptoEngine,
        bob: &mut VoiceChatCryptoEngine,
        conv: &[u8],
        first: &[u8],
        ad: &[u8],
    ) -> (SessionId, SessionId) {
        let bob_bundle = bob.generate_public_prekey_bundle(3).unwrap();
        let (sid_a, init) = alice
            .establish_outbound_session(&bob_bundle, conv, first, ad)
            .unwrap();
        let (sid_b, pt) = bob.process_inbound_session(&init, conv, ad).unwrap();
        assert_eq!(pt, first);
        (sid_a, sid_b)
    }

    fn linked_pair() -> (
        VoiceChatCryptoEngine,
        VoiceChatCryptoEngine,
        SessionId,
        SessionId,
    ) {
        let mut alice = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
        let mut bob = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
            device_id: b"device-2".to_vec(),
            profile: CryptoProfile::ClassicalV1,
        })
        .unwrap();
        let (sid_a, sid_b) = handshake(&mut alice, &mut bob, b"conv-1", b"A0", b"ad");
        (alice, bob, sid_a, sid_b)
    }

    #[test]
    fn outbound_encrypt_decrypt_roundtrip() {
        let (mut alice, mut bob, sid_a, sid_b) = linked_pair();
        let sealed = alice.encrypt(&sid_a, b"hello", b"ad").unwrap();
        let pt = bob.decrypt(&sid_b, &sealed, b"ad").unwrap();
        assert_eq!(pt, b"hello");

        let reply = bob.encrypt(&sid_b, b"hi-alice", b"ad").unwrap();
        let pt2 = alice.decrypt(&sid_a, &reply, b"ad").unwrap();
        assert_eq!(pt2, b"hi-alice");
    }

    #[test]
    fn wrong_conversation_ad_fails() {
        let (mut alice, mut bob, sid_a, sid_b) = linked_pair();
        let sealed = alice.encrypt(&sid_a, b"hello", b"ad").unwrap();
        assert!(bob.decrypt(&sid_b, &sealed, b"other-ad").is_err());
    }

    #[test]
    fn voice_profile_forbidden_in_ad() {
        let mut eng = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
        let _bundle = eng.generate_public_prekey_bundle(1).unwrap();
        let mut remote = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
            device_id: b"r".to_vec(),
            profile: CryptoProfile::ClassicalV1,
        })
        .unwrap();
        let remote_bundle = remote.generate_public_prekey_bundle(1).unwrap();
        let (sid, _init) = eng
            .establish_outbound_session(&remote_bundle, b"c", b"A0", b"ad")
            .unwrap();
        let err = eng.encrypt_voice_payload(&sid, b"opus-bytes", b"voice_profile=secret");
        assert_eq!(err, Err(CryptoError::VoiceProfileForbidden));
    }

    #[test]
    fn voice_payload_ok_without_profile_metadata() {
        let mut eng = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
        let mut remote = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
            device_id: b"r".to_vec(),
            profile: CryptoProfile::ClassicalV1,
        })
        .unwrap();
        let remote_bundle = remote.generate_public_prekey_bundle(1).unwrap();
        let (sid, _init) = eng
            .establish_outbound_session(&remote_bundle, b"c", b"A0", b"ad")
            .unwrap();
        let sealed = eng
            .encrypt_voice_payload(&sid, b"opus-audio-payload", b"msg-meta")
            .unwrap();
        assert!(!sealed.ciphertext.is_empty());
    }

    #[test]
    fn recommended_config_uses_preference_head() {
        let c = DeviceConfig::recommended(b"dev".to_vec());
        assert_eq!(c.profile, crate::policy::PROFILE_PREFERENCE[0]);
    }

    #[test]
    fn fingerprint_symmetric_via_engine() {
        let a = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
        let b = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
            device_id: b"other".to_vec(),
            profile: CryptoProfile::ClassicalV1,
        })
        .unwrap();
        let fa = a
            .safety_fingerprint(&b.local_identity_public(), Some(b"other"))
            .unwrap();
        let fb = b
            .safety_fingerprint(&a.local_identity_public(), Some(b"device-1"))
            .unwrap();
        assert_eq!(fa.binary, fb.binary);
    }

    #[test]
    fn initiation_packet_encode_decode_roundtrip() {
        let mut alice = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
        let mut bob = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
            device_id: b"bob".to_vec(),
            profile: CryptoProfile::ClassicalV1,
        })
        .unwrap();
        let bundle = bob.generate_public_prekey_bundle(1).unwrap();
        let (_sid, packet) = alice
            .establish_outbound_session(&bundle, b"c", b"A0", b"ad")
            .unwrap();
        let decoded = InitiationPacket::decode(&packet.encode()).unwrap();
        assert_eq!(
            decoded.sender_identity_public,
            packet.sender_identity_public
        );
        assert_eq!(decoded.kem_ciphertext, packet.kem_ciphertext);
        assert_eq!(decoded.used_spk_id, packet.used_spk_id);
        let (_sid_b, pt) = bob.process_inbound_session(&decoded, b"c", b"ad").unwrap();
        assert_eq!(pt.as_slice(), b"A0");
    }

    #[test]
    fn delete_session_removes() {
        let mut eng = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
        let mut remote = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
            device_id: b"r".to_vec(),
            profile: CryptoProfile::ClassicalV1,
        })
        .unwrap();
        let bundle = remote.generate_public_prekey_bundle(1).unwrap();
        let (sid, _init) = eng
            .establish_outbound_session(&bundle, b"c", b"A0", b"ad")
            .unwrap();
        assert!(eng.has_session(&sid));
        eng.delete_session(&sid).unwrap();
        assert!(!eng.has_session(&sid));
    }

    #[test]
    fn replay_rejected() {
        let mut eng = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
        let mut remote = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
            device_id: b"r".to_vec(),
            profile: CryptoProfile::ClassicalV1,
        })
        .unwrap();
        let bundle = remote.generate_public_prekey_bundle(1).unwrap();
        let (sid, init) = eng
            .establish_outbound_session(&bundle, b"c", b"x", b"ad")
            .unwrap();
        let (sid_b, pt0) = remote.process_inbound_session(&init, b"c", b"ad").unwrap();
        assert_eq!(pt0, b"x");
        assert_eq!(
            remote.decrypt(&sid_b, &init.first_message, b"ad"),
            Err(CryptoError::Replay)
        );
        let _ = sid;
    }

    #[test]
    fn handshake_opk_and_session_atomic_across_reload() {
        let mut alice = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
        let mut bob = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
            device_id: b"bob".to_vec(),
            profile: CryptoProfile::ClassicalV1,
        })
        .unwrap();
        let bundle = bob.generate_public_prekey_bundle(1).unwrap();
        let (sid_a, init) = alice
            .establish_outbound_session(&bundle, b"c", b"hello", b"ad")
            .unwrap();
        let (sid_b, pt) = bob.process_inbound_session(&init, b"c", b"ad").unwrap();
        assert_eq!(pt, b"hello");
        bob.simulate_crash_reload().unwrap();
        assert_eq!(
            bob.process_inbound_session(&init, b"c", b"ad").unwrap_err(),
            CryptoError::Replay
        );
        assert_eq!(
            bob.decrypt(&sid_b, &init.first_message, b"ad").unwrap_err(),
            CryptoError::Replay
        );
        let s = alice.encrypt(&sid_a, b"more", b"ad").unwrap();
        assert_eq!(bob.decrypt(&sid_b, &s, b"ad").unwrap(), b"more");
    }

    #[test]
    fn initiation_replay_without_one_time_prekeys_is_rejected() {
        let mut alice = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
        let mut bob = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
            device_id: b"bob".to_vec(),
            profile: CryptoProfile::ClassicalV1,
        })
        .unwrap();
        let bundle = bob.generate_public_prekey_bundle(0).unwrap();
        assert!(bundle.one_time_ec.is_none());
        assert!(!bundle.is_pq_one_time);
        let (_sid_a, init) = alice
            .establish_outbound_session(&bundle, b"replay-conv", b"hello", b"ad")
            .unwrap();
        let (_sid_b, pt) = bob
            .process_inbound_session(&init, b"replay-conv", b"ad")
            .unwrap();
        assert_eq!(pt, b"hello");
        assert_eq!(
            bob.process_inbound_session(&init, b"replay-conv", b"ad")
                .unwrap_err(),
            CryptoError::Replay
        );
    }

    #[test]
    fn delete_session_remains_deleted_after_reload() {
        let (mut alice, _bob, sid_a, _sid_b) = linked_pair();
        alice.delete_session(&sid_a).unwrap();
        alice.simulate_crash_reload().unwrap();
        assert!(!alice.has_session(&sid_a));
    }

    #[test]
    fn trust_not_implied_by_session_until_ack() {
        let mut alice = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
        let mut bob = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
            device_id: b"bob".to_vec(),
            profile: CryptoProfile::ClassicalV1,
        })
        .unwrap();
        let bundle = bob.generate_public_prekey_bundle(1).unwrap();
        let (_sid, init) = alice
            .establish_outbound_session(&bundle, b"c", b"x", b"ad")
            .unwrap();
        let _ = bob.process_inbound_session(&init, b"c", b"ad").unwrap();
        let alice_ik = alice.local_identity_public();
        match bob.remote_identity_state(&alice_ik, None).unwrap() {
            IdentityState::Unknown => {}
            other => panic!("expected Unknown, got {other:?}"),
        }
        bob.acknowledge_identity_change(&alice_ik, None).unwrap();
        bob.simulate_crash_reload().unwrap();
        match bob.remote_identity_state(&alice_ik, None).unwrap() {
            IdentityState::Verified => {}
            other => panic!("expected Verified after ack+reload, got {other:?}"),
        }
    }

    #[cfg(any(feature = "hybrid", feature = "header-encrypt"))]
    fn linked_with(
        profile: CryptoProfile,
    ) -> (
        VoiceChatCryptoEngine,
        VoiceChatCryptoEngine,
        SessionId,
        SessionId,
    ) {
        let mut alice = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
            device_id: b"device-1".to_vec(),
            profile,
        })
        .unwrap();
        let mut bob = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
            device_id: b"device-2".to_vec(),
            profile,
        })
        .unwrap();
        let (sid_a, sid_b) = handshake(&mut alice, &mut bob, b"conv-1", b"A0", b"ad");
        (alice, bob, sid_a, sid_b)
    }

    #[cfg(feature = "hybrid")]
    #[test]
    fn hybrid_engine_roundtrip_and_no_classical_mix() {
        let (mut alice, mut bob, sid_a, sid_b) = linked_with(CryptoProfile::HybridPqV1);
        let sealed = alice.encrypt(&sid_a, b"hybrid", b"ad").unwrap();
        assert!(sealed.header.len() > 40);
        assert_eq!(bob.decrypt(&sid_b, &sealed, b"ad").unwrap(), b"hybrid");
        let reply = bob.encrypt(&sid_b, b"ok", b"ad").unwrap();
        assert_eq!(alice.decrypt(&sid_a, &reply, b"ad").unwrap(), b"ok");

        let (mut c_alice, mut c_bob, c_sid_a, c_sid_b) = linked_with(CryptoProfile::ClassicalV1);
        let classical = c_alice.encrypt(&c_sid_a, b"class", b"ad").unwrap();
        assert!(bob.decrypt(&sid_b, &classical, b"ad").is_err());
        assert!(c_bob.decrypt(&c_sid_b, &sealed, b"ad").is_err());
    }

    #[cfg(feature = "header-encrypt")]
    #[test]
    fn header_encrypt_engine_roundtrip() {
        let (mut alice, mut bob, sid_a, sid_b) = linked_with(CryptoProfile::ClassicalHeV1);
        let sealed = alice.encrypt(&sid_a, b"hidden-hdr", b"ad").unwrap();
        assert_eq!(bob.decrypt(&sid_b, &sealed, b"ad").unwrap(), b"hidden-hdr");
        let reply = bob.encrypt(&sid_b, b"back", b"ad").unwrap();
        assert_eq!(alice.decrypt(&sid_a, &reply, b"ad").unwrap(), b"back");
    }

    #[test]
    fn delete_all_sessions_clears() {
        let (mut alice, _bob, sid_a, _sid_b) = linked_pair();
        alice.delete_all_sessions().unwrap();
        assert!(!alice.has_session(&sid_a));
    }

    #[test]
    fn crash_reload_rejects_reused_one_time_prekey() {
        let mut alice = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
        let mut bob = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
            device_id: b"device-2".to_vec(),
            profile: CryptoProfile::ClassicalV1,
        })
        .unwrap();
        let bundle = bob.generate_public_prekey_bundle(1).unwrap();
        let (_sid_a, init) = alice
            .establish_outbound_session(&bundle, b"c1", b"A0", b"ad")
            .unwrap();
        let (_sid_b, pt) = bob.process_inbound_session(&init, b"c1", b"ad").unwrap();
        assert_eq!(pt, b"A0");
        bob.simulate_crash_reload().unwrap();
        let mut alice2 = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
        let (_s2, init2) = alice2
            .establish_outbound_session(&bundle, b"c2", b"A1", b"ad")
            .unwrap();
        assert!(bob.process_inbound_session(&init2, b"c2", b"ad").is_err());
    }

    #[test]
    fn crash_reload_classical_continues() {
        let (mut alice, mut bob, sid_a, sid_b) = linked_pair();
        let s = alice.encrypt(&sid_a, b"pre", b"ad").unwrap();
        assert_eq!(bob.decrypt(&sid_b, &s, b"ad").unwrap(), b"pre");
        alice.simulate_crash_reload().unwrap();
        bob.simulate_crash_reload().unwrap();
        let s2 = alice.encrypt(&sid_a, b"post", b"ad").unwrap();
        assert_eq!(bob.decrypt(&sid_b, &s2, b"ad").unwrap(), b"post");
        let s3 = bob.encrypt(&sid_b, b"reply", b"ad").unwrap();
        assert_eq!(alice.decrypt(&sid_a, &s3, b"ad").unwrap(), b"reply");
    }

    #[cfg(feature = "header-encrypt")]
    #[test]
    fn crash_reload_header_encrypt_continues() {
        let (mut alice, mut bob, sid_a, sid_b) = linked_with(CryptoProfile::ClassicalHeV1);
        let s = alice.encrypt(&sid_a, b"he-pre", b"ad").unwrap();
        assert_eq!(bob.decrypt(&sid_b, &s, b"ad").unwrap(), b"he-pre");
        alice.simulate_crash_reload().unwrap();
        bob.simulate_crash_reload().unwrap();
        let s2 = bob.encrypt(&sid_b, b"he-post", b"ad").unwrap();
        assert_eq!(alice.decrypt(&sid_a, &s2, b"ad").unwrap(), b"he-post");
    }

    #[test]
    fn delete_all_prevents_crash_reload() {
        let (mut alice, _bob, sid_a, _sid_b) = linked_pair();
        assert!(!alice
            .encrypt(&sid_a, b"gone", b"ad")
            .unwrap()
            .ciphertext
            .is_empty());
        alice.delete_all_sessions().unwrap();
        alice.simulate_crash_reload().unwrap();
        assert!(!alice.has_session(&sid_a));
    }

    #[cfg(feature = "hybrid")]
    #[test]
    fn crash_reload_hybrid_continues() {
        let (mut alice, mut bob, sid_a, sid_b) = linked_with(CryptoProfile::HybridPqV1);
        let s = alice.encrypt(&sid_a, b"hy-pre", b"ad").unwrap();
        assert_eq!(bob.decrypt(&sid_b, &s, b"ad").unwrap(), b"hy-pre");
        alice.simulate_crash_reload().unwrap();
        bob.simulate_crash_reload().unwrap();
        let s2 = bob.encrypt(&sid_b, b"hy-post", b"ad").unwrap();
        assert_eq!(alice.decrypt(&sid_a, &s2, b"ad").unwrap(), b"hy-post");
    }
}
