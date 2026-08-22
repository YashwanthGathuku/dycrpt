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
use crate::identity::PeerIdentityStore;
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
        if hlen > data.len().saturating_sub(i + 4) {
            return Err(CryptoError::InvalidArgument);
        }
        let header = data[i..i + hlen].to_vec();
        i += hlen;
        let clen = u32::from_le_bytes(data[i..i + 4].try_into().unwrap()) as usize;
        i += 4;
        if clen != data.len().saturating_sub(i) {
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
            if n > data.len().saturating_sub(*i) {
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
        let used_ec_opk_id = match take(&mut i, 1)?[0] {
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

/// Application-facing API.
///
/// Production integrations should prefer the `*_for_peer` methods for session
/// establishment, because those bind a stable application peer id to the
/// cryptographic identity and can therefore detect key replacement.
pub trait CryptoEngineApi {
    fn generate_public_prekey_bundle(
        &mut self,
        one_time_count: usize,
    ) -> Result<PublicPrekeyBundle, CryptoError>;

    fn replenish_prekeys(
        &mut self,
        one_time_count: usize,
    ) -> Result<PublicPrekeyBundle, CryptoError>;

    fn rotate_signed_prekey(
        &mut self,
        retain_previous: usize,
    ) -> Result<PublicPrekeyBundle, CryptoError>;

    fn rotate_last_resort_pq(
        &mut self,
        retain_previous: usize,
    ) -> Result<PublicPrekeyBundle, CryptoError>;

    /// Legacy/session-local establishment without a stable application peer id.
    /// Prefer [`Self::establish_outbound_session_for_peer`] in production.
    fn establish_outbound_session(
        &mut self,
        remote_bundle: &PublicPrekeyBundle,
        conversation_context: &[u8],
        first_plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(SessionId, InitiationPacket), CryptoError>;

    fn establish_outbound_session_for_peer(
        &mut self,
        peer_id: &[u8],
        remote_device_id: Option<&[u8]>,
        remote_bundle: &PublicPrekeyBundle,
        conversation_context: &[u8],
        first_plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(SessionId, InitiationPacket), CryptoError>;

    /// Legacy/session-local receive without a stable application peer id.
    /// Prefer [`Self::process_inbound_session_from_peer`] in production.
    fn process_inbound_session(
        &mut self,
        message: &InitiationPacket,
        conversation_context: &[u8],
        associated_data: &[u8],
    ) -> Result<(SessionId, Vec<u8>), CryptoError>;

    fn process_inbound_session_from_peer(
        &mut self,
        peer_id: &[u8],
        remote_device_id: Option<&[u8]>,
        message: &InitiationPacket,
        conversation_context: &[u8],
        associated_data: &[u8],
    ) -> Result<(SessionId, Vec<u8>), CryptoError>;

    fn peer_identity_state(
        &self,
        peer_id: &[u8],
        remote_identity_public: &[u8; 32],
        remote_device_id: Option<&[u8]>,
    ) -> Result<IdentityState, CryptoError>;

    fn acknowledge_peer_identity(
        &mut self,
        peer_id: &[u8],
        remote_identity_public: &[u8; 32],
        remote_device_id: Option<&[u8]>,
        now_unix: u64,
    ) -> Result<(), CryptoError>;

    fn encrypt(
        &mut self,
        session_id: &SessionId,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<SealedMessage, CryptoError>;

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

    /// Legacy key-indexed acknowledgement. Prefer peer-aware acknowledgement.
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
// Ratchet profile dispatch
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
    if clen > data.len().saturating_sub(i) {
        return Err(CryptoError::Storage);
    }
    let conversation = data[i..i + clen].to_vec();
    i += clen;
    let alen = take_len(&mut i)?;
    if alen > data.len().saturating_sub(i) {
        return Err(CryptoError::Storage);
    }
    let handshake_ad = data[i..i + alen].to_vec();
    i += alen;
    let rlen = take_len(&mut i)?;
    if rlen != data.len().saturating_sub(i) {
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

// ---------------------------------------------------------------------------
// Engine / persistence
// ---------------------------------------------------------------------------

pub struct VoiceChatCryptoEngine {
    identity: IdentityKeyPair,
    device_id: Vec<u8>,
    profile: CryptoProfile,
    prekeys: PrekeyStore,
    sessions: HashMap<SessionId, LiveSession>,
    replay: ReplayCache,
    trust: TrustStore,
    peer_identities: PeerIdentityStore,
    storage: Box<dyn TransactionalStorage>,
    monotonic: Box<dyn MonotonicCounter>,
    rollback_guard: RollbackGuard,
    storage_poisoned: bool,
}

impl VoiceChatCryptoEngine {
    pub fn initialize_device(config: DeviceConfig) -> Result<Self, CryptoError> {
        Self::initialize_device_with_backends(
            config,
            Box::new(MemoryStorage::default()),
            Box::new(MemoryCounter::default()),
        )
    }

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
            peer_identities: PeerIdentityStore::new(),
            storage,
            monotonic,
            rollback_guard: RollbackGuard::default(),
            storage_poisoned: false,
        };
        engine.persist_device_state()?;
        Ok(engine)
    }

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
        let peer_identities = match storage
            .get(Self::KEY_PEER_IDENTITIES)
            .map_err(|_| CryptoError::Storage)?
        {
            Some(blob) => PeerIdentityStore::deserialize(&blob.0).map_err(CryptoError::from)?,
            None => PeerIdentityStore::new(),
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
            peer_identities,
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
    const KEY_PEER_IDENTITIES: &'static [u8] = b"peer-identities-v1";
    const KEY_STORAGE_EPOCH: &'static [u8] = b"storage-epoch-v1";

    fn persist_device_state(&mut self) -> Result<(), CryptoError> {
        let identity = self.identity.serialize();
        let prekeys = self.prekeys.serialize();
        let replay = self.replay.serialize();
        let trust = self.trust.serialize();
        let peers = self.peer_identities.serialize();
        self.commit_pairs(&[
            (Self::KEY_IDENTITY, identity),
            (Self::KEY_PREKEYS, prekeys),
            (Self::KEY_REPLAY, replay),
            (Self::KEY_TRUST, trust),
            (Self::KEY_PEER_IDENTITIES, peers),
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
        let peers = self.peer_identities.serialize();
        self.commit_pairs(&[
            (session_id.0.as_slice(), blob),
            (Self::KEY_REPLAY, replay),
            (Self::KEY_TRUST, trust),
            (Self::KEY_PEER_IDENTITIES, peers),
        ])
    }

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
        let peers = self.peer_identities.serialize();
        self.commit_pairs(&[
            (Self::KEY_IDENTITY, identity),
            (Self::KEY_PREKEYS, prekeys),
            (session_id.0.as_slice(), blob),
            (Self::KEY_REPLAY, replay),
            (Self::KEY_TRUST, trust),
            (Self::KEY_PEER_IDENTITIES, peers),
        ])
    }

    fn ensure_storage_healthy(&self) -> Result<(), CryptoError> {
        if self.storage_poisoned {
            Err(CryptoError::Storage)
        } else {
            Ok(())
        }
    }

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
        if persisted != current
            || self
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
        if self
            .replay
            .check_and_insert(rkey)
            .map_err(|_| CryptoError::Internal)?
        {
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

        let mut restored = HashMap::new();
        for key in self.storage.keys().map_err(|_| CryptoError::Storage)? {
            let blob = self
                .storage
                .get(&key)
                .map_err(|_| CryptoError::Storage)?
                .ok_or(CryptoError::Storage)?;
            if blob.0.len() >= 8 && &blob.0[..8] == b"VCSESS01" {
                let (sid, sess) = decode_session(&blob.0)?;
                restored.insert(sid, sess);
            }
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
        if let Some(blob) = self
            .storage
            .get(Self::KEY_PEER_IDENTITIES)
            .map_err(|_| CryptoError::Storage)?
        {
            self.peer_identities =
                PeerIdentityStore::deserialize(&blob.0).map_err(CryptoError::from)?;
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

    fn peer_material(
        remote_identity_public: &[u8; 32],
        remote_device_id: Option<&[u8]>,
    ) -> Result<IdentityMaterial, CryptoError> {
        Ok(IdentityMaterial {
            identity_key: X25519Public::from_bytes(*remote_identity_public)
                .map_err(CryptoError::from)?,
            device_id: remote_device_id.map(|d| d.to_vec()),
        })
    }

    fn prepare_peer(
        &mut self,
        peer_id: &[u8],
        material: &IdentityMaterial,
    ) -> Result<PeerIdentityStore, CryptoError> {
        match self.peer_identities.observe(peer_id, material) {
            IdentityState::IdentityChanged { .. } => return Err(CryptoError::IdentityChanged),
            IdentityState::Unknown => {}
            IdentityState::Verified => return Ok(self.peer_identities.clone()),
        }
        let before = self.peer_identities.clone();
        self.peer_identities
            .record_seen(peer_id, material.clone())
            .map_err(CryptoError::from)?;
        Ok(before)
    }
}

fn contains_seq(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// API implementation
// ---------------------------------------------------------------------------

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

    fn rotate_signed_prekey(
        &mut self,
        retain_previous: usize,
    ) -> Result<PublicPrekeyBundle, CryptoError> {
        self.ensure_storage_healthy()?;
        self.prekeys
            .rotate_signed_prekey(&self.identity, retain_previous)
            .map_err(CryptoError::from)?;
        self.persist_device_state()?;
        self.prekeys
            .public_bundle(&self.identity)
            .map_err(CryptoError::from)
    }

    fn rotate_last_resort_pq(
        &mut self,
        retain_previous: usize,
    ) -> Result<PublicPrekeyBundle, CryptoError> {
        self.ensure_storage_healthy()?;
        self.prekeys
            .rotate_last_resort_pq(&self.identity, retain_previous)
            .map_err(CryptoError::from)?;
        self.persist_device_state()?;
        self.prekeys
            .public_bundle(&self.identity)
            .map_err(CryptoError::from)
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
        self.trust.record_seen(remote_mat);
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
            kem_ciphertext: initiation.kem_ciphertext,
            used_spk_id: remote_bundle.signed_prekey_id,
            used_ec_opk_id: initiation.used_ec_opk_id,
            pq_prekey_id: initiation.used_pq_prekey_id,
            first_message,
        };
        Ok((sid, packet))
    }

    fn establish_outbound_session_for_peer(
        &mut self,
        peer_id: &[u8],
        remote_device_id: Option<&[u8]>,
        remote_bundle: &PublicPrekeyBundle,
        conversation_context: &[u8],
        first_plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(SessionId, InitiationPacket), CryptoError> {
        let material = Self::peer_material(&remote_bundle.identity_key.to_bytes(), remote_device_id)?;
        let before = self.prepare_peer(peer_id, &material)?;
        match self.establish_outbound_session(
            remote_bundle,
            conversation_context,
            first_plaintext,
            associated_data,
        ) {
            Ok(v) => Ok(v),
            Err(e) => {
                self.peer_identities = before;
                Err(e)
            }
        }
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

        // Resolve the exact reusable signed prekey referenced by this packet.
        // It may be a retained previous key if the public bundle rotated while
        // the initiation was delayed in the network.
        self.prekeys
            .signed_prekey(message.used_spk_id)
            .map_err(CryptoError::from)?;

        let peeked_ec = match message.used_ec_opk_id {
            Some(id) => Some(self.prekeys.peek_ec(id).map_err(CryptoError::from)?.clone()),
            None => None,
        };
        let last_resort = self.prekeys.is_last_resort_pq(message.pq_prekey_id);
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
            let signed = self
                .prekeys
                .signed_prekey(message.used_spk_id)
                .map_err(CryptoError::from)?;
            let pq_secret = if let Some(ref opk) = peeked_pq {
                &opk.secret
            } else {
                &self
                    .prekeys
                    .last_resort_pq(message.pq_prekey_id)
                    .map_err(CryptoError::from)?
                    .secret
            };
            let pq_public = pq_secret.public_key().map_err(CryptoError::from)?;
            let bob_mat = BobPrivateMaterial {
                identity: &self.identity,
                signed_prekey: signed,
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

        let bob_dh = {
            let signed = self
                .prekeys
                .signed_prekey(message.used_spk_id)
                .map_err(CryptoError::from)?;
            X25519Secret::from_bytes(signed.secret.to_bytes())
        };
        let ratchet = init_bob_ratchet(self.profile, &shared.sk, bob_dh)?;

        let sid = self.next_session_id()?;
        self.trust.record_seen(IdentityMaterial {
            identity_key: alice_ik,
            device_id: None,
        });
        self.sessions.insert(
            sid.clone(),
            LiveSession {
                ratchet,
                remote_identity: alice_ik,
                conversation: conversation_context.to_vec(),
                identity_tracker: self.trust.tracker_for(&alice_ik),
                handshake_ad: shared.ad,
            },
        );

        let plaintext = match self.apply_decrypt(&sid, &message.first_message, associated_data) {
            Ok(pt) => pt,
            Err(e) => {
                self.sessions.remove(&sid);
                return Err(e);
            }
        };

        if self
            .replay
            .check_and_insert(initiation_replay)
            .map_err(|_| CryptoError::Internal)?
        {
            self.sessions.remove(&sid);
            return Err(CryptoError::Replay);
        }

        if let Some(id) = message.used_ec_opk_id {
            let _ = self.prekeys.consume_ec(id).map_err(CryptoError::from)?;
        }
        if !last_resort {
            let _ = self
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

    fn process_inbound_session_from_peer(
        &mut self,
        peer_id: &[u8],
        remote_device_id: Option<&[u8]>,
        message: &InitiationPacket,
        conversation_context: &[u8],
        associated_data: &[u8],
    ) -> Result<(SessionId, Vec<u8>), CryptoError> {
        let material = Self::peer_material(&message.sender_identity_public, remote_device_id)?;
        let before = self.prepare_peer(peer_id, &material)?;
        match self.process_inbound_session(message, conversation_context, associated_data) {
            Ok(v) => Ok(v),
            Err(e) => {
                self.peer_identities = before;
                Err(e)
            }
        }
    }

    fn peer_identity_state(
        &self,
        peer_id: &[u8],
        remote_identity_public: &[u8; 32],
        remote_device_id: Option<&[u8]>,
    ) -> Result<IdentityState, CryptoError> {
        let material = Self::peer_material(remote_identity_public, remote_device_id)?;
        Ok(self.peer_identities.observe(peer_id, &material))
    }

    fn acknowledge_peer_identity(
        &mut self,
        peer_id: &[u8],
        remote_identity_public: &[u8; 32],
        remote_device_id: Option<&[u8]>,
        now_unix: u64,
    ) -> Result<(), CryptoError> {
        self.ensure_storage_healthy()?;
        let material = Self::peer_material(remote_identity_public, remote_device_id)?;
        self.peer_identities
            .acknowledge(
                peer_id,
                material,
                now_unix,
                VerificationMethod::SafetyNumber,
            )
            .map_err(CryptoError::from)?;
        self.persist_device_state()
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
        self.persist_device_state()
    }

    fn has_session(&self, session_id: &SessionId) -> bool {
        self.sessions.contains_key(session_id)
    }

    fn delete_session(&mut self, session_id: &SessionId) -> Result<(), CryptoError> {
        self.ensure_storage_healthy()?;
        if !self.sessions.contains_key(session_id) {
            return Err(CryptoError::NoSession);
        }
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

#[cfg(test)]
mod tests;
