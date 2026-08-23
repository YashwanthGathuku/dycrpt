//! Application-facing CryptoEngine.
//!
//! The engine owns long-lived identity/prekey state and provides internally
//! synchronized per-session execution. Steady-state ratchet/AEAD work for
//! different sessions can run concurrently; operations on the same session are
//! serialized by that session's mutex. Durable storage/rollback epoch commits
//! remain globally ordered through a short persistence critical section.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::fingerprint::{
    compute_fingerprint, validate_identity_material, IdentityMaterial, IdentityState,
    IdentityTracker, SafetyFingerprint, TrustStore, VerificationMethod,
};
use crate::identity::PeerIdentityStore;
use crate::policy::{CryptoProfile, PROTOCOL_VERSION};
use crate::pqxdh::{alice_initiate, bob_process, BobPrivateMaterial};
use crate::prekeys::{IdentityKeyPair, PrekeyStore, PublicPrekeyBundle};
use crate::primitives::aead::TAG_LEN;
use crate::primitives::error::PrimitiveError;
use crate::primitives::kdf::sha256_parts;
#[cfg(feature = "header-encrypt")]
use crate::primitives::kdf::{hkdf_extract_expand, LABELS};
use crate::primitives::x25519::{X25519Public, X25519Secret};
#[cfg(feature = "header-encrypt")]
use crate::ratchet::header_encrypt::HeaderEncryptState;
#[cfg(feature = "hybrid")]
use crate::ratchet::triple::TripleRatchetState;
use crate::ratchet::{DoubleRatchetState, Header, DEFAULT_MAX_SKIP};
use crate::replay::{ReplayCache, ReplayKey, DEFAULT_REPLAY_CACHE_SIZE};
use crate::storage::monotonic::{MemoryCounter, MonotonicCounter};
use crate::storage::{
    MemoryStorage, RollbackGuard, StateBlob, StorageEpoch, TransactionalStorage,
};
use zeroize::Zeroize;

const MAX_DEVICE_ID_LEN: usize = 4 * 1024;
const MAX_PEER_ID_LEN: usize = 4 * 1024;
const MAX_CONVERSATION_LEN: usize = 64 * 1024;
const MAX_ASSOCIATED_DATA_LEN: usize = 1024 * 1024;
const MAX_HEADER_LEN: usize = 64 * 1024;
const MAX_CIPHERTEXT_LEN: usize = 64 * 1024 * 1024;
const MAX_PLAINTEXT_LEN: usize = MAX_CIPHERTEXT_LEN - TAG_LEN;
const MAX_KEM_CIPHERTEXT_LEN: usize = 8 * 1024;
const MAX_PENDING_INITIATION_LEN: usize = MAX_CIPHERTEXT_LEN + 128 * 1024;
const MAX_SESSIONS: usize = 100_000;
const DEVICE_CONFIG_MAGIC: &[u8; 8] = b"VCCFG002";

// ---------------------------------------------------------------------------
// Public wire/domain types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; 16]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionTag(pub [u8; 16]);

impl SessionTag {
    fn is_zero(&self) -> bool {
        self.0 == [0u8; 16]
    }
}

#[derive(Clone, Debug)]
pub struct DeviceConfig {
    pub device_id: Vec<u8>,
    pub profile: CryptoProfile,
}

impl DeviceConfig {
    pub fn recommended(device_id: Vec<u8>) -> Self {
        Self {
            device_id,
            profile: crate::policy::PROFILE_PREFERENCE[0],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedMessage {
    pub protocol_version: u16,
    pub profile: CryptoProfile,
    pub session_tag: SessionTag,
    pub header: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct InitiationPacket {
    pub protocol_version: u16,
    pub profile: CryptoProfile,
    pub sender_identity_public: [u8; 32],
    pub sender_ephemeral_public: [u8; 32],
    pub kem_ciphertext: Vec<u8>,
    pub used_spk_id: u32,
    pub used_ec_opk_id: Option<u32>,
    pub pq_prekey_id: u32,
    pub first_message: SealedMessage,
}

pub type InboundSessionMessage = InitiationPacket;

impl SealedMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = b"VCSEAL02".to_vec();
        out.extend_from_slice(&self.protocol_version.to_le_bytes());
        out.push(self.profile.as_u8());
        out.extend_from_slice(&self.session_tag.0);
        out.extend_from_slice(&(self.header.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.header);
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < 8 + 2 + 1 + 16 + 4 + 4 || &data[..8] != b"VCSEAL02" {
            return Err(CryptoError::InvalidArgument);
        }
        if data.len() > MAX_PENDING_INITIATION_LEN {
            return Err(CryptoError::LimitExceeded);
        }
        let mut i = 8usize;
        let protocol_version = read_u16(data, &mut i)?;
        if protocol_version != PROTOCOL_VERSION {
            return Err(CryptoError::CryptoFailure);
        }
        let profile = CryptoProfile::from_u8(take(data, &mut i, 1)?[0])
            .map_err(CryptoError::from)?;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(take(data, &mut i, 16)?);
        let session_tag = SessionTag(tag);
        if session_tag.is_zero() {
            return Err(CryptoError::InvalidArgument);
        }
        let hlen = read_u32(data, &mut i)? as usize;
        if hlen > MAX_HEADER_LEN {
            return Err(CryptoError::LimitExceeded);
        }
        let header = take(data, &mut i, hlen)?.to_vec();
        let clen = read_u32(data, &mut i)? as usize;
        validate_ciphertext_len(clen)?;
        let ciphertext = take(data, &mut i, clen)?.to_vec();
        if i != data.len() {
            return Err(CryptoError::InvalidArgument);
        }
        Ok(Self {
            protocol_version,
            profile,
            session_tag,
            header,
            ciphertext,
        })
    }
}

impl InitiationPacket {
    pub fn encode(&self) -> Vec<u8> {
        let first = self.first_message.encode();
        let mut out = b"VCINIT02".to_vec();
        out.extend_from_slice(&self.protocol_version.to_le_bytes());
        out.push(self.profile.as_u8());
        out.extend_from_slice(&self.sender_identity_public);
        out.extend_from_slice(&self.sender_ephemeral_public);
        out.extend_from_slice(&(self.kem_ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.kem_ciphertext);
        out.extend_from_slice(&self.used_spk_id.to_le_bytes());
        match self.used_ec_opk_id {
            None => out.push(0),
            Some(id) => {
                out.push(1);
                out.extend_from_slice(&id.to_le_bytes());
            }
        }
        out.extend_from_slice(&self.pq_prekey_id.to_le_bytes());
        out.extend_from_slice(&(first.len() as u32).to_le_bytes());
        out.extend_from_slice(&first);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < 8 + 2 + 1 + 32 + 32 + 4 + 4 + 1 + 4 + 4
            || &data[..8] != b"VCINIT02"
        {
            return Err(CryptoError::InvalidArgument);
        }
        if data.len() > MAX_PENDING_INITIATION_LEN {
            return Err(CryptoError::LimitExceeded);
        }
        let mut i = 8usize;
        let protocol_version = read_u16(data, &mut i)?;
        if protocol_version != PROTOCOL_VERSION {
            return Err(CryptoError::CryptoFailure);
        }
        let profile = CryptoProfile::from_u8(take(data, &mut i, 1)?[0])
            .map_err(CryptoError::from)?;
        let mut ik = [0u8; 32];
        ik.copy_from_slice(take(data, &mut i, 32)?);
        let mut ek = [0u8; 32];
        ek.copy_from_slice(take(data, &mut i, 32)?);
        let kem_len = read_u32(data, &mut i)? as usize;
        if kem_len > MAX_KEM_CIPHERTEXT_LEN {
            return Err(CryptoError::LimitExceeded);
        }
        let kem_ciphertext = take(data, &mut i, kem_len)?.to_vec();
        let used_spk_id = read_u32(data, &mut i)?;
        let used_ec_opk_id = match take(data, &mut i, 1)?[0] {
            0 => None,
            1 => Some(read_u32(data, &mut i)?),
            _ => return Err(CryptoError::InvalidArgument),
        };
        let pq_prekey_id = read_u32(data, &mut i)?;
        let first_len = read_u32(data, &mut i)? as usize;
        if first_len > MAX_PENDING_INITIATION_LEN {
            return Err(CryptoError::LimitExceeded);
        }
        let first_message = SealedMessage::decode(take(data, &mut i, first_len)?)?;
        if i != data.len()
            || first_message.protocol_version != protocol_version
            || first_message.profile != profile
        {
            return Err(CryptoError::CryptoFailure);
        }
        Ok(Self {
            protocol_version,
            profile,
            sender_identity_public: ik,
            sender_ephemeral_public: ek,
            kem_ciphertext,
            used_spk_id,
            used_ec_opk_id,
            pq_prekey_id,
            first_message,
        })
    }
}

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

fn take<'a>(data: &'a [u8], i: &mut usize, n: usize) -> Result<&'a [u8], CryptoError> {
    let end = i.checked_add(n).ok_or(CryptoError::LimitExceeded)?;
    if end > data.len() {
        return Err(CryptoError::InvalidArgument);
    }
    let out = &data[*i..end];
    *i = end;
    Ok(out)
}

fn read_u16(data: &[u8], i: &mut usize) -> Result<u16, CryptoError> {
    Ok(u16::from_le_bytes(
        take(data, i, 2)?
            .try_into()
            .map_err(|_| CryptoError::InvalidArgument)?,
    ))
}

fn read_u32(data: &[u8], i: &mut usize) -> Result<u32, CryptoError> {
    Ok(u32::from_le_bytes(
        take(data, i, 4)?
            .try_into()
            .map_err(|_| CryptoError::InvalidArgument)?,
    ))
}

fn validate_context_lengths(
    conversation: &[u8],
    associated_data: &[u8],
) -> Result<(), CryptoError> {
    if conversation.len() > MAX_CONVERSATION_LEN || associated_data.len() > MAX_ASSOCIATED_DATA_LEN
    {
        return Err(CryptoError::LimitExceeded);
    }
    Ok(())
}

fn validate_plaintext_len(len: usize) -> Result<(), CryptoError> {
    if len > MAX_PLAINTEXT_LEN {
        Err(CryptoError::LimitExceeded)
    } else {
        Ok(())
    }
}

fn validate_ciphertext_len(len: usize) -> Result<(), CryptoError> {
    if len < TAG_LEN {
        Err(CryptoError::InvalidArgument)
    } else if len > MAX_CIPHERTEXT_LEN {
        Err(CryptoError::LimitExceeded)
    } else {
        Ok(())
    }
}

fn validate_peer_id_input(peer_id: &[u8]) -> Result<(), CryptoError> {
    if peer_id.is_empty() || peer_id.len() > MAX_PEER_ID_LEN {
        Err(CryptoError::InvalidArgument)
    } else {
        Ok(())
    }
}

fn validate_device_id(device_id: &[u8]) -> Result<(), CryptoError> {
    if device_id.is_empty() || device_id.len() > MAX_DEVICE_ID_LEN {
        Err(CryptoError::InvalidArgument)
    } else {
        Ok(())
    }
}

fn contains_seq(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.len() >= needle.len() && hay.windows(needle.len()).any(|w| w == needle)
}

fn encode_device_config(device_id: &[u8], profile: CryptoProfile) -> Vec<u8> {
    let mut out = DEVICE_CONFIG_MAGIC.to_vec();
    out.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    out.push(profile.as_u8());
    out.extend_from_slice(&(device_id.len() as u32).to_le_bytes());
    out.extend_from_slice(device_id);
    out
}

fn decode_device_config(data: &[u8]) -> Result<DeviceConfig, CryptoError> {
    if data.len() < 8 + 2 + 1 + 4 || &data[..8] != DEVICE_CONFIG_MAGIC {
        return Err(CryptoError::Storage);
    }
    let mut i = 8usize;
    let version = read_u16(data, &mut i).map_err(|_| CryptoError::Storage)?;
    if version != PROTOCOL_VERSION {
        return Err(CryptoError::Storage);
    }
    let profile = CryptoProfile::from_u8(take(data, &mut i, 1).map_err(|_| CryptoError::Storage)?[0])
        .map_err(|_| CryptoError::Storage)?;
    let len = read_u32(data, &mut i).map_err(|_| CryptoError::Storage)? as usize;
    if len == 0 || len > MAX_DEVICE_ID_LEN {
        return Err(CryptoError::Storage);
    }
    let device_id = take(data, &mut i, len)
        .map_err(|_| CryptoError::Storage)?
        .to_vec();
    if i != data.len() {
        return Err(CryptoError::Storage);
    }
    Ok(DeviceConfig { device_id, profile })
}

fn ensure_config_matches(
    storage: &dyn TransactionalStorage,
    expected: &DeviceConfig,
) -> Result<(), CryptoError> {
    let blob = storage
        .get(VoiceChatCryptoEngine::KEY_DEVICE_CONFIG)
        .map_err(|_| CryptoError::Storage)?
        .ok_or(CryptoError::Storage)?;
    let persisted = decode_device_config(&blob.0)?;
    if persisted.profile != expected.profile || persisted.device_id != expected.device_id {
        return Err(CryptoError::Storage);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Application API
// ---------------------------------------------------------------------------

/// Thread-safe application API. Every mutating method uses interior
/// synchronization; callers may share one engine through `Arc` without placing
/// an outer global mutex around it.
pub trait CryptoEngineApi: Send + Sync {
    fn generate_public_prekey_bundle(
        &self,
        one_time_count: usize,
    ) -> Result<PublicPrekeyBundle, CryptoError>;
    fn replenish_prekeys(
        &self,
        one_time_count: usize,
    ) -> Result<PublicPrekeyBundle, CryptoError>;
    fn rotate_signed_prekey(
        &self,
        retain_previous: usize,
    ) -> Result<PublicPrekeyBundle, CryptoError>;
    fn rotate_last_resort_pq(
        &self,
        retain_previous: usize,
    ) -> Result<PublicPrekeyBundle, CryptoError>;

    fn establish_outbound_session(
        &self,
        remote_bundle: &PublicPrekeyBundle,
        conversation_context: &[u8],
        first_plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(SessionId, InitiationPacket), CryptoError>;
    fn establish_outbound_session_for_peer(
        &self,
        peer_id: &[u8],
        remote_device_id: Option<&[u8]>,
        remote_bundle: &PublicPrekeyBundle,
        conversation_context: &[u8],
        first_plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(SessionId, InitiationPacket), CryptoError>;
    fn process_inbound_session(
        &self,
        message: &InitiationPacket,
        conversation_context: &[u8],
        associated_data: &[u8],
    ) -> Result<(SessionId, Vec<u8>), CryptoError>;
    fn process_inbound_session_from_peer(
        &self,
        peer_id: &[u8],
        remote_device_id: Option<&[u8]>,
        message: &InitiationPacket,
        conversation_context: &[u8],
        associated_data: &[u8],
    ) -> Result<(SessionId, Vec<u8>), CryptoError>;

    fn pending_outbound_initiation(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<InitiationPacket>, CryptoError>;
    fn acknowledge_outbound_initiation(
        &self,
        session_id: &SessionId,
    ) -> Result<(), CryptoError>;

    fn peer_identity_state(
        &self,
        peer_id: &[u8],
        remote_identity_public: &[u8; 32],
        remote_device_id: Option<&[u8]>,
    ) -> Result<IdentityState, CryptoError>;
    fn acknowledge_peer_identity(
        &self,
        peer_id: &[u8],
        remote_identity_public: &[u8; 32],
        remote_device_id: Option<&[u8]>,
        now_unix: u64,
    ) -> Result<(), CryptoError>;

    fn encrypt(
        &self,
        session_id: &SessionId,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<SealedMessage, CryptoError>;
    fn encrypt_voice_payload(
        &self,
        session_id: &SessionId,
        voice_payload: &[u8],
        associated_data: &[u8],
    ) -> Result<SealedMessage, CryptoError>;
    fn decrypt(
        &self,
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
        &self,
        remote_identity_public: &[u8; 32],
        remote_device_id: Option<&[u8]>,
    ) -> Result<(), CryptoError>;
    fn has_session(&self, session_id: &SessionId) -> bool;
    fn delete_session(&self, session_id: &SessionId) -> Result<(), CryptoError>;
    fn delete_all_sessions(&self) -> Result<(), CryptoError>;
    fn local_identity_public(&self) -> [u8; 32];
}

// ---------------------------------------------------------------------------
// Ratchet dispatch
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
                let mut trial = r.clone_for_trial();
                let (h, ct) = trial.encrypt(plaintext, ad).map_err(CryptoError::from)?;
                *r = trial;
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
        if data.len() < 2 {
            return Err(CryptoError::Storage);
        }
        match data[0] {
            1 => Ok(Self::Classical(
                DoubleRatchetState::deserialize(&data[1..], DEFAULT_MAX_SKIP)
                    .map_err(CryptoError::from)?,
            )),
            #[cfg(feature = "hybrid")]
            2 => Ok(Self::Hybrid(
                TripleRatchetState::deserialize(&data[1..], DEFAULT_MAX_SKIP)
                    .map_err(CryptoError::from)?,
            )),
            #[cfg(feature = "header-encrypt")]
            3 => Ok(Self::HeaderEncrypt(
                HeaderEncryptState::deserialize(&data[1..], DEFAULT_MAX_SKIP)
                    .map_err(CryptoError::from)?,
            )),
            _ => Err(CryptoError::Storage),
        }
    }
}

#[cfg(feature = "header-encrypt")]
fn he_keys_from_sk(sk: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let mut okm = [0u8; 64];
    let result = hkdf_extract_expand(None, sk, LABELS::DR_HEADER, &mut okm);
    if let Err(e) = result {
        okm.zeroize();
        return Err(CryptoError::from(e));
    }
    let mut hka = [0u8; 32];
    let mut nhkb = [0u8; 32];
    hka.copy_from_slice(&okm[..32]);
    nhkb.copy_from_slice(&okm[32..]);
    okm.zeroize();
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
            let (mut hka, mut nhkb) = he_keys_from_sk(sk)?;
            let result = HeaderEncryptState::init_alice(sk, bob_spk, &hka, &nhkb, DEFAULT_MAX_SKIP)
                .map(LiveRatchet::HeaderEncrypt)
                .map_err(CryptoError::from);
            hka.zeroize();
            nhkb.zeroize();
            result
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
            let (mut hka, mut nhkb) = he_keys_from_sk(sk)?;
            let state = HeaderEncryptState::init_bob(sk, bob_dh, &hka, &nhkb, DEFAULT_MAX_SKIP);
            hka.zeroize();
            nhkb.zeroize();
            Ok(LiveRatchet::HeaderEncrypt(state))
        }
        #[cfg(feature = "hybrid")]
        CryptoProfile::HybridPqV1 => Ok(LiveRatchet::Hybrid(
            TripleRatchetState::init_bob(sk, bob_dh).map_err(CryptoError::from)?,
        )),
    }
}

struct LiveSession {
    profile: CryptoProfile,
    session_tag: SessionTag,
    ratchet: LiveRatchet,
    remote_identity: X25519Public,
    conversation: Vec<u8>,
    identity_tracker: IdentityTracker,
    handshake_ad: Vec<u8>,
    pending_initiation: Option<Vec<u8>>,
}

struct SessionEntry {
    tag: SessionTag,
    inner: Mutex<LiveSession>,
}

impl SessionEntry {
    fn new(session: LiveSession) -> Self {
        Self {
            tag: session.session_tag,
            inner: Mutex::new(session),
        }
    }
}

// ---------------------------------------------------------------------------
// Persistence format
// ---------------------------------------------------------------------------

fn put_u32_vec(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn encode_session(sid: &SessionId, sess: &LiveSession) -> Vec<u8> {
    let ratchet = sess.ratchet.persist_blob();
    let mut out = b"VCSESS02".to_vec();
    out.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    out.extend_from_slice(&sid.0);
    out.push(sess.profile.as_u8());
    out.extend_from_slice(&sess.session_tag.0);
    out.extend_from_slice(&sess.remote_identity.to_bytes());
    put_u32_vec(&mut out, &sess.conversation);
    put_u32_vec(&mut out, &sess.handshake_ad);
    match &sess.pending_initiation {
        Some(packet) => {
            out.push(1);
            put_u32_vec(&mut out, packet);
        }
        None => out.push(0),
    }
    put_u32_vec(&mut out, &ratchet);
    out
}

fn take_bounded_vec(data: &[u8], i: &mut usize, max: usize) -> Result<Vec<u8>, CryptoError> {
    let n = read_u32(data, i).map_err(|_| CryptoError::Storage)? as usize;
    if n > max {
        return Err(CryptoError::Storage);
    }
    Ok(take(data, i, n)
        .map_err(|_| CryptoError::Storage)?
        .to_vec())
}

fn decode_session(data: &[u8]) -> Result<(SessionId, LiveSession), CryptoError> {
    if data.len() < 8 + 2 + 16 + 1 + 16 + 32 + 4 + 4 + 1 + 4
        || &data[..8] != b"VCSESS02"
    {
        return Err(CryptoError::Storage);
    }
    let mut i = 8usize;
    let version = read_u16(data, &mut i).map_err(|_| CryptoError::Storage)?;
    if version != PROTOCOL_VERSION {
        return Err(CryptoError::Storage);
    }
    let mut sid = [0u8; 16];
    sid.copy_from_slice(take(data, &mut i, 16).map_err(|_| CryptoError::Storage)?);
    if sid == [0u8; 16] {
        return Err(CryptoError::Storage);
    }
    let profile = CryptoProfile::from_u8(
        take(data, &mut i, 1).map_err(|_| CryptoError::Storage)?[0],
    )
    .map_err(|_| CryptoError::Storage)?;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(take(data, &mut i, 16).map_err(|_| CryptoError::Storage)?);
    let session_tag = SessionTag(tag);
    if session_tag.is_zero() {
        return Err(CryptoError::Storage);
    }
    let mut remote = [0u8; 32];
    remote.copy_from_slice(take(data, &mut i, 32).map_err(|_| CryptoError::Storage)?);

    let conversation = take_bounded_vec(data, &mut i, MAX_CONVERSATION_LEN)?;
    let handshake_ad = take_bounded_vec(data, &mut i, MAX_ASSOCIATED_DATA_LEN)?;
    let pending_initiation = match take(data, &mut i, 1).map_err(|_| CryptoError::Storage)?[0] {
        0 => None,
        1 => Some(take_bounded_vec(data, &mut i, MAX_PENDING_INITIATION_LEN)?),
        _ => return Err(CryptoError::Storage),
    };
    let ratchet_blob = take_bounded_vec(data, &mut i, MAX_PENDING_INITIATION_LEN)?;
    if i != data.len() {
        return Err(CryptoError::Storage);
    }
    if let Some(packet) = &pending_initiation {
        let parsed = InitiationPacket::decode(packet).map_err(|_| CryptoError::Storage)?;
        if parsed.profile != profile || parsed.first_message.session_tag != session_tag {
            return Err(CryptoError::Storage);
        }
    }

    Ok((
        SessionId(sid),
        LiveSession {
            profile,
            session_tag,
            ratchet: LiveRatchet::restore(&ratchet_blob)?,
            remote_identity: X25519Public::from_bytes(remote).map_err(|_| CryptoError::Storage)?,
            conversation,
            identity_tracker: IdentityTracker::new(),
            handshake_ad,
            pending_initiation,
        },
    ))
}

fn load_sessions(
    storage: &dyn TransactionalStorage,
    profile: CryptoProfile,
) -> Result<HashMap<SessionId, LiveSession>, CryptoError> {
    let mut sessions = HashMap::new();
    let mut tags = HashSet::new();
    for key in storage.keys().map_err(|_| CryptoError::Storage)? {
        let Some(blob) = storage.get(&key).map_err(|_| CryptoError::Storage)? else {
            continue;
        };
        if blob.0.len() >= 8 && &blob.0[..8] == b"VCSESS01" {
            continue;
        }
        if blob.0.len() < 8 || &blob.0[..8] != b"VCSESS02" {
            continue;
        }
        if sessions.len() >= MAX_SESSIONS {
            return Err(CryptoError::LimitExceeded);
        }
        let (sid, sess) = decode_session(&blob.0)?;
        if sess.profile != profile || key.as_slice() != sid.0.as_slice() {
            return Err(CryptoError::Storage);
        }
        if !tags.insert(sess.session_tag) || sessions.insert(sid, sess).is_some() {
            return Err(CryptoError::Storage);
        }
    }
    Ok(sessions)
}

struct LoadedState {
    identity: IdentityKeyPair,
    prekeys: PrekeyStore,
    sessions: HashMap<SessionId, LiveSession>,
    replay: ReplayCache,
    trust: TrustStore,
    peer_identities: PeerIdentityStore,
}

fn load_state(
    storage: &dyn TransactionalStorage,
    profile: CryptoProfile,
) -> Result<LoadedState, CryptoError> {
    let identity_blob = storage
        .get(VoiceChatCryptoEngine::KEY_IDENTITY)
        .map_err(|_| CryptoError::Storage)?
        .ok_or(CryptoError::Storage)?;
    let prekeys_blob = storage
        .get(VoiceChatCryptoEngine::KEY_PREKEYS)
        .map_err(|_| CryptoError::Storage)?
        .ok_or(CryptoError::Storage)?;
    let identity = IdentityKeyPair::deserialize(&identity_blob.0).map_err(CryptoError::from)?;
    let prekeys = PrekeyStore::deserialize(&prekeys_blob.0).map_err(CryptoError::from)?;
    let replay = match storage
        .get(VoiceChatCryptoEngine::KEY_REPLAY)
        .map_err(|_| CryptoError::Storage)?
    {
        Some(blob) => ReplayCache::deserialize(&blob.0).map_err(CryptoError::from)?,
        None => ReplayCache::new(DEFAULT_REPLAY_CACHE_SIZE),
    };
    let trust = match storage
        .get(VoiceChatCryptoEngine::KEY_TRUST)
        .map_err(|_| CryptoError::Storage)?
    {
        Some(blob) => TrustStore::deserialize(&blob.0).map_err(CryptoError::from)?,
        None => TrustStore::new(),
    };
    let peer_identities = match storage
        .get(VoiceChatCryptoEngine::KEY_PEER_IDENTITIES)
        .map_err(|_| CryptoError::Storage)?
    {
        Some(blob) => PeerIdentityStore::deserialize(&blob.0).map_err(CryptoError::from)?,
        None => PeerIdentityStore::new(),
    };
    let mut sessions = load_sessions(storage, profile)?;
    let local_identity = identity.public().to_bytes();
    for session in sessions.values_mut() {
        if let Some(packet) = &session.pending_initiation {
            let parsed = InitiationPacket::decode(packet).map_err(|_| CryptoError::Storage)?;
            if parsed.sender_identity_public != local_identity {
                return Err(CryptoError::Storage);
            }
        }
        session.identity_tracker = trust.tracker_for(&session.remote_identity);
    }
    Ok(LoadedState {
        identity,
        prekeys,
        sessions,
        replay,
        trust,
        peer_identities,
    })
}

struct ReplayState {
    cache: ReplayCache,
    pending: HashSet<ReplayKey>,
}

impl ReplayState {
    fn new(cache: ReplayCache) -> Self {
        Self {
            cache,
            pending: HashSet::new(),
        }
    }
}

struct PersistenceState {
    storage: Box<dyn TransactionalStorage>,
    monotonic: Box<dyn MonotonicCounter>,
    rollback_guard: RollbackGuard,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

pub struct VoiceChatCryptoEngine {
    identity: IdentityKeyPair,
    device_id: Vec<u8>,
    profile: CryptoProfile,
    prekeys: Mutex<PrekeyStore>,
    sessions: RwLock<HashMap<SessionId, Arc<SessionEntry>>>,
    replay: Mutex<ReplayState>,
    trust: Mutex<TrustStore>,
    peer_identities: Mutex<PeerIdentityStore>,
    persistence: Mutex<PersistenceState>,
    lifecycle: RwLock<()>,
    storage_poisoned: AtomicBool,
}

impl VoiceChatCryptoEngine {
    const KEY_IDENTITY: &'static [u8] = b"identity";
    const KEY_PREKEYS: &'static [u8] = b"prekeys";
    const KEY_REPLAY: &'static [u8] = b"replay";
    const KEY_TRUST: &'static [u8] = b"trust";
    const KEY_PEER_IDENTITIES: &'static [u8] = b"peer-identities-v1";
    const KEY_DEVICE_CONFIG: &'static [u8] = b"device-config-v2";
    const KEY_STORAGE_EPOCH: &'static [u8] = b"storage-epoch-v1";

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
        validate_device_id(&config.device_id)?;
        if storage
            .get(Self::KEY_IDENTITY)
            .map_err(|_| CryptoError::Storage)?
            .is_some()
            || storage
                .get(Self::KEY_DEVICE_CONFIG)
                .map_err(|_| CryptoError::Storage)?
                .is_some()
        {
            return Err(CryptoError::Storage);
        }
        let identity = IdentityKeyPair::generate().map_err(CryptoError::from)?;
        let prekeys = PrekeyStore::new(&identity).map_err(CryptoError::from)?;
        let engine = Self {
            identity,
            device_id: config.device_id,
            profile: config.profile,
            prekeys: Mutex::new(prekeys),
            sessions: RwLock::new(HashMap::new()),
            replay: Mutex::new(ReplayState::new(ReplayCache::new(DEFAULT_REPLAY_CACHE_SIZE))),
            trust: Mutex::new(TrustStore::new()),
            peer_identities: Mutex::new(PeerIdentityStore::new()),
            persistence: Mutex::new(PersistenceState {
                storage,
                monotonic,
                rollback_guard: RollbackGuard::default(),
            }),
            lifecycle: RwLock::new(()),
            storage_poisoned: AtomicBool::new(false),
        };
        engine.persist_device_state()?;
        Ok(engine)
    }

    pub fn restore_device_with_backends(
        config: DeviceConfig,
        storage: Box<dyn TransactionalStorage>,
        monotonic: Box<dyn MonotonicCounter>,
    ) -> Result<Self, CryptoError> {
        validate_device_id(&config.device_id)?;
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
        ensure_config_matches(storage.as_ref(), &config)?;
        let loaded = load_state(storage.as_ref(), config.profile)?;
        let mut rollback_guard = RollbackGuard::default();
        rollback_guard
            .observe(StorageEpoch(persisted_epoch))
            .map_err(|_| CryptoError::Storage)?;
        let sessions = loaded
            .sessions
            .into_iter()
            .map(|(id, session)| (id, Arc::new(SessionEntry::new(session))))
            .collect();
        Ok(Self {
            identity: loaded.identity,
            device_id: config.device_id,
            profile: config.profile,
            prekeys: Mutex::new(loaded.prekeys),
            sessions: RwLock::new(sessions),
            replay: Mutex::new(ReplayState::new(loaded.replay)),
            trust: Mutex::new(loaded.trust),
            peer_identities: Mutex::new(loaded.peer_identities),
            persistence: Mutex::new(PersistenceState {
                storage,
                monotonic,
                rollback_guard,
            }),
            lifecycle: RwLock::new(()),
            storage_poisoned: AtomicBool::new(false),
        })
    }

    fn mutex<'a, T>(&self, mutex: &'a Mutex<T>) -> Result<MutexGuard<'a, T>, CryptoError> {
        mutex.lock().map_err(|_| {
            self.storage_poisoned.store(true, Ordering::Release);
            CryptoError::Internal
        })
    }

    fn read_lock<'a, T>(&self, lock: &'a RwLock<T>) -> Result<RwLockReadGuard<'a, T>, CryptoError> {
        lock.read().map_err(|_| {
            self.storage_poisoned.store(true, Ordering::Release);
            CryptoError::Internal
        })
    }

    fn write_lock<'a, T>(&self, lock: &'a RwLock<T>) -> Result<RwLockWriteGuard<'a, T>, CryptoError> {
        lock.write().map_err(|_| {
            self.storage_poisoned.store(true, Ordering::Release);
            CryptoError::Internal
        })
    }

    fn ensure_storage_healthy(&self) -> Result<(), CryptoError> {
        if self.storage_poisoned.load(Ordering::Acquire) {
            Err(CryptoError::Storage)
        } else {
            Ok(())
        }
    }

    fn poison<T>(&self) -> Result<T, CryptoError> {
        self.storage_poisoned.store(true, Ordering::Release);
        Err(CryptoError::Storage)
    }

    fn lifecycle_read(&self) -> Result<RwLockReadGuard<'_, ()>, CryptoError> {
        self.read_lock(&self.lifecycle)
    }

    fn lifecycle_write(&self) -> Result<RwLockWriteGuard<'_, ()>, CryptoError> {
        self.write_lock(&self.lifecycle)
    }

    fn persisted_config(&self) -> Vec<u8> {
        encode_device_config(&self.device_id, self.profile)
    }

    fn commit_changes(
        &self,
        pairs: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), CryptoError> {
        self.ensure_storage_healthy()?;
        let mut p = self.mutex(&self.persistence)?;
        self.ensure_storage_healthy()?;
        let epoch = match p.monotonic.increment() {
            Ok(v) if v > p.rollback_guard.last_seen() => v,
            _ => return self.poison(),
        };
        let tx = match p.storage.begin() {
            Ok(tx) => tx,
            Err(_) => return self.poison(),
        };
        for (key, value) in pairs {
            if p.storage.put(tx, key, &StateBlob(value.clone())).is_err() {
                let _ = p.storage.abort(tx);
                return self.poison();
            }
        }
        for key in deletes {
            if p.storage.delete(tx, key).is_err() {
                let _ = p.storage.abort(tx);
                return self.poison();
            }
        }
        if p.storage
            .put(
                tx,
                Self::KEY_STORAGE_EPOCH,
                &StateBlob(epoch.to_le_bytes().to_vec()),
            )
            .is_err()
        {
            let _ = p.storage.abort(tx);
            return self.poison();
        }
        if p.storage.commit(tx).is_err() {
            return self.poison();
        }
        if p.rollback_guard.observe(StorageEpoch(epoch)).is_err() {
            return self.poison();
        }
        Ok(())
    }

    fn persist_device_state(&self) -> Result<(), CryptoError> {
        let prekeys = self.mutex(&self.prekeys)?.serialize();
        let replay = self.mutex(&self.replay)?.cache.serialize();
        let trust = self.mutex(&self.trust)?.serialize();
        let peers = self.mutex(&self.peer_identities)?.serialize();
        self.commit_changes(
            &[
                (Self::KEY_IDENTITY.to_vec(), self.identity.serialize()),
                (Self::KEY_PREKEYS.to_vec(), prekeys),
                (Self::KEY_REPLAY.to_vec(), replay),
                (Self::KEY_TRUST.to_vec(), trust),
                (Self::KEY_PEER_IDENTITIES.to_vec(), peers),
                (Self::KEY_DEVICE_CONFIG.to_vec(), self.persisted_config()),
            ],
            &[],
        )
    }

    fn persist_session_only(&self, session_id: &SessionId, session: &LiveSession) -> Result<(), CryptoError> {
        self.commit_changes(
            &[(session_id.0.to_vec(), encode_session(session_id, session))],
            &[],
        )
    }

    fn persist_handshake(&self, session_id: &SessionId, session: &LiveSession) -> Result<(), CryptoError> {
        let prekeys = self.mutex(&self.prekeys)?.serialize();
        let replay = self.mutex(&self.replay)?.cache.serialize();
        let trust = self.mutex(&self.trust)?.serialize();
        let peers = self.mutex(&self.peer_identities)?.serialize();
        self.commit_changes(
            &[
                (Self::KEY_IDENTITY.to_vec(), self.identity.serialize()),
                (Self::KEY_PREKEYS.to_vec(), prekeys),
                (session_id.0.to_vec(), encode_session(session_id, session)),
                (Self::KEY_REPLAY.to_vec(), replay),
                (Self::KEY_TRUST.to_vec(), trust),
                (Self::KEY_PEER_IDENTITIES.to_vec(), peers),
                (Self::KEY_DEVICE_CONFIG.to_vec(), self.persisted_config()),
            ],
            &[],
        )
    }

    fn verify_storage_epoch_locked(&self, p: &mut PersistenceState) -> Result<(), CryptoError> {
        self.ensure_storage_healthy()?;
        let blob = match p.storage.get(Self::KEY_STORAGE_EPOCH) {
            Ok(Some(blob)) => blob,
            _ => return self.poison(),
        };
        if blob.0.len() != 8 {
            return self.poison();
        }
        let persisted = u64::from_le_bytes(
            blob.0
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::Storage)?,
        );
        let current = match p.monotonic.current() {
            Ok(v) => v,
            Err(_) => return self.poison(),
        };
        if persisted != current || p.rollback_guard.observe(StorageEpoch(persisted)).is_err() {
            return self.poison();
        }
        Ok(())
    }

    fn ensure_session_capacity(&self) -> Result<(), CryptoError> {
        if self.read_lock(&self.sessions)?.len() >= MAX_SESSIONS {
            Err(CryptoError::LimitExceeded)
        } else {
            Ok(())
        }
    }

    fn session_tag_in_use(&self, tag: SessionTag) -> Result<bool, CryptoError> {
        Ok(self
            .read_lock(&self.sessions)?
            .values()
            .any(|entry| entry.tag == tag))
    }

    fn next_session_id(&self) -> Result<SessionId, CryptoError> {
        for _ in 0..8 {
            let mut id = [0u8; 16];
            crate::primitives::random::fill_random(&mut id).map_err(CryptoError::from)?;
            if id == [0u8; 16] {
                continue;
            }
            let sid = SessionId(id);
            if !self.read_lock(&self.sessions)?.contains_key(&sid) {
                return Ok(sid);
            }
        }
        Err(CryptoError::Internal)
    }

    fn next_session_tag(&self) -> Result<SessionTag, CryptoError> {
        for _ in 0..8 {
            let mut tag = [0u8; 16];
            crate::primitives::random::fill_random(&mut tag).map_err(CryptoError::from)?;
            let candidate = SessionTag(tag);
            if !candidate.is_zero() && !self.session_tag_in_use(candidate)? {
                return Ok(candidate);
            }
        }
        Err(CryptoError::Internal)
    }

    fn session_entry(&self, session_id: &SessionId) -> Result<Arc<SessionEntry>, CryptoError> {
        self.read_lock(&self.sessions)?
            .get(session_id)
            .cloned()
            .ok_or(CryptoError::NoSession)
    }

    fn validate_sealed_for_session(
        sess: &LiveSession,
        sealed: &SealedMessage,
    ) -> Result<(), CryptoError> {
        if sealed.protocol_version != PROTOCOL_VERSION
            || sealed.profile != sess.profile
            || sealed.session_tag != sess.session_tag
            || sealed.session_tag.is_zero()
        {
            return Err(CryptoError::CryptoFailure);
        }
        if sealed.header.len() > MAX_HEADER_LEN {
            return Err(CryptoError::LimitExceeded);
        }
        validate_ciphertext_len(sealed.ciphertext.len())
    }

    fn bound_ad(sess: &LiveSession, associated_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if associated_data.len() > MAX_ASSOCIATED_DATA_LEN {
            return Err(CryptoError::LimitExceeded);
        }
        let mut out = Vec::with_capacity(
            6 + 2 + 1 + 16 + 12 + sess.handshake_ad.len() + sess.conversation.len()
                + associated_data.len(),
        );
        out.extend_from_slice(b"VCAD02");
        out.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        out.push(sess.profile.as_u8());
        out.extend_from_slice(&sess.session_tag.0);
        put_u32_vec(&mut out, &sess.handshake_ad);
        put_u32_vec(&mut out, &sess.conversation);
        put_u32_vec(&mut out, associated_data);
        Ok(out)
    }

    fn replay_key(sess: &LiveSession, sealed: &SealedMessage) -> ReplayKey {
        let version = sealed.protocol_version.to_le_bytes();
        let profile = [sealed.profile.as_u8()];
        let digest = sha256_parts(&[
            b"VCREPLAY02",
            &version,
            &profile,
            &sealed.session_tag.0,
            &sealed.header,
            &sealed.ciphertext,
        ]);
        ReplayKey {
            conversation_id: sess.conversation.clone(),
            sender_device_id: sess.remote_identity.to_bytes().to_vec(),
            message_id: digest.to_vec(),
        }
    }

    fn initiation_replay_key(message: &InitiationPacket, conversation: &[u8]) -> ReplayKey {
        let version = message.protocol_version.to_le_bytes();
        let profile = [message.profile.as_u8()];
        let kem_len = (message.kem_ciphertext.len() as u64).to_le_bytes();
        let spk = message.used_spk_id.to_le_bytes();
        let opk_flag = [u8::from(message.used_ec_opk_id.is_some())];
        let opk = message.used_ec_opk_id.unwrap_or(0).to_le_bytes();
        let pq = message.pq_prekey_id.to_le_bytes();
        let first_version = message.first_message.protocol_version.to_le_bytes();
        let first_profile = [message.first_message.profile.as_u8()];
        let header_len = (message.first_message.header.len() as u64).to_le_bytes();
        let ciphertext_len = (message.first_message.ciphertext.len() as u64).to_le_bytes();
        let digest = sha256_parts(&[
            b"VCINIT-REPLAY02",
            &version,
            &profile,
            &message.sender_identity_public,
            &message.sender_ephemeral_public,
            &kem_len,
            &message.kem_ciphertext,
            &spk,
            &opk_flag,
            &opk,
            &pq,
            &first_version,
            &first_profile,
            &message.first_message.session_tag.0,
            &header_len,
            &message.first_message.header,
            &ciphertext_len,
            &message.first_message.ciphertext,
        ]);
        ReplayKey {
            conversation_id: conversation.to_vec(),
            sender_device_id: message.sender_identity_public.to_vec(),
            message_id: digest.to_vec(),
        }
    }

    fn peer_material(
        remote_identity_public: &[u8; 32],
        remote_device_id: Option<&[u8]>,
    ) -> Result<IdentityMaterial, CryptoError> {
        let material = IdentityMaterial {
            identity_key: X25519Public::from_bytes(*remote_identity_public)
                .map_err(CryptoError::from)?,
            device_id: remote_device_id.map(|d| d.to_vec()),
        };
        validate_identity_material(&material).map_err(CryptoError::from)?;
        Ok(material)
    }

    fn check_peer(&self, peer_id: &[u8], material: &IdentityMaterial) -> Result<bool, CryptoError> {
        validate_peer_id_input(peer_id)?;
        validate_identity_material(material).map_err(CryptoError::from)?;
        match self.mutex(&self.peer_identities)?.observe(peer_id, material) {
            IdentityState::IdentityChanged { .. } => Err(CryptoError::IdentityChanged),
            IdentityState::Unknown => Ok(true),
            IdentityState::Verified => Ok(false),
        }
    }

    fn restore_identity_trackers(&self) -> Result<(), CryptoError> {
        let trust = self.mutex(&self.trust)?.clone();
        let sessions: Vec<Arc<SessionEntry>> = self
            .read_lock(&self.sessions)?
            .values()
            .cloned()
            .collect();
        for entry in sessions {
            let mut session = self.mutex(&entry.inner)?;
            session.identity_tracker = trust.tracker_for(&session.remote_identity);
        }
        Ok(())
    }

    fn restore_prekeys_from(&self, bytes: &[u8]) -> Result<(), CryptoError> {
        let restored = PrekeyStore::deserialize(bytes).map_err(CryptoError::from)?;
        *self.mutex(&self.prekeys)? = restored;
        Ok(())
    }

    fn restore_replay_from(&self, bytes: &[u8]) -> Result<(), CryptoError> {
        let restored = ReplayCache::deserialize(bytes).map_err(CryptoError::from)?;
        *self.mutex(&self.replay)? = ReplayState::new(restored);
        Ok(())
    }

    fn establish_outbound_impl(
        &self,
        peer: Option<(&[u8], IdentityMaterial)>,
        remote_bundle: &PublicPrekeyBundle,
        conversation_context: &[u8],
        first_plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(SessionId, InitiationPacket), CryptoError> {
        let _life = self.lifecycle_write()?;
        self.ensure_storage_healthy()?;
        self.ensure_session_capacity()?;
        validate_context_lengths(conversation_context, associated_data)?;
        validate_plaintext_len(first_plaintext.len())?;
        remote_bundle.validate().map_err(CryptoError::from)?;
        let should_record_peer = match &peer {
            Some((peer_id, material)) => self.check_peer(peer_id, material)?,
            None => false,
        };

        let initiation = alice_initiate(&self.identity, remote_bundle).map_err(CryptoError::from)?;
        if initiation.kem_ciphertext.len() > MAX_KEM_CIPHERTEXT_LEN {
            return Err(CryptoError::LimitExceeded);
        }
        let ratchet = init_alice_ratchet(
            self.profile,
            &initiation.shared.sk,
            &remote_bundle.signed_prekey,
        )?;
        let sid = self.next_session_id()?;
        let session_tag = self.next_session_tag()?;
        let remote_identity = remote_bundle.identity_key;
        let tracker = self.mutex(&self.trust)?.tracker_for(&remote_identity);
        let mut session = LiveSession {
            profile: self.profile,
            session_tag,
            ratchet,
            remote_identity,
            conversation: conversation_context.to_vec(),
            identity_tracker: tracker,
            handshake_ad: initiation.shared.ad.clone(),
            pending_initiation: None,
        };
        let ad = Self::bound_ad(&session, associated_data)?;
        let (header, ciphertext) = session.ratchet.encrypt(first_plaintext, &ad)?;
        if header.len() > MAX_HEADER_LEN || ciphertext.len() > MAX_CIPHERTEXT_LEN {
            return self.poison().map_err(|_| CryptoError::Internal);
        }
        let first_message = SealedMessage {
            protocol_version: PROTOCOL_VERSION,
            profile: self.profile,
            session_tag,
            header,
            ciphertext,
        };
        let packet = InitiationPacket {
            protocol_version: PROTOCOL_VERSION,
            profile: self.profile,
            sender_identity_public: self.identity.public().to_bytes(),
            sender_ephemeral_public: initiation.ephemeral_public.to_bytes(),
            kem_ciphertext: initiation.kem_ciphertext,
            used_spk_id: remote_bundle.signed_prekey_id,
            used_ec_opk_id: initiation.used_ec_opk_id,
            pq_prekey_id: initiation.used_pq_prekey_id,
            first_message,
        };
        let pending = packet.encode();
        if pending.len() > MAX_PENDING_INITIATION_LEN {
            return Err(CryptoError::LimitExceeded);
        }
        session.pending_initiation = Some(pending);

        let trust_before = self.mutex(&self.trust)?.clone();
        let peers_before = self.mutex(&self.peer_identities)?.clone();
        {
            if should_record_peer {
                if let Some((peer_id, material)) = &peer {
                    self.mutex(&self.peer_identities)?
                        .record_seen(peer_id, material.clone())
                        .map_err(CryptoError::from)?;
                }
            }
            self.mutex(&self.trust)?.record_seen(IdentityMaterial {
                identity_key: remote_identity,
                device_id: None,
            });
        }

        let entry = Arc::new(SessionEntry::new(session));
        {
            let mut sessions = self.write_lock(&self.sessions)?;
            if sessions.insert(sid.clone(), entry.clone()).is_some() {
                *self.mutex(&self.trust)? = trust_before;
                *self.mutex(&self.peer_identities)? = peers_before;
                self.storage_poisoned.store(true, Ordering::Release);
                return Err(CryptoError::Internal);
            }
        }

        let persist_result = {
            let session = self.mutex(&entry.inner)?;
            self.persist_handshake(&sid, &session)
        };
        if let Err(e) = persist_result {
            self.write_lock(&self.sessions)?.remove(&sid);
            *self.mutex(&self.trust)? = trust_before;
            *self.mutex(&self.peer_identities)? = peers_before;
            return Err(e);
        }
        Ok((sid, packet))
    }

    fn process_inbound_impl(
        &self,
        peer: Option<(&[u8], IdentityMaterial)>,
        message: &InitiationPacket,
        conversation_context: &[u8],
        associated_data: &[u8],
    ) -> Result<(SessionId, Vec<u8>), CryptoError> {
        let _life = self.lifecycle_write()?;
        self.ensure_storage_healthy()?;
        self.ensure_session_capacity()?;
        validate_context_lengths(conversation_context, associated_data)?;
        validate_ciphertext_len(message.first_message.ciphertext.len())?;
        if message.protocol_version != PROTOCOL_VERSION
            || message.profile != self.profile
            || message.first_message.protocol_version != PROTOCOL_VERSION
            || message.first_message.profile != self.profile
            || message.first_message.session_tag.is_zero()
        {
            return Err(CryptoError::CryptoFailure);
        }
        if message.kem_ciphertext.len() > MAX_KEM_CIPHERTEXT_LEN
            || message.first_message.header.len() > MAX_HEADER_LEN
        {
            return Err(CryptoError::LimitExceeded);
        }
        if self.session_tag_in_use(message.first_message.session_tag)? {
            return Err(CryptoError::CryptoFailure);
        }
        let should_record_peer = match &peer {
            Some((peer_id, material)) => self.check_peer(peer_id, material)?,
            None => false,
        };
        let initiation_replay = Self::initiation_replay_key(message, conversation_context);
        {
            let replay = self.mutex(&self.replay)?;
            if replay.cache.contains(&initiation_replay) || replay.pending.contains(&initiation_replay) {
                return Err(CryptoError::Replay);
            }
        }

        let alice_ik =
            X25519Public::from_bytes(message.sender_identity_public).map_err(CryptoError::from)?;
        let alice_ek =
            X25519Public::from_bytes(message.sender_ephemeral_public).map_err(CryptoError::from)?;

        let (ratchet, handshake_ad, last_resort) = {
            let prekeys = self.mutex(&self.prekeys)?;
            let signed = prekeys
                .signed_prekey(message.used_spk_id)
                .map_err(CryptoError::from)?;
            let peeked_ec = match message.used_ec_opk_id {
                Some(id) => Some(prekeys.peek_ec(id).map_err(CryptoError::from)?.clone()),
                None => None,
            };
            let last_resort = prekeys.is_last_resort_pq(message.pq_prekey_id);
            let peeked_pq = if last_resort {
                None
            } else {
                Some(
                    prekeys
                        .peek_pq(message.pq_prekey_id)
                        .map_err(CryptoError::from)?
                        .clone(),
                )
            };
            let pq_secret = if let Some(ref pq) = peeked_pq {
                &pq.secret
            } else {
                &prekeys
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
            let shared = bob_process(
                &bob_mat,
                &alice_ik,
                &alice_ek,
                &message.kem_ciphertext,
                message.used_ec_opk_id,
            )
            .map_err(CryptoError::from)?;
            let bob_dh = X25519Secret::from_bytes(signed.secret.to_bytes());
            let ratchet = init_bob_ratchet(self.profile, &shared.sk, bob_dh)?;
            (ratchet, shared.ad, last_resort)
        };

        let sid = self.next_session_id()?;
        let tracker = self.mutex(&self.trust)?.tracker_for(&alice_ik);
        let mut session = LiveSession {
            profile: self.profile,
            session_tag: message.first_message.session_tag,
            ratchet,
            remote_identity: alice_ik,
            conversation: conversation_context.to_vec(),
            identity_tracker: tracker,
            handshake_ad,
            pending_initiation: None,
        };
        Self::validate_sealed_for_session(&session, &message.first_message)?;
        let message_replay = Self::replay_key(&session, &message.first_message);
        {
            let replay = self.mutex(&self.replay)?;
            if replay.cache.contains(&message_replay) || replay.pending.contains(&message_replay) {
                return Err(CryptoError::Replay);
            }
        }
        let ad = Self::bound_ad(&session, associated_data)?;
        let plaintext = session
            .ratchet
            .decrypt(
                &message.first_message.header,
                &message.first_message.ciphertext,
                &ad,
            )?;

        // The first message authenticated. All mutable global state from here to
        // the durable commit is treated as one trial transaction and restored on
        // any local failure. A storage ambiguity still poisons the engine.
        let prekeys_before = self.mutex(&self.prekeys)?.serialize();
        let replay_before = self.mutex(&self.replay)?.cache.serialize();
        let trust_before = self.mutex(&self.trust)?.clone();
        let peers_before = self.mutex(&self.peer_identities)?.clone();

        let trial_result = (|| -> Result<(), CryptoError> {
            {
                let mut prekeys = self.mutex(&self.prekeys)?;
                if let Some(id) = message.used_ec_opk_id {
                    prekeys.consume_ec(id).map_err(CryptoError::from)?;
                }
                if !last_resort {
                    prekeys
                        .consume_pq(message.pq_prekey_id)
                        .map_err(CryptoError::from)?;
                }
            }
            {
                let mut replay = self.mutex(&self.replay)?;
                if replay
                    .cache
                    .check_and_insert(message_replay.clone())
                    .map_err(CryptoError::from)?
                {
                    return Err(CryptoError::Replay);
                }
                if replay
                    .cache
                    .check_and_insert(initiation_replay.clone())
                    .map_err(CryptoError::from)?
                {
                    return Err(CryptoError::Replay);
                }
            }
            if should_record_peer {
                if let Some((peer_id, material)) = &peer {
                    self.mutex(&self.peer_identities)?
                        .record_seen(peer_id, material.clone())
                        .map_err(CryptoError::from)?;
                }
            }
            self.mutex(&self.trust)?.record_seen(IdentityMaterial {
                identity_key: alice_ik,
                device_id: None,
            });
            Ok(())
        })();
        if let Err(e) = trial_result {
            let _ = self.restore_prekeys_from(&prekeys_before);
            let _ = self.restore_replay_from(&replay_before);
            *self.mutex(&self.trust)? = trust_before;
            *self.mutex(&self.peer_identities)? = peers_before;
            self.storage_poisoned.store(true, Ordering::Release);
            return Err(e);
        }

        let entry = Arc::new(SessionEntry::new(session));
        if self
            .write_lock(&self.sessions)?
            .insert(sid.clone(), entry.clone())
            .is_some()
        {
            let _ = self.restore_prekeys_from(&prekeys_before);
            let _ = self.restore_replay_from(&replay_before);
            *self.mutex(&self.trust)? = trust_before;
            *self.mutex(&self.peer_identities)? = peers_before;
            self.storage_poisoned.store(true, Ordering::Release);
            return Err(CryptoError::Internal);
        }

        let persist_result = {
            let session = self.mutex(&entry.inner)?;
            self.persist_handshake(&sid, &session)
        };
        if let Err(e) = persist_result {
            self.write_lock(&self.sessions)?.remove(&sid);
            let _ = self.restore_prekeys_from(&prekeys_before);
            let _ = self.restore_replay_from(&replay_before);
            *self.mutex(&self.trust)? = trust_before;
            *self.mutex(&self.peer_identities)? = peers_before;
            return Err(e);
        }
        Ok((sid, plaintext))
    }

    pub fn remote_identity_state(
        &self,
        remote_identity_public: &[u8; 32],
        remote_device_id: Option<&[u8]>,
    ) -> Result<IdentityState, CryptoError> {
        let _life = self.lifecycle_read()?;
        self.ensure_storage_healthy()?;
        let mat = Self::peer_material(remote_identity_public, remote_device_id)?;
        Ok(self.mutex(&self.trust)?.tracker_for(&mat.identity_key).observe(&mat))
    }

    pub fn simulate_crash_reload(&self) -> Result<(), CryptoError> {
        let _life = self.lifecycle_write()?;
        self.ensure_storage_healthy()?;
        let expected = DeviceConfig {
            device_id: self.device_id.clone(),
            profile: self.profile,
        };

        let loaded = {
            let mut p = self.mutex(&self.persistence)?;
            self.verify_storage_epoch_locked(&mut p)?;
            if ensure_config_matches(p.storage.as_ref(), &expected).is_err() {
                return self.poison();
            }
            match load_state(p.storage.as_ref(), self.profile) {
                Ok(state) => state,
                Err(_) => return self.poison(),
            }
        };

        *self.mutex(&self.prekeys)? = loaded.prekeys;
        *self.mutex(&self.replay)? = ReplayState::new(loaded.replay);
        *self.mutex(&self.trust)? = loaded.trust;
        *self.mutex(&self.peer_identities)? = loaded.peer_identities;
        let sessions = loaded
            .sessions
            .into_iter()
            .map(|(id, session)| (id, Arc::new(SessionEntry::new(session))))
            .collect();
        *self.write_lock(&self.sessions)? = sessions;
        self.restore_identity_trackers()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// API implementation
// ---------------------------------------------------------------------------

impl CryptoEngineApi for VoiceChatCryptoEngine {
    fn generate_public_prekey_bundle(
        &self,
        one_time_count: usize,
    ) -> Result<PublicPrekeyBundle, CryptoError> {
        let _life = self.lifecycle_write()?;
        self.ensure_storage_healthy()?;
        let before = self.mutex(&self.prekeys)?.serialize();
        let bundle = {
            let mut prekeys = self.mutex(&self.prekeys)?;
            if let Err(e) = prekeys.replenish(&self.identity, one_time_count, one_time_count) {
                return Err(CryptoError::from(e));
            }
            match prekeys.public_bundle(&self.identity) {
                Ok(bundle) => bundle,
                Err(e) => {
                    drop(prekeys);
                    self.restore_prekeys_from(&before)?;
                    return Err(CryptoError::from(e));
                }
            }
        };
        if let Err(e) = self.persist_device_state() {
            let _ = self.restore_prekeys_from(&before);
            return Err(e);
        }
        Ok(bundle)
    }

    fn replenish_prekeys(
        &self,
        one_time_count: usize,
    ) -> Result<PublicPrekeyBundle, CryptoError> {
        self.generate_public_prekey_bundle(one_time_count)
    }

    fn rotate_signed_prekey(
        &self,
        retain_previous: usize,
    ) -> Result<PublicPrekeyBundle, CryptoError> {
        let _life = self.lifecycle_write()?;
        self.ensure_storage_healthy()?;
        let before = self.mutex(&self.prekeys)?.serialize();
        let bundle = {
            let mut prekeys = self.mutex(&self.prekeys)?;
            if let Err(e) = prekeys.rotate_signed_prekey(&self.identity, retain_previous) {
                return Err(CryptoError::from(e));
            }
            match prekeys.public_bundle(&self.identity) {
                Ok(bundle) => bundle,
                Err(e) => {
                    drop(prekeys);
                    self.restore_prekeys_from(&before)?;
                    return Err(CryptoError::from(e));
                }
            }
        };
        if let Err(e) = self.persist_device_state() {
            let _ = self.restore_prekeys_from(&before);
            return Err(e);
        }
        Ok(bundle)
    }

    fn rotate_last_resort_pq(
        &self,
        retain_previous: usize,
    ) -> Result<PublicPrekeyBundle, CryptoError> {
        let _life = self.lifecycle_write()?;
        self.ensure_storage_healthy()?;
        let before = self.mutex(&self.prekeys)?.serialize();
        let bundle = {
            let mut prekeys = self.mutex(&self.prekeys)?;
            if let Err(e) = prekeys.rotate_last_resort_pq(&self.identity, retain_previous) {
                return Err(CryptoError::from(e));
            }
            match prekeys.public_bundle(&self.identity) {
                Ok(bundle) => bundle,
                Err(e) => {
                    drop(prekeys);
                    self.restore_prekeys_from(&before)?;
                    return Err(CryptoError::from(e));
                }
            }
        };
        if let Err(e) = self.persist_device_state() {
            let _ = self.restore_prekeys_from(&before);
            return Err(e);
        }
        Ok(bundle)
    }

    fn establish_outbound_session(
        &self,
        remote_bundle: &PublicPrekeyBundle,
        conversation_context: &[u8],
        first_plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(SessionId, InitiationPacket), CryptoError> {
        self.establish_outbound_impl(
            None,
            remote_bundle,
            conversation_context,
            first_plaintext,
            associated_data,
        )
    }

    fn establish_outbound_session_for_peer(
        &self,
        peer_id: &[u8],
        remote_device_id: Option<&[u8]>,
        remote_bundle: &PublicPrekeyBundle,
        conversation_context: &[u8],
        first_plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(SessionId, InitiationPacket), CryptoError> {
        validate_peer_id_input(peer_id)?;
        let material = Self::peer_material(&remote_bundle.identity_key.to_bytes(), remote_device_id)?;
        self.establish_outbound_impl(
            Some((peer_id, material)),
            remote_bundle,
            conversation_context,
            first_plaintext,
            associated_data,
        )
    }

    fn process_inbound_session(
        &self,
        message: &InitiationPacket,
        conversation_context: &[u8],
        associated_data: &[u8],
    ) -> Result<(SessionId, Vec<u8>), CryptoError> {
        self.process_inbound_impl(None, message, conversation_context, associated_data)
    }

    fn process_inbound_session_from_peer(
        &self,
        peer_id: &[u8],
        remote_device_id: Option<&[u8]>,
        message: &InitiationPacket,
        conversation_context: &[u8],
        associated_data: &[u8],
    ) -> Result<(SessionId, Vec<u8>), CryptoError> {
        validate_peer_id_input(peer_id)?;
        let material = Self::peer_material(&message.sender_identity_public, remote_device_id)?;
        self.process_inbound_impl(
            Some((peer_id, material)),
            message,
            conversation_context,
            associated_data,
        )
    }

    fn pending_outbound_initiation(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<InitiationPacket>, CryptoError> {
        let _life = self.lifecycle_read()?;
        self.ensure_storage_healthy()?;
        let entry = self.session_entry(session_id)?;
        let session = self.mutex(&entry.inner)?;
        match &session.pending_initiation {
            Some(bytes) => Ok(Some(InitiationPacket::decode(bytes)?)),
            None => Ok(None),
        }
    }

    fn acknowledge_outbound_initiation(
        &self,
        session_id: &SessionId,
    ) -> Result<(), CryptoError> {
        let _life = self.lifecycle_read()?;
        self.ensure_storage_healthy()?;
        let entry = self.session_entry(session_id)?;
        let mut session = self.mutex(&entry.inner)?;
        let previous = match session.pending_initiation.take() {
            Some(value) => value,
            None => return Ok(()),
        };
        if let Err(e) = self.persist_session_only(session_id, &session) {
            session.pending_initiation = Some(previous);
            return Err(e);
        }
        Ok(())
    }

    fn peer_identity_state(
        &self,
        peer_id: &[u8],
        remote_identity_public: &[u8; 32],
        remote_device_id: Option<&[u8]>,
    ) -> Result<IdentityState, CryptoError> {
        let _life = self.lifecycle_read()?;
        self.ensure_storage_healthy()?;
        validate_peer_id_input(peer_id)?;
        let material = Self::peer_material(remote_identity_public, remote_device_id)?;
        Ok(self.mutex(&self.peer_identities)?.observe(peer_id, &material))
    }

    fn acknowledge_peer_identity(
        &self,
        peer_id: &[u8],
        remote_identity_public: &[u8; 32],
        remote_device_id: Option<&[u8]>,
        now_unix: u64,
    ) -> Result<(), CryptoError> {
        let _life = self.lifecycle_write()?;
        self.ensure_storage_healthy()?;
        validate_peer_id_input(peer_id)?;
        let material = Self::peer_material(remote_identity_public, remote_device_id)?;
        let before = self.mutex(&self.peer_identities)?.clone();
        self.mutex(&self.peer_identities)?
            .acknowledge(
                peer_id,
                material,
                now_unix,
                VerificationMethod::SafetyNumber,
            )
            .map_err(CryptoError::from)?;
        if let Err(e) = self.persist_device_state() {
            *self.mutex(&self.peer_identities)? = before;
            return Err(e);
        }
        Ok(())
    }

    fn encrypt(
        &self,
        session_id: &SessionId,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<SealedMessage, CryptoError> {
        let _life = self.lifecycle_read()?;
        self.ensure_storage_healthy()?;
        validate_context_lengths(&[], associated_data)?;
        validate_plaintext_len(plaintext.len())?;
        let entry = self.session_entry(session_id)?;
        let mut session = self.mutex(&entry.inner)?;
        self.ensure_storage_healthy()?;
        let ad = Self::bound_ad(&session, associated_data)?;
        let (header, ciphertext) = session.ratchet.encrypt(plaintext, &ad)?;
        if header.len() > MAX_HEADER_LEN || ciphertext.len() > MAX_CIPHERTEXT_LEN {
            self.storage_poisoned.store(true, Ordering::Release);
            return Err(CryptoError::Internal);
        }
        let sealed = SealedMessage {
            protocol_version: PROTOCOL_VERSION,
            profile: session.profile,
            session_tag: session.session_tag,
            header,
            ciphertext,
        };
        self.persist_session_only(session_id, &session)?;
        Ok(sealed)
    }

    fn encrypt_voice_payload(
        &self,
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
        &self,
        session_id: &SessionId,
        sealed: &SealedMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let _life = self.lifecycle_read()?;
        self.ensure_storage_healthy()?;
        validate_context_lengths(&[], associated_data)?;
        validate_ciphertext_len(sealed.ciphertext.len())?;
        let entry = self.session_entry(session_id)?;
        let mut session = self.mutex(&entry.inner)?;
        Self::validate_sealed_for_session(&session, sealed)?;
        let rkey = Self::replay_key(&session, sealed);

        {
            let mut replay = self.mutex(&self.replay)?;
            if replay.cache.contains(&rkey) || replay.pending.contains(&rkey) {
                return Err(CryptoError::Replay);
            }
            replay.pending.insert(rkey.clone());
        }

        let decrypt_result = (|| {
            let ad = Self::bound_ad(&session, associated_data)?;
            session
                .ratchet
                .decrypt(&sealed.header, &sealed.ciphertext, &ad)
        })();
        let plaintext = match decrypt_result {
            Ok(plaintext) => plaintext,
            Err(e) => {
                self.mutex(&self.replay)?.pending.remove(&rkey);
                return Err(e);
            }
        };
        session.pending_initiation = None;
        let session_blob = encode_session(session_id, &session);

        // Replay finalization and persistence are serialized only for this short
        // stage; expensive ratchet/AEAD work above remains per-session parallel.
        let mut replay = self.mutex(&self.replay)?;
        if !replay.pending.remove(&rkey) {
            self.storage_poisoned.store(true, Ordering::Release);
            return Err(CryptoError::Internal);
        }
        if replay
            .cache
            .check_and_insert(rkey)
            .map_err(CryptoError::from)?
        {
            self.storage_poisoned.store(true, Ordering::Release);
            return Err(CryptoError::Replay);
        }
        let replay_blob = replay.cache.serialize();
        self.commit_changes(
            &[
                (session_id.0.to_vec(), session_blob),
                (Self::KEY_REPLAY.to_vec(), replay_blob),
            ],
            &[],
        )?;
        Ok(plaintext)
    }

    fn safety_fingerprint(
        &self,
        remote_identity_public: &[u8; 32],
        remote_device_id: Option<&[u8]>,
    ) -> Result<SafetyFingerprint, CryptoError> {
        let _life = self.lifecycle_read()?;
        self.ensure_storage_healthy()?;
        let remote = Self::peer_material(remote_identity_public, remote_device_id)?;
        let local = IdentityMaterial {
            identity_key: self.identity.public(),
            device_id: Some(self.device_id.clone()),
        };
        validate_identity_material(&local).map_err(CryptoError::from)?;
        compute_fingerprint(&local, &remote).map_err(CryptoError::from)
    }

    fn acknowledge_identity_change(
        &self,
        remote_identity_public: &[u8; 32],
        remote_device_id: Option<&[u8]>,
    ) -> Result<(), CryptoError> {
        let _life = self.lifecycle_write()?;
        self.ensure_storage_healthy()?;
        let mat = Self::peer_material(remote_identity_public, remote_device_id)?;
        let trust_before = self.mutex(&self.trust)?.clone();
        {
            let sessions: Vec<Arc<SessionEntry>> = self
                .read_lock(&self.sessions)?
                .values()
                .cloned()
                .collect();
            for entry in sessions {
                let mut session = self.mutex(&entry.inner)?;
                if session.remote_identity.to_bytes() == *remote_identity_public
                    || matches!(
                        session.identity_tracker.observe(&mat),
                        IdentityState::IdentityChanged { .. }
                    )
                {
                    session.identity_tracker.acknowledge(mat.clone());
                }
            }
        }
        self.mutex(&self.trust)?
            .acknowledge(mat, 0, VerificationMethod::SafetyNumber);
        if let Err(e) = self.persist_device_state() {
            *self.mutex(&self.trust)? = trust_before;
            let _ = self.restore_identity_trackers();
            return Err(e);
        }
        Ok(())
    }

    fn has_session(&self, session_id: &SessionId) -> bool {
        if self.storage_poisoned.load(Ordering::Acquire) {
            return false;
        }
        self.sessions
            .read()
            .map(|sessions| sessions.contains_key(session_id))
            .unwrap_or(false)
    }

    fn delete_session(&self, session_id: &SessionId) -> Result<(), CryptoError> {
        let _life = self.lifecycle_write()?;
        self.ensure_storage_healthy()?;
        if !self.read_lock(&self.sessions)?.contains_key(session_id) {
            return Err(CryptoError::NoSession);
        }
        self.commit_changes(&[], &[session_id.0.to_vec()])?;
        self.write_lock(&self.sessions)?.remove(session_id);
        Ok(())
    }

    fn delete_all_sessions(&self) -> Result<(), CryptoError> {
        let _life = self.lifecycle_write()?;
        self.ensure_storage_healthy()?;
        let session_keys = {
            let p = self.mutex(&self.persistence)?;
            let mut keys = Vec::new();
            for key in p.storage.keys().map_err(|_| CryptoError::Storage)? {
                let Some(blob) = p.storage.get(&key).map_err(|_| CryptoError::Storage)? else {
                    continue;
                };
                if blob.0.len() >= 8
                    && (&blob.0[..8] == b"VCSESS01" || &blob.0[..8] == b"VCSESS02")
                {
                    keys.push(key);
                }
            }
            keys
        };
        self.commit_changes(&[], &session_keys)?;
        self.write_lock(&self.sessions)?.clear();
        Ok(())
    }

    fn local_identity_public(&self) -> [u8; 32] {
        self.identity.public().to_bytes()
    }
}

#[cfg(test)]
mod tests;
