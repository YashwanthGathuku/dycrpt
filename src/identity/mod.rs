//! Identity lifecycle.
//!
//! A cryptographic public key cannot by itself answer the question “is this
//! still the same contact/device I talked to yesterday?” because a changed key
//! would simply be a different lookup key. `PeerIdentityStore` therefore binds
//! an application-defined stable peer identifier to the last seen/acknowledged
//! cryptographic identity.
//!
//! The peer identifier is opaque to this crate. It should be a stable account
//! or device identifier supplied by the application — never a display name and
//! never a phone number treated as cryptographic proof.

pub use crate::prekeys::IdentityKeyPair;

use std::collections::HashMap;

use crate::fingerprint::{
    validate_identity_material, IdentityChangeReason, IdentityMaterial, IdentityState,
    VerificationMethod,
};
use crate::primitives::error::PrimitiveError;
use crate::primitives::x25519::X25519Public;

const PEER_STORE_MAGIC: &[u8; 8] = b"VCPEER01";
const MAX_PEER_ID_LEN: usize = 4096;
const MAX_DEVICE_ID_LEN: usize = 4096;
const MAX_PEER_RECORDS: usize = 100_000;
const MAX_PEER_STORE_LEN: usize = 64 * 1024 * 1024;

/// Persisted trust state for one stable application peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerTrustRecord {
    pub identity: IdentityMaterial,
    pub acknowledged: bool,
    pub acknowledged_unix: u64,
    pub method: VerificationMethod,
}

/// Stable peer-id → cryptographic-identity mapping.
#[derive(Clone, Debug, Default)]
pub struct PeerIdentityStore {
    by_peer: HashMap<Vec<u8>, PeerTrustRecord>,
}

impl PeerIdentityStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, peer_id: &[u8]) -> Option<&PeerTrustRecord> {
        self.by_peer.get(peer_id)
    }

    /// Compare the currently presented identity to the identity previously
    /// associated with this stable peer id.
    pub fn observe(&self, peer_id: &[u8], current: &IdentityMaterial) -> IdentityState {
        match self.by_peer.get(peer_id) {
            None => IdentityState::Unknown,
            Some(prev) => {
                let key_changed =
                    prev.identity.identity_key.to_bytes() != current.identity_key.to_bytes();
                let device_changed = prev.identity.device_id != current.device_id;
                if key_changed || device_changed {
                    let reason = match (key_changed, device_changed) {
                        (true, true) => IdentityChangeReason::Both,
                        (true, false) => IdentityChangeReason::IdentityKeyChanged,
                        (false, true) => IdentityChangeReason::DeviceIdChanged,
                        (false, false) => unreachable!(),
                    };
                    IdentityState::IdentityChanged {
                        previous: prev.identity.clone(),
                        current: current.clone(),
                        reason,
                    }
                } else if prev.acknowledged {
                    IdentityState::Verified
                } else {
                    IdentityState::Unknown
                }
            }
        }
    }

    /// Record first contact without silently overwriting an existing mapping.
    /// Call `observe` first; a changed mapping must require explicit user action.
    pub fn record_seen(
        &mut self,
        peer_id: &[u8],
        identity: IdentityMaterial,
    ) -> Result<(), PrimitiveError> {
        validate_peer_id(peer_id)?;
        validate_peer_identity(&identity)?;
        if let Some(existing) = self.by_peer.get(peer_id) {
            if existing.identity != identity {
                return Err(PrimitiveError::Internal);
            }
            return Ok(());
        }
        if self.by_peer.len() >= MAX_PEER_RECORDS {
            return Err(PrimitiveError::LimitExceeded);
        }
        self.by_peer.insert(
            peer_id.to_vec(),
            PeerTrustRecord {
                identity,
                acknowledged: false,
                acknowledged_unix: 0,
                method: VerificationMethod::None,
            },
        );
        Ok(())
    }

    /// Explicitly trust the presented identity for this stable peer id.
    pub fn acknowledge(
        &mut self,
        peer_id: &[u8],
        identity: IdentityMaterial,
        now_unix: u64,
        method: VerificationMethod,
    ) -> Result<(), PrimitiveError> {
        validate_peer_id(peer_id)?;
        validate_peer_identity(&identity)?;
        if self.by_peer.len() >= MAX_PEER_RECORDS && !self.by_peer.contains_key(peer_id) {
            return Err(PrimitiveError::LimitExceeded);
        }
        self.by_peer.insert(
            peer_id.to_vec(),
            PeerTrustRecord {
                identity,
                acknowledged: true,
                acknowledged_unix: now_unix,
                method,
            },
        );
        Ok(())
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = PEER_STORE_MAGIC.to_vec();
        out.extend_from_slice(&(self.by_peer.len() as u32).to_le_bytes());
        for (peer_id, rec) in &self.by_peer {
            debug_assert!(validate_peer_id(peer_id).is_ok());
            debug_assert!(validate_peer_identity(&rec.identity).is_ok());
            put_vec(&mut out, peer_id);
            out.extend_from_slice(&rec.identity.identity_key.to_bytes());
            put_vec(
                &mut out,
                rec.identity.device_id.as_deref().unwrap_or_default(),
            );
            out.push(u8::from(rec.acknowledged));
            out.extend_from_slice(&rec.acknowledged_unix.to_le_bytes());
            out.push(rec.method as u8);
        }
        debug_assert!(out.len() <= MAX_PEER_STORE_LEN);
        out
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, PrimitiveError> {
        if data.len() < 12 || data.len() > MAX_PEER_STORE_LEN || &data[..8] != PEER_STORE_MAGIC {
            return Err(PrimitiveError::InvalidLength);
        }
        let count = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        if count > MAX_PEER_RECORDS {
            return Err(PrimitiveError::LimitExceeded);
        }
        let mut i = 12usize;
        let mut by_peer = HashMap::with_capacity(count);
        for _ in 0..count {
            let peer_id = take_vec(data, &mut i, MAX_PEER_ID_LEN)?;
            validate_peer_id(&peer_id)?;
            let mut key = [0u8; 32];
            key.copy_from_slice(take(data, &mut i, 32)?);
            let device = take_vec(data, &mut i, MAX_DEVICE_ID_LEN)?;
            let acknowledged = match take(data, &mut i, 1)?[0] {
                0 => false,
                1 => true,
                _ => return Err(PrimitiveError::InvalidLength),
            };
            let acknowledged_unix =
                u64::from_le_bytes(take(data, &mut i, 8)?.try_into().unwrap());
            let method = match take(data, &mut i, 1)?[0] {
                0 => VerificationMethod::None,
                1 => VerificationMethod::SafetyNumber,
                _ => return Err(PrimitiveError::InvalidLength),
            };
            let identity = IdentityMaterial {
                identity_key: X25519Public::from_bytes(key)?,
                device_id: if device.is_empty() { None } else { Some(device) },
            };
            validate_peer_identity(&identity)?;
            if by_peer
                .insert(
                    peer_id,
                    PeerTrustRecord {
                        identity,
                        acknowledged,
                        acknowledged_unix,
                        method,
                    },
                )
                .is_some()
            {
                return Err(PrimitiveError::InvalidLength);
            }
        }
        if i != data.len() {
            return Err(PrimitiveError::InvalidLength);
        }
        Ok(Self { by_peer })
    }
}

fn validate_peer_id(peer_id: &[u8]) -> Result<(), PrimitiveError> {
    if peer_id.is_empty() || peer_id.len() > MAX_PEER_ID_LEN {
        return Err(PrimitiveError::InvalidLength);
    }
    Ok(())
}

fn validate_peer_identity(identity: &IdentityMaterial) -> Result<(), PrimitiveError> {
    validate_identity_material(identity)?;
    if identity
        .device_id
        .as_deref()
        .is_some_and(|device| device.len() > MAX_DEVICE_ID_LEN)
    {
        return Err(PrimitiveError::LimitExceeded);
    }
    Ok(())
}

fn put_vec(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn take<'a>(data: &'a [u8], i: &mut usize, len: usize) -> Result<&'a [u8], PrimitiveError> {
    let end = i.checked_add(len).ok_or(PrimitiveError::LimitExceeded)?;
    if end > data.len() {
        return Err(PrimitiveError::InvalidLength);
    }
    let out = &data[*i..end];
    *i = end;
    Ok(out)
}

fn take_vec(data: &[u8], i: &mut usize, max: usize) -> Result<Vec<u8>, PrimitiveError> {
    let len = u32::from_le_bytes(take(data, i, 4)?.try_into().unwrap()) as usize;
    if len > max {
        return Err(PrimitiveError::LimitExceeded);
    }
    Ok(take(data, i, len)?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::x25519::X25519Secret;

    fn identity(seed: u8, device: &[u8]) -> IdentityMaterial {
        let mut bytes = [seed; 32];
        bytes[31] = seed.wrapping_add(1);
        IdentityMaterial {
            identity_key: X25519Secret::from_bytes(bytes).public_key(),
            device_id: Some(device.to_vec()),
        }
    }

    #[test]
    fn stable_peer_detects_key_replacement() {
        let peer = b"account-42/device-1";
        let old = identity(3, b"dev-1");
        let new = identity(9, b"dev-1");
        let mut store = PeerIdentityStore::new();
        store.record_seen(peer, old.clone()).unwrap();
        store
            .acknowledge(peer, old, 1, VerificationMethod::SafetyNumber)
            .unwrap();
        assert!(matches!(
            store.observe(peer, &new),
            IdentityState::IdentityChanged {
                reason: IdentityChangeReason::IdentityKeyChanged,
                ..
            }
        ));
    }

    #[test]
    fn changed_unverified_first_seen_identity_is_not_silently_overwritten() {
        let peer = b"peer";
        let a = identity(1, b"d");
        let b = identity(2, b"d");
        let mut store = PeerIdentityStore::new();
        store.record_seen(peer, a).unwrap();
        assert!(store.record_seen(peer, b).is_err());
    }

    #[test]
    fn oversized_identity_device_is_rejected_before_mutation() {
        let peer = b"peer";
        let oversized = identity(3, &vec![7u8; MAX_DEVICE_ID_LEN + 1]);
        let mut store = PeerIdentityStore::new();
        assert!(store.record_seen(peer, oversized).is_err());
        assert!(store.get(peer).is_none());
    }

    #[test]
    fn roundtrip_preserves_peer_binding() {
        let peer = b"peer-7";
        let id = identity(7, b"device-x");
        let mut store = PeerIdentityStore::new();
        store
            .acknowledge(peer, id.clone(), 44, VerificationMethod::SafetyNumber)
            .unwrap();
        let restored = PeerIdentityStore::deserialize(&store.serialize()).unwrap();
        assert_eq!(restored.get(peer).unwrap().identity, id);
        assert_eq!(restored.observe(peer, &id), IdentityState::Verified);
    }

    #[test]
    fn parser_rejects_duplicate_peer_records() {
        let peer = b"dup";
        let id = identity(4, b"d");
        let mut one = PeerIdentityStore::new();
        one.record_seen(peer, id).unwrap();
        let blob = one.serialize();
        let record = blob[12..].to_vec();
        let mut dup = PEER_STORE_MAGIC.to_vec();
        dup.extend_from_slice(&2u32.to_le_bytes());
        dup.extend_from_slice(&record);
        dup.extend_from_slice(&record);
        assert!(PeerIdentityStore::deserialize(&dup).is_err());
    }
}
