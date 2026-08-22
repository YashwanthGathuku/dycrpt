//! Cryptographic safety numbers / fingerprints and identity-change detection.
//!
//! Cryptographic identity is derived solely from long-term public keys and
//! device identifiers. A mobile / phone number is never treated as proof of
//! cryptographic identity.

use crate::primitives::error::PrimitiveError;
use crate::primitives::kdf::{sha512, LABELS};
use crate::primitives::x25519::X25519Public;
use zeroize::Zeroize;

pub const NUMERIC_DIGIT_COUNT: usize = 60;
pub const NUMERIC_GROUP_SIZE: usize = 5;
pub const MAX_IDENTITY_DEVICE_ID_LEN: usize = 4096;
const MAX_TRUST_RECORDS: usize = 100_000;
const MAX_TRUST_STATE_LEN: usize = 16 * 1024 * 1024;
const FINGERPRINT_ITERATIONS: u32 = 5200;
const NUMERIC_V2_LABEL: &[u8] = b"VoiceChat/Fingerprint/v2/Numeric60";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafetyFingerprint {
    pub binary: [u8; 32],
    pub numeric: String,
}

impl SafetyFingerprint {
    pub fn numeric_display(&self) -> String {
        self.numeric
            .as_bytes()
            .chunks(NUMERIC_GROUP_SIZE)
            .map(|c| std::str::from_utf8(c).unwrap_or(""))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityMaterial {
    pub identity_key: X25519Public,
    pub device_id: Option<Vec<u8>>,
}

pub fn validate_identity_material(identity: &IdentityMaterial) -> Result<(), PrimitiveError> {
    if identity
        .device_id
        .as_deref()
        .is_some_and(|device| device.len() > MAX_IDENTITY_DEVICE_ID_LEN)
    {
        return Err(PrimitiveError::LimitExceeded);
    }
    Ok(())
}

pub fn compute_fingerprint(
    party_a: &IdentityMaterial,
    party_b: &IdentityMaterial,
) -> Result<SafetyFingerprint, PrimitiveError> {
    validate_identity_material(party_a)?;
    validate_identity_material(party_b)?;
    let (first, second) = canonical_order(party_a, party_b);

    let mut material = Vec::new();
    material.extend_from_slice(LABELS::FINGERPRINT);
    append_identity_material(&mut material, first);
    append_identity_material(&mut material, second);

    let mut hash = sha512(&material);
    for _ in 1..FINGERPRINT_ITERATIONS {
        hash = sha512(&hash);
    }
    let mut binary = [0u8; 32];
    binary.copy_from_slice(&hash[..32]);
    let numeric = binary_to_numeric(&binary);
    material.zeroize();
    hash.zeroize();
    Ok(SafetyFingerprint { binary, numeric })
}

fn append_identity_material(out: &mut Vec<u8>, identity: &IdentityMaterial) {
    out.extend_from_slice(&identity.identity_key.to_bytes());
    match identity.device_id.as_deref() {
        Some(device) => {
            // Input was validated to <= 4096, so this conversion is exact.
            out.extend_from_slice(&(device.len() as u16).to_le_bytes());
            out.extend_from_slice(device);
        }
        None => out.extend_from_slice(&0u16.to_le_bytes()),
    }
}

fn canonical_order<'a>(
    a: &'a IdentityMaterial,
    b: &'a IdentityMaterial,
) -> (&'a IdentityMaterial, &'a IdentityMaterial) {
    let a_bytes = a.identity_key.to_bytes();
    let b_bytes = b.identity_key.to_bytes();
    if a_bytes < b_bytes {
        (a, b)
    } else if b_bytes < a_bytes {
        (b, a)
    } else {
        let a_dev = a.device_id.as_deref().unwrap_or(&[]);
        let b_dev = b.device_id.as_deref().unwrap_or(&[]);
        if a_dev <= b_dev {
            (a, b)
        } else {
            (b, a)
        }
    }
}

fn binary_to_numeric(binary: &[u8; 32]) -> String {
    let mut input = Vec::with_capacity(NUMERIC_V2_LABEL.len() + binary.len());
    input.extend_from_slice(NUMERIC_V2_LABEL);
    input.extend_from_slice(binary);
    let mut expanded = sha512(&input);
    input.zeroize();

    let mut digits = String::with_capacity(NUMERIC_DIGIT_COUNT);
    for chunk in expanded[..60].chunks_exact(5) {
        let mut buf = [0u8; 8];
        buf[..5].copy_from_slice(chunk);
        let n = u64::from_le_bytes(buf) % 100_000;
        digits.push_str(&format!("{n:05}"));
        buf.zeroize();
    }
    expanded.zeroize();
    debug_assert_eq!(digits.len(), NUMERIC_DIGIT_COUNT);
    digits
}

// ---------------------------------------------------------------------------
// Identity change tracking
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityState {
    Unknown,
    Verified,
    IdentityChanged {
        previous: IdentityMaterial,
        current: IdentityMaterial,
        reason: IdentityChangeReason,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityChangeReason {
    IdentityKeyChanged,
    DeviceIdChanged,
    Both,
}

#[derive(Clone, Debug)]
pub struct IdentityTracker {
    acknowledged: Option<IdentityMaterial>,
}

impl IdentityTracker {
    pub fn new() -> Self {
        Self { acknowledged: None }
    }

    pub fn with_acknowledged(id: IdentityMaterial) -> Self {
        Self {
            acknowledged: Some(id),
        }
    }

    pub fn observe(&self, current: &IdentityMaterial) -> IdentityState {
        match &self.acknowledged {
            None => IdentityState::Unknown,
            Some(previous) => {
                let key_changed =
                    previous.identity_key.to_bytes() != current.identity_key.to_bytes();
                let device_changed = previous.device_id != current.device_id;
                if !key_changed && !device_changed {
                    IdentityState::Verified
                } else {
                    let reason = match (key_changed, device_changed) {
                        (true, true) => IdentityChangeReason::Both,
                        (true, false) => IdentityChangeReason::IdentityKeyChanged,
                        (false, true) => IdentityChangeReason::DeviceIdChanged,
                        (false, false) => unreachable!(),
                    };
                    IdentityState::IdentityChanged {
                        previous: previous.clone(),
                        current: current.clone(),
                        reason,
                    }
                }
            }
        }
    }

    pub fn acknowledge(&mut self, current: IdentityMaterial) {
        self.acknowledged = Some(current);
    }

    pub fn acknowledged(&self) -> Option<&IdentityMaterial> {
        self.acknowledged.as_ref()
    }
}

impl Default for IdentityTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum VerificationMethod {
    None = 0,
    SafetyNumber = 1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustRecord {
    pub identity: IdentityMaterial,
    pub acknowledged: bool,
    pub acknowledged_unix: u64,
    pub method: VerificationMethod,
}

#[derive(Clone, Debug, Default)]
pub struct TrustStore {
    by_key: std::collections::HashMap<[u8; 32], TrustRecord>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, identity_key: &[u8; 32]) -> Option<&TrustRecord> {
        self.by_key.get(identity_key)
    }

    pub fn record_seen(&mut self, identity: IdentityMaterial) {
        let key = identity.identity_key.to_bytes();
        self.by_key.entry(key).or_insert(TrustRecord {
            identity,
            acknowledged: false,
            acknowledged_unix: 0,
            method: VerificationMethod::None,
        });
    }

    pub fn acknowledge(
        &mut self,
        identity: IdentityMaterial,
        now_unix: u64,
        method: VerificationMethod,
    ) {
        let key = identity.identity_key.to_bytes();
        self.by_key.insert(
            key,
            TrustRecord {
                identity,
                acknowledged: true,
                acknowledged_unix: now_unix,
                method,
            },
        );
    }

    pub fn tracker_for(&self, identity_key: &X25519Public) -> IdentityTracker {
        match self.by_key.get(&identity_key.to_bytes()) {
            Some(record) if record.acknowledged => {
                IdentityTracker::with_acknowledged(record.identity.clone())
            }
            _ => IdentityTracker::new(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = b"VCTRUST1".to_vec();
        out.extend_from_slice(&(self.by_key.len() as u32).to_le_bytes());
        for record in self.by_key.values() {
            out.extend_from_slice(&record.identity.identity_key.to_bytes());
            let device = record.identity.device_id.as_deref().unwrap_or(&[]);
            // Engine-facing paths validate identity material before inserting.
            debug_assert!(device.len() <= MAX_IDENTITY_DEVICE_ID_LEN);
            out.extend_from_slice(&(device.len() as u16).to_le_bytes());
            out.extend_from_slice(device);
            out.push(u8::from(record.acknowledged));
            out.extend_from_slice(&record.acknowledged_unix.to_le_bytes());
            out.push(record.method as u8);
        }
        out
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, PrimitiveError> {
        if data.len() < 12 || data.len() > MAX_TRUST_STATE_LEN || &data[..8] != b"VCTRUST1" {
            return Err(PrimitiveError::InvalidLength);
        }
        let count = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        if count > MAX_TRUST_RECORDS {
            return Err(PrimitiveError::LimitExceeded);
        }
        let mut i = 12usize;
        let mut store = Self::new();
        for _ in 0..count {
            let mut key = [0u8; 32];
            key.copy_from_slice(take(data, &mut i, 32)?);
            let device_len = u16::from_le_bytes(take(data, &mut i, 2)?.try_into().unwrap()) as usize;
            if device_len > MAX_IDENTITY_DEVICE_ID_LEN {
                return Err(PrimitiveError::LimitExceeded);
            }
            let device = take(data, &mut i, device_len)?;
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
                device_id: if device.is_empty() {
                    None
                } else {
                    Some(device.to_vec())
                },
            };
            validate_identity_material(&identity)?;
            if store
                .by_key
                .insert(
                    key,
                    TrustRecord {
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
        Ok(store)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::x25519::X25519Secret;

    fn material(seed: u8, device: Option<&[u8]>) -> IdentityMaterial {
        let mut bytes = [seed; 32];
        bytes[31] = seed.wrapping_add(1);
        if bytes == [0u8; 32] {
            bytes[0] = 1;
        }
        let sk = X25519Secret::from_bytes(bytes);
        IdentityMaterial {
            identity_key: sk.public_key(),
            device_id: device.map(|d| d.to_vec()),
        }
    }

    #[test]
    fn fingerprint_is_symmetric() {
        let a = material(1, Some(b"dev-a"));
        let b = material(2, Some(b"dev-b"));
        let fab = compute_fingerprint(&a, &b).unwrap();
        let fba = compute_fingerprint(&b, &a).unwrap();
        assert_eq!(fab.binary, fba.binary);
        assert_eq!(fab.numeric, fba.numeric);
    }

    #[test]
    fn different_identities_different_fingerprint() {
        let a = material(1, None);
        let b = material(2, None);
        let c = material(3, None);
        assert_ne!(
            compute_fingerprint(&a, &b).unwrap().binary,
            compute_fingerprint(&a, &c).unwrap().binary
        );
    }

    #[test]
    fn device_change_affects_fingerprint() {
        let a = material(1, Some(b"device-1"));
        let b1 = material(2, Some(b"device-X"));
        let b2 = material(2, Some(b"device-Y"));
        assert_ne!(
            compute_fingerprint(&a, &b1).unwrap().binary,
            compute_fingerprint(&a, &b2).unwrap().binary
        );
    }

    #[test]
    fn numeric_length_and_display() {
        let fp = compute_fingerprint(&material(5, None), &material(9, None)).unwrap();
        assert_eq!(fp.numeric.len(), NUMERIC_DIGIT_COUNT);
        assert!(fp.numeric.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(fp.numeric_display().split(' ').count(), 12);
    }

    #[test]
    fn numeric_tail_is_data_bearing_not_zero_padding() {
        let a = material(5, None);
        let f1 = compute_fingerprint(&a, &material(9, None)).unwrap();
        let f2 = compute_fingerprint(&a, &material(11, None)).unwrap();
        assert_ne!(&f1.numeric[35..], "0000000000000000000000000");
        assert_ne!(&f1.numeric[35..], &f2.numeric[35..]);
    }

    #[test]
    fn oversized_device_identifier_is_rejected() {
        let a = material(1, Some(&vec![7u8; MAX_IDENTITY_DEVICE_ID_LEN + 1]));
        let b = material(2, None);
        assert!(compute_fingerprint(&a, &b).is_err());
    }

    #[test]
    fn trust_store_roundtrip_does_not_imply_ack() {
        let mut store = TrustStore::new();
        let id = material(4, Some(b"dev"));
        store.record_seen(id.clone());
        assert!(!store.get(&id.identity_key.to_bytes()).unwrap().acknowledged);
        store.acknowledge(id.clone(), 42, VerificationMethod::SafetyNumber);
        let restored = TrustStore::deserialize(&store.serialize()).unwrap();
        let record = restored.get(&id.identity_key.to_bytes()).unwrap();
        assert!(record.acknowledged);
        assert_eq!(record.acknowledged_unix, 42);
        assert_eq!(record.method, VerificationMethod::SafetyNumber);
    }

    #[test]
    fn identity_change_on_key_swap() {
        let original = material(10, Some(b"device-1"));
        let mut tracker = IdentityTracker::with_acknowledged(original);
        let attacker = material(99, Some(b"device-1"));
        assert!(matches!(
            tracker.observe(&attacker),
            IdentityState::IdentityChanged {
                reason: IdentityChangeReason::IdentityKeyChanged,
                ..
            }
        ));
        tracker.acknowledge(attacker.clone());
        assert_eq!(tracker.observe(&attacker), IdentityState::Verified);
    }

    #[test]
    fn device_change_detected() {
        let tracker = IdentityTracker::with_acknowledged(material(10, Some(b"device-old")));
        let new_device = material(10, Some(b"device-new"));
        assert!(matches!(
            tracker.observe(&new_device),
            IdentityState::IdentityChanged {
                reason: IdentityChangeReason::DeviceIdChanged,
                ..
            }
        ));
    }

    #[test]
    fn phone_number_irrelevant() {
        let tracker = IdentityTracker::with_acknowledged(material(1, None));
        assert!(matches!(
            tracker.observe(&material(2, None)),
            IdentityState::IdentityChanged { .. }
        ));
    }

    #[test]
    fn trust_deserialize_rejects_noncanonical_boolean() {
        let mut store = TrustStore::new();
        store.record_seen(material(4, Some(b"d")));
        let mut blob = store.serialize();
        blob[47] = 2;
        assert!(TrustStore::deserialize(&blob).is_err());
    }

    #[test]
    fn trust_deserialize_rejects_duplicate_identity_keys() {
        let mut store = TrustStore::new();
        store.record_seen(material(4, Some(b"d")));
        let one = store.serialize();
        let record = &one[12..];
        let mut blob = b"VCTRUST1".to_vec();
        blob.extend_from_slice(&2u32.to_le_bytes());
        blob.extend_from_slice(record);
        blob.extend_from_slice(record);
        assert!(TrustStore::deserialize(&blob).is_err());
    }
}
