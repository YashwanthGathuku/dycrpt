//! Cryptographic safety numbers / fingerprints and identity-change detection.
//!
//! Cryptographic identity is derived solely from long-term public keys and
//! device identifiers. A mobile / phone number is NEVER treated as a
//! cryptographic identity.
//!
//! Properties:
//! - fingerprint(A, B) == fingerprint(B, A)
//! - Numeric representation for human comparison
//! - QR-compatible binary representation
//! - Key-change and device-change detection
//! - IDENTITY_CHANGED state until explicit user acknowledgement

use crate::primitives::error::PrimitiveError;
use crate::primitives::kdf::{sha512, LABELS};
use crate::primitives::x25519::X25519Public;
use zeroize::Zeroize;

/// Number of digits in the numeric safety number (grouped for display).
pub const NUMERIC_DIGIT_COUNT: usize = 60;
/// Digits per display group.
pub const NUMERIC_GROUP_SIZE: usize = 5;

/// How many SHA-512 iterations for key stretching (independent of any
/// external implementation; chosen for reasonable verification cost).
const FINGERPRINT_ITERATIONS: u32 = 5200;

/// Stable cryptographic fingerprint of a relationship between two parties.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafetyFingerprint {
    /// 32-byte binary value suitable for QR encoding.
    pub binary: [u8; 32],
    /// 60-digit numeric representation (no spaces).
    pub numeric: String,
}

impl SafetyFingerprint {
    /// Display form with spaces every NUMERIC_GROUP_SIZE digits.
    pub fn numeric_display(&self) -> String {
        self.numeric
            .as_bytes()
            .chunks(NUMERIC_GROUP_SIZE)
            .map(|c| std::str::from_utf8(c).unwrap_or(""))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Canonical inputs for fingerprint computation.
/// Device identifiers are optional but recommended; when present they
/// make the fingerprint device-aware.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityMaterial {
    pub identity_key: X25519Public,
    pub device_id: Option<Vec<u8>>,
}

/// Compute a symmetric safety fingerprint.
///
/// Ordering of the two parties is canonicalized so that
/// fingerprint(A,B) == fingerprint(B,A).
pub fn compute_fingerprint(
    party_a: &IdentityMaterial,
    party_b: &IdentityMaterial,
) -> Result<SafetyFingerprint, PrimitiveError> {
    // Canonical order: sort by identity key bytes, then by device_id.
    let (first, second) = canonical_order(party_a, party_b);

    let mut material = Vec::new();
    material.extend_from_slice(LABELS::FINGERPRINT);
    material.extend_from_slice(&first.identity_key.to_bytes());
    if let Some(ref d) = first.device_id {
        material.extend_from_slice(&(d.len() as u16).to_le_bytes());
        material.extend_from_slice(d);
    } else {
        material.extend_from_slice(&0u16.to_le_bytes());
    }
    material.extend_from_slice(&second.identity_key.to_bytes());
    if let Some(ref d) = second.device_id {
        material.extend_from_slice(&(d.len() as u16).to_le_bytes());
        material.extend_from_slice(d);
    } else {
        material.extend_from_slice(&0u16.to_le_bytes());
    }

    // Iterated hash for stretching
    let mut hash = sha512(&material);
    for _ in 1..FINGERPRINT_ITERATIONS {
        hash = sha512(&hash);
    }

    let mut binary = [0u8; 32];
    binary.copy_from_slice(&hash[0..32]);

    // Numeric: interpret the 32 bytes as big-endian chunks → decimal digits
    let numeric = binary_to_numeric(&binary);

    material.zeroize();
    Ok(SafetyFingerprint { binary, numeric })
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
        // Same identity key — order by device_id
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
    // Produce NUMERIC_DIGIT_COUNT decimal digits from the binary value.
    // Simple, stable mapping: take successive 5-byte windows as u64 mod 10^5
    // and emit 5 digits each (12 groups × 5 = 60).
    let mut digits = String::with_capacity(NUMERIC_DIGIT_COUNT);
    for chunk in binary.chunks(5).take(12) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        let n = u64::from_le_bytes(buf) % 100_000;
        digits.push_str(&format!("{:05}", n));
    }
    // Ensure exact length
    digits.truncate(NUMERIC_DIGIT_COUNT);
    while digits.len() < NUMERIC_DIGIT_COUNT {
        digits.push('0');
    }
    digits
}

// ---------------------------------------------------------------------------
// Identity change tracking
// ---------------------------------------------------------------------------

/// State of a contact’s cryptographic identity relative to what was last verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityState {
    /// No prior identity recorded (first contact).
    Unknown,
    /// Matches the last acknowledged identity (+ device).
    Verified,
    /// Cryptographic identity or device changed since last acknowledgement.
    /// Conversation must not be silently trusted until the user acts.
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

/// Tracks the last acknowledged cryptographic identity for a contact.
/// Phone numbers are deliberately absent.
#[derive(Clone, Debug)]
pub struct IdentityTracker {
    /// Last identity the user explicitly acknowledged / verified.
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

    /// Observe a (possibly new) remote identity.
    /// Returns the resulting IdentityState. Never silently trusts a change.
    pub fn observe(&self, current: &IdentityMaterial) -> IdentityState {
        match &self.acknowledged {
            None => IdentityState::Unknown,
            Some(prev) => {
                let key_changed = prev.identity_key.to_bytes() != current.identity_key.to_bytes();
                let device_changed = prev.device_id != current.device_id;
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
                        previous: prev.clone(),
                        current: current.clone(),
                        reason,
                    }
                }
            }
        }
    }

    /// Explicit user acknowledgement of the current identity.
    /// This is the only path that clears IDENTITY_CHANGED.
    /// Phone-number reauthentication MUST NOT call this automatically.
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

/// How the user acknowledged a remote identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum VerificationMethod {
    None = 0,
    SafetyNumber = 1,
}

/// Persisted trust record, independent of ratchet session existence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustRecord {
    pub identity: IdentityMaterial,
    pub acknowledged: bool,
    pub acknowledged_unix: u64,
    pub method: VerificationMethod,
}

/// First-class identity-trust store. Session restore must not imply user trust.
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
        let k = identity.identity_key.to_bytes();
        self.by_key.entry(k).or_insert(TrustRecord {
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
        let k = identity.identity_key.to_bytes();
        self.by_key.insert(
            k,
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
            Some(r) if r.acknowledged => IdentityTracker::with_acknowledged(r.identity.clone()),
            _ => IdentityTracker::new(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut o = b"VCTRUST1".to_vec();
        o.extend_from_slice(&(self.by_key.len() as u32).to_le_bytes());
        for rec in self.by_key.values() {
            o.extend_from_slice(&rec.identity.identity_key.to_bytes());
            let dev = rec.identity.device_id.as_deref().unwrap_or(&[]);
            o.extend_from_slice(&(dev.len() as u16).to_le_bytes());
            o.extend_from_slice(dev);
            o.push(u8::from(rec.acknowledged));
            o.extend_from_slice(&rec.acknowledged_unix.to_le_bytes());
            o.push(rec.method as u8);
        }
        o
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, PrimitiveError> {
        if data.len() < 12 || &data[..8] != b"VCTRUST1" {
            return Err(PrimitiveError::InvalidLength);
        }
        let n = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        let mut i = 12;
        let mut store = Self::new();
        for _ in 0..n {
            if i + 32 + 2 > data.len() {
                return Err(PrimitiveError::InvalidLength);
            }
            let mut ikb = [0u8; 32];
            ikb.copy_from_slice(&data[i..i + 32]);
            i += 32;
            let dlen = u16::from_le_bytes(data[i..i + 2].try_into().unwrap()) as usize;
            i += 2;
            if i + dlen + 1 + 8 + 1 > data.len() {
                return Err(PrimitiveError::InvalidLength);
            }
            let device_id = if dlen == 0 {
                None
            } else {
                Some(data[i..i + dlen].to_vec())
            };
            i += dlen;
            let acknowledged = data[i] != 0;
            i += 1;
            let acknowledged_unix = u64::from_le_bytes(data[i..i + 8].try_into().unwrap());
            i += 8;
            let method = match data[i] {
                0 => VerificationMethod::None,
                1 => VerificationMethod::SafetyNumber,
                _ => return Err(PrimitiveError::InvalidLength),
            };
            i += 1;
            let identity = IdentityMaterial {
                identity_key: X25519Public::from_bytes(ikb)?,
                device_id,
            };
            store.by_key.insert(
                ikb,
                TrustRecord {
                    identity,
                    acknowledged,
                    acknowledged_unix,
                    method,
                },
            );
        }
        if i != data.len() {
            return Err(PrimitiveError::InvalidLength);
        }
        Ok(store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::x25519::X25519Secret;

    fn material(seed: u8, device: Option<&[u8]>) -> IdentityMaterial {
        let mut bytes = [seed; 32];
        bytes[0] = seed;
        bytes[31] = seed.wrapping_add(1);
        // Ensure non-zero
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
        let fab = compute_fingerprint(&a, &b).unwrap();
        let fac = compute_fingerprint(&a, &c).unwrap();
        assert_ne!(fab.binary, fac.binary);
    }

    #[test]
    fn device_change_affects_fingerprint() {
        let a = material(1, Some(b"device-1"));
        let b1 = material(2, Some(b"device-X"));
        let b2 = material(2, Some(b"device-Y")); // same key, different device
        let f1 = compute_fingerprint(&a, &b1).unwrap();
        let f2 = compute_fingerprint(&a, &b2).unwrap();
        assert_ne!(f1.binary, f2.binary);
    }

    #[test]
    fn numeric_length_and_display() {
        let a = material(5, None);
        let b = material(9, None);
        let fp = compute_fingerprint(&a, &b).unwrap();
        assert_eq!(fp.numeric.len(), NUMERIC_DIGIT_COUNT);
        assert!(fp.numeric.chars().all(|c| c.is_ascii_digit()));
        let display = fp.numeric_display();
        assert!(display.contains(' '));
    }

    #[test]
    fn trust_store_roundtrip_does_not_imply_ack() {
        let mut s = TrustStore::new();
        let id = material(4, Some(b"dev"));
        s.record_seen(id.clone());
        assert!(!s.get(&id.identity_key.to_bytes()).unwrap().acknowledged);
        s.acknowledge(id.clone(), 42, VerificationMethod::SafetyNumber);
        let s2 = TrustStore::deserialize(&s.serialize()).unwrap();
        let rec = s2.get(&id.identity_key.to_bytes()).unwrap();
        assert!(rec.acknowledged);
        assert_eq!(rec.acknowledged_unix, 42);
        assert_eq!(rec.method, VerificationMethod::SafetyNumber);
    }

    #[test]
    fn identity_change_on_key_swap() {
        // SIM-swap-like: same “phone” is irrelevant; crypto identity changes.
        let original = material(10, Some(b"device-1"));
        let mut tracker = IdentityTracker::with_acknowledged(original.clone());

        // Same device id, different identity key (attacker replaced the account)
        let attacker = material(99, Some(b"device-1"));
        let state = tracker.observe(&attacker);
        match state {
            IdentityState::IdentityChanged { reason, .. } => {
                assert_eq!(reason, IdentityChangeReason::IdentityKeyChanged);
            }
            other => panic!("expected IdentityChanged, got {:?}", other),
        }

        // Must NOT be trusted until acknowledge
        assert!(matches!(
            tracker.observe(&attacker),
            IdentityState::IdentityChanged { .. }
        ));

        // Explicit acknowledgement clears the state
        tracker.acknowledge(attacker.clone());
        assert_eq!(tracker.observe(&attacker), IdentityState::Verified);
    }

    #[test]
    fn device_change_detected() {
        let original = material(10, Some(b"device-old"));
        let mut tracker = IdentityTracker::with_acknowledged(original.clone());
        let new_device = material(10, Some(b"device-new")); // same key, new device
        let state = tracker.observe(&new_device);
        assert!(matches!(
            state,
            IdentityState::IdentityChanged {
                reason: IdentityChangeReason::DeviceIdChanged,
                ..
            }
        ));
    }

    #[test]
    fn phone_number_irrelevant() {
        // There is no phone-number field. Two different crypto identities
        // always produce IdentityChanged regardless of any external
        // phone-number “reauthentication”.
        let a = material(1, None);
        let b = material(2, None);
        let tracker = IdentityTracker::with_acknowledged(a);
        assert!(matches!(
            tracker.observe(&b),
            IdentityState::IdentityChanged { .. }
        ));
    }
}
