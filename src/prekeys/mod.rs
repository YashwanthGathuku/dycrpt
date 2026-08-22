//! Explicit prekey models for PQXDH.
//!
//! One-time prekeys are consumed exactly once. Signed EC and last-resort PQ
//! prekeys are rotated by policy, while a small bounded set of previous private
//! keys may be retained temporarily so delayed initiation messages can still be
//! processed after the public bundle has rotated.

use std::collections::HashMap;

use crate::primitives::encoding::{encode_ec, encode_kem};
use crate::primitives::error::PrimitiveError;
use crate::primitives::kem::{MlKemPublic, MlKemSecret};
use crate::primitives::x25519::{X25519Public, X25519Secret};
use crate::primitives::xeddsa;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Unique identifier for an elliptic-curve prekey.
pub type EcPrekeyId = u32;
/// Unique identifier for a PQ KEM prekey.
pub type PqPrekeyId = u32;

/// Hard parser/storage bound. Normal deployments should keep far fewer keys.
const MAX_STORED_PREKEYS: usize = 100_000;
/// Hard bound on previous signed/last-resort keys retained for delayed messages.
pub const MAX_RETAINED_ROTATED_PREKEYS: usize = 8;

/// Long-term identity key pair (X25519 + XEd25519).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdentityKeyPair {
    pub secret: X25519Secret,
}

impl IdentityKeyPair {
    pub fn generate() -> Result<Self, PrimitiveError> {
        Ok(Self {
            secret: X25519Secret::generate()?,
        })
    }

    pub fn public(&self) -> X25519Public {
        self.secret.public_key()
    }

    /// XEd25519 signature over `message`.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64], PrimitiveError> {
        xeddsa::sign(&self.secret, message)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = b"VCIDENT1".to_vec();
        out.extend_from_slice(&self.secret.to_bytes());
        out
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, PrimitiveError> {
        if data.len() != 8 + 32 || &data[0..8] != b"VCIDENT1" {
            return Err(PrimitiveError::InvalidLength);
        }
        let mut sec = [0u8; 32];
        sec.copy_from_slice(&data[8..40]);
        Ok(Self {
            secret: X25519Secret::from_bytes(sec),
        })
    }
}

/// Signed prekey (medium-term). Signed by the identity key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SignedPrekey {
    pub id: EcPrekeyId,
    pub secret: X25519Secret,
    /// XEd25519 signature over EncodeEC(public).
    pub signature: [u8; 64],
}

impl SignedPrekey {
    pub fn generate(identity: &IdentityKeyPair, id: EcPrekeyId) -> Result<Self, PrimitiveError> {
        let secret = X25519Secret::generate()?;
        let signature = identity.sign(&encode_ec(&secret.public_key()))?;
        Ok(Self {
            id,
            secret,
            signature,
        })
    }

    pub fn public_key(&self) -> X25519Public {
        self.secret.public_key()
    }
}

/// One-time elliptic-curve prekey. Must be consumed exactly once.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OneTimeEcPrekey {
    pub id: EcPrekeyId,
    pub secret: X25519Secret,
}

/// Last-resort (signed) PQ KEM prekey.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct LastResortPqPrekey {
    pub id: PqPrekeyId,
    pub secret: MlKemSecret,
    pub signature: [u8; 64],
}

impl LastResortPqPrekey {
    pub fn generate(identity: &IdentityKeyPair, id: PqPrekeyId) -> Result<Self, PrimitiveError> {
        let (secret, public) = MlKemSecret::generate()?;
        let signature = identity.sign(&encode_kem(&public))?;
        Ok(Self {
            id,
            secret,
            signature,
        })
    }

    pub fn public(&self) -> Result<MlKemPublic, PrimitiveError> {
        self.secret.public_key()
    }
}

/// One-time PQ KEM prekey. Consumed exactly once.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OneTimePqPrekey {
    pub id: PqPrekeyId,
    pub secret: MlKemSecret,
    pub signature: [u8; 64],
}

impl OneTimePqPrekey {
    pub fn generate(identity: &IdentityKeyPair, id: PqPrekeyId) -> Result<Self, PrimitiveError> {
        let (secret, public) = MlKemSecret::generate()?;
        let signature = identity.sign(&encode_kem(&public))?;
        Ok(Self {
            id,
            secret,
            signature,
        })
    }

    pub fn public(&self) -> Result<MlKemPublic, PrimitiveError> {
        self.secret.public_key()
    }
}

/// Public view of a prekey bundle published by Bob.
#[derive(Clone)]
pub struct PublicPrekeyBundle {
    pub identity_key: X25519Public,
    pub signed_prekey_id: EcPrekeyId,
    pub signed_prekey: X25519Public,
    pub signed_prekey_sig: [u8; 64],
    pub one_time_ec: Option<(EcPrekeyId, X25519Public)>,
    pub pq_prekey_id: PqPrekeyId,
    pub pq_prekey_public: Vec<u8>,
    pub pq_prekey_sig: [u8; 64],
    pub is_pq_one_time: bool,
}

impl PublicPrekeyBundle {
    /// Validate signatures and structural invariants. Fail-closed.
    pub fn validate(&self) -> Result<(), PrimitiveError> {
        if self.identity_key.to_bytes() == [0u8; 32] {
            return Err(PrimitiveError::InvalidPublicKey);
        }
        if self.signed_prekey.to_bytes() == [0u8; 32] {
            return Err(PrimitiveError::InvalidPublicKey);
        }

        xeddsa::verify(
            &self.identity_key,
            &encode_ec(&self.signed_prekey),
            &self.signed_prekey_sig,
        )?;

        let pq = MlKemPublic::from_bytes(&self.pq_prekey_public)?;
        xeddsa::verify(&self.identity_key, &encode_kem(&pq), &self.pq_prekey_sig)?;

        if let Some((_, opk)) = &self.one_time_ec {
            if opk.to_bytes() == [0u8; 32] {
                return Err(PrimitiveError::InvalidPublicKey);
            }
        }
        Ok(())
    }

    /// Public-only encoding for the network / FFI. No secrets.
    pub fn encode(&self) -> Vec<u8> {
        let mut o = b"VCBUNDL1".to_vec();
        o.extend_from_slice(&self.identity_key.to_bytes());
        o.extend_from_slice(&self.signed_prekey_id.to_le_bytes());
        o.extend_from_slice(&self.signed_prekey.to_bytes());
        o.extend_from_slice(&self.signed_prekey_sig);
        match &self.one_time_ec {
            None => o.push(0),
            Some((id, pk)) => {
                o.push(1);
                o.extend_from_slice(&id.to_le_bytes());
                o.extend_from_slice(&pk.to_bytes());
            }
        }
        o.extend_from_slice(&self.pq_prekey_id.to_le_bytes());
        let pq_len = self.pq_prekey_public.len() as u16;
        o.extend_from_slice(&pq_len.to_le_bytes());
        o.extend_from_slice(&self.pq_prekey_public);
        o.extend_from_slice(&self.pq_prekey_sig);
        o.push(u8::from(self.is_pq_one_time));
        o
    }

    /// Decode and validate a public bundle.
    pub fn decode(data: &[u8]) -> Result<Self, PrimitiveError> {
        if data.len() < 8 + 32 + 4 + 32 + 64 + 1 + 4 + 2 + 64 + 1 {
            return Err(PrimitiveError::InvalidLength);
        }
        if &data[0..8] != b"VCBUNDL1" {
            return Err(PrimitiveError::InvalidLength);
        }
        let mut i = 8;
        let take = |i: &mut usize, n: usize| -> Result<&[u8], PrimitiveError> {
            if *i + n > data.len() {
                return Err(PrimitiveError::InvalidLength);
            }
            let s = &data[*i..*i + n];
            *i += n;
            Ok(s)
        };
        let mut ik = [0u8; 32];
        ik.copy_from_slice(take(&mut i, 32)?);
        let spk_id = u32::from_le_bytes(take(&mut i, 4)?.try_into().unwrap());
        let mut spk = [0u8; 32];
        spk.copy_from_slice(take(&mut i, 32)?);
        let mut spk_sig = [0u8; 64];
        spk_sig.copy_from_slice(take(&mut i, 64)?);
        let has_opk = take(&mut i, 1)?[0];
        let one_time_ec = match has_opk {
            0 => None,
            1 => {
                let id = u32::from_le_bytes(take(&mut i, 4)?.try_into().unwrap());
                let mut pk = [0u8; 32];
                pk.copy_from_slice(take(&mut i, 32)?);
                Some((id, X25519Public::from_bytes(pk)?))
            }
            _ => return Err(PrimitiveError::InvalidLength),
        };
        let pq_id = u32::from_le_bytes(take(&mut i, 4)?.try_into().unwrap());
        let pq_len = u16::from_le_bytes(take(&mut i, 2)?.try_into().unwrap()) as usize;
        let pq = take(&mut i, pq_len)?.to_vec();
        let mut pq_sig = [0u8; 64];
        pq_sig.copy_from_slice(take(&mut i, 64)?);
        let is_one = match take(&mut i, 1)?[0] {
            0 => false,
            1 => true,
            _ => return Err(PrimitiveError::InvalidLength),
        };
        if i != data.len() {
            return Err(PrimitiveError::InvalidLength);
        }
        let bundle = Self {
            identity_key: X25519Public::from_bytes(ik)?,
            signed_prekey_id: spk_id,
            signed_prekey: X25519Public::from_bytes(spk)?,
            signed_prekey_sig: spk_sig,
            one_time_ec,
            pq_prekey_id: pq_id,
            pq_prekey_public: pq,
            pq_prekey_sig: pq_sig,
            is_pq_one_time: is_one,
        };
        bundle.validate()?;
        Ok(bundle)
    }
}

/// Public inventory item that a server may allocate exactly once.
#[derive(Clone)]
pub struct PublicEcOneTimePrekey {
    pub id: EcPrekeyId,
    pub public: X25519Public,
}

/// Public inventory item that a server may allocate exactly once.
#[derive(Clone)]
pub struct PublicPqOneTimePrekey {
    pub id: PqPrekeyId,
    pub public: Vec<u8>,
    pub signature: [u8; 64],
}

/// Device-local prekey store with atomic one-time consumption and bounded
/// retention of recently rotated reusable prekeys.
pub struct PrekeyStore {
    pub signed: SignedPrekey,
    pub last_resort_pq: LastResortPqPrekey,
    previous_signed: HashMap<EcPrekeyId, SignedPrekey>,
    previous_last_resort_pq: HashMap<PqPrekeyId, LastResortPqPrekey>,
    one_time_ec: HashMap<EcPrekeyId, OneTimeEcPrekey>,
    one_time_pq: HashMap<PqPrekeyId, OneTimePqPrekey>,
    /// Shared EC id allocator. Signed-prekey rotations and EC OPKs both consume
    /// ids from it, so ids are never reused by this device.
    next_ec: EcPrekeyId,
    /// Shared PQ id allocator. LR-PQ rotations and PQ OPKs both consume ids
    /// from it, preventing ambiguous collisions in the single `pq_prekey_id`.
    next_pq: PqPrekeyId,
}

impl PrekeyStore {
    pub fn new(identity: &IdentityKeyPair) -> Result<Self, PrimitiveError> {
        Ok(Self {
            signed: SignedPrekey::generate(identity, 1)?,
            last_resort_pq: LastResortPqPrekey::generate(identity, 1)?,
            previous_signed: HashMap::new(),
            previous_last_resort_pq: HashMap::new(),
            one_time_ec: HashMap::new(),
            one_time_pq: HashMap::new(),
            next_ec: 2,
            next_pq: 2,
        })
    }

    fn allocate_ec_id(&mut self) -> Result<EcPrekeyId, PrimitiveError> {
        let id = self.next_ec;
        self.next_ec = self
            .next_ec
            .checked_add(1)
            .ok_or(PrimitiveError::LimitExceeded)?;
        Ok(id)
    }

    fn allocate_pq_id(&mut self) -> Result<PqPrekeyId, PrimitiveError> {
        let id = self.next_pq;
        self.next_pq = self
            .next_pq
            .checked_add(1)
            .ok_or(PrimitiveError::LimitExceeded)?;
        Ok(id)
    }

    pub fn replenish(
        &mut self,
        identity: &IdentityKeyPair,
        ec_count: usize,
        pq_count: usize,
    ) -> Result<(), PrimitiveError> {
        if ec_count > MAX_STORED_PREKEYS || pq_count > MAX_STORED_PREKEYS {
            return Err(PrimitiveError::LimitExceeded);
        }
        while self.one_time_ec.len() < ec_count {
            let id = self.allocate_ec_id()?;
            self.one_time_ec.insert(
                id,
                OneTimeEcPrekey {
                    id,
                    secret: X25519Secret::generate()?,
                },
            );
        }
        while self.one_time_pq.len() < pq_count {
            let id = self.allocate_pq_id()?;
            self.one_time_pq
                .insert(id, OneTimePqPrekey::generate(identity, id)?);
        }
        Ok(())
    }

    /// Rotate the signed EC prekey. The previous current key is retained for
    /// delayed initiations, bounded by `retain_previous`.
    pub fn rotate_signed_prekey(
        &mut self,
        identity: &IdentityKeyPair,
        retain_previous: usize,
    ) -> Result<EcPrekeyId, PrimitiveError> {
        if retain_previous > MAX_RETAINED_ROTATED_PREKEYS {
            return Err(PrimitiveError::LimitExceeded);
        }
        let id = self.allocate_ec_id()?;
        let replacement = SignedPrekey::generate(identity, id)?;
        let old = std::mem::replace(&mut self.signed, replacement);
        self.previous_signed.insert(old.id, old);
        prune_oldest(&mut self.previous_signed, retain_previous);
        Ok(id)
    }

    /// Rotate the signed last-resort PQ prekey. The previous current key is
    /// retained temporarily for delayed initiations.
    pub fn rotate_last_resort_pq(
        &mut self,
        identity: &IdentityKeyPair,
        retain_previous: usize,
    ) -> Result<PqPrekeyId, PrimitiveError> {
        if retain_previous > MAX_RETAINED_ROTATED_PREKEYS {
            return Err(PrimitiveError::LimitExceeded);
        }
        let id = self.allocate_pq_id()?;
        let replacement = LastResortPqPrekey::generate(identity, id)?;
        let old = std::mem::replace(&mut self.last_resort_pq, replacement);
        self.previous_last_resort_pq.insert(old.id, old);
        prune_oldest(&mut self.previous_last_resort_pq, retain_previous);
        Ok(id)
    }

    /// Explicitly expire all retained signed EC keys older than `min_id`.
    pub fn expire_signed_before(&mut self, min_id: EcPrekeyId) {
        self.previous_signed.retain(|id, _| *id >= min_id);
    }

    /// Explicitly expire all retained LR-PQ keys older than `min_id`.
    pub fn expire_last_resort_pq_before(&mut self, min_id: PqPrekeyId) {
        self.previous_last_resort_pq
            .retain(|id, _| *id >= min_id);
    }

    pub fn retained_signed_count(&self) -> usize {
        self.previous_signed.len()
    }

    pub fn retained_last_resort_pq_count(&self) -> usize {
        self.previous_last_resort_pq.len()
    }

    /// Resolve the exact signed prekey referenced by an initiation packet.
    pub fn signed_prekey(&self, id: EcPrekeyId) -> Result<&SignedPrekey, PrimitiveError> {
        if self.signed.id == id {
            return Ok(&self.signed);
        }
        self.previous_signed
            .get(&id)
            .ok_or(PrimitiveError::InvalidSecretKey)
    }

    pub fn is_last_resort_pq(&self, id: PqPrekeyId) -> bool {
        self.last_resort_pq.id == id || self.previous_last_resort_pq.contains_key(&id)
    }

    pub fn last_resort_pq(&self, id: PqPrekeyId) -> Result<&LastResortPqPrekey, PrimitiveError> {
        if self.last_resort_pq.id == id {
            return Ok(&self.last_resort_pq);
        }
        self.previous_last_resort_pq
            .get(&id)
            .ok_or(PrimitiveError::InvalidSecretKey)
    }

    /// Publish a convenience bundle. This method does **not** reserve a one-time
    /// prekey; repeated calls may display the same local OPK. A production
    /// service must upload the inventory and atomically allocate/pop one OPK per
    /// bundle request. See `public_*_inventory` and PREKEY_SERVER_CONTRACT.md.
    pub fn public_bundle(
        &self,
        identity: &IdentityKeyPair,
    ) -> Result<PublicPrekeyBundle, PrimitiveError> {
        let one_time_ec = self
            .one_time_ec
            .values()
            .next()
            .map(|o| (o.id, o.secret.public_key()));

        let (pq_id, pq_pub, pq_sig, is_one_time) =
            if let Some(opk) = self.one_time_pq.values().next() {
                (
                    opk.id,
                    opk.public()?.as_bytes().to_vec(),
                    opk.signature,
                    true,
                )
            } else {
                (
                    self.last_resort_pq.id,
                    self.last_resort_pq.public()?.as_bytes().to_vec(),
                    self.last_resort_pq.signature,
                    false,
                )
            };

        Ok(PublicPrekeyBundle {
            identity_key: identity.public(),
            signed_prekey_id: self.signed.id,
            signed_prekey: self.signed.public_key(),
            signed_prekey_sig: self.signed.signature,
            one_time_ec,
            pq_prekey_id: pq_id,
            pq_prekey_public: pq_pub,
            pq_prekey_sig: pq_sig,
            is_pq_one_time: is_one_time,
        })
    }

    /// Export public EC OPK inventory for upload to an allocating server.
    pub fn public_ec_inventory(&self) -> Vec<PublicEcOneTimePrekey> {
        self.one_time_ec
            .values()
            .map(|k| PublicEcOneTimePrekey {
                id: k.id,
                public: k.secret.public_key(),
            })
            .collect()
    }

    /// Export public PQ OPK inventory for upload to an allocating server.
    pub fn public_pq_inventory(&self) -> Result<Vec<PublicPqOneTimePrekey>, PrimitiveError> {
        self.one_time_pq
            .values()
            .map(|k| {
                Ok(PublicPqOneTimePrekey {
                    id: k.id,
                    public: k.public()?.as_bytes().to_vec(),
                    signature: k.signature,
                })
            })
            .collect()
    }

    /// Inspect a one-time EC prekey without consuming it.
    pub fn peek_ec(&self, id: EcPrekeyId) -> Result<&OneTimeEcPrekey, PrimitiveError> {
        self.one_time_ec
            .get(&id)
            .ok_or(PrimitiveError::InvalidSecretKey)
    }

    /// Inspect a one-time PQ prekey without consuming it.
    pub fn peek_pq(&self, id: PqPrekeyId) -> Result<&OneTimePqPrekey, PrimitiveError> {
        self.one_time_pq
            .get(&id)
            .ok_or(PrimitiveError::InvalidSecretKey)
    }

    /// Atomically consume a one-time EC prekey. Fails if already consumed or unknown.
    pub fn consume_ec(&mut self, id: EcPrekeyId) -> Result<OneTimeEcPrekey, PrimitiveError> {
        self.one_time_ec
            .remove(&id)
            .ok_or(PrimitiveError::InvalidSecretKey)
    }

    /// Atomically consume a one-time PQ prekey.
    pub fn consume_pq(&mut self, id: PqPrekeyId) -> Result<OneTimePqPrekey, PrimitiveError> {
        self.one_time_pq
            .remove(&id)
            .ok_or(PrimitiveError::InvalidSecretKey)
    }

    pub fn one_time_ec_count(&self) -> usize {
        self.one_time_ec.len()
    }

    pub fn one_time_pq_count(&self) -> usize {
        self.one_time_pq.len()
    }

    /// Persist the store (includes remaining/retained private prekeys).
    /// Caller must protect this blob at rest.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = b"VCPREK02".to_vec();
        write_signed(&mut out, &self.signed);
        write_last_resort(&mut out, &self.last_resort_pq);
        out.extend_from_slice(&self.next_ec.to_le_bytes());
        out.extend_from_slice(&self.next_pq.to_le_bytes());

        out.extend_from_slice(&(self.previous_signed.len() as u32).to_le_bytes());
        for k in self.previous_signed.values() {
            write_signed(&mut out, k);
        }
        out.extend_from_slice(&(self.previous_last_resort_pq.len() as u32).to_le_bytes());
        for k in self.previous_last_resort_pq.values() {
            write_last_resort(&mut out, k);
        }

        out.extend_from_slice(&(self.one_time_ec.len() as u32).to_le_bytes());
        for (id, k) in &self.one_time_ec {
            out.extend_from_slice(&id.to_le_bytes());
            out.extend_from_slice(&k.secret.to_bytes());
        }
        out.extend_from_slice(&(self.one_time_pq.len() as u32).to_le_bytes());
        for (id, k) in &self.one_time_pq {
            out.extend_from_slice(&id.to_le_bytes());
            out.extend_from_slice(k.secret.as_seed());
            out.extend_from_slice(&k.signature);
        }
        out
    }

    /// Restore v2 state. V1 blobs are accepted for migration with empty retained sets.
    pub fn deserialize(data: &[u8]) -> Result<Self, PrimitiveError> {
        if data.len() < 8 {
            return Err(PrimitiveError::InvalidLength);
        }
        if &data[..8] == b"VCPREK01" {
            return Self::deserialize_v1(data);
        }
        if &data[..8] != b"VCPREK02" {
            return Err(PrimitiveError::InvalidLength);
        }
        let mut i = 8;
        let signed = read_signed(data, &mut i)?;
        let last_resort_pq = read_last_resort(data, &mut i)?;
        let next_ec = read_u32(data, &mut i)?;
        let next_pq = read_u32(data, &mut i)?;

        let previous_signed_n = read_count(data, &mut i, MAX_RETAINED_ROTATED_PREKEYS)?;
        let mut previous_signed = HashMap::new();
        for _ in 0..previous_signed_n {
            let k = read_signed(data, &mut i)?;
            if k.id == signed.id || previous_signed.insert(k.id, k).is_some() {
                return Err(PrimitiveError::InvalidLength);
            }
        }

        let previous_lr_n = read_count(data, &mut i, MAX_RETAINED_ROTATED_PREKEYS)?;
        let mut previous_last_resort_pq = HashMap::new();
        for _ in 0..previous_lr_n {
            let k = read_last_resort(data, &mut i)?;
            if k.id == last_resort_pq.id || previous_last_resort_pq.insert(k.id, k).is_some() {
                return Err(PrimitiveError::InvalidLength);
            }
        }

        let ec_n = read_count(data, &mut i, MAX_STORED_PREKEYS)?;
        let mut one_time_ec = HashMap::new();
        for _ in 0..ec_n {
            let id = read_u32(data, &mut i)?;
            let mut sec = [0u8; 32];
            sec.copy_from_slice(take(data, &mut i, 32)?);
            if one_time_ec
                .insert(
                    id,
                    OneTimeEcPrekey {
                        id,
                        secret: X25519Secret::from_bytes(sec),
                    },
                )
                .is_some()
            {
                return Err(PrimitiveError::InvalidLength);
            }
        }

        let pq_n = read_count(data, &mut i, MAX_STORED_PREKEYS)?;
        let mut one_time_pq = HashMap::new();
        for _ in 0..pq_n {
            let id = read_u32(data, &mut i)?;
            if id == last_resort_pq.id || previous_last_resort_pq.contains_key(&id) {
                return Err(PrimitiveError::InvalidLength);
            }
            let mut seed = [0u8; 64];
            seed.copy_from_slice(take(data, &mut i, 64)?);
            let mut sig = [0u8; 64];
            sig.copy_from_slice(take(data, &mut i, 64)?);
            if one_time_pq
                .insert(
                    id,
                    OneTimePqPrekey {
                        id,
                        secret: MlKemSecret::from_seed_bytes(seed),
                        signature: sig,
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
        validate_next_ids(
            next_ec,
            next_pq,
            &signed,
            &previous_signed,
            &one_time_ec,
            &last_resort_pq,
            &previous_last_resort_pq,
            &one_time_pq,
        )?;
        Ok(Self {
            signed,
            last_resort_pq,
            previous_signed,
            previous_last_resort_pq,
            one_time_ec,
            one_time_pq,
            next_ec,
            next_pq,
        })
    }

    fn deserialize_v1(data: &[u8]) -> Result<Self, PrimitiveError> {
        if data.len() < 8 + 4 + 32 + 64 + 4 + 64 + 64 + 8 + 8 {
            return Err(PrimitiveError::InvalidLength);
        }
        let mut i = 8;
        let signed = read_signed(data, &mut i)?;
        let last_resort_pq = read_last_resort(data, &mut i)?;
        let next_ec = read_u32(data, &mut i)?;
        let next_pq = read_u32(data, &mut i)?;
        let ec_n = read_count(data, &mut i, MAX_STORED_PREKEYS)?;
        let mut one_time_ec = HashMap::new();
        for _ in 0..ec_n {
            let id = read_u32(data, &mut i)?;
            let mut sec = [0u8; 32];
            sec.copy_from_slice(take(data, &mut i, 32)?);
            if one_time_ec
                .insert(
                    id,
                    OneTimeEcPrekey {
                        id,
                        secret: X25519Secret::from_bytes(sec),
                    },
                )
                .is_some()
            {
                return Err(PrimitiveError::InvalidLength);
            }
        }
        let pq_n = read_count(data, &mut i, MAX_STORED_PREKEYS)?;
        let mut one_time_pq = HashMap::new();
        for _ in 0..pq_n {
            let id = read_u32(data, &mut i)?;
            if id == last_resort_pq.id {
                return Err(PrimitiveError::InvalidLength);
            }
            let mut seed = [0u8; 64];
            seed.copy_from_slice(take(data, &mut i, 64)?);
            let mut sig = [0u8; 64];
            sig.copy_from_slice(take(data, &mut i, 64)?);
            if one_time_pq
                .insert(
                    id,
                    OneTimePqPrekey {
                        id,
                        secret: MlKemSecret::from_seed_bytes(seed),
                        signature: sig,
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
        let previous_signed = HashMap::new();
        let previous_last_resort_pq = HashMap::new();
        validate_next_ids(
            next_ec,
            next_pq,
            &signed,
            &previous_signed,
            &one_time_ec,
            &last_resort_pq,
            &previous_last_resort_pq,
            &one_time_pq,
        )?;
        Ok(Self {
            signed,
            last_resort_pq,
            previous_signed,
            previous_last_resort_pq,
            one_time_ec,
            one_time_pq,
            next_ec,
            next_pq,
        })
    }

    pub fn get_pq_secret(&self, id: PqPrekeyId) -> Result<&MlKemSecret, PrimitiveError> {
        if let Ok(k) = self.last_resort_pq(id) {
            return Ok(&k.secret);
        }
        self.one_time_pq
            .get(&id)
            .map(|k| &k.secret)
            .ok_or(PrimitiveError::InvalidSecretKey)
    }
}

fn prune_oldest<T>(map: &mut HashMap<u32, T>, keep: usize) {
    while map.len() > keep {
        if let Some(oldest) = map.keys().copied().min() {
            map.remove(&oldest);
        } else {
            break;
        }
    }
}

fn write_signed(out: &mut Vec<u8>, k: &SignedPrekey) {
    out.extend_from_slice(&k.id.to_le_bytes());
    out.extend_from_slice(&k.secret.to_bytes());
    out.extend_from_slice(&k.signature);
}

fn write_last_resort(out: &mut Vec<u8>, k: &LastResortPqPrekey) {
    out.extend_from_slice(&k.id.to_le_bytes());
    out.extend_from_slice(k.secret.as_seed());
    out.extend_from_slice(&k.signature);
}

fn read_signed(data: &[u8], i: &mut usize) -> Result<SignedPrekey, PrimitiveError> {
    let id = read_u32(data, i)?;
    let mut sec = [0u8; 32];
    sec.copy_from_slice(take(data, i, 32)?);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(take(data, i, 64)?);
    Ok(SignedPrekey {
        id,
        secret: X25519Secret::from_bytes(sec),
        signature: sig,
    })
}

fn read_last_resort(data: &[u8], i: &mut usize) -> Result<LastResortPqPrekey, PrimitiveError> {
    let id = read_u32(data, i)?;
    let mut seed = [0u8; 64];
    seed.copy_from_slice(take(data, i, 64)?);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(take(data, i, 64)?);
    Ok(LastResortPqPrekey {
        id,
        secret: MlKemSecret::from_seed_bytes(seed),
        signature: sig,
    })
}

fn take<'a>(data: &'a [u8], i: &mut usize, n: usize) -> Result<&'a [u8], PrimitiveError> {
    if n > data.len().saturating_sub(*i) {
        return Err(PrimitiveError::InvalidLength);
    }
    let s = &data[*i..*i + n];
    *i += n;
    Ok(s)
}

fn read_u32(data: &[u8], i: &mut usize) -> Result<u32, PrimitiveError> {
    Ok(u32::from_le_bytes(take(data, i, 4)?.try_into().unwrap()))
}

fn read_count(data: &[u8], i: &mut usize, max: usize) -> Result<usize, PrimitiveError> {
    let n = read_u32(data, i)? as usize;
    if n > max {
        return Err(PrimitiveError::LimitExceeded);
    }
    Ok(n)
}

#[allow(clippy::too_many_arguments)]
fn validate_next_ids(
    next_ec: u32,
    next_pq: u32,
    signed: &SignedPrekey,
    previous_signed: &HashMap<EcPrekeyId, SignedPrekey>,
    one_time_ec: &HashMap<EcPrekeyId, OneTimeEcPrekey>,
    last_resort_pq: &LastResortPqPrekey,
    previous_last_resort_pq: &HashMap<PqPrekeyId, LastResortPqPrekey>,
    one_time_pq: &HashMap<PqPrekeyId, OneTimePqPrekey>,
) -> Result<(), PrimitiveError> {
    let max_ec = std::iter::once(signed.id)
        .chain(previous_signed.keys().copied())
        .chain(one_time_ec.keys().copied())
        .max()
        .unwrap_or(0);
    let max_pq = std::iter::once(last_resort_pq.id)
        .chain(previous_last_resort_pq.keys().copied())
        .chain(one_time_pq.keys().copied())
        .max()
        .unwrap_or(0);
    if next_ec <= max_ec || next_pq <= max_pq {
        return Err(PrimitiveError::InvalidLength);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consume_ec_once() {
        let ik = IdentityKeyPair::generate().unwrap();
        let mut store = PrekeyStore::new(&ik).unwrap();
        store.replenish(&ik, 1, 0).unwrap();
        let id = store.one_time_ec.keys().copied().next().unwrap();
        store.consume_ec(id).unwrap();
        assert!(store.consume_ec(id).is_err());
    }

    #[test]
    fn bundle_signatures_validate() {
        let ik = IdentityKeyPair::generate().unwrap();
        let mut store = PrekeyStore::new(&ik).unwrap();
        store.replenish(&ik, 1, 1).unwrap();
        let bundle = store.public_bundle(&ik).unwrap();
        bundle.validate().unwrap();
        let decoded = PublicPrekeyBundle::decode(&bundle.encode()).unwrap();
        assert_eq!(decoded.signed_prekey_id, bundle.signed_prekey_id);
        assert_eq!(decoded.pq_prekey_id, bundle.pq_prekey_id);
        assert_eq!(
            decoded.identity_key.to_bytes(),
            bundle.identity_key.to_bytes()
        );
    }

    #[test]
    fn bundle_decode_rejects_noncanonical_pq_one_time_flag() {
        let ik = IdentityKeyPair::generate().unwrap();
        let store = PrekeyStore::new(&ik).unwrap();
        let mut encoded = store.public_bundle(&ik).unwrap().encode();
        *encoded.last_mut().unwrap() = 2;
        assert!(PublicPrekeyBundle::decode(&encoded).is_err());
    }

    #[test]
    fn serialize_reload_preserves_consumed_set() {
        let ik = IdentityKeyPair::generate().unwrap();
        let mut store = PrekeyStore::new(&ik).unwrap();
        store.replenish(&ik, 2, 2).unwrap();
        let id = store.one_time_ec.keys().copied().next().unwrap();
        store.consume_ec(id).unwrap();
        let blob = store.serialize();
        let mut store2 = PrekeyStore::deserialize(&blob).unwrap();
        assert!(store2.consume_ec(id).is_err());
        assert_eq!(store2.one_time_ec_count(), 1);
        assert_eq!(store2.one_time_pq_count(), 2);
        assert_eq!(store2.signed.id, store.signed.id);
    }

    #[test]
    fn signed_rotation_retains_delayed_key_then_expires_it() {
        let ik = IdentityKeyPair::generate().unwrap();
        let mut store = PrekeyStore::new(&ik).unwrap();
        let old = store.signed.id;
        let new = store.rotate_signed_prekey(&ik, 1).unwrap();
        assert_ne!(new, old);
        assert_eq!(store.signed_prekey(old).unwrap().id, old);
        store.rotate_signed_prekey(&ik, 1).unwrap();
        assert!(store.signed_prekey(old).is_err());
    }

    #[test]
    fn last_resort_rotation_retains_delayed_key_then_expires_it() {
        let ik = IdentityKeyPair::generate().unwrap();
        let mut store = PrekeyStore::new(&ik).unwrap();
        let old = store.last_resort_pq.id;
        let new = store.rotate_last_resort_pq(&ik, 1).unwrap();
        assert_ne!(new, old);
        assert!(store.is_last_resort_pq(old));
        assert_eq!(store.last_resort_pq(old).unwrap().id, old);
        store.rotate_last_resort_pq(&ik, 1).unwrap();
        assert!(!store.is_last_resort_pq(old));
    }

    #[test]
    fn rotated_state_roundtrips() {
        let ik = IdentityKeyPair::generate().unwrap();
        let mut store = PrekeyStore::new(&ik).unwrap();
        let old_spk = store.signed.id;
        let old_pq = store.last_resort_pq.id;
        store.rotate_signed_prekey(&ik, 2).unwrap();
        store.rotate_last_resort_pq(&ik, 2).unwrap();
        store.replenish(&ik, 2, 2).unwrap();
        let restored = PrekeyStore::deserialize(&store.serialize()).unwrap();
        assert!(restored.signed_prekey(old_spk).is_ok());
        assert!(restored.last_resort_pq(old_pq).is_ok());
        assert_eq!(restored.one_time_ec_count(), 2);
        assert_eq!(restored.one_time_pq_count(), 2);
    }

    #[test]
    fn public_inventory_lists_all_one_time_keys() {
        let ik = IdentityKeyPair::generate().unwrap();
        let mut store = PrekeyStore::new(&ik).unwrap();
        store.replenish(&ik, 5, 6).unwrap();
        assert_eq!(store.public_ec_inventory().len(), 5);
        assert_eq!(store.public_pq_inventory().unwrap().len(), 6);
    }

    #[test]
    fn tampered_signed_prekey_rejected() {
        let ik = IdentityKeyPair::generate().unwrap();
        let store = PrekeyStore::new(&ik).unwrap();
        let mut bundle = store.public_bundle(&ik).unwrap();
        bundle.signed_prekey_sig[0] ^= 0xff;
        assert!(bundle.validate().is_err());
    }
}
