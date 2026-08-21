//! Explicit prekey models for PQXDH.
//!
//! One-time prekeys are consumed atomically. Last-resort PQ prekeys are
//! rotated by policy and are never treated as one-time.

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
        let is_one = take(&mut i, 1)?[0];
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
            is_pq_one_time: is_one == 1,
        };
        bundle.validate()?;
        Ok(bundle)
    }
}

/// Device-local prekey store with atomic one-time consumption.
pub struct PrekeyStore {
    pub signed: SignedPrekey,
    pub last_resort_pq: LastResortPqPrekey,
    one_time_ec: HashMap<EcPrekeyId, OneTimeEcPrekey>,
    one_time_pq: HashMap<PqPrekeyId, OneTimePqPrekey>,
    next_ec: EcPrekeyId,
    next_pq: PqPrekeyId,
}

impl PrekeyStore {
    pub fn new(identity: &IdentityKeyPair) -> Result<Self, PrimitiveError> {
        Ok(Self {
            signed: SignedPrekey::generate(identity, 1)?,
            last_resort_pq: LastResortPqPrekey::generate(identity, 1)?,
            one_time_ec: HashMap::new(),
            one_time_pq: HashMap::new(),
            next_ec: 2,
            next_pq: 2,
        })
    }

    pub fn replenish(
        &mut self,
        identity: &IdentityKeyPair,
        ec_count: usize,
        pq_count: usize,
    ) -> Result<(), PrimitiveError> {
        while self.one_time_ec.len() < ec_count {
            let id = self.next_ec;
            self.next_ec = self
                .next_ec
                .checked_add(1)
                .ok_or(PrimitiveError::LimitExceeded)?;
            if self.next_ec < 2 {
                return Err(PrimitiveError::LimitExceeded);
            }
            self.one_time_ec.insert(
                id,
                OneTimeEcPrekey {
                    id,
                    secret: X25519Secret::generate()?,
                },
            );
        }
        while self.one_time_pq.len() < pq_count {
            let id = self.next_pq;
            self.next_pq = self
                .next_pq
                .checked_add(1)
                .ok_or(PrimitiveError::LimitExceeded)?;
            if self.next_pq < 2 {
                return Err(PrimitiveError::LimitExceeded);
            }
            self.one_time_pq
                .insert(id, OneTimePqPrekey::generate(identity, id)?);
        }
        Ok(())
    }

    /// Publish a bundle. Prefers one-time PQ over last-resort.
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

    /// Persist the store (includes remaining one-time secrets). Caller protects the blob.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = b"VCPREK01".to_vec();
        out.extend_from_slice(&self.signed.id.to_le_bytes());
        out.extend_from_slice(&self.signed.secret.to_bytes());
        out.extend_from_slice(&self.signed.signature);
        out.extend_from_slice(&self.last_resort_pq.id.to_le_bytes());
        out.extend_from_slice(self.last_resort_pq.secret.as_seed());
        out.extend_from_slice(&self.last_resort_pq.signature);
        out.extend_from_slice(&self.next_ec.to_le_bytes());
        out.extend_from_slice(&self.next_pq.to_le_bytes());
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

    /// Restore from [`Self::serialize`].
    pub fn deserialize(data: &[u8]) -> Result<Self, PrimitiveError> {
        if data.len() < 8 + 4 + 32 + 64 + 4 + 64 + 64 + 8 + 8 {
            return Err(PrimitiveError::InvalidLength);
        }
        if &data[0..8] != b"VCPREK01" {
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
        let signed_id = u32::from_le_bytes(take(&mut i, 4)?.try_into().unwrap());
        let mut signed_sec = [0u8; 32];
        signed_sec.copy_from_slice(take(&mut i, 32)?);
        let mut signed_sig = [0u8; 64];
        signed_sig.copy_from_slice(take(&mut i, 64)?);
        let lr_id = u32::from_le_bytes(take(&mut i, 4)?.try_into().unwrap());
        let mut lr_seed = [0u8; 64];
        lr_seed.copy_from_slice(take(&mut i, 64)?);
        let mut lr_sig = [0u8; 64];
        lr_sig.copy_from_slice(take(&mut i, 64)?);
        let next_ec = u32::from_le_bytes(take(&mut i, 4)?.try_into().unwrap());
        let next_pq = u32::from_le_bytes(take(&mut i, 4)?.try_into().unwrap());
        let ec_n = u32::from_le_bytes(take(&mut i, 4)?.try_into().unwrap()) as usize;
        let mut one_time_ec = HashMap::new();
        for _ in 0..ec_n {
            let id = u32::from_le_bytes(take(&mut i, 4)?.try_into().unwrap());
            let mut sec = [0u8; 32];
            sec.copy_from_slice(take(&mut i, 32)?);
            one_time_ec.insert(
                id,
                OneTimeEcPrekey {
                    id,
                    secret: X25519Secret::from_bytes(sec),
                },
            );
        }
        let pq_n = u32::from_le_bytes(take(&mut i, 4)?.try_into().unwrap()) as usize;
        let mut one_time_pq = HashMap::new();
        for _ in 0..pq_n {
            let id = u32::from_le_bytes(take(&mut i, 4)?.try_into().unwrap());
            let mut seed = [0u8; 64];
            seed.copy_from_slice(take(&mut i, 64)?);
            let mut sig = [0u8; 64];
            sig.copy_from_slice(take(&mut i, 64)?);
            one_time_pq.insert(
                id,
                OneTimePqPrekey {
                    id,
                    secret: crate::primitives::kem::MlKemSecret::from_seed_bytes(seed),
                    signature: sig,
                },
            );
        }
        if i != data.len() {
            return Err(PrimitiveError::InvalidLength);
        }
        Ok(Self {
            signed: SignedPrekey {
                id: signed_id,
                secret: X25519Secret::from_bytes(signed_sec),
                signature: signed_sig,
            },
            last_resort_pq: LastResortPqPrekey {
                id: lr_id,
                secret: crate::primitives::kem::MlKemSecret::from_seed_bytes(lr_seed),
                signature: lr_sig,
            },
            one_time_ec,
            one_time_pq,
            next_ec,
            next_pq,
        })
    }

    pub fn get_pq_secret(&self, id: PqPrekeyId) -> Result<&MlKemSecret, PrimitiveError> {
        if id == self.last_resort_pq.id {
            return Ok(&self.last_resort_pq.secret);
        }
        self.one_time_pq
            .get(&id)
            .map(|k| &k.secret)
            .ok_or(PrimitiveError::InvalidSecretKey)
    }
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
    fn tampered_signed_prekey_rejected() {
        let ik = IdentityKeyPair::generate().unwrap();
        let store = PrekeyStore::new(&ik).unwrap();
        let mut bundle = store.public_bundle(&ik).unwrap();
        bundle.signed_prekey_sig[0] ^= 0xff;
        assert!(bundle.validate().is_err());
    }
}
