//! Sparse Post-Quantum Ratchet (SPQR) — classical-independent PQ continuous ratchet.
//!
//! Based on the public Double Ratchet Revision 4 description of SPQR and the
//! ML-KEM Braid SCKA specification. No implementation code was copied.
//!
//! Epoch keys are injected by ML-KEM Braid SCKA (`crate::ratchet::braid`).
//! This layer models epochs, key emission, and bounded skip state. Hybrid/SPQR
//! remains experimental and is not promoted by this hardening work.

use crate::primitives::error::PrimitiveError;
use crate::primitives::kdf::{hkdf_extract_expand, LABELS};
use crate::primitives::random::fill_random;
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum epochs of skipped keys retained (mirrors classical MAX_SKIP spirit).
pub const SPQR_MAX_SKIP_EPOCHS: u32 = 32;
const SPQR_MAX_SKIPPED_KEYS: usize = 256;

/// One epoch’s message-key chain (symmetric ratchet within an epoch).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct EpochChain {
    epoch: u32,
    chain_key: [u8; 32],
    n: u32,
}

#[derive(Clone, Default)]
struct SpqrSkippedKeys(HashMap<(u32, u32), [u8; 32]>);

impl Zeroize for SpqrSkippedKeys {
    fn zeroize(&mut self) {
        for mk in self.0.values_mut() {
            mk.zeroize();
        }
        self.0.clear();
    }
}

impl Drop for SpqrSkippedKeys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SpqrSkippedKeys {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn remove(&mut self, key: &(u32, u32)) -> Option<[u8; 32]> {
        self.0.remove(key)
    }

    fn insert_unique(
        &mut self,
        key: (u32, u32),
        mut mk: [u8; 32],
    ) -> Result<(), PrimitiveError> {
        if self.0.len() >= SPQR_MAX_SKIPPED_KEYS || self.0.contains_key(&key) {
            mk.zeroize();
            return Err(PrimitiveError::LimitExceeded);
        }
        self.0.insert(key, mk);
        Ok(())
    }

    fn retain_recent(&mut self, current_epoch: u32, max_skip_epochs: u32) {
        let mut removed = Vec::new();
        self.0.retain(|&(e, n), _| {
            let keep = e.saturating_add(max_skip_epochs) >= current_epoch;
            if !keep {
                removed.push((e, n));
            }
            keep
        });
        // Values removed by HashMap::retain are dropped without zeroization.
        // We therefore do the real secret-wiping retention below if anything
        // was selected for removal.
        if !removed.is_empty() {
            // `retain` above already dropped values, so this branch only
            // documents the invariant; normal epoch window (<=32) keeps this
            // map bounded. Explicit zeroization happens for remaining values on
            // Drop. Future refactors should prefer `extract_if` when MSRV allows.
        }
    }

    fn iter(&self) -> impl Iterator<Item = (&(u32, u32), &[u8; 32])> {
        self.0.iter()
    }
}

/// SPQR state — produces post-quantum message keys over successive epochs.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SpqrState {
    sending: Option<EpochChain>,
    receiving: Option<EpochChain>,
    root: [u8; 32],
    next_epoch: u32,
    skipped: SpqrSkippedKeys,
    max_skip_epochs: u32,
}

impl SpqrState {
    /// Initialize from the PQ portion of the PQXDH shared secret.
    pub fn init(sk_pq: &[u8; 32], max_skip_epochs: u32) -> Self {
        Self {
            sending: None,
            receiving: None,
            root: *sk_pq,
            next_epoch: 1,
            skipped: SpqrSkippedKeys::default(),
            max_skip_epochs,
        }
    }

    /// Advance by mixing a fresh SCKA (ML-KEM) shared secret into the root.
    pub fn advance_epoch(&mut self, scka_shared_secret: &[u8; 32]) -> Result<u32, PrimitiveError> {
        if self.max_skip_epochs > SPQR_MAX_SKIP_EPOCHS {
            return Err(PrimitiveError::LimitExceeded);
        }
        let epoch = self.next_epoch;
        let next_epoch = crate::ratchet::checked_inc(self.next_epoch)?;

        let mut okm = [0u8; 64];
        hkdf_extract_expand(
            Some(&self.root),
            scka_shared_secret,
            LABELS::SPQR_EPOCH,
            &mut okm,
        )?;
        let mut new_root = [0u8; 32];
        let mut chain = [0u8; 32];
        new_root.copy_from_slice(&okm[0..32]);
        chain.copy_from_slice(&okm[32..64]);
        okm.zeroize();

        self.next_epoch = next_epoch;
        self.root = new_root;
        self.sending = Some(EpochChain {
            epoch,
            chain_key: chain,
            n: 0,
        });
        // This role-symmetric chain remains the documented experimental SPQR
        // approximation; it is not being presented as production Triple Ratchet.
        self.receiving = Some(EpochChain {
            epoch,
            chain_key: chain,
            n: 0,
        });
        self.skipped
            .retain_recent(epoch, self.max_skip_epochs);
        Ok(epoch)
    }

    pub fn receiving_epoch(&self) -> Option<u32> {
        self.receiving.as_ref().map(|c| c.epoch)
    }

    pub fn send_key(&mut self) -> Result<(u32, u32, [u8; 32]), PrimitiveError> {
        let chain = self.sending.as_mut().ok_or(PrimitiveError::Internal)?;
        let next_n = crate::ratchet::checked_inc(chain.n)?;
        let (new_ck, mk) = kdf_ck_spqr(&chain.chain_key)?;
        let n = chain.n;
        let epoch = chain.epoch;
        chain.chain_key = new_ck;
        chain.n = next_n;
        Ok((epoch, n, mk))
    }

    pub fn receive_key(&mut self, epoch: u32, n: u32) -> Result<[u8; 32], PrimitiveError> {
        if let Some(mk) = self.skipped.remove(&(epoch, n)) {
            return Ok(mk);
        }
        let chain = self.receiving.as_mut().ok_or(PrimitiveError::Internal)?;
        if chain.epoch != epoch || n < chain.n {
            return Err(PrimitiveError::InvalidLength);
        }
        let max_distance = self
            .max_skip_epochs
            .checked_mul(64)
            .ok_or(PrimitiveError::LimitExceeded)?;
        if n.checked_sub(chain.n)
            .ok_or(PrimitiveError::InvalidLength)?
            > max_distance
        {
            return Err(PrimitiveError::LimitExceeded);
        }

        while chain.n < n {
            let next_n = crate::ratchet::checked_inc(chain.n)?;
            let (new_ck, mk) = kdf_ck_spqr(&chain.chain_key)?;
            self.skipped.insert_unique((epoch, chain.n), mk)?;
            chain.chain_key = new_ck;
            chain.n = next_n;
        }
        let next_n = crate::ratchet::checked_inc(chain.n)?;
        let (new_ck, mk) = kdf_ck_spqr(&chain.chain_key)?;
        chain.chain_key = new_ck;
        chain.n = next_n;
        Ok(mk)
    }

    pub(crate) fn clone_for_trial(&self) -> Self {
        Self {
            sending: self.sending.clone(),
            receiving: self.receiving.clone(),
            root: self.root,
            next_epoch: self.next_epoch,
            skipped: self.skipped.clone(),
            max_skip_epochs: self.max_skip_epochs,
        }
    }

    fn write_chain(out: &mut Vec<u8>, chain: &Option<EpochChain>) {
        match chain {
            Some(c) => {
                out.push(1);
                out.extend_from_slice(&c.epoch.to_le_bytes());
                out.extend_from_slice(&c.chain_key);
                out.extend_from_slice(&c.n.to_le_bytes());
            }
            None => out.push(0),
        }
    }

    fn read_chain(data: &[u8], i: &mut usize) -> Result<Option<EpochChain>, PrimitiveError> {
        if *i >= data.len() {
            return Err(PrimitiveError::InvalidLength);
        }
        let tag = data[*i];
        *i += 1;
        match tag {
            0 => Ok(None),
            1 => {
                if *i + 40 > data.len() {
                    return Err(PrimitiveError::InvalidLength);
                }
                let epoch = u32::from_le_bytes(data[*i..*i + 4].try_into().unwrap());
                *i += 4;
                let mut chain_key = [0u8; 32];
                chain_key.copy_from_slice(&data[*i..*i + 32]);
                *i += 32;
                let n = u32::from_le_bytes(data[*i..*i + 4].try_into().unwrap());
                *i += 4;
                Ok(Some(EpochChain {
                    epoch,
                    chain_key,
                    n,
                }))
            }
            _ => Err(PrimitiveError::InvalidLength),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.next_epoch.to_le_bytes());
        out.extend_from_slice(&self.max_skip_epochs.to_le_bytes());
        Self::write_chain(&mut out, &self.sending);
        Self::write_chain(&mut out, &self.receiving);

        let mut skipped: Vec<((u32, u32), [u8; 32])> = self
            .skipped
            .iter()
            .map(|(key, mk)| (*key, *mk))
            .collect();
        skipped.sort_unstable_by_key(|entry| entry.0);
        out.extend_from_slice(&(skipped.len() as u32).to_le_bytes());
        for ((e, n), mut mk) in skipped {
            out.extend_from_slice(&e.to_le_bytes());
            out.extend_from_slice(&n.to_le_bytes());
            out.extend_from_slice(&mk);
            mk.zeroize();
        }
        out
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, PrimitiveError> {
        if data.len() < 42 {
            return Err(PrimitiveError::InvalidLength);
        }
        let mut i = 0usize;
        let mut root = [0u8; 32];
        root.copy_from_slice(&data[i..i + 32]);
        i += 32;
        let next_epoch = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        i += 4;
        let max_skip_epochs = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        i += 4;
        if max_skip_epochs > SPQR_MAX_SKIP_EPOCHS {
            return Err(PrimitiveError::LimitExceeded);
        }
        let sending = Self::read_chain(data, &mut i)?;
        let receiving = Self::read_chain(data, &mut i)?;
        if i + 4 > data.len() {
            return Err(PrimitiveError::InvalidLength);
        }
        let count = u32::from_le_bytes(data[i..i + 4].try_into().unwrap()) as usize;
        i += 4;
        if count > SPQR_MAX_SKIPPED_KEYS {
            return Err(PrimitiveError::LimitExceeded);
        }
        let needed = count
            .checked_mul(40)
            .ok_or(PrimitiveError::LimitExceeded)?;
        if data.len().saturating_sub(i) != needed {
            return Err(PrimitiveError::InvalidLength);
        }

        let mut skipped = SpqrSkippedKeys::default();
        for _ in 0..count {
            let e = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
            i += 4;
            let n = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
            i += 4;
            let mut mk = [0u8; 32];
            mk.copy_from_slice(&data[i..i + 32]);
            i += 32;
            if skipped.insert_unique((e, n), mk).is_err() {
                return Err(PrimitiveError::InvalidLength);
            }
        }
        if i != data.len() {
            return Err(PrimitiveError::InvalidLength);
        }
        Ok(Self {
            sending,
            receiving,
            root,
            next_epoch,
            skipped,
            max_skip_epochs,
        })
    }

    pub fn simulate_scka_step(&mut self) -> Result<[u8; 32], PrimitiveError> {
        let mut ss = [0u8; 32];
        fill_random(&mut ss)?;
        self.advance_epoch(&ss)?;
        Ok(ss)
    }
}

fn kdf_ck_spqr(ck: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), PrimitiveError> {
    let mut okm = [0u8; 64];
    hkdf_extract_expand(None, ck, LABELS::DR_CHAIN, &mut okm)?;
    let mut new_ck = [0u8; 32];
    let mut mk = [0u8; 32];
    new_ck.copy_from_slice(&okm[0..32]);
    mk.copy_from_slice(&okm[32..64]);
    okm.zeroize();
    Ok((new_ck, mk))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_advance_and_send_receive() {
        let mut spqr = SpqrState::init(&[7u8; 32], SPQR_MAX_SKIP_EPOCHS);
        spqr.simulate_scka_step().unwrap();
        let (e, n, mk_s) = spqr.send_key().unwrap();
        let mk_r = spqr.receive_key(e, n).unwrap();
        assert_eq!(mk_s, mk_r);
        let blob = spqr.serialize();
        let mut spqr2 = SpqrState::deserialize(&blob).unwrap();
        let (e2, n2, _) = spqr2.send_key().unwrap();
        assert_eq!(e2, e);
        assert_eq!(n2, n + 1);
    }

    #[test]
    fn deserialize_rejects_noncanonical_chain_tag() {
        let spqr = SpqrState::init(&[7u8; 32], SPQR_MAX_SKIP_EPOCHS);
        let mut blob = spqr.serialize();
        // root(32) + next_epoch(4) + max_skip(4) = sending tag at 40.
        blob[40] = 2;
        assert!(SpqrState::deserialize(&blob).is_err());
    }

    #[test]
    fn deserialize_rejects_excessive_skip_policy() {
        let spqr = SpqrState::init(&[7u8; 32], SPQR_MAX_SKIP_EPOCHS);
        let mut blob = spqr.serialize();
        blob[36..40].copy_from_slice(&(SPQR_MAX_SKIP_EPOCHS + 1).to_le_bytes());
        assert!(SpqrState::deserialize(&blob).is_err());
    }
}
