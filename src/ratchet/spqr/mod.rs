//! Sparse Post-Quantum Ratchet (SPQR) — classical-independent PQ continuous ratchet.
//!
//! Based on the public Double Ratchet Revision 4 description of SPQR and the
//! ML-KEM Braid SCKA specification. No implementation code was copied.
//!
//! This module provides the SCKA-driven epoch key stream that the Triple
//! Ratchet combines with classical message keys.
//!
//! Epoch keys are injected by ML-KEM Braid SCKA (`crate::ratchet::braid`).
//! This layer models epochs, key emission, and bounded skip state.

use crate::primitives::error::PrimitiveError;
use crate::primitives::kdf::{hkdf_extract_expand, LABELS};
use crate::primitives::random::fill_random;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum epochs of skipped keys retained (mirrors classical MAX_SKIP spirit).
pub const SPQR_MAX_SKIP_EPOCHS: u32 = 32;

/// One epoch’s message-key chain (symmetric ratchet within an epoch).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct EpochChain {
    epoch: u32,
    chain_key: [u8; 32],
    n: u32,
}

/// SPQR state — produces post-quantum message keys over successive epochs.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SpqrState {
    /// Current sending epoch chain.
    sending: Option<EpochChain>,
    /// Current receiving epoch chain.
    receiving: Option<EpochChain>,
    /// Root key mixed with each new SCKA shared secret.
    root: [u8; 32],
    /// Next epoch number to assign when a new SCKA secret is obtained.
    next_epoch: u32,
    /// Bounded map of skipped (epoch, n) → message key.
    #[zeroize(skip)]
    skipped: std::collections::HashMap<(u32, u32), [u8; 32]>,
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
            skipped: std::collections::HashMap::new(),
            max_skip_epochs,
        }
    }

    /// Advance by mixing a fresh SCKA (ML-KEM) shared secret into the root
    /// and opening a new sending + receiving chain for the new epoch.
    /// Called when the ML-KEM Braid / SCKA emits a new key.
    pub fn advance_epoch(&mut self, scka_shared_secret: &[u8; 32]) -> Result<u32, PrimitiveError> {
        let epoch = self.next_epoch;
        self.next_epoch = crate::ratchet::checked_inc(self.next_epoch)?;

        // Mix SCKA secret into root → new root + chain key material
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
        self.root = new_root;

        // Spec: create both sender and receiver chains for the new epoch
        self.sending = Some(EpochChain {
            epoch,
            chain_key: chain,
            n: 0,
        });
        // Receiving chain starts from the same material; real braid separates
        // roles more carefully — this is the control-flow equivalent.
        self.receiving = Some(EpochChain {
            epoch,
            chain_key: chain,
            n: 0,
        });

        // Bound skipped state to recent epochs only
        self.skipped
            .retain(|&(e, _), _| e + self.max_skip_epochs >= epoch);
        Ok(epoch)
    }

    pub fn receiving_epoch(&self) -> Option<u32> {
        self.receiving.as_ref().map(|c| c.epoch)
    }

    /// Derive the next sending message key for the current epoch.
    pub fn send_key(&mut self) -> Result<(u32, u32, [u8; 32]), PrimitiveError> {
        let chain = self.sending.as_mut().ok_or(PrimitiveError::Internal)?;
        let (new_ck, mk) = kdf_ck_spqr(&chain.chain_key)?;
        chain.chain_key = new_ck;
        let n = chain.n;
        let epoch = chain.epoch;
        chain.n = crate::ratchet::checked_inc(chain.n)?;
        Ok((epoch, n, mk))
    }

    /// Derive / look up a receiving message key for (epoch, n).
    pub fn receive_key(&mut self, epoch: u32, n: u32) -> Result<[u8; 32], PrimitiveError> {
        if let Some(mk) = self.skipped.remove(&(epoch, n)) {
            return Ok(mk);
        }
        let chain = self.receiving.as_mut().ok_or(PrimitiveError::Internal)?;
        if chain.epoch != epoch {
            // Epoch mismatch — in full braid this triggers SCKA receive;
            // here we reject until advance_epoch has been called for it.
            return Err(PrimitiveError::InvalidLength);
        }
        if n < chain.n {
            return Err(PrimitiveError::InvalidLength); // already passed
        }
        if n.saturating_sub(chain.n) > self.max_skip_epochs.saturating_mul(64) {
            return Err(PrimitiveError::InvalidLength); // bound
        }
        while chain.n < n {
            let (new_ck, mk) = kdf_ck_spqr(&chain.chain_key)?;
            chain.chain_key = new_ck;
            self.skipped.insert((epoch, chain.n), mk);
            chain.n = crate::ratchet::checked_inc(chain.n)?;
            if self.skipped.len() > 256 {
                return Err(PrimitiveError::InvalidLength);
            }
        }
        let (new_ck, mk) = kdf_ck_spqr(&chain.chain_key)?;
        chain.chain_key = new_ck;
        chain.n = crate::ratchet::checked_inc(chain.n)?;
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
        if tag == 0 {
            return Ok(None);
        }
        if tag != 1 || *i + 40 > data.len() {
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

    /// Persist SPQR (root, epoch chains, skipped keys).
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.next_epoch.to_le_bytes());
        out.extend_from_slice(&self.max_skip_epochs.to_le_bytes());
        Self::write_chain(&mut out, &self.sending);
        Self::write_chain(&mut out, &self.receiving);
        out.extend_from_slice(&(self.skipped.len() as u32).to_le_bytes());
        for ((e, n), mk) in &self.skipped {
            out.extend_from_slice(&e.to_le_bytes());
            out.extend_from_slice(&n.to_le_bytes());
            out.extend_from_slice(mk);
        }
        out
    }

    /// Restore SPQR from [`Self::serialize`].
    pub fn deserialize(data: &[u8]) -> Result<Self, PrimitiveError> {
        if data.len() < 40 {
            return Err(PrimitiveError::InvalidLength);
        }
        let mut i = 0;
        let mut root = [0u8; 32];
        root.copy_from_slice(&data[i..i + 32]);
        i += 32;
        let next_epoch = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        i += 4;
        let max_skip_epochs = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        i += 4;
        let sending = Self::read_chain(data, &mut i)?;
        let receiving = Self::read_chain(data, &mut i)?;
        if i + 4 > data.len() {
            return Err(PrimitiveError::InvalidLength);
        }
        let count = u32::from_le_bytes(data[i..i + 4].try_into().unwrap()) as usize;
        i += 4;
        let mut skipped = std::collections::HashMap::new();
        for _ in 0..count {
            if i + 40 > data.len() {
                return Err(PrimitiveError::InvalidLength);
            }
            let e = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
            i += 4;
            let n = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
            i += 4;
            let mut mk = [0u8; 32];
            mk.copy_from_slice(&data[i..i + 32]);
            i += 32;
            skipped.insert((e, n), mk);
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

    /// Simulate one SCKA key-agreement step (KEM encaps/decaps stand-in).
    /// Epoch secrets arrive from Braid SCKA via [`Self::advance_epoch`].
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
        let (e2, n2, mk2) = spqr2.send_key().unwrap();
        assert_eq!(e2, e);
        assert_eq!(n2, n + 1);
        let _ = mk2;
    }
}
