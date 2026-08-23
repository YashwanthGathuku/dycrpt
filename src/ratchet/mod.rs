//! Classical Double Ratchet — implemented directly from the official
//! public specification (Double Ratchet Algorithm, Revision 4).
//!
//! No libsignal source was consulted. Algorithms follow the public
//! RatchetEncrypt / RatchetDecrypt / DHRatchet / SkipMessageKeys /
//! TrySkippedMessageKeys definitions exactly.

#[cfg(feature = "hybrid")]
pub mod braid;
#[cfg(feature = "header-encrypt")]
pub mod header_encrypt;
#[cfg(feature = "hybrid")]
pub mod scka;
#[cfg(feature = "hybrid")]
pub mod spqr;
#[cfg(feature = "hybrid")]
pub mod triple;

use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::primitives::aead::{self, AeadKey};
use crate::primitives::error::PrimitiveError;
use crate::primitives::kdf::{hkdf_extract_expand, LABELS};
use crate::primitives::x25519::{X25519Public, X25519Secret};

pub const DEFAULT_MAX_SKIP: u32 = 1000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub dh: X25519Public,
    pub pn: u32,
    pub n: u32,
}

impl Header {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(40);
        out.extend_from_slice(&self.dh.to_bytes());
        out.extend_from_slice(&self.pn.to_le_bytes());
        out.extend_from_slice(&self.n.to_le_bytes());
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, PrimitiveError> {
        if data.len() != 40 {
            return Err(PrimitiveError::InvalidLength);
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&data[..32]);
        Ok(Self {
            dh: X25519Public::from_bytes(pk)?,
            pn: u32::from_le_bytes(data[32..36].try_into().unwrap()),
            n: u32::from_le_bytes(data[36..40].try_into().unwrap()),
        })
    }
}

type SkipKey = ([u8; 32], u32);

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DoubleRatchetState {
    dhs: Option<X25519Secret>,
    #[zeroize(skip)]
    dhr: Option<X25519Public>,
    rk: [u8; 32],
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    mkskipped: SkippedKeys,
    max_skip: u32,
}

#[derive(Clone, Default)]
struct SkippedKeys(HashMap<SkipKey, [u8; 32]>);

impl Zeroize for SkippedKeys {
    fn zeroize(&mut self) {
        for mk in self.0.values_mut() {
            mk.zeroize();
        }
        self.0.clear();
    }
}

impl Drop for SkippedKeys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SkippedKeys {
    fn remove(&mut self, key: &SkipKey) -> Option<[u8; 32]> {
        self.0.remove(key)
    }

    fn insert_unique(
        &mut self,
        key: SkipKey,
        mut mk: [u8; 32],
    ) -> Result<(), PrimitiveError> {
        if self.0.contains_key(&key) {
            mk.zeroize();
            return Err(PrimitiveError::Internal);
        }
        self.0.insert(key, mk);
        Ok(())
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn iter(&self) -> impl Iterator<Item = (&SkipKey, &[u8; 32])> {
        self.0.iter()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct RatchetScalarSnapshot {
    dhs: Option<X25519Secret>,
    #[zeroize(skip)]
    dhr: Option<X25519Public>,
    rk: [u8; 32],
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
}

impl RatchetScalarSnapshot {
    fn capture(state: &DoubleRatchetState) -> Self {
        Self {
            dhs: state
                .dhs
                .as_ref()
                .map(|secret| X25519Secret::from_bytes(secret.to_bytes())),
            dhr: state.dhr,
            rk: state.rk,
            cks: state.cks,
            ckr: state.ckr,
            ns: state.ns,
            nr: state.nr,
            pn: state.pn,
        }
    }
}

#[derive(Default)]
struct SkippedMutationJournal {
    inserted: Vec<SkipKey>,
    removed: Option<(SkipKey, [u8; 32])>,
}

impl Drop for SkippedMutationJournal {
    fn drop(&mut self) {
        if let Some((_, mut mk)) = self.removed.take() {
            mk.zeroize();
        }
    }
}

pub(crate) fn checked_inc(n: u32) -> Result<u32, PrimitiveError> {
    n.checked_add(1).ok_or(PrimitiveError::LimitExceeded)
}

impl DoubleRatchetState {
    pub fn init_alice(
        sk: &[u8; 32],
        bob_dh_public: &X25519Public,
        max_skip: u32,
    ) -> Result<Self, PrimitiveError> {
        let dhs = X25519Secret::generate()?;
        let dh_out = Zeroizing::new(dhs.diffie_hellman_checked(bob_dh_public)?);
        let (rk, cks) = kdf_rk(sk, &dh_out)?;
        Ok(Self {
            dhs: Some(dhs),
            dhr: Some(*bob_dh_public),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: SkippedKeys::default(),
            max_skip,
        })
    }

    pub fn init_bob(sk: &[u8; 32], bob_dh_keypair: X25519Secret, max_skip: u32) -> Self {
        Self {
            dhs: Some(bob_dh_keypair),
            dhr: None,
            rk: *sk,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: SkippedKeys::default(),
            max_skip,
        }
    }

    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        ad: &[u8],
    ) -> Result<(Header, Vec<u8>), PrimitiveError> {
        let old_cks = self.cks;
        let old_ns = self.ns;
        let (ns, mut mk) = match self.ratchet_send_key() {
            Ok(value) => value,
            Err(error) => {
                self.cks = old_cks;
                self.ns = old_ns;
                return Err(error);
            }
        };
        let result = (|| {
            let dhs = self.dhs.as_ref().ok_or(PrimitiveError::Internal)?;
            let header = Header {
                dh: dhs.public_key(),
                pn: self.pn,
                n: ns,
            };
            let associated = concat_ad(ad, &header);
            let (key, nonce) = aead_from_mk(&mk)?;
            let ciphertext = aead::seal(&key, &nonce, plaintext, &associated)?;
            Ok((header, ciphertext))
        })();
        mk.zeroize();
        if result.is_err() {
            self.cks = old_cks;
            self.ns = old_ns;
        }
        result
    }

    pub fn decrypt(
        &mut self,
        header: &Header,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, PrimitiveError> {
        let snapshot = RatchetScalarSnapshot::capture(self);
        let mut journal = SkippedMutationJournal::default();
        let mut mk = match self.ratchet_receive_key_journaled(header, &mut journal) {
            Ok(mk) => mk,
            Err(error) => {
                self.rollback_receive(&snapshot, &mut journal)?;
                return Err(error);
            }
        };
        let associated = concat_ad(ad, header);
        let plaintext = match aead_from_mk(&mk) {
            Ok((key, nonce)) => aead::open(&key, &nonce, ciphertext, &associated),
            Err(error) => Err(error),
        };
        mk.zeroize();
        match plaintext {
            Ok(plaintext) => Ok(plaintext),
            Err(error) => {
                self.rollback_receive(&snapshot, &mut journal)?;
                Err(error)
            }
        }
    }

    /// Derive a sending message key transactionally for Triple Ratchet.
    pub fn send_message_key(&mut self) -> Result<(Header, [u8; 32]), PrimitiveError> {
        let old_cks = self.cks;
        let old_ns = self.ns;
        let (ns, mut mk) = match self.ratchet_send_key() {
            Ok(value) => value,
            Err(error) => {
                self.cks = old_cks;
                self.ns = old_ns;
                return Err(error);
            }
        };
        let Some(dhs) = self.dhs.as_ref() else {
            self.cks = old_cks;
            self.ns = old_ns;
            mk.zeroize();
            return Err(PrimitiveError::Internal);
        };
        Ok((
            Header {
                dh: dhs.public_key(),
                pn: self.pn,
                n: ns,
            },
            mk,
        ))
    }

    /// Derive a receiving message key transactionally for Triple Ratchet.
    pub fn receive_message_key(&mut self, header: &Header) -> Result<[u8; 32], PrimitiveError> {
        let snapshot = RatchetScalarSnapshot::capture(self);
        let mut journal = SkippedMutationJournal::default();
        match self.ratchet_receive_key_journaled(header, &mut journal) {
            Ok(mk) => Ok(mk),
            Err(error) => {
                self.rollback_receive(&snapshot, &mut journal)?;
                Err(error)
            }
        }
    }

    fn ratchet_send_key(&mut self) -> Result<(u32, [u8; 32]), PrimitiveError> {
        let cks = self.cks.ok_or(PrimitiveError::Internal)?;
        let next_ns = checked_inc(self.ns)?;
        let (new_cks, mk) = kdf_ck(&cks)?;
        let ns = self.ns;
        self.cks = Some(new_cks);
        self.ns = next_ns;
        Ok((ns, mk))
    }

    fn ratchet_receive_key_journaled(
        &mut self,
        header: &Header,
        journal: &mut SkippedMutationJournal,
    ) -> Result<[u8; 32], PrimitiveError> {
        let skipped_key = (header.dh.to_bytes(), header.n);
        if let Some(mk) = self.mkskipped.remove(&skipped_key) {
            journal.removed = Some((skipped_key, mk));
            return Ok(mk);
        }
        if self.dhr.map(|dh| dh.to_bytes()) != Some(header.dh.to_bytes()) {
            self.skip_message_keys_journaled(header.pn, journal)?;
            self.dh_ratchet(header)?;
        }
        self.skip_message_keys_journaled(header.n, journal)?;
        let ckr = self.ckr.ok_or(PrimitiveError::Internal)?;
        let next_nr = checked_inc(self.nr)?;
        let (new_ckr, mk) = kdf_ck(&ckr)?;
        self.ckr = Some(new_ckr);
        self.nr = next_nr;
        Ok(mk)
    }

    fn skip_message_keys_journaled(
        &mut self,
        until: u32,
        journal: &mut SkippedMutationJournal,
    ) -> Result<(), PrimitiveError> {
        let limit = self
            .nr
            .checked_add(self.max_skip)
            .ok_or(PrimitiveError::LimitExceeded)?;
        if limit < until {
            return Err(PrimitiveError::LimitExceeded);
        }
        if let Some(mut ckr) = self.ckr {
            while self.nr < until {
                if self.mkskipped.len() as u32 >= self.max_skip {
                    return Err(PrimitiveError::LimitExceeded);
                }
                let next_nr = checked_inc(self.nr)?;
                let (new_ckr, mk) = kdf_ck(&ckr)?;
                let dhr = self.dhr.ok_or(PrimitiveError::Internal)?;
                let key = (dhr.to_bytes(), self.nr);
                self.mkskipped.insert_unique(key, mk)?;
                journal.inserted.push(key);
                ckr = new_ckr;
                self.nr = next_nr;
            }
            self.ckr = Some(ckr);
        }
        Ok(())
    }

    /// Perform the two DH root-ratchet KDFs without committing any field until
    /// both peer DH operations have passed the all-zero contributory check and
    /// both KDFs have succeeded.
    fn dh_ratchet(&mut self, header: &Header) -> Result<(), PrimitiveError> {
        let current_dhs = self.dhs.as_ref().ok_or(PrimitiveError::Internal)?;
        let dh_out1 = Zeroizing::new(current_dhs.diffie_hellman_checked(&header.dh)?);
        let (rk1, ckr) = kdf_rk(&self.rk, &dh_out1)?;

        let new_dhs = X25519Secret::generate()?;
        let dh_out2 = Zeroizing::new(new_dhs.diffie_hellman_checked(&header.dh)?);
        let (rk2, cks) = kdf_rk(&rk1, &dh_out2)?;

        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(header.dh);
        self.rk = rk2;
        self.ckr = Some(ckr);
        self.cks = Some(cks);
        self.dhs = Some(new_dhs);
        Ok(())
    }

    fn rollback_receive(
        &mut self,
        snapshot: &RatchetScalarSnapshot,
        journal: &mut SkippedMutationJournal,
    ) -> Result<(), PrimitiveError> {
        for key in journal.inserted.drain(..).rev() {
            let mut mk = self
                .mkskipped
                .remove(&key)
                .ok_or(PrimitiveError::Internal)?;
            mk.zeroize();
        }
        if let Some((key, mk)) = journal.removed.take() {
            self.mkskipped.insert_unique(key, mk)?;
        }
        self.dhs = snapshot
            .dhs
            .as_ref()
            .map(|secret| X25519Secret::from_bytes(secret.to_bytes()));
        self.dhr = snapshot.dhr;
        self.rk = snapshot.rk;
        self.cks = snapshot.cks;
        self.ckr = snapshot.ckr;
        self.ns = snapshot.ns;
        self.nr = snapshot.nr;
        self.pn = snapshot.pn;
        Ok(())
    }

    pub fn clone_for_trial(&self) -> Self {
        Self {
            dhs: self
                .dhs
                .as_ref()
                .map(|secret| X25519Secret::from_bytes(secret.to_bytes())),
            dhr: self.dhr,
            rk: self.rk,
            cks: self.cks,
            ckr: self.ckr,
            ns: self.ns,
            nr: self.nr,
            pn: self.pn,
            mkskipped: self.mkskipped.clone(),
            max_skip: self.max_skip,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match &self.dhs {
            Some(secret) => {
                out.push(1);
                out.extend_from_slice(&secret.to_bytes());
            }
            None => out.push(0),
        }
        match &self.dhr {
            Some(public) => {
                out.push(1);
                out.extend_from_slice(&public.to_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.rk);
        write_opt32(&mut out, self.cks.as_ref());
        write_opt32(&mut out, self.ckr.as_ref());
        out.extend_from_slice(&self.ns.to_le_bytes());
        out.extend_from_slice(&self.nr.to_le_bytes());
        out.extend_from_slice(&self.pn.to_le_bytes());
        out.extend_from_slice(&self.max_skip.to_le_bytes());
        let mut skipped: Vec<(SkipKey, [u8; 32])> = self
            .mkskipped
            .iter()
            .map(|(key, mk)| (*key, *mk))
            .collect();
        skipped.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        out.extend_from_slice(&(skipped.len() as u32).to_le_bytes());
        for ((pk, n), mut mk) in skipped {
            out.extend_from_slice(&pk);
            out.extend_from_slice(&n.to_le_bytes());
            out.extend_from_slice(&mk);
            mk.zeroize();
        }
        out
    }

    pub fn deserialize(data: &[u8], max_skip: u32) -> Result<Self, PrimitiveError> {
        let mut i = 0usize;
        let dhs = read_opt32(data, &mut i)?.map(X25519Secret::from_bytes);
        let dhr = match read_opt32(data, &mut i)? {
            Some(bytes) => Some(X25519Public::from_bytes(bytes)?),
            None => None,
        };
        let mut rk = [0u8; 32];
        rk.copy_from_slice(take(data, &mut i, 32)?);
        let cks = read_opt32(data, &mut i)?;
        let ckr = read_opt32(data, &mut i)?;
        let ns = read_u32(data, &mut i)?;
        let nr = read_u32(data, &mut i)?;
        let pn = read_u32(data, &mut i)?;
        let stored_max = read_u32(data, &mut i)?;
        if stored_max != max_skip {
            return Err(PrimitiveError::InvalidLength);
        }
        let count = read_u32(data, &mut i)? as usize;
        if count > max_skip as usize {
            return Err(PrimitiveError::LimitExceeded);
        }
        let needed = count
            .checked_mul(68)
            .ok_or(PrimitiveError::LimitExceeded)?;
        if data.len().saturating_sub(i) != needed {
            return Err(PrimitiveError::InvalidLength);
        }
        let mut mkskipped = SkippedKeys::default();
        for _ in 0..count {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(take(data, &mut i, 32)?);
            let n = read_u32(data, &mut i)?;
            let mut mk = [0u8; 32];
            mk.copy_from_slice(take(data, &mut i, 32)?);
            if mkskipped.insert_unique((pk, n), mk).is_err() {
                return Err(PrimitiveError::InvalidLength);
            }
        }
        if i != data.len() {
            return Err(PrimitiveError::InvalidLength);
        }
        Ok(Self {
            dhs,
            dhr,
            rk,
            cks,
            ckr,
            ns,
            nr,
            pn,
            mkskipped,
            max_skip,
        })
    }

    pub fn skipped_count(&self) -> usize {
        self.mkskipped.len()
    }
}

fn take<'a>(data: &'a [u8], i: &mut usize, n: usize) -> Result<&'a [u8], PrimitiveError> {
    let end = i.checked_add(n).ok_or(PrimitiveError::LimitExceeded)?;
    if end > data.len() {
        return Err(PrimitiveError::InvalidLength);
    }
    let out = &data[*i..end];
    *i = end;
    Ok(out)
}

fn read_u32(data: &[u8], i: &mut usize) -> Result<u32, PrimitiveError> {
    Ok(u32::from_le_bytes(take(data, i, 4)?.try_into().unwrap()))
}

fn write_opt32(out: &mut Vec<u8>, value: Option<&[u8; 32]>) {
    match value {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(value);
        }
        None => out.push(0),
    }
}

fn read_opt32(data: &[u8], i: &mut usize) -> Result<Option<[u8; 32]>, PrimitiveError> {
    match take(data, i, 1)?[0] {
        0 => Ok(None),
        1 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(take(data, i, 32)?);
            Ok(Some(out))
        }
        _ => Err(PrimitiveError::InvalidLength),
    }
}

fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), PrimitiveError> {
    let mut okm = [0u8; 64];
    if let Err(error) = hkdf_extract_expand(Some(rk), dh_out, LABELS::DR_ROOT, &mut okm) {
        okm.zeroize();
        return Err(error);
    }
    let mut new_rk = [0u8; 32];
    let mut ck = [0u8; 32];
    new_rk.copy_from_slice(&okm[..32]);
    ck.copy_from_slice(&okm[32..]);
    okm.zeroize();
    Ok((new_rk, ck))
}

fn kdf_ck(ck: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), PrimitiveError> {
    let mk = crate::primitives::kdf::hmac_sha256(ck, &[0x01]);
    let new_ck = crate::primitives::kdf::hmac_sha256(ck, &[0x02]);
    Ok((new_ck, mk))
}

fn aead_from_mk(mk: &[u8; 32]) -> Result<(AeadKey, [u8; 12]), PrimitiveError> {
    let salt = [0u8; 32];
    let mut okm = [0u8; 44];
    if let Err(error) = hkdf_extract_expand(Some(&salt), mk, LABELS::DR_MESSAGE, &mut okm) {
        okm.zeroize();
        return Err(error);
    }
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..]);
    okm.zeroize();
    Ok((AeadKey::from_bytes(key), nonce))
}

fn concat_ad(ad: &[u8], header: &Header) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + ad.len() + 40);
    out.extend_from_slice(&(ad.len() as u64).to_le_bytes());
    out.extend_from_slice(ad);
    out.extend_from_slice(&header.encode());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_sk() -> [u8; 32] {
        let mut sk = [0u8; 32];
        crate::primitives::random::fill_random(&mut sk).unwrap();
        sk
    }

    fn low_order_public() -> X25519Public {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        X25519Public::from_bytes(bytes).unwrap()
    }

    #[test]
    fn alice_init_rejects_noncontributory_peer_dh() {
        assert!(matches!(
            DoubleRatchetState::init_alice(&fresh_sk(), &low_order_public(), DEFAULT_MAX_SKIP),
            Err(PrimitiveError::InvalidPublicKey)
        ));
    }

    #[test]
    fn low_order_ratchet_header_fails_without_state_change() {
        let sk = fresh_sk();
        let bob_dh = X25519Secret::generate().unwrap();
        let mut bob = DoubleRatchetState::init_bob(&sk, bob_dh, DEFAULT_MAX_SKIP);
        let before = bob.serialize();
        let header = Header {
            dh: low_order_public(),
            pn: 0,
            n: 0,
        };
        assert!(matches!(
            bob.decrypt(&header, &[0u8; 16], b"ad"),
            Err(PrimitiveError::InvalidPublicKey)
        ));
        assert_eq!(before, bob.serialize());
    }

    #[test]
    fn sequence_a1_a2_a3_b1_b2_a4() {
        let sk = fresh_sk();
        let bob_dh = X25519Secret::generate().unwrap();
        let bob_pub = bob_dh.public_key();
        let mut alice = DoubleRatchetState::init_alice(&sk, &bob_pub, DEFAULT_MAX_SKIP).unwrap();
        let mut bob = DoubleRatchetState::init_bob(&sk, bob_dh, DEFAULT_MAX_SKIP);
        for message in [b"A1".as_slice(), b"A2", b"A3"] {
            let (header, ciphertext) = alice.encrypt(message, b"ad").unwrap();
            assert_eq!(bob.decrypt(&header, &ciphertext, b"ad").unwrap(), message);
        }
        for message in [b"B1".as_slice(), b"B2"] {
            let (header, ciphertext) = bob.encrypt(message, b"ad").unwrap();
            assert_eq!(alice.decrypt(&header, &ciphertext, b"ad").unwrap(), message);
        }
        let (header, ciphertext) = alice.encrypt(b"A4", b"ad").unwrap();
        assert_eq!(bob.decrypt(&header, &ciphertext, b"ad").unwrap(), b"A4");
    }

    #[test]
    fn tampered_message_leaves_state_unchanged() {
        let sk = fresh_sk();
        let bob_dh = X25519Secret::generate().unwrap();
        let mut alice =
            DoubleRatchetState::init_alice(&sk, &bob_dh.public_key(), DEFAULT_MAX_SKIP).unwrap();
        let mut bob = DoubleRatchetState::init_bob(&sk, bob_dh, DEFAULT_MAX_SKIP);
        let (header, mut ciphertext) = alice.encrypt(b"secret", b"ad").unwrap();
        let before = bob.serialize();
        if let Some(byte) = ciphertext.last_mut() {
            *byte ^= 0xff;
        }
        assert!(bob.decrypt(&header, &ciphertext, b"ad").is_err());
        assert_eq!(before, bob.serialize());
    }

    #[test]
    fn tampered_out_of_order_message_restores_skipped_map() {
        let sk = fresh_sk();
        let bob_dh = X25519Secret::generate().unwrap();
        let mut alice =
            DoubleRatchetState::init_alice(&sk, &bob_dh.public_key(), DEFAULT_MAX_SKIP).unwrap();
        let mut bob = DoubleRatchetState::init_bob(&sk, bob_dh, DEFAULT_MAX_SKIP);
        let (h1, c1) = alice.encrypt(b"1", b"ad").unwrap();
        let (h2, c2) = alice.encrypt(b"2", b"ad").unwrap();
        let (h3, mut c3) = alice.encrypt(b"3", b"ad").unwrap();
        assert_eq!(bob.decrypt(&h1, &c1, b"ad").unwrap(), b"1");
        let before = bob.serialize();
        c3[0] ^= 1;
        assert!(bob.decrypt(&h3, &c3, b"ad").is_err());
        assert_eq!(before, bob.serialize());
        assert_eq!(bob.decrypt(&h2, &c2, b"ad").unwrap(), b"2");
    }

    #[test]
    fn max_skip_protects_against_explosion() {
        let sk = fresh_sk();
        let bob_dh = X25519Secret::generate().unwrap();
        let mut alice = DoubleRatchetState::init_alice(&sk, &bob_dh.public_key(), 5).unwrap();
        let mut bob = DoubleRatchetState::init_bob(&sk, bob_dh, 5);
        let (h0, c0) = alice.encrypt(b"0", b"ad").unwrap();
        bob.decrypt(&h0, &c0, b"ad").unwrap();
        let (mut header, ciphertext) = alice.encrypt(b"far", b"ad").unwrap();
        header.n = 10_000;
        assert!(bob.decrypt(&header, &ciphertext, b"ad").is_err());
        assert!(bob.skipped_count() <= 5);
    }

    #[test]
    fn serialize_reload_preserves_session() {
        let sk = fresh_sk();
        let bob_dh = X25519Secret::generate().unwrap();
        let mut alice =
            DoubleRatchetState::init_alice(&sk, &bob_dh.public_key(), DEFAULT_MAX_SKIP).unwrap();
        let bob = DoubleRatchetState::init_bob(&sk, bob_dh, DEFAULT_MAX_SKIP);
        let (header, ciphertext) = alice.encrypt(b"before-reload", b"ad").unwrap();
        let mut bob2 = DoubleRatchetState::deserialize(&bob.serialize(), DEFAULT_MAX_SKIP).unwrap();
        assert_eq!(
            bob2.decrypt(&header, &ciphertext, b"ad").unwrap(),
            b"before-reload"
        );
        let (header2, ciphertext2) = bob2.encrypt(b"after-reload", b"ad").unwrap();
        assert_eq!(
            alice.decrypt(&header2, &ciphertext2, b"ad").unwrap(),
            b"after-reload"
        );
    }

    #[test]
    fn out_of_order_within_bound() {
        let sk = fresh_sk();
        let bob_dh = X25519Secret::generate().unwrap();
        let mut alice =
            DoubleRatchetState::init_alice(&sk, &bob_dh.public_key(), DEFAULT_MAX_SKIP).unwrap();
        let mut bob = DoubleRatchetState::init_bob(&sk, bob_dh, DEFAULT_MAX_SKIP);
        let (h1, c1) = alice.encrypt(b"1", b"ad").unwrap();
        let (h2, c2) = alice.encrypt(b"2", b"ad").unwrap();
        let (h3, c3) = alice.encrypt(b"3", b"ad").unwrap();
        assert_eq!(bob.decrypt(&h1, &c1, b"ad").unwrap(), b"1");
        assert_eq!(bob.decrypt(&h3, &c3, b"ad").unwrap(), b"3");
        assert_eq!(bob.decrypt(&h2, &c2, b"ad").unwrap(), b"2");
    }

    #[test]
    fn deserialize_rejects_noncanonical_presence_tag() {
        let sk = fresh_sk();
        let bob_dh = X25519Secret::generate().unwrap();
        let bob = DoubleRatchetState::init_bob(&sk, bob_dh, DEFAULT_MAX_SKIP);
        let mut blob = bob.serialize();
        blob[0] = 2;
        assert!(DoubleRatchetState::deserialize(&blob, DEFAULT_MAX_SKIP).is_err());
    }

    #[test]
    fn deserialize_rejects_max_skip_mismatch() {
        let sk = fresh_sk();
        let bob_dh = X25519Secret::generate().unwrap();
        let bob = DoubleRatchetState::init_bob(&sk, bob_dh, DEFAULT_MAX_SKIP);
        assert!(
            DoubleRatchetState::deserialize(&bob.serialize(), DEFAULT_MAX_SKIP - 1).is_err()
        );
    }

    #[test]
    fn deserialize_rejects_trailing_bytes() {
        let sk = fresh_sk();
        let bob_dh = X25519Secret::generate().unwrap();
        let bob = DoubleRatchetState::init_bob(&sk, bob_dh, DEFAULT_MAX_SKIP);
        let mut blob = bob.serialize();
        blob.push(0);
        assert!(DoubleRatchetState::deserialize(&blob, DEFAULT_MAX_SKIP).is_err());
    }
}
