//! Double Ratchet — Header Encryption variant (optional profile).
//!
//! Implemented from the public Double Ratchet Revision 4 specification
//! (Header Encryption section). No libsignal code was consulted.
//!
//! Goal: reduce metadata visible to passive observers (session linkage,
//! message ordering within a session).
//!
//! This is an **optional** profile. See docs/HEADER_ENCRYPTION.md for the
//! full tradeoff analysis.

use std::collections::{HashMap, HashSet};

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::primitives::aead::{self, AeadKey, TAG_LEN};
use crate::primitives::error::PrimitiveError;
use crate::primitives::kdf::{hkdf_extract_expand, LABELS};
use crate::primitives::x25519::{X25519Public, X25519Secret};
use crate::ratchet::Header;
#[cfg(test)]
use crate::ratchet::DEFAULT_MAX_SKIP;

type HeSkipKey = ([u8; 32], u32);
const HEADER_LEN: usize = 40;
const HEADER_NONCE_LEN: usize = 12;
const ENCRYPTED_HEADER_LEN: usize = HEADER_NONCE_LEN + HEADER_LEN + TAG_LEN;

#[derive(Clone, Default)]
struct HeSkippedKeys(HashMap<HeSkipKey, [u8; 32]>);

impl Zeroize for HeSkippedKeys {
    fn zeroize(&mut self) {
        for mk in self.0.values_mut() {
            mk.zeroize();
        }
        self.0.clear();
    }
}

impl Drop for HeSkippedKeys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl HeSkippedKeys {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn remove(&mut self, key: &HeSkipKey) -> Option<[u8; 32]> {
        self.0.remove(key)
    }

    fn insert_unique(&mut self, key: HeSkipKey, mut mk: [u8; 32]) -> Result<(), PrimitiveError> {
        if self.0.contains_key(&key) {
            mk.zeroize();
            return Err(PrimitiveError::Internal);
        }
        self.0.insert(key, mk);
        Ok(())
    }

    fn header_keys(&self) -> HashSet<[u8; 32]> {
        self.0.keys().map(|(hk, _)| *hk).collect()
    }

    fn iter(&self) -> impl Iterator<Item = (&HeSkipKey, &[u8; 32])> {
        self.0.iter()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HeaderEncryptState {
    dhs: Option<X25519Secret>,
    #[zeroize(skip)]
    dhr: Option<X25519Public>,
    rk: [u8; 32],
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    hks: Option<[u8; 32]>,
    hkr: Option<[u8; 32]>,
    nhks: Option<[u8; 32]>,
    nhkr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    mkskipped: HeSkippedKeys,
    max_skip: u32,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct HeScalarSnapshot {
    dhs: Option<X25519Secret>,
    #[zeroize(skip)]
    dhr: Option<X25519Public>,
    rk: [u8; 32],
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    hks: Option<[u8; 32]>,
    hkr: Option<[u8; 32]>,
    nhks: Option<[u8; 32]>,
    nhkr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
}

impl HeScalarSnapshot {
    fn capture(state: &HeaderEncryptState) -> Self {
        Self {
            dhs: state
                .dhs
                .as_ref()
                .map(|secret| X25519Secret::from_bytes(secret.to_bytes())),
            dhr: state.dhr,
            rk: state.rk,
            cks: state.cks,
            ckr: state.ckr,
            hks: state.hks,
            hkr: state.hkr,
            nhks: state.nhks,
            nhkr: state.nhkr,
            ns: state.ns,
            nr: state.nr,
            pn: state.pn,
        }
    }
}

#[derive(Default)]
struct HeSkippedMutationJournal {
    inserted: Vec<HeSkipKey>,
    removed: Option<(HeSkipKey, [u8; 32])>,
}

impl Drop for HeSkippedMutationJournal {
    fn drop(&mut self) {
        if let Some((_, mut mk)) = self.removed.take() {
            mk.zeroize();
        }
    }
}

impl HeaderEncryptState {
    pub fn init_alice(
        sk: &[u8; 32],
        bob_dh_public: &X25519Public,
        shared_hka: &[u8; 32],
        shared_nhkb: &[u8; 32],
        max_skip: u32,
    ) -> Result<Self, PrimitiveError> {
        let dhs = X25519Secret::generate()?;
        let dh_out = Zeroizing::new(dhs.diffie_hellman_checked(bob_dh_public)?);
        let (rk, cks, nhks) = kdf_rk_he(sk, &dh_out)?;
        Ok(Self {
            dhs: Some(dhs),
            dhr: Some(*bob_dh_public),
            rk,
            cks: Some(cks),
            ckr: None,
            hks: Some(*shared_hka),
            hkr: None,
            nhks: Some(nhks),
            nhkr: Some(*shared_nhkb),
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HeSkippedKeys::default(),
            max_skip,
        })
    }

    pub fn init_bob(
        sk: &[u8; 32],
        bob_dh_keypair: X25519Secret,
        shared_hka: &[u8; 32],
        shared_nhkb: &[u8; 32],
        max_skip: u32,
    ) -> Self {
        Self {
            dhs: Some(bob_dh_keypair),
            dhr: None,
            rk: *sk,
            cks: None,
            ckr: None,
            hks: None,
            nhks: Some(*shared_nhkb),
            hkr: None,
            nhkr: Some(*shared_hka),
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HeSkippedKeys::default(),
            max_skip,
        }
    }

    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        ad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), PrimitiveError> {
        let old_cks = self.cks;
        let old_ns = self.ns;
        let cks = self.cks.ok_or(PrimitiveError::Internal)?;
        let next_ns = crate::ratchet::checked_inc(self.ns)?;
        let (new_cks, mut mk) = kdf_ck(&cks)?;
        let ns = self.ns;
        self.cks = Some(new_cks);
        self.ns = next_ns;

        let result = (|| {
            let dhs = self.dhs.as_ref().ok_or(PrimitiveError::Internal)?;
            let header = Header {
                dh: dhs.public_key(),
                pn: self.pn,
                n: ns,
            };
            let hks = self.hks.ok_or(PrimitiveError::Internal)?;
            let enc_header = hencrypt(&hks, &header.encode())?;
            let associated = concat_ad(ad, &enc_header);
            let key = AeadKey::from_bytes(mk);
            let nonce = derive_nonce(&mk);
            let ct = aead::seal(&key, &nonce, plaintext, &associated)?;
            Ok((enc_header, ct))
        })();
        mk.zeroize();
        if result.is_err() {
            self.cks = old_cks;
            self.ns = old_ns;
        }
        result
    }

    /// Authenticate and advance receive state without cloning the skipped-key
    /// map. Only scalar ratchet fields are snapshotted; skipped-key insertions
    /// and removals are recorded in a bounded mutation journal and reversed on
    /// any header/KDF/AEAD failure.
    pub fn decrypt(
        &mut self,
        enc_header: &[u8],
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, PrimitiveError> {
        let snapshot = HeScalarSnapshot::capture(self);
        let mut journal = HeSkippedMutationJournal::default();
        let mut mk = match self.receive_key_journaled(enc_header, &mut journal) {
            Ok(mk) => mk,
            Err(error) => {
                self.rollback_receive(&snapshot, &mut journal)?;
                return Err(error);
            }
        };
        let associated = concat_ad(ad, enc_header);
        let key = AeadKey::from_bytes(mk);
        let nonce = derive_nonce(&mk);
        let plaintext = aead::open(&key, &nonce, ciphertext, &associated);
        mk.zeroize();
        match plaintext {
            Ok(plaintext) => Ok(plaintext),
            Err(error) => {
                self.rollback_receive(&snapshot, &mut journal)?;
                Err(error)
            }
        }
    }

    fn receive_key_journaled(
        &mut self,
        enc_header: &[u8],
        journal: &mut HeSkippedMutationJournal,
    ) -> Result<[u8; 32], PrimitiveError> {
        if let Some(mk) = self.try_skipped_journaled(enc_header, journal)? {
            return Ok(mk);
        }

        if let Some(hkr) = self.hkr {
            if let Ok(header) = hdecrypt(&hkr, enc_header) {
                self.skip_message_keys_journaled(header.n, journal)?;
                let ckr = self.ckr.ok_or(PrimitiveError::Internal)?;
                let next_nr = crate::ratchet::checked_inc(self.nr)?;
                let (new_ckr, mk) = kdf_ck(&ckr)?;
                self.ckr = Some(new_ckr);
                self.nr = next_nr;
                return Ok(mk);
            }
        }

        if let Some(nhkr) = self.nhkr {
            if let Ok(header) = hdecrypt(&nhkr, enc_header) {
                self.skip_message_keys_journaled(header.pn, journal)?;
                self.dh_ratchet(&header)?;
                self.skip_message_keys_journaled(header.n, journal)?;
                let ckr = self.ckr.ok_or(PrimitiveError::Internal)?;
                let next_nr = crate::ratchet::checked_inc(self.nr)?;
                let (new_ckr, mk) = kdf_ck(&ckr)?;
                self.ckr = Some(new_ckr);
                self.nr = next_nr;
                return Ok(mk);
            }
        }

        Err(PrimitiveError::AeadAuthFailed)
    }

    fn try_skipped_journaled(
        &mut self,
        enc_header: &[u8],
        journal: &mut HeSkippedMutationJournal,
    ) -> Result<Option<[u8; 32]>, PrimitiveError> {
        for hk in self.mkskipped.header_keys() {
            if let Ok(header) = hdecrypt(&hk, enc_header) {
                let key = (hk, header.n);
                if let Some(mk) = self.mkskipped.remove(&key) {
                    if journal.removed.is_some() {
                        self.mkskipped.insert_unique(key, mk)?;
                        return Err(PrimitiveError::Internal);
                    }
                    journal.removed = Some((key, mk));
                    return Ok(journal.removed.as_ref().map(|(_, value)| *value));
                }
            }
        }
        Ok(None)
    }

    fn skip_message_keys_journaled(
        &mut self,
        until: u32,
        journal: &mut HeSkippedMutationJournal,
    ) -> Result<(), PrimitiveError> {
        let limit = self
            .nr
            .checked_add(self.max_skip)
            .ok_or(PrimitiveError::LimitExceeded)?;
        if limit < until {
            return Err(PrimitiveError::LimitExceeded);
        }
        if let (Some(mut ckr), Some(hkr)) = (self.ckr, self.hkr) {
            while self.nr < until {
                if self.mkskipped.len() as u32 >= self.max_skip {
                    return Err(PrimitiveError::LimitExceeded);
                }
                let next_nr = crate::ratchet::checked_inc(self.nr)?;
                let (new_ckr, mk) = kdf_ck(&ckr)?;
                let key = (hkr, self.nr);
                self.mkskipped.insert_unique(key, mk)?;
                journal.inserted.push(key);
                ckr = new_ckr;
                self.nr = next_nr;
            }
            self.ckr = Some(ckr);
        }
        Ok(())
    }

    /// Perform both checked X25519 root-ratchet transitions before committing
    /// any ratchet scalar. Non-contributory/low-order headers therefore cannot
    /// partially advance HE state.
    fn dh_ratchet(&mut self, header: &Header) -> Result<(), PrimitiveError> {
        let dhs = self.dhs.as_ref().ok_or(PrimitiveError::Internal)?;
        let dh_out1 = Zeroizing::new(dhs.diffie_hellman_checked(&header.dh)?);
        let (rk1, ckr, nhkr) = kdf_rk_he(&self.rk, &dh_out1)?;

        let new_dhs = X25519Secret::generate()?;
        let dh_out2 = Zeroizing::new(new_dhs.diffie_hellman_checked(&header.dh)?);
        let (rk2, cks, nhks) = kdf_rk_he(&rk1, &dh_out2)?;

        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.hks = self.nhks;
        self.hkr = self.nhkr;
        self.dhr = Some(header.dh);
        self.rk = rk2;
        self.ckr = Some(ckr);
        self.nhkr = Some(nhkr);
        self.cks = Some(cks);
        self.nhks = Some(nhks);
        self.dhs = Some(new_dhs);
        Ok(())
    }

    fn rollback_receive(
        &mut self,
        snapshot: &HeScalarSnapshot,
        journal: &mut HeSkippedMutationJournal,
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
        self.hks = snapshot.hks;
        self.hkr = snapshot.hkr;
        self.nhks = snapshot.nhks;
        self.nhkr = snapshot.nhkr;
        self.ns = snapshot.ns;
        self.nr = snapshot.nr;
        self.pn = snapshot.pn;
        Ok(())
    }

    fn write_opt32(out: &mut Vec<u8>, v: Option<&[u8; 32]>) {
        match v {
            Some(b) => {
                out.push(1);
                out.extend_from_slice(b);
            }
            None => out.push(0),
        }
    }

    fn read_opt32(data: &[u8], i: &mut usize) -> Result<Option<[u8; 32]>, PrimitiveError> {
        if *i >= data.len() {
            return Err(PrimitiveError::InvalidLength);
        }
        let tag = data[*i];
        *i += 1;
        match tag {
            0 => Ok(None),
            1 => {
                let mut b = [0u8; 32];
                b.copy_from_slice(take(data, i, 32)?);
                Ok(Some(b))
            }
            _ => Err(PrimitiveError::InvalidLength),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match &self.dhs {
            Some(s) => {
                out.push(1);
                out.extend_from_slice(&s.to_bytes());
            }
            None => out.push(0),
        }
        match &self.dhr {
            Some(p) => {
                out.push(1);
                out.extend_from_slice(&p.to_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.rk);
        Self::write_opt32(&mut out, self.cks.as_ref());
        Self::write_opt32(&mut out, self.ckr.as_ref());
        Self::write_opt32(&mut out, self.hks.as_ref());
        Self::write_opt32(&mut out, self.hkr.as_ref());
        Self::write_opt32(&mut out, self.nhks.as_ref());
        Self::write_opt32(&mut out, self.nhkr.as_ref());
        out.extend_from_slice(&self.ns.to_le_bytes());
        out.extend_from_slice(&self.nr.to_le_bytes());
        out.extend_from_slice(&self.pn.to_le_bytes());
        out.extend_from_slice(&self.max_skip.to_le_bytes());

        let mut skipped: Vec<(HeSkipKey, [u8; 32])> =
            self.mkskipped.iter().map(|(key, mk)| (*key, *mk)).collect();
        skipped.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        out.extend_from_slice(&(skipped.len() as u32).to_le_bytes());
        for ((hk, n), mut mk) in skipped {
            out.extend_from_slice(&hk);
            out.extend_from_slice(&n.to_le_bytes());
            out.extend_from_slice(&mk);
            mk.zeroize();
        }
        out
    }

    pub fn deserialize(data: &[u8], max_skip: u32) -> Result<Self, PrimitiveError> {
        let mut i = 0usize;
        let dhs = Self::read_opt32(data, &mut i)?.map(X25519Secret::from_bytes);
        let dhr = match Self::read_opt32(data, &mut i)? {
            Some(b) => Some(X25519Public::from_bytes(b)?),
            None => None,
        };
        let mut rk = [0u8; 32];
        rk.copy_from_slice(take(data, &mut i, 32)?);
        let cks = Self::read_opt32(data, &mut i)?;
        let ckr = Self::read_opt32(data, &mut i)?;
        let hks = Self::read_opt32(data, &mut i)?;
        let hkr = Self::read_opt32(data, &mut i)?;
        let nhks = Self::read_opt32(data, &mut i)?;
        let nhkr = Self::read_opt32(data, &mut i)?;
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
        let needed = count.checked_mul(68).ok_or(PrimitiveError::LimitExceeded)?;
        if data.len().saturating_sub(i) != needed {
            return Err(PrimitiveError::InvalidLength);
        }

        let mut mkskipped = HeSkippedKeys::default();
        for _ in 0..count {
            let mut hk = [0u8; 32];
            hk.copy_from_slice(take(data, &mut i, 32)?);
            let n = read_u32(data, &mut i)?;
            let mut mk = [0u8; 32];
            mk.copy_from_slice(take(data, &mut i, 32)?);
            if mkskipped.insert_unique((hk, n), mk).is_err() {
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
            hks,
            hkr,
            nhks,
            nhkr,
            ns,
            nr,
            pn,
            mkskipped,
            max_skip,
        })
    }
}

#[allow(clippy::type_complexity)]
fn kdf_rk_he(
    rk: &[u8; 32],
    dh_out: &[u8; 32],
) -> Result<([u8; 32], [u8; 32], [u8; 32]), PrimitiveError> {
    let mut okm = [0u8; 96];
    if let Err(error) = hkdf_extract_expand(Some(rk), dh_out, LABELS::DR_ROOT, &mut okm) {
        okm.zeroize();
        return Err(error);
    }
    let mut new_rk = [0u8; 32];
    let mut ck = [0u8; 32];
    let mut nhk = [0u8; 32];
    new_rk.copy_from_slice(&okm[0..32]);
    ck.copy_from_slice(&okm[32..64]);
    nhk.copy_from_slice(&okm[64..96]);
    okm.zeroize();
    Ok((new_rk, ck, nhk))
}

fn kdf_ck(ck: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), PrimitiveError> {
    let mut okm = [0u8; 64];
    if let Err(error) = hkdf_extract_expand(None, ck, LABELS::DR_CHAIN, &mut okm) {
        okm.zeroize();
        return Err(error);
    }
    let mut new_ck = [0u8; 32];
    let mut mk = [0u8; 32];
    new_ck.copy_from_slice(&okm[0..32]);
    mk.copy_from_slice(&okm[32..64]);
    let mut mk2 = [0u8; 32];
    let result = hkdf_extract_expand(None, &mk, LABELS::DR_MESSAGE, &mut mk2);
    mk.zeroize();
    okm.zeroize();
    if let Err(error) = result {
        mk2.zeroize();
        return Err(error);
    }
    Ok((new_ck, mk2))
}

fn hencrypt(hk: &[u8; 32], header_bytes: &[u8]) -> Result<Vec<u8>, PrimitiveError> {
    if header_bytes.len() != HEADER_LEN {
        return Err(PrimitiveError::InvalidLength);
    }
    let mut nonce = [0u8; HEADER_NONCE_LEN];
    crate::primitives::random::fill_random(&mut nonce)?;
    let key = AeadKey::from_bytes(*hk);
    let mut out = nonce.to_vec();
    let ct = aead::seal(&key, &nonce, header_bytes, b"")?;
    out.extend_from_slice(&ct);
    if out.len() != ENCRYPTED_HEADER_LEN {
        out.zeroize();
        return Err(PrimitiveError::Internal);
    }
    Ok(out)
}

fn hdecrypt(hk: &[u8; 32], enc_header: &[u8]) -> Result<Header, PrimitiveError> {
    if enc_header.len() != ENCRYPTED_HEADER_LEN {
        return Err(PrimitiveError::InvalidLength);
    }
    let nonce: [u8; HEADER_NONCE_LEN] = enc_header[..HEADER_NONCE_LEN]
        .try_into()
        .map_err(|_| PrimitiveError::InvalidLength)?;
    let ct = &enc_header[HEADER_NONCE_LEN..];
    let key = AeadKey::from_bytes(*hk);
    let mut plain = aead::open(&key, &nonce, ct, b"")?;
    let result = Header::decode(&plain);
    plain.zeroize();
    result
}

fn concat_ad(ad: &[u8], enc_header: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + ad.len() + enc_header.len());
    out.extend_from_slice(&(ad.len() as u64).to_le_bytes());
    out.extend_from_slice(ad);
    out.extend_from_slice(enc_header);
    out
}

fn derive_nonce(mk: &[u8; 32]) -> [u8; 12] {
    let mut n = [0u8; 12];
    n.copy_from_slice(&mk[0..12]);
    n
}

fn take<'a>(data: &'a [u8], i: &mut usize, n: usize) -> Result<&'a [u8], PrimitiveError> {
    let end = i.checked_add(n).ok_or(PrimitiveError::LimitExceeded)?;
    if end > data.len() {
        return Err(PrimitiveError::InvalidLength);
    }
    let value = &data[*i..end];
    *i = end;
    Ok(value)
}

fn read_u32(data: &[u8], i: &mut usize) -> Result<u32, PrimitiveError> {
    Ok(u32::from_le_bytes(
        take(data, i, 4)?
            .try_into()
            .map_err(|_| PrimitiveError::InvalidLength)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (HeaderEncryptState, HeaderEncryptState) {
        let sk = [5u8; 32];
        let shared_hka = [1u8; 32];
        let shared_nhkb = [2u8; 32];
        let bob_dh = X25519Secret::generate().unwrap();
        let alice = HeaderEncryptState::init_alice(
            &sk,
            &bob_dh.public_key(),
            &shared_hka,
            &shared_nhkb,
            DEFAULT_MAX_SKIP,
        )
        .unwrap();
        let bob =
            HeaderEncryptState::init_bob(&sk, bob_dh, &shared_hka, &shared_nhkb, DEFAULT_MAX_SKIP);
        (alice, bob)
    }

    #[test]
    fn he_roundtrip() {
        let (mut alice, mut bob) = pair();
        let (eh, ct) = alice.encrypt(b"secret", b"ad").unwrap();
        assert_eq!(bob.decrypt(&eh, &ct, b"ad").unwrap(), b"secret");
        let (eh2, ct2) = bob.encrypt(b"reply", b"ad").unwrap();
        assert_eq!(alice.decrypt(&eh2, &ct2, b"ad").unwrap(), b"reply");

        let mut alice =
            HeaderEncryptState::deserialize(&alice.serialize(), DEFAULT_MAX_SKIP).unwrap();
        let mut bob = HeaderEncryptState::deserialize(&bob.serialize(), DEFAULT_MAX_SKIP).unwrap();
        let (eh3, ct3) = alice.encrypt(b"after-reload", b"ad").unwrap();
        assert_eq!(bob.decrypt(&eh3, &ct3, b"ad").unwrap(), b"after-reload");
    }

    #[test]
    fn failed_aead_rolls_back_scalars_and_skipped_mutations() {
        let (mut alice, mut bob) = pair();
        let (h0, c0) = alice.encrypt(b"zero", b"ad").unwrap();
        let (h1, c1) = alice.encrypt(b"one", b"ad").unwrap();
        assert_eq!(bob.decrypt(&h1, &c1, b"ad").unwrap(), b"one");
        let before = bob.serialize();

        let mut bad = c0.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(bob.decrypt(&h0, &bad, b"ad").is_err());
        assert_eq!(bob.serialize(), before);
        assert_eq!(bob.decrypt(&h0, &c0, b"ad").unwrap(), b"zero");
    }

    #[test]
    fn encrypted_header_encoding_is_canonical_length() {
        let (mut alice, mut bob) = pair();
        let (header, ct) = alice.encrypt(b"x", b"ad").unwrap();
        assert_eq!(header.len(), ENCRYPTED_HEADER_LEN);
        let before = bob.serialize();
        let mut trailing = header.clone();
        trailing.push(0);
        assert!(bob.decrypt(&trailing, &ct, b"ad").is_err());
        assert_eq!(bob.serialize(), before);
        assert!(bob
            .decrypt(&header[..header.len() - 1], &ct, b"ad")
            .is_err());
        assert_eq!(bob.serialize(), before);
    }

    #[test]
    fn init_rejects_nonzero_low_order_dh() {
        let sk = [5u8; 32];
        let shared_hka = [1u8; 32];
        let shared_nhkb = [2u8; 32];
        let mut low_order = [0u8; 32];
        low_order[0] = 1;
        let low_order = X25519Public::from_bytes(low_order).unwrap();
        assert!(matches!(
            HeaderEncryptState::init_alice(
                &sk,
                &low_order,
                &shared_hka,
                &shared_nhkb,
                DEFAULT_MAX_SKIP,
            ),
            Err(PrimitiveError::InvalidPublicKey)
        ));
    }

    #[test]
    fn dh_ratchet_rejects_low_order_transactionally() {
        let (_, mut bob) = pair();
        let before = bob.serialize();
        let mut low_order = [0u8; 32];
        low_order[0] = 1;
        let header = Header {
            dh: X25519Public::from_bytes(low_order).unwrap(),
            pn: 0,
            n: 0,
        };
        assert!(matches!(
            bob.dh_ratchet(&header),
            Err(PrimitiveError::InvalidPublicKey)
        ));
        assert_eq!(bob.serialize(), before);
    }

    #[test]
    fn deserialize_rejects_noncanonical_presence_tag() {
        let (_, bob) = pair();
        let mut blob = bob.serialize();
        blob[0] = 2;
        assert!(HeaderEncryptState::deserialize(&blob, DEFAULT_MAX_SKIP).is_err());
    }

    #[test]
    fn deserialize_rejects_max_skip_mismatch() {
        let (_, bob) = pair();
        assert!(HeaderEncryptState::deserialize(&bob.serialize(), DEFAULT_MAX_SKIP - 1).is_err());
    }

    #[test]
    fn deserialize_rejects_trailing_bytes() {
        let (_, bob) = pair();
        let mut blob = bob.serialize();
        blob.push(0);
        assert!(HeaderEncryptState::deserialize(&blob, DEFAULT_MAX_SKIP).is_err());
    }
}
