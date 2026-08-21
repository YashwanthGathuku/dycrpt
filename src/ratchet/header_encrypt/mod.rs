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

use std::collections::HashMap;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::primitives::aead::{self, AeadKey};
use crate::primitives::error::PrimitiveError;
use crate::primitives::kdf::{hkdf_extract_expand, LABELS};
use crate::primitives::x25519::{X25519Public, X25519Secret};
use crate::ratchet::Header;
#[cfg(test)]
use crate::ratchet::DEFAULT_MAX_SKIP;

/// Additional state for the Header Encryption variant.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HeaderEncryptState {
    dhs: Option<X25519Secret>,
    #[zeroize(skip)]
    dhr: Option<X25519Public>,
    rk: [u8; 32],
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    /// Sending / receiving header keys
    hks: Option<[u8; 32]>,
    hkr: Option<[u8; 32]>,
    /// Next header keys
    nhks: Option<[u8; 32]>,
    nhkr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    /// Skipped message keys indexed by (header_key_bytes, n)
    #[zeroize(skip)]
    mkskipped: HashMap<([u8; 32], u32), [u8; 32]>,
    max_skip: u32,
}

impl HeaderEncryptState {
    /// Alice init with shared header-key material from the handshake.
    pub fn init_alice(
        sk: &[u8; 32],
        bob_dh_public: &X25519Public,
        shared_hka: &[u8; 32],
        shared_nhkb: &[u8; 32],
        max_skip: u32,
    ) -> Result<Self, PrimitiveError> {
        let dhs = X25519Secret::generate()?;
        let dh_out = dhs.diffie_hellman(bob_dh_public);
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
            mkskipped: HashMap::new(),
            max_skip,
        })
    }

    /// Bob init with the matching shared header-key material.
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
            mkskipped: HashMap::new(),
            max_skip,
        }
    }

    /// Encrypt: returns (encrypted_header, ciphertext).
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        ad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), PrimitiveError> {
        let cks = self.cks.ok_or(PrimitiveError::Internal)?;
        let (new_cks, mk) = kdf_ck(&cks)?;
        self.cks = Some(new_cks);
        let ns = self.ns;
        self.ns = crate::ratchet::checked_inc(self.ns)?;

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
    }

    /// Decrypt. Transactional: on AEAD failure state is left unchanged.
    pub fn decrypt(
        &mut self,
        enc_header: &[u8],
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, PrimitiveError> {
        let mut trial = self.clone_for_trial();
        let mk = trial.receive_key(enc_header)?;
        let associated = concat_ad(ad, enc_header);
        let key = AeadKey::from_bytes(mk);
        let nonce = derive_nonce(&mk);
        let plaintext = aead::open(&key, &nonce, ciphertext, &associated)?;
        *self = trial;
        Ok(plaintext)
    }

    fn receive_key(&mut self, enc_header: &[u8]) -> Result<[u8; 32], PrimitiveError> {
        // Try skipped first (indexed by header key)
        if let Some(mk) = self.try_skipped(enc_header)? {
            return Ok(mk);
        }

        // Try current HKr
        if let Some(hkr) = self.hkr {
            if let Ok(header) = hdecrypt(&hkr, enc_header) {
                self.skip_message_keys(header.n)?;
                let ckr = self.ckr.ok_or(PrimitiveError::Internal)?;
                let (new_ckr, mk) = kdf_ck(&ckr)?;
                self.ckr = Some(new_ckr);
                self.nr = crate::ratchet::checked_inc(self.nr)?;
                return Ok(mk);
            }
        }

        // Try next header key → triggers DH ratchet
        if let Some(nhkr) = self.nhkr {
            if let Ok(header) = hdecrypt(&nhkr, enc_header) {
                self.skip_message_keys(header.pn)?;
                self.dh_ratchet(&header)?;
                self.skip_message_keys(header.n)?;
                let ckr = self.ckr.ok_or(PrimitiveError::Internal)?;
                let (new_ckr, mk) = kdf_ck(&ckr)?;
                self.ckr = Some(new_ckr);
                self.nr = crate::ratchet::checked_inc(self.nr)?;
                return Ok(mk);
            }
        }

        Err(PrimitiveError::AeadAuthFailed)
    }

    fn try_skipped(&mut self, enc_header: &[u8]) -> Result<Option<[u8; 32]>, PrimitiveError> {
        // Attempt decrypt under each stored header key (bounded)
        let keys: Vec<[u8; 32]> = self.mkskipped.keys().map(|(hk, _)| *hk).collect();
        for hk in keys {
            if let Ok(header) = hdecrypt(&hk, enc_header) {
                let key = (hk, header.n);
                if let Some(mk) = self.mkskipped.remove(&key) {
                    return Ok(Some(mk));
                }
            }
        }
        Ok(None)
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<(), PrimitiveError> {
        if self.nr.saturating_add(self.max_skip) < until {
            return Err(PrimitiveError::InvalidLength);
        }
        if let (Some(mut ckr), Some(hkr)) = (self.ckr, self.hkr) {
            while self.nr < until {
                if self.mkskipped.len() as u32 >= self.max_skip {
                    return Err(PrimitiveError::InvalidLength);
                }
                let (new_ckr, mk) = kdf_ck(&ckr)?;
                self.mkskipped.insert((hkr, self.nr), mk);
                ckr = new_ckr;
                self.nr = crate::ratchet::checked_inc(self.nr)?;
            }
            self.ckr = Some(ckr);
        }
        Ok(())
    }

    fn dh_ratchet(&mut self, header: &Header) -> Result<(), PrimitiveError> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        // Shift header keys
        self.hks = self.nhks;
        self.hkr = self.nhkr;
        self.dhr = Some(header.dh);

        let dhs = self.dhs.as_ref().ok_or(PrimitiveError::Internal)?;
        let dh_out1 = dhs.diffie_hellman(&header.dh);
        let (rk1, ckr, nhkr) = kdf_rk_he(&self.rk, &dh_out1)?;
        self.rk = rk1;
        self.ckr = Some(ckr);
        self.nhkr = Some(nhkr);

        let new_dhs = X25519Secret::generate()?;
        let dh_out2 = new_dhs.diffie_hellman(&header.dh);
        let (rk2, cks, nhks) = kdf_rk_he(&self.rk, &dh_out2)?;
        self.rk = rk2;
        self.cks = Some(cks);
        self.nhks = Some(nhks);
        self.dhs = Some(new_dhs);
        Ok(())
    }

    pub(crate) fn clone_for_trial(&self) -> Self {
        Self {
            dhs: self
                .dhs
                .as_ref()
                .map(|s| X25519Secret::from_bytes(s.to_bytes())),
            dhr: self.dhr,
            rk: self.rk,
            cks: self.cks,
            ckr: self.ckr,
            hks: self.hks,
            hkr: self.hkr,
            nhks: self.nhks,
            nhkr: self.nhkr,
            ns: self.ns,
            nr: self.nr,
            pn: self.pn,
            mkskipped: self.mkskipped.clone(),
            max_skip: self.max_skip,
        }
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
        if tag == 0 {
            return Ok(None);
        }
        if tag != 1 || *i + 32 > data.len() {
            return Err(PrimitiveError::InvalidLength);
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(&data[*i..*i + 32]);
        *i += 32;
        Ok(Some(b))
    }

    /// Persist HE ratchet (DH, root/chain/header keys, skipped MKs).
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
        out.extend_from_slice(&(self.mkskipped.len() as u32).to_le_bytes());
        for ((hk, n), mk) in &self.mkskipped {
            out.extend_from_slice(hk);
            out.extend_from_slice(&n.to_le_bytes());
            out.extend_from_slice(mk);
        }
        out
    }

    /// Restore HE ratchet from [`Self::serialize`].
    pub fn deserialize(data: &[u8], max_skip: u32) -> Result<Self, PrimitiveError> {
        let mut i = 0;
        let dhs = Self::read_opt32(data, &mut i)?.map(X25519Secret::from_bytes);
        let dhr = match Self::read_opt32(data, &mut i)? {
            Some(b) => Some(X25519Public::from_bytes(b)?),
            None => None,
        };
        if i + 32 > data.len() {
            return Err(PrimitiveError::InvalidLength);
        }
        let mut rk = [0u8; 32];
        rk.copy_from_slice(&data[i..i + 32]);
        i += 32;
        let cks = Self::read_opt32(data, &mut i)?;
        let ckr = Self::read_opt32(data, &mut i)?;
        let hks = Self::read_opt32(data, &mut i)?;
        let hkr = Self::read_opt32(data, &mut i)?;
        let nhks = Self::read_opt32(data, &mut i)?;
        let nhkr = Self::read_opt32(data, &mut i)?;
        if i + 16 > data.len() {
            return Err(PrimitiveError::InvalidLength);
        }
        let ns = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        i += 4;
        let nr = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        i += 4;
        let pn = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        i += 4;
        let _stored_max = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        i += 4;
        if i + 4 > data.len() {
            return Err(PrimitiveError::InvalidLength);
        }
        let count = u32::from_le_bytes(data[i..i + 4].try_into().unwrap()) as usize;
        i += 4;
        let mut mkskipped = HashMap::new();
        for _ in 0..count {
            if i + 68 > data.len() {
                return Err(PrimitiveError::InvalidLength);
            }
            let mut hk = [0u8; 32];
            hk.copy_from_slice(&data[i..i + 32]);
            i += 32;
            let n = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
            i += 4;
            let mut mk = [0u8; 32];
            mk.copy_from_slice(&data[i..i + 32]);
            i += 32;
            mkskipped.insert((hk, n), mk);
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

// ---------------------------------------------------------------------------
// KDFs and header AEAD
// ---------------------------------------------------------------------------

#[allow(clippy::type_complexity)]
fn kdf_rk_he(
    rk: &[u8; 32],
    dh_out: &[u8; 32],
) -> Result<([u8; 32], [u8; 32], [u8; 32]), PrimitiveError> {
    let mut okm = [0u8; 96];
    hkdf_extract_expand(Some(rk), dh_out, LABELS::DR_ROOT, &mut okm)?;
    let mut new_rk = [0u8; 32];
    let mut ck = [0u8; 32];
    let mut nhk = [0u8; 32];
    new_rk.copy_from_slice(&okm[0..32]);
    ck.copy_from_slice(&okm[32..64]);
    nhk.copy_from_slice(&okm[64..96]);
    Ok((new_rk, ck, nhk))
}

fn kdf_ck(ck: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), PrimitiveError> {
    let mut okm = [0u8; 64];
    hkdf_extract_expand(None, ck, LABELS::DR_CHAIN, &mut okm)?;
    let mut new_ck = [0u8; 32];
    let mut mk = [0u8; 32];
    new_ck.copy_from_slice(&okm[0..32]);
    mk.copy_from_slice(&okm[32..64]);
    let mut mk2 = [0u8; 32];
    hkdf_extract_expand(None, &mk, LABELS::DR_MESSAGE, &mut mk2)?;
    Ok((new_ck, mk2))
}

fn hencrypt(hk: &[u8; 32], header_bytes: &[u8]) -> Result<Vec<u8>, PrimitiveError> {
    // Random 12-byte nonce (spec: ≥128 bits entropy or stateful non-repeating)
    let mut nonce = [0u8; 12];
    crate::primitives::random::fill_random(&mut nonce)?;
    let key = AeadKey::from_bytes(*hk);
    let mut out = nonce.to_vec();
    let ct = aead::seal(&key, &nonce, header_bytes, b"")?;
    out.extend_from_slice(&ct);
    Ok(out)
}

fn hdecrypt(hk: &[u8; 32], enc_header: &[u8]) -> Result<Header, PrimitiveError> {
    if enc_header.len() < 12 {
        return Err(PrimitiveError::InvalidLength);
    }
    let nonce: [u8; 12] = enc_header[0..12].try_into().unwrap();
    let ct = &enc_header[12..];
    let key = AeadKey::from_bytes(*hk);
    let plain = aead::open(&key, &nonce, ct, b"")?;
    Header::decode(&plain)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn he_roundtrip() {
        let sk = [5u8; 32];
        let shared_hka = [1u8; 32];
        let shared_nhkb = [2u8; 32];
        let bob_dh = X25519Secret::generate().unwrap();
        let mut alice = HeaderEncryptState::init_alice(
            &sk,
            &bob_dh.public_key(),
            &shared_hka,
            &shared_nhkb,
            DEFAULT_MAX_SKIP,
        )
        .unwrap();
        let mut bob =
            HeaderEncryptState::init_bob(&sk, bob_dh, &shared_hka, &shared_nhkb, DEFAULT_MAX_SKIP);

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
}
