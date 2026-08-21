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

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::primitives::aead::{self, AeadKey};
use crate::primitives::error::PrimitiveError;
use crate::primitives::kdf::{hkdf_extract_expand, LABELS};
use crate::primitives::x25519::{X25519Public, X25519Secret};

/// Configurable hard limit on skipped message keys per chain.
/// An attacker cannot force more than this many stored keys or
/// more than this many KDF steps in a single SkipMessageKeys call.
pub const DEFAULT_MAX_SKIP: u32 = 1000;

/// Message header as defined by the public specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub dh: X25519Public,
    pub pn: u32,
    pub n: u32,
}

impl Header {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + 4);
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
        pk.copy_from_slice(&data[0..32]);
        let dh = X25519Public::from_bytes(pk)?;
        let pn = u32::from_le_bytes(data[32..36].try_into().unwrap());
        let n = u32::from_le_bytes(data[36..40].try_into().unwrap());
        Ok(Self { dh, pn, n })
    }
}

/// Index for skipped message keys: (ratchet public key bytes, message number).
type SkipKey = ([u8; 32], u32);

/// Classical Double Ratchet state.
///
/// All secret material implements Zeroize / ZeroizeOnDrop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DoubleRatchetState {
    /// Sending DH ratchet key pair.
    dhs: Option<X25519Secret>,
    /// Received (remote) DH ratchet public key (public, not secret).
    #[zeroize(skip)]
    dhr: Option<X25519Public>,
    /// 32-byte root key.
    rk: [u8; 32],
    /// Sending chain key.
    cks: Option<[u8; 32]>,
    /// Receiving chain key.
    ckr: Option<[u8; 32]>,
    /// Sending message number.
    ns: u32,
    /// Receiving message number.
    nr: u32,
    /// Previous sending chain length.
    pn: u32,
    /// Skipped message keys. Hard-bounded by max_skip. Zeroized on drop.
    mkskipped: SkippedKeys,
    /// Hard limit on skipped keys / skip distance.
    max_skip: u32,
}

/// HashMap of skipped message keys with explicit zeroization of every MK.
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

    fn insert(&mut self, key: SkipKey, mk: [u8; 32]) {
        if let Some(mut old) = self.0.insert(key, mk) {
            old.zeroize();
        }
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn iter(&self) -> impl Iterator<Item = (&SkipKey, &[u8; 32])> {
        self.0.iter()
    }
}

pub(crate) fn checked_inc(n: u32) -> Result<u32, PrimitiveError> {
    n.checked_add(1).ok_or(PrimitiveError::LimitExceeded)
}

impl DoubleRatchetState {
    /// Initialize Alice (initiator) after PQXDH shared secret SK is known
    /// and Bob’s first ratchet public key is available.
    pub fn init_alice(
        sk: &[u8; 32],
        bob_dh_public: &X25519Public,
        max_skip: u32,
    ) -> Result<Self, PrimitiveError> {
        let dhs = X25519Secret::generate()?;
        let dh_out = dhs.diffie_hellman(bob_dh_public);
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

    /// Initialize Bob (responder). Bob still has the DH key pair that Alice used
    /// (the signed prekey advertised in the bundle).
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

    /// Encrypt a plaintext. Returns (header, ciphertext).
    /// State is updated only after the message key is derived.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        ad: &[u8],
    ) -> Result<(Header, Vec<u8>), PrimitiveError> {
        let (ns, mut mk) = self.ratchet_send_key()?;
        let dhs = self.dhs.as_ref().ok_or(PrimitiveError::Internal)?;
        let header = Header {
            dh: dhs.public_key(),
            pn: self.pn,
            n: ns,
        };
        let associated = concat_ad(ad, &header);
        let (key, nonce) = aead_from_mk(&mk)?;
        let ct = aead::seal(&key, &nonce, plaintext, &associated)?;
        mk.zeroize();
        Ok((header, ct))
    }

    /// Decrypt a ciphertext.  
    /// **Critical invariant**: if authentication fails, the persistent state
    /// is left exactly as it was before the call.
    pub fn decrypt(
        &mut self,
        header: &Header,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, PrimitiveError> {
        // Work on a temporary copy so we can discard all mutations on failure.
        let mut trial = self.clone_for_trial();
        let mut mk = trial.ratchet_receive_key(header)?;
        let associated = concat_ad(ad, header);
        let (key, nonce) = aead_from_mk(&mk)?;
        let plaintext = aead::open(&key, &nonce, ciphertext, &associated)?;
        mk.zeroize();
        // Authentication succeeded — commit the trial state.
        *self = trial;
        Ok(plaintext)
    }

    // ------------------------------------------------------------------
    // Internal algorithms from the public specification
    // ------------------------------------------------------------------

    /// Derive the next sending message key without AEAD (Triple Ratchet).
    pub fn send_message_key(&mut self) -> Result<(Header, [u8; 32]), PrimitiveError> {
        let (ns, mk) = self.ratchet_send_key()?;
        let dhs = self.dhs.as_ref().ok_or(PrimitiveError::Internal)?;
        let header = Header {
            dh: dhs.public_key(),
            pn: self.pn,
            n: ns,
        };
        Ok((header, mk))
    }

    /// Derive the receiving message key for `header` without AEAD (Triple Ratchet).
    pub fn receive_message_key(&mut self, header: &Header) -> Result<[u8; 32], PrimitiveError> {
        self.ratchet_receive_key(header)
    }

    fn ratchet_send_key(&mut self) -> Result<(u32, [u8; 32]), PrimitiveError> {
        let cks = self.cks.ok_or(PrimitiveError::Internal)?;
        let (new_cks, mk) = kdf_ck(&cks)?;
        self.cks = Some(new_cks);
        let ns = self.ns;
        self.ns = checked_inc(self.ns)?;
        Ok((ns, mk))
    }

    fn ratchet_receive_key(&mut self, header: &Header) -> Result<[u8; 32], PrimitiveError> {
        if let Some(mk) = self.try_skipped_message_keys(header) {
            return Ok(mk);
        }
        if self.dhr.map(|d| d.to_bytes()) != Some(header.dh.to_bytes()) {
            self.skip_message_keys(header.pn)?;
            self.dh_ratchet(header)?;
        }
        self.skip_message_keys(header.n)?;
        let ckr = self.ckr.ok_or(PrimitiveError::Internal)?;
        let (new_ckr, mk) = kdf_ck(&ckr)?;
        self.ckr = Some(new_ckr);
        self.nr = checked_inc(self.nr)?;
        Ok(mk)
    }

    fn try_skipped_message_keys(&mut self, header: &Header) -> Option<[u8; 32]> {
        let key = (header.dh.to_bytes(), header.n);
        self.mkskipped.remove(&key)
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<(), PrimitiveError> {
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
                let (new_ckr, mk) = kdf_ck(&ckr)?;
                let dhr = self.dhr.ok_or(PrimitiveError::Internal)?;
                self.mkskipped.insert((dhr.to_bytes(), self.nr), mk);
                ckr = new_ckr;
                self.nr = checked_inc(self.nr)?;
            }
            self.ckr = Some(ckr);
        }
        Ok(())
    }

    fn dh_ratchet(&mut self, header: &Header) -> Result<(), PrimitiveError> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(header.dh);

        let dhs = self.dhs.as_ref().ok_or(PrimitiveError::Internal)?;
        let dh_out1 = dhs.diffie_hellman(&header.dh);
        let (rk1, ckr) = kdf_rk(&self.rk, &dh_out1)?;
        self.rk = rk1;
        self.ckr = Some(ckr);

        let new_dhs = X25519Secret::generate()?;
        let dh_out2 = new_dhs.diffie_hellman(&header.dh);
        let (rk2, cks) = kdf_rk(&self.rk, &dh_out2)?;
        self.rk = rk2;
        self.cks = Some(cks);
        self.dhs = Some(new_dhs);
        Ok(())
    }

    /// Clone only the fields needed for a speculative decrypt.
    /// Secrets are copied; on failure the trial is dropped and zeroized.
    /// Snapshot for transactional encrypt/decrypt (discarded on failure).
    pub fn clone_for_trial(&self) -> Self {
        Self {
            dhs: self
                .dhs
                .as_ref()
                .map(|s| X25519Secret::from_bytes(s.to_bytes())),
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

    // ------------------------------------------------------------------
    // Serialization (for reload tests after every transition)
    // ------------------------------------------------------------------

    /// Serialize state for persistence / crash-recovery tests.
    /// Secrets are included; caller must protect the blob.
    pub fn serialize(&self) -> Vec<u8> {
        // Simple length-prefixed encoding sufficient for tests.
        let mut out = Vec::new();
        // dhs
        match &self.dhs {
            Some(s) => {
                out.push(1);
                out.extend_from_slice(&s.to_bytes());
            }
            None => out.push(0),
        }
        // dhr
        match &self.dhr {
            Some(p) => {
                out.push(1);
                out.extend_from_slice(&p.to_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.rk);
        // cks
        match &self.cks {
            Some(c) => {
                out.push(1);
                out.extend_from_slice(c);
            }
            None => out.push(0),
        }
        // ckr
        match &self.ckr {
            Some(c) => {
                out.push(1);
                out.extend_from_slice(c);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.ns.to_le_bytes());
        out.extend_from_slice(&self.nr.to_le_bytes());
        out.extend_from_slice(&self.pn.to_le_bytes());
        out.extend_from_slice(&self.max_skip.to_le_bytes());
        // mkskipped count + entries
        let count = self.mkskipped.len() as u32;
        out.extend_from_slice(&count.to_le_bytes());
        for ((pk, n), mk) in self.mkskipped.iter() {
            out.extend_from_slice(pk);
            out.extend_from_slice(&n.to_le_bytes());
            out.extend_from_slice(mk);
        }
        out
    }

    pub fn deserialize(data: &[u8], max_skip: u32) -> Result<Self, PrimitiveError> {
        // Minimal parser for tests; production would use a proper format.
        let mut i = 0;
        fn take(i: &mut usize, n: usize, data: &[u8]) -> Result<Vec<u8>, PrimitiveError> {
            if *i + n > data.len() {
                return Err(PrimitiveError::InvalidLength);
            }
            let s = data[*i..*i + n].to_vec();
            *i += n;
            Ok(s)
        }

        let has_dhs = take(&mut i, 1, data)?[0];
        let dhs = if has_dhs == 1 {
            let b = take(&mut i, 32, data)?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            Some(X25519Secret::from_bytes(arr))
        } else {
            None
        };

        let has_dhr = take(&mut i, 1, data)?[0];
        let dhr = if has_dhr == 1 {
            let b = take(&mut i, 32, data)?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            Some(X25519Public::from_bytes(arr)?)
        } else {
            None
        };

        let mut rk = [0u8; 32];
        rk.copy_from_slice(&take(&mut i, 32, data)?);

        let has_cks = take(&mut i, 1, data)?[0];
        let cks = if has_cks == 1 {
            let mut c = [0u8; 32];
            c.copy_from_slice(&take(&mut i, 32, data)?);
            Some(c)
        } else {
            None
        };

        let has_ckr = take(&mut i, 1, data)?[0];
        let ckr = if has_ckr == 1 {
            let mut c = [0u8; 32];
            c.copy_from_slice(&take(&mut i, 32, data)?);
            Some(c)
        } else {
            None
        };

        let ns_b = take(&mut i, 4, data)?;
        let nr_b = take(&mut i, 4, data)?;
        let pn_b = take(&mut i, 4, data)?;
        let _ms = take(&mut i, 4, data)?;
        let ns = u32::from_le_bytes(ns_b.try_into().unwrap());
        let nr = u32::from_le_bytes(nr_b.try_into().unwrap());
        let pn = u32::from_le_bytes(pn_b.try_into().unwrap());

        let count_b = take(&mut i, 4, data)?;
        let count = u32::from_le_bytes(count_b.try_into().unwrap());
        let mut mkskipped = SkippedKeys::default();
        for _ in 0..count {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&take(&mut i, 32, data)?);
            let n_b = take(&mut i, 4, data)?;
            let n = u32::from_le_bytes(n_b.try_into().unwrap());
            let mut mk = [0u8; 32];
            mk.copy_from_slice(&take(&mut i, 32, data)?);
            mkskipped.insert((pk, n), mk);
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

    /// Number of currently skipped keys (for tests / bounds checks).
    pub fn skipped_count(&self) -> usize {
        self.mkskipped.len()
    }
}

// ---------------------------------------------------------------------------
// KDF helpers matching the public specification’s KDF_RK / KDF_CK
// ---------------------------------------------------------------------------

fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), PrimitiveError> {
    let mut okm = [0u8; 64];
    hkdf_extract_expand(Some(rk), dh_out, LABELS::DR_ROOT, &mut okm)?;
    let mut new_rk = [0u8; 32];
    let mut ck = [0u8; 32];
    new_rk.copy_from_slice(&okm[0..32]);
    ck.copy_from_slice(&okm[32..64]);
    Ok((new_rk, ck))
}

fn kdf_ck(ck: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), PrimitiveError> {
    // Double Ratchet Rev 4 §7.2: HMAC(ck, 0x01) → message key, HMAC(ck, 0x02) → next chain key.
    let mk = crate::primitives::kdf::hmac_sha256(ck, &[0x01]);
    let new_ck = crate::primitives::kdf::hmac_sha256(ck, &[0x02]);
    Ok((new_ck, mk))
}

/// Derive an independent AEAD key and nonce from a unique message key (KEY-SEPARATION).
fn aead_from_mk(mk: &[u8; 32]) -> Result<(AeadKey, [u8; 12]), PrimitiveError> {
    let salt = [0u8; 32];
    let mut okm = [0u8; 44];
    hkdf_extract_expand(Some(&salt), mk, LABELS::DR_MESSAGE, &mut okm)?;
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..44]);
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::x25519::X25519Secret;

    fn fresh_sk() -> [u8; 32] {
        let mut s = [0u8; 32];
        crate::primitives::random::fill_random(&mut s).unwrap();
        s
    }

    /// Classic A1 A2 A3 B1 B2 A4 sequence from the public documentation style.
    #[test]
    fn sequence_a1_a2_a3_b1_b2_a4() {
        let sk = fresh_sk();
        let bob_dh = X25519Secret::generate().unwrap();
        let bob_pub = bob_dh.public_key();

        let mut alice = DoubleRatchetState::init_alice(&sk, &bob_pub, DEFAULT_MAX_SKIP).unwrap();
        let mut bob = DoubleRatchetState::init_bob(&sk, bob_dh, DEFAULT_MAX_SKIP);

        // A1
        let (h1, c1) = alice.encrypt(b"A1", b"ad").unwrap();
        let p1 = bob.decrypt(&h1, &c1, b"ad").unwrap();
        assert_eq!(p1, b"A1");

        // A2
        let (h2, c2) = alice.encrypt(b"A2", b"ad").unwrap();
        let p2 = bob.decrypt(&h2, &c2, b"ad").unwrap();
        assert_eq!(p2, b"A2");

        // A3
        let (h3, c3) = alice.encrypt(b"A3", b"ad").unwrap();
        let p3 = bob.decrypt(&h3, &c3, b"ad").unwrap();
        assert_eq!(p3, b"A3");

        // B1
        let (hb1, cb1) = bob.encrypt(b"B1", b"ad").unwrap();
        let pb1 = alice.decrypt(&hb1, &cb1, b"ad").unwrap();
        assert_eq!(pb1, b"B1");

        // B2
        let (hb2, cb2) = bob.encrypt(b"B2", b"ad").unwrap();
        let pb2 = alice.decrypt(&hb2, &cb2, b"ad").unwrap();
        assert_eq!(pb2, b"B2");

        // A4
        let (h4, c4) = alice.encrypt(b"A4", b"ad").unwrap();
        let p4 = bob.decrypt(&h4, &c4, b"ad").unwrap();
        assert_eq!(p4, b"A4");
    }

    #[test]
    fn tampered_message_leaves_state_unchanged() {
        let sk = fresh_sk();
        let bob_dh = X25519Secret::generate().unwrap();
        let mut alice =
            DoubleRatchetState::init_alice(&sk, &bob_dh.public_key(), DEFAULT_MAX_SKIP).unwrap();
        let mut bob = DoubleRatchetState::init_bob(&sk, bob_dh, DEFAULT_MAX_SKIP);

        let (h, mut ct) = alice.encrypt(b"secret", b"ad").unwrap();
        let before = bob.serialize();

        // Tamper ciphertext
        if let Some(b) = ct.last_mut() {
            *b ^= 0xff;
        }
        let res = bob.decrypt(&h, &ct, b"ad");
        assert!(res.is_err());

        let after = bob.serialize();
        assert_eq!(
            before, after,
            "persistent state must be unchanged after failed decrypt"
        );
    }

    #[test]
    fn max_skip_protects_against_explosion() {
        let sk = fresh_sk();
        let bob_dh = X25519Secret::generate().unwrap();
        let mut alice = DoubleRatchetState::init_alice(&sk, &bob_dh.public_key(), 5).unwrap(); // tiny limit
        let mut bob = DoubleRatchetState::init_bob(&sk, bob_dh, 5);

        // First message establishes the receiving chain on Bob
        let (h0, c0) = alice.encrypt(b"0", b"ad").unwrap();
        bob.decrypt(&h0, &c0, b"ad").unwrap();

        // Alice sends a message with an enormous N
        let (mut h, c) = alice.encrypt(b"far", b"ad").unwrap();
        h.n = 10_000; // far beyond MAX_SKIP = 5
        let res = bob.decrypt(&h, &c, b"ad");
        assert!(res.is_err());
        assert!(bob.skipped_count() <= 5);
    }

    #[test]
    fn forward_secrecy_after_deletion() {
        let sk = fresh_sk();
        let bob_dh = X25519Secret::generate().unwrap();
        let mut alice =
            DoubleRatchetState::init_alice(&sk, &bob_dh.public_key(), DEFAULT_MAX_SKIP).unwrap();
        let mut bob = DoubleRatchetState::init_bob(&sk, bob_dh, DEFAULT_MAX_SKIP);

        let (h1, c1) = alice.encrypt(b"old", b"ad").unwrap();
        assert_eq!(bob.decrypt(&h1, &c1, b"ad").unwrap(), b"old");

        // Advance chains so old message key is gone
        for _ in 0..5 {
            let (h, c) = alice.encrypt(b"next", b"ad").unwrap();
            assert_eq!(bob.decrypt(&h, &c, b"ad").unwrap(), b"next");
        }

        // The old ciphertext must not decrypt under the current state
        // (message key was deleted after use; no API exposes it).
        let res = bob.decrypt(&h1, &c1, b"ad");
        assert!(res.is_err());
    }

    #[test]
    fn serialize_reload_preserves_session() {
        let sk = fresh_sk();
        let bob_dh = X25519Secret::generate().unwrap();
        let mut alice =
            DoubleRatchetState::init_alice(&sk, &bob_dh.public_key(), DEFAULT_MAX_SKIP).unwrap();
        let mut bob = DoubleRatchetState::init_bob(&sk, bob_dh, DEFAULT_MAX_SKIP);

        let (h, c) = alice.encrypt(b"before-reload", b"ad").unwrap();
        let blob = bob.serialize();
        let mut bob2 = DoubleRatchetState::deserialize(&blob, DEFAULT_MAX_SKIP).unwrap();
        let p = bob2.decrypt(&h, &c, b"ad").unwrap();
        assert_eq!(p, b"before-reload");

        // Continue after reload
        let (h2, c2) = bob2.encrypt(b"after-reload", b"ad").unwrap();
        let p2 = alice.decrypt(&h2, &c2, b"ad").unwrap();
        assert_eq!(p2, b"after-reload");
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

        // Deliver 1, 3, 2
        assert_eq!(bob.decrypt(&h1, &c1, b"ad").unwrap(), b"1");
        assert_eq!(bob.decrypt(&h3, &c3, b"ad").unwrap(), b"3");
        assert_eq!(bob.decrypt(&h2, &c2, b"ad").unwrap(), b"2");
    }
}
