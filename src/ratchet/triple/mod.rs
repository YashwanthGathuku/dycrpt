//! Triple Ratchet — hybrid of classical Double Ratchet + SPQR.
//!
//! From the public Double Ratchet Revision 4 specification:
//!   Run classical DR and SPQR in parallel; combine message keys with
//!   KDF_HYBRID to obtain the encryption key.
//!
//! This does NOT replace the classical implementation.

use crate::primitives::aead::{self, AeadKey};
use crate::primitives::error::PrimitiveError;
use crate::primitives::kdf::{hkdf_extract_expand, LABELS};
use crate::primitives::x25519::{X25519Public, X25519Secret};
use crate::ratchet::braid::{BraidMessage, BraidScka};
use crate::ratchet::spqr::{SpqrState, SPQR_MAX_SKIP_EPOCHS};
use crate::ratchet::{DoubleRatchetState, Header, DEFAULT_MAX_SKIP};
use zeroize::Zeroize;

/// Hybrid message header: classical DR header + SPQR epoch/n + optional CKA blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TripleHeader {
    pub classical: Header,
    pub pq_epoch: u32,
    pub pq_n: u32,
    pub scka: Option<BraidMessage>,
}

impl TripleHeader {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.classical.encode();
        out.extend_from_slice(&self.pq_epoch.to_le_bytes());
        out.extend_from_slice(&self.pq_n.to_le_bytes());
        match &self.scka {
            None => out.push(0),
            Some(m) => {
                let blob = m.encode();
                out.push(1);
                out.extend_from_slice(&(blob.len() as u16).to_le_bytes());
                out.extend_from_slice(&blob);
            }
        }
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, PrimitiveError> {
        if data.len() < 48 {
            return Err(PrimitiveError::InvalidLength);
        }
        let classical = Header::decode(&data[0..40])?;
        let pq_epoch = u32::from_le_bytes(data[40..44].try_into().unwrap());
        let pq_n = u32::from_le_bytes(data[44..48].try_into().unwrap());
        let scka = if data.len() == 48 {
            None
        } else if data.len() >= 49 && data[48] == 0 {
            if data.len() != 49 {
                return Err(PrimitiveError::InvalidLength);
            }
            None
        } else if data.len() >= 51 && data[48] == 1 {
            let n = u16::from_le_bytes(data[49..51].try_into().unwrap()) as usize;
            if data.len() != 51 + n {
                return Err(PrimitiveError::InvalidLength);
            }
            Some(BraidMessage::decode(&data[51..])?)
        } else {
            return Err(PrimitiveError::InvalidLength);
        };
        Ok(Self {
            classical,
            pq_epoch,
            pq_n,
            scka,
        })
    }
}

/// Triple Ratchet state = classical Double Ratchet ‖ SPQR ‖ ML-KEM Braid SCKA.
pub struct TripleRatchetState {
    pub classical: DoubleRatchetState,
    pub spqr: SpqrState,
    pub braid: BraidScka,
}

impl TripleRatchetState {
    /// Expand PQXDH SK into independent classical and SPQR roots (spec §7.1).
    fn split_sk(sk: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), PrimitiveError> {
        let mut okm = [0u8; 64];
        hkdf_extract_expand(None, sk, LABELS::TRIPLE_HYBRID, &mut okm)?;
        let mut sk_ec = [0u8; 32];
        let mut sk_pq = [0u8; 32];
        sk_ec.copy_from_slice(&okm[..32]);
        sk_pq.copy_from_slice(&okm[32..]);
        okm.zeroize();
        Ok((sk_ec, sk_pq))
    }

    pub fn init_alice(sk: &[u8; 32], bob_dh_public: &X25519Public) -> Result<Self, PrimitiveError> {
        let (sk_ec, sk_pq) = Self::split_sk(sk)?;
        let classical = DoubleRatchetState::init_alice(&sk_ec, bob_dh_public, DEFAULT_MAX_SKIP)?;
        let mut spqr = SpqrState::init(&sk_pq, SPQR_MAX_SKIP_EPOCHS);
        // Handshake PQ secret seeds SPQR; Braid then injects later epoch keys.
        spqr.advance_epoch(&sk_pq)?;
        Ok(Self {
            classical,
            spqr,
            braid: BraidScka::init_alice(&sk_pq)?,
        })
    }

    pub fn init_bob(sk: &[u8; 32], bob_dh_keypair: X25519Secret) -> Result<Self, PrimitiveError> {
        let (sk_ec, sk_pq) = Self::split_sk(sk)?;
        let classical = DoubleRatchetState::init_bob(&sk_ec, bob_dh_keypair, DEFAULT_MAX_SKIP);
        let mut spqr = SpqrState::init(&sk_pq, SPQR_MAX_SKIP_EPOCHS);
        spqr.advance_epoch(&sk_pq)?;
        Ok(Self {
            classical,
            spqr,
            braid: BraidScka::init_bob(&sk_pq)?,
        })
    }

    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        ad: &[u8],
    ) -> Result<(TripleHeader, Vec<u8>), PrimitiveError> {
        let (scka_msg, _send_ep, new_ss) = self.braid.send()?;
        if let Some(o) = new_ss {
            self.spqr.advance_epoch(&o.key)?;
        }
        let (classical_header, mut ec_mk) = self.classical.send_message_key()?;
        let (pq_epoch, pq_n, mut pq_mk) = self.spqr.send_key()?;
        let mut hybrid_mk = kdf_hybrid(&ec_mk, &pq_mk)?;
        ec_mk.zeroize();
        pq_mk.zeroize();

        let header = TripleHeader {
            classical: classical_header,
            pq_epoch,
            pq_n,
            scka: Some(scka_msg),
        };
        let associated = concat_triple_ad(ad, &header);
        let (key, nonce) = aead_from_hybrid(&hybrid_mk)?;
        let ct = aead::seal(&key, &nonce, plaintext, &associated)?;
        hybrid_mk.zeroize();
        Ok((header, ct))
    }

    /// Decrypt under the hybrid message key. State is unchanged on failure.
    pub fn decrypt(
        &mut self,
        header: &TripleHeader,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, PrimitiveError> {
        let mut trial_c = self.classical.clone_for_trial();
        let mut trial_s = self.spqr.clone_for_trial();
        let mut trial_b = self.braid.clone();
        let mut pending_scka: Option<[u8; 32]> = None;
        if let Some(ref msg) = header.scka {
            let (_, out) = trial_b.receive(msg)?;
            if let Some(o) = out {
                // Encapsulator learns the peer finished (header uses the new
                // SPQR epoch) → advance before receive_key. Decapsulator
                // finishes on a message still in the old epoch → delay.
                if trial_s.receiving_epoch() != Some(header.pq_epoch) {
                    trial_s.advance_epoch(&o.key)?;
                } else {
                    pending_scka = Some(o.key);
                }
            }
        }
        let mut ec_mk = trial_c.receive_message_key(&header.classical)?;
        let mut pq_mk = trial_s.receive_key(header.pq_epoch, header.pq_n)?;
        let mut hybrid_mk = kdf_hybrid(&ec_mk, &pq_mk)?;
        ec_mk.zeroize();
        pq_mk.zeroize();
        let associated = concat_triple_ad(ad, header);
        let (key, nonce) = aead_from_hybrid(&hybrid_mk)?;
        let plaintext = aead::open(&key, &nonce, ciphertext, &associated)?;
        hybrid_mk.zeroize();
        if let Some(k) = pending_scka {
            trial_s.advance_epoch(&k)?;
        }
        self.classical = trial_c;
        self.spqr = trial_s;
        self.braid = trial_b;
        Ok(plaintext)
    }

    /// Header size (bytes) of a freshly encrypted message — used for measurements.
    pub fn last_header_len(header: &TripleHeader) -> usize {
        header.encode().len()
    }

    /// Snapshot for transactional encrypt/decrypt (discarded on failure).
    pub fn clone_for_trial(&self) -> Self {
        Self {
            classical: self.classical.clone_for_trial(),
            spqr: self.spqr.clone_for_trial(),
            braid: self.braid.clone(),
        }
    }

    /// Persist classical + SPQR + CKA. Caller must protect the blob.
    pub fn serialize(&self) -> Vec<u8> {
        let c = self.classical.serialize();
        let s = self.spqr.serialize();
        let k = self.braid.serialize();
        let mut out = Vec::with_capacity(12 + c.len() + s.len() + k.len());
        out.extend_from_slice(&(c.len() as u32).to_le_bytes());
        out.extend_from_slice(&c);
        out.extend_from_slice(&(s.len() as u32).to_le_bytes());
        out.extend_from_slice(&s);
        out.extend_from_slice(&(k.len() as u32).to_le_bytes());
        out.extend_from_slice(&k);
        out
    }

    /// Restore Triple Ratchet from [`Self::serialize`].
    pub fn deserialize(data: &[u8], max_skip: u32) -> Result<Self, PrimitiveError> {
        let mut i = 0;
        let take = |i: &mut usize, n: usize| -> Result<&[u8], PrimitiveError> {
            if *i + n > data.len() {
                return Err(PrimitiveError::InvalidLength);
            }
            let s = &data[*i..*i + n];
            *i += n;
            Ok(s)
        };
        let clen = u32::from_le_bytes(take(&mut i, 4)?.try_into().unwrap()) as usize;
        let classical = DoubleRatchetState::deserialize(take(&mut i, clen)?, max_skip)?;
        let slen = u32::from_le_bytes(take(&mut i, 4)?.try_into().unwrap()) as usize;
        let spqr = SpqrState::deserialize(take(&mut i, slen)?)?;
        let klen = u32::from_le_bytes(take(&mut i, 4)?.try_into().unwrap()) as usize;
        let braid = BraidScka::deserialize(take(&mut i, klen)?)?;
        if i != data.len() {
            return Err(PrimitiveError::InvalidLength);
        }
        Ok(Self {
            classical,
            spqr,
            braid,
        })
    }
}

fn kdf_hybrid(classical_mk: &[u8; 32], pq_mk: &[u8; 32]) -> Result<[u8; 32], PrimitiveError> {
    // Spec §7.2 KDF_HYBRID: salt = scka_mk, ikm = ec_mk, info = TR_PROTOCOL_INFO.
    let mut out = [0u8; 32];
    hkdf_extract_expand(Some(pq_mk), classical_mk, LABELS::TRIPLE_HYBRID, &mut out)?;
    Ok(out)
}

fn aead_from_hybrid(mk: &[u8; 32]) -> Result<(AeadKey, [u8; 12]), PrimitiveError> {
    let salt = [0u8; 32];
    let mut okm = [0u8; 44];
    hkdf_extract_expand(Some(&salt), mk, LABELS::DR_MESSAGE, &mut okm)?;
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..]);
    okm.zeroize();
    Ok((AeadKey::from_bytes(key), nonce))
}

fn concat_triple_ad(ad: &[u8], header: &TripleHeader) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + ad.len() + 48);
    out.extend_from_slice(&(ad.len() as u64).to_le_bytes());
    out.extend_from_slice(ad);
    out.extend_from_slice(&header.encode());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_roundtrip() {
        let sk = [9u8; 32];
        let bob_dh = X25519Secret::generate().unwrap();
        let mut alice = TripleRatchetState::init_alice(&sk, &bob_dh.public_key()).unwrap();
        let mut bob = TripleRatchetState::init_bob(&sk, bob_dh).unwrap();

        let (h, ct) = alice.encrypt(b"hybrid-hello", b"ad").unwrap();
        let pt = bob.decrypt(&h, &ct, b"ad").unwrap();
        assert_eq!(pt, b"hybrid-hello");

        let (h2, ct2) = bob.encrypt(b"reply", b"ad").unwrap();
        let pt2 = alice.decrypt(&h2, &ct2, b"ad").unwrap();
        assert_eq!(pt2, b"reply");
    }

    #[test]
    fn tamper_does_not_commit() {
        let sk = [3u8; 32];
        let bob_dh = X25519Secret::generate().unwrap();
        let mut alice = TripleRatchetState::init_alice(&sk, &bob_dh.public_key()).unwrap();
        let mut bob = TripleRatchetState::init_bob(&sk, bob_dh).unwrap();
        let (h, mut ct) = alice.encrypt(b"secret", b"ad").unwrap();
        if let Some(b) = ct.last_mut() {
            *b ^= 0xff;
        }
        assert!(bob.decrypt(&h, &ct, b"ad").is_err());
    }

    #[test]
    fn header_encode_decode() {
        let sk = [1u8; 32];
        let bob_dh = X25519Secret::generate().unwrap();
        let mut alice = TripleRatchetState::init_alice(&sk, &bob_dh.public_key()).unwrap();
        let (h, _) = alice.encrypt(b"x", b"").unwrap();
        let bytes = h.encode();
        let h2 = TripleHeader::decode(&bytes).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn serialize_reload_continues_conversation() {
        let sk = [5u8; 32];
        let bob_dh = X25519Secret::generate().unwrap();
        let mut alice = TripleRatchetState::init_alice(&sk, &bob_dh.public_key()).unwrap();
        let mut bob = TripleRatchetState::init_bob(&sk, bob_dh).unwrap();
        let (h, ct) = alice.encrypt(b"before", b"ad").unwrap();
        assert_eq!(bob.decrypt(&h, &ct, b"ad").unwrap(), b"before");

        let mut alice =
            TripleRatchetState::deserialize(&alice.serialize(), DEFAULT_MAX_SKIP).unwrap();
        let mut bob = TripleRatchetState::deserialize(&bob.serialize(), DEFAULT_MAX_SKIP).unwrap();
        let (h2, ct2) = bob.encrypt(b"after", b"ad").unwrap();
        assert_eq!(alice.decrypt(&h2, &ct2, b"ad").unwrap(), b"after");
        let (h3, ct3) = alice.encrypt(b"again", b"ad").unwrap();
        assert_eq!(bob.decrypt(&h3, &ct3, b"ad").unwrap(), b"again");
    }

    fn note_braid(
        msg: Option<&BraidMessage>,
        saw_hdr: &mut bool,
        saw_ct1: &mut bool,
        saw_ek: &mut bool,
        saw_ct2: &mut bool,
        ct1_before_ek: &mut bool,
    ) {
        let Some(m) = msg else {
            return;
        };
        match m.typ {
            crate::ratchet::braid::BraidType::Hdr => *saw_hdr = true,
            crate::ratchet::braid::BraidType::Ct1 => {
                if !*saw_ek {
                    *ct1_before_ek = true;
                }
                *saw_ct1 = true;
            }
            crate::ratchet::braid::BraidType::Ek | crate::ratchet::braid::BraidType::EkCt1Ack => {
                *saw_ek = true;
            }
            crate::ratchet::braid::BraidType::Ct2 => *saw_ct2 = true,
            _ => {}
        }
    }

    #[test]
    fn braid_completes_epoch_and_ct1_precedes_ek() {
        let sk = [9u8; 32];
        let bob_dh = X25519Secret::generate().unwrap();
        let mut alice = TripleRatchetState::init_alice(&sk, &bob_dh.public_key()).unwrap();
        let mut bob = TripleRatchetState::init_bob(&sk, bob_dh).unwrap();

        let mut saw_hdr = false;
        let mut saw_ct1 = false;
        let mut saw_ek = false;
        let mut saw_ct2 = false;
        let mut ct1_before_ek = false;

        for i in 0..160u32 {
            let body = format!("a{i}");
            let (h, ct) = alice.encrypt(body.as_bytes(), b"ad").unwrap();
            note_braid(
                h.scka.as_ref(),
                &mut saw_hdr,
                &mut saw_ct1,
                &mut saw_ek,
                &mut saw_ct2,
                &mut ct1_before_ek,
            );
            assert_eq!(bob.decrypt(&h, &ct, b"ad").unwrap(), body.as_bytes());

            let body = format!("b{i}");
            let (h, ct) = bob.encrypt(body.as_bytes(), b"ad").unwrap();
            note_braid(
                h.scka.as_ref(),
                &mut saw_hdr,
                &mut saw_ct1,
                &mut saw_ek,
                &mut saw_ct2,
                &mut ct1_before_ek,
            );
            assert_eq!(alice.decrypt(&h, &ct, b"ad").unwrap(), body.as_bytes());
            if saw_ct2 {
                break;
            }
        }
        assert!(saw_hdr, "header chunks");
        assert!(saw_ct1, "Encaps1 ct1");
        assert!(saw_ek, "ek vector");
        assert!(saw_ct2, "Encaps2 ct2");
        assert!(ct1_before_ek, "Bob emits ct1 before Alice sends ek");

        let (h, ct) = alice.encrypt(b"after-epoch", b"ad").unwrap();
        assert_eq!(bob.decrypt(&h, &ct, b"ad").unwrap(), b"after-epoch");
    }

    #[test]
    fn serialize_mid_braid_then_finish_epoch() {
        let sk = [13u8; 32];
        let bob_dh = X25519Secret::generate().unwrap();
        let mut alice = TripleRatchetState::init_alice(&sk, &bob_dh.public_key()).unwrap();
        let mut bob = TripleRatchetState::init_bob(&sk, bob_dh).unwrap();
        for i in 0..20u32 {
            let (h, ct) = alice.encrypt(&[i as u8], b"ad").unwrap();
            assert_eq!(bob.decrypt(&h, &ct, b"ad").unwrap(), vec![i as u8]);
            let (h, ct) = bob.encrypt(&[200 + i as u8], b"ad").unwrap();
            assert_eq!(alice.decrypt(&h, &ct, b"ad").unwrap(), vec![200 + i as u8]);
        }
        let mut alice =
            TripleRatchetState::deserialize(&alice.serialize(), DEFAULT_MAX_SKIP).unwrap();
        let mut bob = TripleRatchetState::deserialize(&bob.serialize(), DEFAULT_MAX_SKIP).unwrap();

        let mut saw_ct2 = false;
        for i in 20..180u32 {
            let (h, ct) = alice.encrypt(&[i as u8], b"ad").unwrap();
            if matches!(
                h.scka.as_ref().map(|m| m.typ),
                Some(crate::ratchet::braid::BraidType::Ct2)
            ) {
                saw_ct2 = true;
            }
            assert_eq!(bob.decrypt(&h, &ct, b"ad").unwrap(), vec![i as u8]);
            let (h, ct) = bob.encrypt(&[200_u8.wrapping_add(i as u8)], b"ad").unwrap();
            if matches!(
                h.scka.as_ref().map(|m| m.typ),
                Some(crate::ratchet::braid::BraidType::Ct2)
            ) {
                saw_ct2 = true;
            }
            assert_eq!(
                alice.decrypt(&h, &ct, b"ad").unwrap(),
                vec![200_u8.wrapping_add(i as u8)]
            );
            if saw_ct2 {
                break;
            }
        }
        assert!(saw_ct2, "Braid epoch must finish after persist");
        let (h, ct) = alice.encrypt(b"post", b"ad").unwrap();
        assert_eq!(bob.decrypt(&h, &ct, b"ad").unwrap(), b"post");
    }
}
