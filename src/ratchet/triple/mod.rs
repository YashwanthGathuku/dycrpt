//! Triple Ratchet — hybrid of classical Double Ratchet + SPQR.
//!
//! From the public Double Ratchet Revision 4 specification:
//! run classical DR and SPQR in parallel and combine message keys with
//! KDF_HYBRID. This feature remains experimental; hardening malformed-state
//! handling does not promote the current SPQR/Braid research implementation.

use crate::primitives::aead::{self, AeadKey};
use crate::primitives::error::PrimitiveError;
use crate::primitives::kdf::{hkdf_extract_expand, LABELS};
use crate::primitives::x25519::{X25519Public, X25519Secret};
use crate::ratchet::braid::rs::CHUNK_WIRE;
use crate::ratchet::braid::{BraidMessage, BraidScka, BraidType};
use crate::ratchet::spqr::{SpqrState, SPQR_MAX_SKIP_EPOCHS};
use crate::ratchet::{DoubleRatchetState, Header, DEFAULT_MAX_SKIP};
use zeroize::Zeroize;

const MAX_TRIPLE_COMPONENT: usize = 1024 * 1024;
const MAX_TRIPLE_STATE: usize = 3 * MAX_TRIPLE_COMPONENT + 12;
const MAX_BRAID_STATE: usize = 256 * 1024;
const MAX_SCKA_HEADER_BLOB: usize = 9 + CHUNK_WIRE;

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
            Some(message) => {
                let blob = message.encode();
                out.push(1);
                out.extend_from_slice(&(blob.len() as u16).to_le_bytes());
                out.extend_from_slice(&blob);
            }
        }
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, PrimitiveError> {
        // Canonical v2 representation always carries the explicit option tag.
        if data.len() < 49 {
            return Err(PrimitiveError::InvalidLength);
        }
        let classical = Header::decode(&data[..40])?;
        let pq_epoch = u32::from_le_bytes(data[40..44].try_into().unwrap());
        let pq_n = u32::from_le_bytes(data[44..48].try_into().unwrap());
        let scka = match data[48] {
            0 => {
                if data.len() != 49 {
                    return Err(PrimitiveError::InvalidLength);
                }
                None
            }
            1 => {
                if data.len() < 51 {
                    return Err(PrimitiveError::InvalidLength);
                }
                let len = u16::from_le_bytes(data[49..51].try_into().unwrap()) as usize;
                if len > MAX_SCKA_HEADER_BLOB || data.len() != 51 + len {
                    return Err(PrimitiveError::LimitExceeded);
                }
                let message = BraidMessage::decode(&data[51..])?;
                validate_braid_message(&message)?;
                Some(message)
            }
            _ => return Err(PrimitiveError::InvalidLength),
        };
        Ok(Self {
            classical,
            pq_epoch,
            pq_n,
            scka,
        })
    }
}

fn validate_braid_message(message: &BraidMessage) -> Result<(), PrimitiveError> {
    match message.typ {
        BraidType::None | BraidType::Ct1Ack => {
            if !message.data.is_empty() {
                return Err(PrimitiveError::InvalidLength);
            }
        }
        _ => {
            if message.data.len() != CHUNK_WIRE {
                return Err(PrimitiveError::InvalidLength);
            }
        }
    }
    Ok(())
}

pub struct TripleRatchetState {
    pub classical: DoubleRatchetState,
    pub spqr: SpqrState,
    pub braid: BraidScka,
}

impl TripleRatchetState {
    fn split_sk(sk: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), PrimitiveError> {
        let mut okm = [0u8; 64];
        let result = hkdf_extract_expand(None, sk, LABELS::TRIPLE_HYBRID, &mut okm);
        if let Err(err) = result {
            okm.zeroize();
            return Err(err);
        }
        let mut sk_ec = [0u8; 32];
        let mut sk_pq = [0u8; 32];
        sk_ec.copy_from_slice(&okm[..32]);
        sk_pq.copy_from_slice(&okm[32..]);
        okm.zeroize();
        Ok((sk_ec, sk_pq))
    }

    pub fn init_alice(sk: &[u8; 32], bob_dh_public: &X25519Public) -> Result<Self, PrimitiveError> {
        let (mut sk_ec, mut sk_pq) = Self::split_sk(sk)?;
        let result = (|| {
            let classical =
                DoubleRatchetState::init_alice(&sk_ec, bob_dh_public, DEFAULT_MAX_SKIP)?;
            let mut spqr = SpqrState::init(&sk_pq, SPQR_MAX_SKIP_EPOCHS);
            spqr.advance_epoch(&sk_pq)?;
            let braid = BraidScka::init_alice(&sk_pq)?;
            Ok(Self {
                classical,
                spqr,
                braid,
            })
        })();
        sk_ec.zeroize();
        sk_pq.zeroize();
        result
    }

    pub fn init_bob(sk: &[u8; 32], bob_dh_keypair: X25519Secret) -> Result<Self, PrimitiveError> {
        let (mut sk_ec, mut sk_pq) = Self::split_sk(sk)?;
        let result = (|| {
            let classical =
                DoubleRatchetState::init_bob(&sk_ec, bob_dh_keypair, DEFAULT_MAX_SKIP);
            let mut spqr = SpqrState::init(&sk_pq, SPQR_MAX_SKIP_EPOCHS);
            spqr.advance_epoch(&sk_pq)?;
            let braid = BraidScka::init_bob(&sk_pq)?;
            Ok(Self {
                classical,
                spqr,
                braid,
            })
        })();
        sk_ec.zeroize();
        sk_pq.zeroize();
        result
    }

    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        ad: &[u8],
    ) -> Result<(TripleHeader, Vec<u8>), PrimitiveError> {
        let (scka_msg, _send_epoch, new_ss) = self.braid.send()?;
        if let Some(output) = new_ss {
            self.spqr.advance_epoch(&output.key)?;
        }
        let (classical_header, mut ec_mk) = self.classical.send_message_key()?;
        let (pq_epoch, pq_n, mut pq_mk) = self.spqr.send_key()?;
        let hybrid_result = kdf_hybrid(&ec_mk, &pq_mk);
        ec_mk.zeroize();
        pq_mk.zeroize();
        let mut hybrid_mk = hybrid_result?;

        let header = TripleHeader {
            classical: classical_header,
            pq_epoch,
            pq_n,
            scka: Some(scka_msg),
        };
        let associated = concat_triple_ad(ad, &header);
        let key_nonce = aead_from_hybrid(&hybrid_mk);
        let (key, nonce) = match key_nonce {
            Ok(v) => v,
            Err(err) => {
                hybrid_mk.zeroize();
                return Err(err);
            }
        };
        let ciphertext_result = aead::seal(&key, &nonce, plaintext, &associated);
        hybrid_mk.zeroize();
        let ciphertext = ciphertext_result?;
        Ok((header, ciphertext))
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
        if let Some(ref message) = header.scka {
            validate_braid_message(message)?;
            let (_, output) = trial_b.receive(message)?;
            if let Some(output) = output {
                if trial_s.receiving_epoch() != Some(header.pq_epoch) {
                    trial_s.advance_epoch(&output.key)?;
                } else {
                    pending_scka = Some(output.key);
                }
            }
        }

        let mut ec_mk = trial_c.receive_message_key(&header.classical)?;
        let mut pq_mk = trial_s.receive_key(header.pq_epoch, header.pq_n)?;
        let hybrid_result = kdf_hybrid(&ec_mk, &pq_mk);
        ec_mk.zeroize();
        pq_mk.zeroize();
        let mut hybrid_mk = hybrid_result?;
        let associated = concat_triple_ad(ad, header);
        let key_nonce = aead_from_hybrid(&hybrid_mk);
        let (key, nonce) = match key_nonce {
            Ok(v) => v,
            Err(err) => {
                hybrid_mk.zeroize();
                if let Some(mut pending) = pending_scka {
                    pending.zeroize();
                }
                return Err(err);
            }
        };
        let plaintext_result = aead::open(&key, &nonce, ciphertext, &associated);
        hybrid_mk.zeroize();
        let plaintext = match plaintext_result {
            Ok(value) => value,
            Err(err) => {
                if let Some(mut pending) = pending_scka {
                    pending.zeroize();
                }
                return Err(err);
            }
        };
        if let Some(mut pending) = pending_scka {
            let advance_result = trial_s.advance_epoch(&pending);
            pending.zeroize();
            advance_result?;
        }
        self.classical = trial_c;
        self.spqr = trial_s;
        self.braid = trial_b;
        Ok(plaintext)
    }

    pub fn last_header_len(header: &TripleHeader) -> usize {
        header.encode().len()
    }

    pub fn clone_for_trial(&self) -> Self {
        Self {
            classical: self.classical.clone_for_trial(),
            spqr: self.spqr.clone_for_trial(),
            braid: self.braid.clone(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let classical = self.classical.serialize();
        let spqr = self.spqr.serialize();
        let braid = self.braid.serialize();
        let mut out = Vec::with_capacity(12 + classical.len() + spqr.len() + braid.len());
        write_component(&mut out, &classical);
        write_component(&mut out, &spqr);
        write_component(&mut out, &braid);
        out
    }

    pub fn deserialize(data: &[u8], max_skip: u32) -> Result<Self, PrimitiveError> {
        if data.len() < 12 || data.len() > MAX_TRIPLE_STATE {
            return Err(PrimitiveError::LimitExceeded);
        }
        let mut i = 0usize;
        let classical_blob = read_component(data, &mut i, MAX_TRIPLE_COMPONENT)?;
        let spqr_blob = read_component(data, &mut i, MAX_TRIPLE_COMPONENT)?;
        let braid_blob = read_component(data, &mut i, MAX_BRAID_STATE)?;
        if i != data.len() {
            return Err(PrimitiveError::InvalidLength);
        }
        validate_braid_state_blob(braid_blob)?;
        Ok(Self {
            classical: DoubleRatchetState::deserialize(classical_blob, max_skip)?,
            spqr: SpqrState::deserialize(spqr_blob)?,
            braid: BraidScka::deserialize(braid_blob)?,
        })
    }
}

fn write_component(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn read_component<'a>(
    data: &'a [u8],
    i: &mut usize,
    max: usize,
) -> Result<&'a [u8], PrimitiveError> {
    let len_bytes = take(data, i, 4)?;
    let len = u32::from_le_bytes(len_bytes.try_into().unwrap()) as usize;
    if len > max {
        return Err(PrimitiveError::LimitExceeded);
    }
    take(data, i, len)
}

fn take<'a>(data: &'a [u8], i: &mut usize, len: usize) -> Result<&'a [u8], PrimitiveError> {
    let end = i.checked_add(len).ok_or(PrimitiveError::LimitExceeded)?;
    if end > data.len() {
        return Err(PrimitiveError::InvalidLength);
    }
    let out = &data[*i..end];
    *i = end;
    Ok(out)
}

fn validate_braid_state_blob(data: &[u8]) -> Result<(), PrimitiveError> {
    if data.len() < 8 || data.len() > MAX_BRAID_STATE {
        return Err(PrimitiveError::LimitExceeded);
    }
    match &data[..8] {
        b"VCBRAID1" | b"VCBRAID2" => {
            // Historical compact form is exactly magic + epoch + auth + bool.
            if data.len() != 81 || !matches!(data[80], 0 | 1) {
                return Err(PrimitiveError::InvalidLength);
            }
        }
        b"VCBRAID3" => {}
        _ => return Err(PrimitiveError::InvalidLength),
    }
    Ok(())
}

fn kdf_hybrid(classical_mk: &[u8; 32], pq_mk: &[u8; 32]) -> Result<[u8; 32], PrimitiveError> {
    let mut out = [0u8; 32];
    let result = hkdf_extract_expand(Some(pq_mk), classical_mk, LABELS::TRIPLE_HYBRID, &mut out);
    if let Err(err) = result {
        out.zeroize();
        return Err(err);
    }
    Ok(out)
}

fn aead_from_hybrid(mk: &[u8; 32]) -> Result<(AeadKey, [u8; 12]), PrimitiveError> {
    let salt = [0u8; 32];
    let mut okm = [0u8; 44];
    let result = hkdf_extract_expand(Some(&salt), mk, LABELS::DR_MESSAGE, &mut okm);
    if let Err(err) = result {
        okm.zeroize();
        return Err(err);
    }
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..]);
    okm.zeroize();
    Ok((AeadKey::from_bytes(key), nonce))
}

fn concat_triple_ad(ad: &[u8], header: &TripleHeader) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + ad.len() + header.encode().len());
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
        let (header, ciphertext) = alice.encrypt(b"hybrid-hello", b"ad").unwrap();
        assert_eq!(
            bob.decrypt(&header, &ciphertext, b"ad").unwrap(),
            b"hybrid-hello"
        );
        let (header, ciphertext) = bob.encrypt(b"reply", b"ad").unwrap();
        assert_eq!(
            alice.decrypt(&header, &ciphertext, b"ad").unwrap(),
            b"reply"
        );
    }

    #[test]
    fn tamper_does_not_commit() {
        let sk = [3u8; 32];
        let bob_dh = X25519Secret::generate().unwrap();
        let mut alice = TripleRatchetState::init_alice(&sk, &bob_dh.public_key()).unwrap();
        let mut bob = TripleRatchetState::init_bob(&sk, bob_dh).unwrap();
        let (header, mut ciphertext) = alice.encrypt(b"secret", b"ad").unwrap();
        if let Some(byte) = ciphertext.last_mut() {
            *byte ^= 0xff;
        }
        assert!(bob.decrypt(&header, &ciphertext, b"ad").is_err());
    }

    #[test]
    fn header_encode_decode() {
        let sk = [1u8; 32];
        let bob_dh = X25519Secret::generate().unwrap();
        let mut alice = TripleRatchetState::init_alice(&sk, &bob_dh.public_key()).unwrap();
        let (header, _) = alice.encrypt(b"x", b"").unwrap();
        assert_eq!(TripleHeader::decode(&header.encode()).unwrap(), header);
    }

    #[test]
    fn header_rejects_noncanonical_implicit_none() {
        let sk = [1u8; 32];
        let bob_dh = X25519Secret::generate().unwrap();
        let mut alice = TripleRatchetState::init_alice(&sk, &bob_dh.public_key()).unwrap();
        let (mut header, _) = alice.encrypt(b"x", b"").unwrap();
        header.scka = None;
        let mut encoded = header.encode();
        encoded.pop();
        assert_eq!(encoded.len(), 48);
        assert!(TripleHeader::decode(&encoded).is_err());
    }

    #[test]
    fn serialize_reload_continues_conversation() {
        let sk = [5u8; 32];
        let bob_dh = X25519Secret::generate().unwrap();
        let mut alice = TripleRatchetState::init_alice(&sk, &bob_dh.public_key()).unwrap();
        let mut bob = TripleRatchetState::init_bob(&sk, bob_dh).unwrap();
        let (header, ciphertext) = alice.encrypt(b"before", b"ad").unwrap();
        assert_eq!(bob.decrypt(&header, &ciphertext, b"ad").unwrap(), b"before");
        let mut alice =
            TripleRatchetState::deserialize(&alice.serialize(), DEFAULT_MAX_SKIP).unwrap();
        let mut bob = TripleRatchetState::deserialize(&bob.serialize(), DEFAULT_MAX_SKIP).unwrap();
        let (header, ciphertext) = bob.encrypt(b"after", b"ad").unwrap();
        assert_eq!(alice.decrypt(&header, &ciphertext, b"ad").unwrap(), b"after");
    }

    #[test]
    fn deserialize_rejects_oversized_component_before_slice() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&((MAX_TRIPLE_COMPONENT as u32) + 1).to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        assert!(TripleRatchetState::deserialize(&blob, DEFAULT_MAX_SKIP).is_err());
    }

    #[test]
    fn old_compact_braid_boolean_is_strict() {
        let mut blob = b"VCBRAID2".to_vec();
        blob.extend_from_slice(&1u64.to_le_bytes());
        blob.extend_from_slice(&[0u8; 64]);
        blob.push(2);
        assert!(validate_braid_state_blob(&blob).is_err());
    }
}
