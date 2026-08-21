//! Continuous key agreement using ML-KEM-768 (full encaps/decaps per turn).
//!
//! This is a bandwidth-heavy CKA, not the sparse ML-KEM Braid. It produces
//! matching shared secrets on both sides so Triple Ratchet can mix new PQ
//! entropy after the handshake.

use crate::primitives::error::PrimitiveError;
use crate::primitives::kem::{
    MlKemPublic, MlKemSecret, MLKEM768_CIPHERTEXT_LEN, MLKEM768_PUBLIC_LEN, MLKEM768_SEED_LEN,
};

/// On-the-wire CKA message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SckaMessage {
    /// Fresh encapsulation key (sender will later decapsulate).
    EncapsulationKey(Vec<u8>),
    /// Ciphertext encapsulating to the peer's last encapsulation key.
    Ciphertext(Vec<u8>),
}

impl SckaMessage {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            SckaMessage::EncapsulationKey(b) => {
                let mut o = Vec::with_capacity(1 + b.len());
                o.push(1);
                o.extend_from_slice(b);
                o
            }
            SckaMessage::Ciphertext(b) => {
                let mut o = Vec::with_capacity(1 + b.len());
                o.push(2);
                o.extend_from_slice(b);
                o
            }
        }
    }

    pub fn decode(data: &[u8]) -> Result<Self, PrimitiveError> {
        if data.is_empty() {
            return Err(PrimitiveError::InvalidLength);
        }
        match data[0] {
            1 => {
                if data.len() != 1 + MLKEM768_PUBLIC_LEN {
                    return Err(PrimitiveError::InvalidPublicKey);
                }
                let _ = MlKemPublic::from_bytes(&data[1..])?;
                Ok(SckaMessage::EncapsulationKey(data[1..].to_vec()))
            }
            2 => {
                if data.len() != 1 + MLKEM768_CIPHERTEXT_LEN {
                    return Err(PrimitiveError::InvalidKemCiphertext);
                }
                Ok(SckaMessage::Ciphertext(data[1..].to_vec()))
            }
            _ => Err(PrimitiveError::InvalidLength),
        }
    }
}

/// Ping-pong ML-KEM CKA state.
#[derive(Clone, Default)]
pub struct MlKemCka {
    pending_dk: Option<MlKemSecret>,
    remote_ek: Option<MlKemPublic>,
}

impl MlKemCka {
    pub fn new() -> Self {
        Self::default()
    }

    /// Produce a CKA message and optionally a newly agreed secret.
    pub fn send(&mut self) -> Result<(SckaMessage, Option<[u8; 32]>), PrimitiveError> {
        if let Some(ek) = self.remote_ek.take() {
            let (ss, ct) = ek.encapsulate()?;
            return Ok((SckaMessage::Ciphertext(ct.as_bytes().to_vec()), Some(ss)));
        }
        if self.pending_dk.is_none() {
            let (dk, pk) = MlKemSecret::generate()?;
            self.pending_dk = Some(dk);
            return Ok((SckaMessage::EncapsulationKey(pk.as_bytes().to_vec()), None));
        }
        // Waiting for peer ciphertext — resend the same public key.
        let pk = self
            .pending_dk
            .as_ref()
            .ok_or(PrimitiveError::Internal)?
            .public_key()?;
        Ok((SckaMessage::EncapsulationKey(pk.as_bytes().to_vec()), None))
    }

    /// Process a peer CKA message. Returns a new shared secret when one is agreed.
    pub fn receive(&mut self, msg: &SckaMessage) -> Result<Option<[u8; 32]>, PrimitiveError> {
        match msg {
            SckaMessage::EncapsulationKey(bytes) => {
                let pk = MlKemPublic::from_bytes(bytes)?;
                self.remote_ek = Some(pk);
                Ok(None)
            }
            SckaMessage::Ciphertext(bytes) => {
                let dk = self
                    .pending_dk
                    .take()
                    .ok_or(PrimitiveError::InvalidKemCiphertext)?;
                let ct = crate::primitives::kem::MlKemCiphertext::from_bytes(bytes)?;
                let ss = dk.decapsulate(&ct)?;
                Ok(Some(ss))
            }
        }
    }

    /// Persist CKA (pending seed + remote EK). Caller must protect the blob.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match &self.pending_dk {
            Some(dk) => {
                out.push(1);
                out.extend_from_slice(dk.as_seed());
            }
            None => out.push(0),
        }
        match &self.remote_ek {
            Some(ek) => {
                out.push(1);
                out.extend_from_slice(ek.as_bytes());
            }
            None => out.push(0),
        }
        out
    }

    /// Restore CKA from [`Self::serialize`].
    pub fn deserialize(data: &[u8]) -> Result<Self, PrimitiveError> {
        if data.is_empty() {
            return Err(PrimitiveError::InvalidLength);
        }
        let mut i = 0;
        let has_dk = data[i];
        i += 1;
        let pending_dk = if has_dk == 1 {
            if i + MLKEM768_SEED_LEN > data.len() {
                return Err(PrimitiveError::InvalidLength);
            }
            let mut seed = [0u8; MLKEM768_SEED_LEN];
            seed.copy_from_slice(&data[i..i + MLKEM768_SEED_LEN]);
            i += MLKEM768_SEED_LEN;
            Some(MlKemSecret::from_seed_bytes(seed))
        } else if has_dk == 0 {
            None
        } else {
            return Err(PrimitiveError::InvalidLength);
        };
        if i >= data.len() {
            return Err(PrimitiveError::InvalidLength);
        }
        let has_ek = data[i];
        i += 1;
        let remote_ek = if has_ek == 1 {
            if i + MLKEM768_PUBLIC_LEN != data.len() {
                return Err(PrimitiveError::InvalidLength);
            }
            Some(MlKemPublic::from_bytes(&data[i..])?)
        } else if has_ek == 0 {
            if i != data.len() {
                return Err(PrimitiveError::InvalidLength);
            }
            None
        } else {
            return Err(PrimitiveError::InvalidLength);
        };
        Ok(Self {
            pending_dk,
            remote_ek,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_pong_secrets_match() {
        let mut a = MlKemCka::new();
        let mut b = MlKemCka::new();

        let (m1, s1) = a.send().unwrap();
        assert!(s1.is_none());
        assert!(b.receive(&m1).unwrap().is_none());

        let (m2, s2) = b.send().unwrap();
        let s2 = s2.expect("bob encapsulates");
        let s1b = a.receive(&m2).unwrap().expect("alice decapsulates");
        assert_eq!(s2, s1b);
    }

    #[test]
    fn encode_decode_ek() {
        let mut a = MlKemCka::new();
        let (m, _) = a.send().unwrap();
        let bytes = m.encode();
        let m2 = SckaMessage::decode(&bytes).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn malformed_rejected() {
        assert!(SckaMessage::decode(&[]).is_err());
        assert!(SckaMessage::decode(&[1, 2, 3]).is_err());
        assert!(SckaMessage::decode(&[9]).is_err());
    }

    #[test]
    fn serialize_reload_preserves_pending() {
        let mut a = MlKemCka::new();
        let _ = a.send().unwrap();
        let blob = a.serialize();
        let mut a2 = MlKemCka::deserialize(&blob).unwrap();
        let mut b = MlKemCka::new();
        let (m1, _) = a2.send().unwrap();
        assert!(b.receive(&m1).unwrap().is_none());
        let (m2, s_b) = b.send().unwrap();
        let s_a = a2.receive(&m2).unwrap();
        assert_eq!(s_a, s_b);
    }
}
