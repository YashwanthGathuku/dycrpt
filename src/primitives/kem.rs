//! ML-KEM-768 (FIPS 203) wrapper around the RustCrypto `ml-kem` crate.
//!
//! No lattice mathematics are implemented here. Secret material is stored as
//! the 64-byte FIPS 203 seed (preferred serialization).

use ml_kem::array::Array;
use ml_kem::ml_kem_768::{Ciphertext as Ct768, DecapsulationKey, EncapsulationKey};
use ml_kem::{Decapsulate, Encapsulate, FromSeed, KeyExport, KeyInit, MlKem768, Seed};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::error::PrimitiveError;
use super::random::fill_random;

/// ML-KEM-768 encapsulation-key length (FIPS 203).
pub const MLKEM768_PUBLIC_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length (FIPS 203).
pub const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
/// ML-KEM-768 seed / decapsulation-key serialization length.
pub const MLKEM768_SEED_LEN: usize = 64;
/// Shared-secret length.
pub const MLKEM768_SHARED_LEN: usize = 32;

/// ML-KEM-768 public (encapsulation) key.
#[derive(Clone)]
pub struct MlKemPublic {
    bytes: [u8; MLKEM768_PUBLIC_LEN],
}

/// ML-KEM-768 secret stored as a FIPS 203 seed. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKemSecret {
    seed: [u8; MLKEM768_SEED_LEN],
}

/// ML-KEM-768 ciphertext.
#[derive(Clone)]
pub struct MlKemCiphertext {
    bytes: [u8; MLKEM768_CIPHERTEXT_LEN],
}

impl MlKemSecret {
    /// Generate a new ML-KEM-768 key pair from OS CSPRNG output.
    pub fn generate() -> Result<(Self, MlKemPublic), PrimitiveError> {
        let mut seed_bytes = [0u8; MLKEM768_SEED_LEN];
        fill_random(&mut seed_bytes)?;
        let seed: Seed = seed_bytes.into();
        let (_dk, ek) = MlKem768::from_seed(&seed);
        let public = encode_public(&ek)?;
        Ok((Self { seed: seed_bytes }, public))
    }

    /// Reconstruct from a 64-byte seed.
    pub fn from_seed_bytes(seed: [u8; MLKEM768_SEED_LEN]) -> Self {
        Self { seed }
    }

    /// Decapsulate. ML-KEM uses implicit rejection for well-formed-length
    /// ciphertexts that do not match this secret.
    pub fn decapsulate(&self, ct: &MlKemCiphertext) -> Result<[u8; 32], PrimitiveError> {
        let seed: Seed = self.seed.into();
        let dk = DecapsulationKey::new(&seed);
        let ct_arr: Ct768 = Array::try_from(ct.bytes.as_slice())
            .map_err(|_| PrimitiveError::InvalidKemCiphertext)?;
        let ss = dk.decapsulate(&ct_arr);
        let mut out = [0u8; 32];
        out.copy_from_slice(ss.as_slice());
        Ok(out)
    }

    /// Corresponding public key.
    pub fn public_key(&self) -> Result<MlKemPublic, PrimitiveError> {
        let seed: Seed = self.seed.into();
        let (_dk, ek) = MlKem768::from_seed(&seed);
        encode_public(&ek)
    }

    /// Raw 64-byte seed.
    pub fn as_seed(&self) -> &[u8; MLKEM768_SEED_LEN] {
        &self.seed
    }
}

impl MlKemPublic {
    /// Encapsulate to this public key. Returns `(shared_secret, ciphertext)`.
    pub fn encapsulate(&self) -> Result<([u8; 32], MlKemCiphertext), PrimitiveError> {
        let arr =
            Array::try_from(self.bytes.as_slice()).map_err(|_| PrimitiveError::InvalidPublicKey)?;
        let ek = EncapsulationKey::new(&arr).map_err(|_| PrimitiveError::InvalidPublicKey)?;
        let (ct, ss) = ek.encapsulate();
        let mut ss_out = [0u8; 32];
        ss_out.copy_from_slice(ss.as_slice());
        let mut ct_bytes = [0u8; MLKEM768_CIPHERTEXT_LEN];
        ct_bytes.copy_from_slice(ct.as_slice());
        Ok((ss_out, MlKemCiphertext { bytes: ct_bytes }))
    }

    /// Exact-length constructor. Rejects malformed lengths and invalid keys.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PrimitiveError> {
        if bytes.len() != MLKEM768_PUBLIC_LEN {
            return Err(PrimitiveError::InvalidPublicKey);
        }
        let mut arr = [0u8; MLKEM768_PUBLIC_LEN];
        arr.copy_from_slice(bytes);
        let encoded =
            Array::try_from(arr.as_slice()).map_err(|_| PrimitiveError::InvalidPublicKey)?;
        let _ = EncapsulationKey::new(&encoded).map_err(|_| PrimitiveError::InvalidPublicKey)?;
        Ok(Self { bytes: arr })
    }

    /// Raw public-key bytes.
    pub fn as_bytes(&self) -> &[u8; MLKEM768_PUBLIC_LEN] {
        &self.bytes
    }
}

impl MlKemCiphertext {
    /// Exact-length constructor.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PrimitiveError> {
        if bytes.len() != MLKEM768_CIPHERTEXT_LEN {
            return Err(PrimitiveError::InvalidKemCiphertext);
        }
        let mut arr = [0u8; MLKEM768_CIPHERTEXT_LEN];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Raw ciphertext bytes.
    pub fn as_bytes(&self) -> &[u8; MLKEM768_CIPHERTEXT_LEN] {
        &self.bytes
    }
}

fn encode_public(ek: &EncapsulationKey) -> Result<MlKemPublic, PrimitiveError> {
    let encoded = ek.to_bytes();
    if encoded.len() != MLKEM768_PUBLIC_LEN {
        return Err(PrimitiveError::InvalidPublicKey);
    }
    let mut bytes = [0u8; MLKEM768_PUBLIC_LEN];
    bytes.copy_from_slice(encoded.as_slice());
    Ok(MlKemPublic { bytes })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encaps_decaps_roundtrip() {
        let (sk, pk) = MlKemSecret::generate().unwrap();
        let (ss1, ct) = pk.encapsulate().unwrap();
        let ss2 = sk.decapsulate(&ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn seed_reload_preserves_decaps() {
        let (sk, pk) = MlKemSecret::generate().unwrap();
        let (ss1, ct) = pk.encapsulate().unwrap();
        let sk2 = MlKemSecret::from_seed_bytes(*sk.as_seed());
        let ss2 = sk2.decapsulate(&ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn rejects_malformed_public_key_length() {
        assert!(matches!(
            MlKemPublic::from_bytes(&[0u8; 32]),
            Err(PrimitiveError::InvalidPublicKey)
        ));
    }

    #[test]
    fn rejects_malformed_ciphertext_length() {
        assert!(matches!(
            MlKemCiphertext::from_bytes(&[0u8; 16]),
            Err(PrimitiveError::InvalidKemCiphertext)
        ));
    }

    #[test]
    fn wrong_secret_does_not_match() {
        let (_sk_a, pk_a) = MlKemSecret::generate().unwrap();
        let (sk_b, _pk_b) = MlKemSecret::generate().unwrap();
        let (ss_a, ct) = pk_a.encapsulate().unwrap();
        let ss_b = sk_b.decapsulate(&ct).unwrap();
        assert_ne!(ss_a, ss_b);
    }
}
