//! PQXDH EncodeEC / EncodeKEM as specified in PQXDH Rev 3 §2.1.
//!
//! Recommended form: one-byte parameter identifier followed by the native
//! public-key encoding. Ranges of all encoding functions are pairwise disjoint
//! by construction (different leading bytes / lengths).

use super::error::PrimitiveError;
use super::kem::{MlKemPublic, MLKEM768_PUBLIC_LEN};
use super::x25519::X25519Public;

/// Implementer-defined single-byte identifier for curve25519.
pub const CURVE_ID_X25519: u8 = 0x01;
/// Implementer-defined single-byte identifier for ML-KEM-768.
pub const KEM_ID_MLKEM768: u8 = 0x81;

/// EncodeEC(PK) = curve_id || u-coordinate (RFC 7748 little-endian).
pub fn encode_ec(pk: &X25519Public) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = CURVE_ID_X25519;
    out[1..].copy_from_slice(&pk.to_bytes());
    out
}

/// DecodeEC. Fails on unrecognized curve or all-zero / invalid public keys.
pub fn decode_ec(bytes: &[u8]) -> Result<X25519Public, PrimitiveError> {
    if bytes.len() != 33 || bytes[0] != CURVE_ID_X25519 {
        return Err(PrimitiveError::InvalidPublicKey);
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&bytes[1..]);
    X25519Public::from_bytes(pk)
}

/// EncodeKEM(PK) = kem_id || FIPS 203 ML-KEM-768 encapsulation key.
pub fn encode_kem(pk: &MlKemPublic) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + MLKEM768_PUBLIC_LEN);
    out.push(KEM_ID_MLKEM768);
    out.extend_from_slice(pk.as_bytes());
    out
}

/// DecodeKEM. Fails on unrecognized KEM or malformed key.
pub fn decode_kem(bytes: &[u8]) -> Result<MlKemPublic, PrimitiveError> {
    if bytes.len() != 1 + MLKEM768_PUBLIC_LEN || bytes[0] != KEM_ID_MLKEM768 {
        return Err(PrimitiveError::InvalidPublicKey);
    }
    MlKemPublic::from_bytes(&bytes[1..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::x25519::X25519Secret;

    #[test]
    fn encode_ec_roundtrip() {
        let pk = X25519Secret::generate().unwrap().public_key();
        let enc = encode_ec(&pk);
        assert_eq!(enc[0], CURVE_ID_X25519);
        assert_eq!(decode_ec(&enc).unwrap().to_bytes(), pk.to_bytes());
    }

    #[test]
    fn decode_ec_rejects_bad_id() {
        let mut enc = encode_ec(&X25519Secret::generate().unwrap().public_key());
        enc[0] = 0x02;
        assert!(decode_ec(&enc).is_err());
    }
}
