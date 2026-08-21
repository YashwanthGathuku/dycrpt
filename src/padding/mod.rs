//! Configurable encrypted padding buckets to reduce message-length leakage.
//!
//! Padding is applied to the plaintext before AEAD. The pad content is
//! random (never deterministic length-revealing patterns). Bucket sizes
//! are policy-configurable.

use crate::primitives::error::PrimitiveError;
use crate::primitives::random::fill_random;

/// Example default buckets (bytes). Research / traffic analysis may
/// refine these; they are not hard-coded assumptions of the crypto.
pub const DEFAULT_BUCKETS: &[usize] = &[64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384];

/// Pad `plaintext` up to the smallest bucket that fits, using random bytes.
/// Returns the padded buffer. The original length is encoded in a small
/// header so the recipient can strip the pad after decryption.
pub fn pad_to_bucket(plaintext: &[u8], buckets: &[usize]) -> Result<Vec<u8>, PrimitiveError> {
    let needed = plaintext
        .len()
        .checked_add(4)
        .ok_or(PrimitiveError::InvalidLength)?; // 4-byte length prefix
    let bucket = buckets
        .iter()
        .copied()
        .find(|&b| b >= needed)
        .ok_or(PrimitiveError::InvalidLength)?; // payload larger than largest bucket

    let mut out = vec![0u8; bucket];
    let len = plaintext.len() as u32;
    out[0..4].copy_from_slice(&len.to_le_bytes());
    out[4..4 + plaintext.len()].copy_from_slice(plaintext);
    // remaining bytes already zero; overwrite with random to avoid
    // deterministic pad content that could leak length via compression
    // or other side channels on the ciphertext.
    if 4 + plaintext.len() < bucket {
        fill_random(&mut out[4 + plaintext.len()..])?;
    }
    Ok(out)
}

/// Strip padding after decryption. Fails if the length prefix is inconsistent.
pub fn unpad(padded: &[u8]) -> Result<Vec<u8>, PrimitiveError> {
    if padded.len() < 4 {
        return Err(PrimitiveError::InvalidLength);
    }
    let len = u32::from_le_bytes(padded[0..4].try_into().unwrap()) as usize;
    if 4 + len > padded.len() {
        return Err(PrimitiveError::InvalidLength);
    }
    Ok(padded[4..4 + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_unpad_roundtrip() {
        let pt = b"short message";
        let padded = pad_to_bucket(pt, DEFAULT_BUCKETS).unwrap();
        assert!(padded.len() >= pt.len() + 4);
        assert!(DEFAULT_BUCKETS.contains(&padded.len()));
        let recovered = unpad(&padded).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn different_lengths_same_bucket() {
        let a = pad_to_bucket(&[0u8; 10], DEFAULT_BUCKETS).unwrap();
        let b = pad_to_bucket(&[0u8; 20], DEFAULT_BUCKETS).unwrap();
        // both fit in 64
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn oversized_rejected() {
        let huge = vec![0u8; 100_000];
        assert!(pad_to_bucket(&huge, DEFAULT_BUCKETS).is_err());
    }
}
