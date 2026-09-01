//! Configurable encrypted padding buckets to reduce message-length leakage.
//!
//! Padding is applied to plaintext before AEAD. Pad bytes are random and the
//! original length is stored in a fixed-width prefix inside the authenticated
//! plaintext. Custom bucket policies are accepted, but every selected bucket is
//! hard-bounded to prevent attacker-controlled allocation sizes.

use crate::primitives::error::PrimitiveError;
use crate::primitives::random::fill_random;

/// Example default buckets (bytes). Research / traffic analysis may refine
/// these; they are not protocol constants.
pub const DEFAULT_BUCKETS: &[usize] = &[64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384];

/// Hard allocation ceiling for a single padded plaintext.
///
/// The engine's current ciphertext ceiling is 64 MiB, so allowing a padding
/// bucket above this value would only allocate data that the engine could not
/// safely emit anyway.
pub const MAX_PADDING_BUCKET: usize = 64 * 1024 * 1024;
const LENGTH_PREFIX_LEN: usize = 4;

/// Pad `plaintext` to the smallest configured bucket that fits.
///
/// Bucket order is intentionally ignored: `[4096, 64, 128]` behaves like
/// `[64, 128, 4096]`. Buckets above [`MAX_PADDING_BUCKET`] are never selected.
pub fn pad_to_bucket(plaintext: &[u8], buckets: &[usize]) -> Result<Vec<u8>, PrimitiveError> {
    if plaintext.len() > u32::MAX as usize {
        return Err(PrimitiveError::LimitExceeded);
    }
    let needed = plaintext
        .len()
        .checked_add(LENGTH_PREFIX_LEN)
        .ok_or(PrimitiveError::LimitExceeded)?;
    if needed > MAX_PADDING_BUCKET {
        return Err(PrimitiveError::LimitExceeded);
    }

    let bucket = buckets
        .iter()
        .copied()
        .filter(|&bucket| bucket >= needed && bucket <= MAX_PADDING_BUCKET)
        .min()
        .ok_or(PrimitiveError::InvalidLength)?;

    let mut out = vec![0u8; bucket];
    let len = u32::try_from(plaintext.len()).map_err(|_| PrimitiveError::LimitExceeded)?;
    out[..LENGTH_PREFIX_LEN].copy_from_slice(&len.to_le_bytes());
    let body_end = LENGTH_PREFIX_LEN
        .checked_add(plaintext.len())
        .ok_or(PrimitiveError::LimitExceeded)?;
    out[LENGTH_PREFIX_LEN..body_end].copy_from_slice(plaintext);
    if body_end < bucket {
        fill_random(&mut out[body_end..])?;
    }
    Ok(out)
}

/// Strip padding after successful AEAD decryption.
///
/// This validates only the authenticated length prefix. Bucket-policy
/// membership is a sender/transport policy and is not required for unpadding.
pub fn unpad(padded: &[u8]) -> Result<Vec<u8>, PrimitiveError> {
    if padded.len() < LENGTH_PREFIX_LEN || padded.len() > MAX_PADDING_BUCKET {
        return Err(PrimitiveError::InvalidLength);
    }
    let len = u32::from_le_bytes(
        padded[..LENGTH_PREFIX_LEN]
            .try_into()
            .map_err(|_| PrimitiveError::InvalidLength)?,
    ) as usize;
    let end = LENGTH_PREFIX_LEN
        .checked_add(len)
        .ok_or(PrimitiveError::LimitExceeded)?;
    if end > padded.len() {
        return Err(PrimitiveError::InvalidLength);
    }
    Ok(padded[LENGTH_PREFIX_LEN..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_unpad_roundtrip() {
        let pt = b"short message";
        let padded = pad_to_bucket(pt, DEFAULT_BUCKETS).unwrap();
        assert!(padded.len() >= pt.len() + LENGTH_PREFIX_LEN);
        assert!(DEFAULT_BUCKETS.contains(&padded.len()));
        assert_eq!(unpad(&padded).unwrap(), pt);
    }

    #[test]
    fn different_lengths_same_bucket() {
        let a = pad_to_bucket(&[0u8; 10], DEFAULT_BUCKETS).unwrap();
        let b = pad_to_bucket(&[0u8; 20], DEFAULT_BUCKETS).unwrap();
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn unsorted_buckets_choose_smallest_fitting_bucket() {
        let padded = pad_to_bucket(b"hello", &[4096, 128, 64, 256]).unwrap();
        assert_eq!(padded.len(), 64);
    }

    #[test]
    fn oversized_payload_rejected() {
        let huge = vec![0u8; 100_000];
        assert!(pad_to_bucket(&huge, DEFAULT_BUCKETS).is_err());
    }

    #[test]
    fn absurd_bucket_is_not_allocated() {
        assert!(pad_to_bucket(b"x", &[usize::MAX]).is_err());
        assert!(pad_to_bucket(b"x", &[MAX_PADDING_BUCKET + 1]).is_err());
    }

    #[test]
    fn unpad_rejects_length_past_authenticated_buffer() {
        let mut padded = vec![0u8; 64];
        padded[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(unpad(&padded).is_err());
    }

    #[test]
    fn unpad_rejects_oversized_buffer() {
        let padded = vec![0u8; MAX_PADDING_BUCKET + 1];
        assert!(unpad(&padded).is_err());
    }
}
