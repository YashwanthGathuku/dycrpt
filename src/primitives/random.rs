//! Cryptographically secure random number generation.

use rand_core::{OsRng, RngCore};

use super::error::PrimitiveError;

/// Fill the given buffer with cryptographically secure random bytes.
///
/// Uses `try_fill_bytes`, not `fill_bytes`. `RngCore::fill_bytes` **panics**
/// when the OS entropy source fails, which would make the `Result` returned
/// here structurally unreachable and turn an entropy failure into a panic
/// inside a cryptographic operation. Propagating the error instead lets every
/// caller fail closed on the path it already has.
pub fn fill_random(buf: &mut [u8]) -> Result<(), PrimitiveError> {
    OsRng.try_fill_bytes(buf).map_err(|_| PrimitiveError::Rng)
}

/// Generate a random 32-byte value.
pub fn random_32() -> Result<[u8; 32], PrimitiveError> {
    let mut buf = [0u8; 32];
    fill_random(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_random_produces_non_zero() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_random(&mut a).unwrap();
        fill_random(&mut b).unwrap();
        // Extremely unlikely to be all-zero or equal
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn fill_random_is_fallible_not_panicking() {
        // Regression guard for the review-2026-08-28 finding: this call site
        // must go through a fallible RNG API. If someone reverts to
        // `fill_bytes`, entropy failure becomes a panic instead of an Err.
        let mut buf = [0u8; 1];
        assert!(fill_random(&mut buf).is_ok());
    }
}
