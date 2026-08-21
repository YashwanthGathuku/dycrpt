//! Cryptographically secure random number generation.

use rand_core::{OsRng, RngCore};

use super::error::PrimitiveError;

/// Fill the given buffer with cryptographically secure random bytes.
pub fn fill_random(buf: &mut [u8]) -> Result<(), PrimitiveError> {
    OsRng.fill_bytes(buf);
    Ok(())
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
}
