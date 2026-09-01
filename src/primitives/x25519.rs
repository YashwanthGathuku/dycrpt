//! X25519 Diffie-Hellman (RFC 7748) wrapper.

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::error::PrimitiveError;
use super::random::fill_random;

/// X25519 secret key (32 bytes). Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct X25519Secret(StaticSecret);

/// X25519 public key (32 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X25519Public(PublicKey);

impl X25519Secret {
    /// Generate a fresh random secret key.
    pub fn generate() -> Result<Self, PrimitiveError> {
        let mut bytes = [0u8; 32];
        fill_random(&mut bytes)?;
        Ok(Self(StaticSecret::from(bytes)))
    }

    /// Construct from raw 32-byte scalar (clamped by X25519).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    pub fn public_key(&self) -> X25519Public {
        X25519Public(PublicKey::from(&self.0))
    }

    /// Raw X25519 result.
    ///
    /// Protocol code should prefer [`Self::diffie_hellman_checked`]. This method
    /// remains for compatibility/test-vector use where the caller deliberately
    /// needs the raw RFC 7748 function output.
    pub fn diffie_hellman(&self, their_public: &X25519Public) -> [u8; 32] {
        *self.0.diffie_hellman(&their_public.0).as_bytes()
    }

    /// X25519 with contributory-behavior validation.
    ///
    /// RFC 7748 permits implementations to reject an all-zero shared secret.
    /// Secure protocols need this check because several nonzero low-order input
    /// encodings can produce all-zero output for every private key. Accepting
    /// such an input would let a malicious peer remove its contribution from a
    /// DH term even though the encoded public key itself is nonzero.
    pub fn diffie_hellman_checked(
        &self,
        their_public: &X25519Public,
    ) -> Result<[u8; 32], PrimitiveError> {
        let shared = self.diffie_hellman(their_public);
        if shared == [0u8; 32] {
            return Err(PrimitiveError::InvalidPublicKey);
        }
        Ok(shared)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl X25519Public {
    /// Construct from 32-byte public key. The literal all-zero encoding is
    /// rejected here; low-order/non-contributory inputs are rejected after DH by
    /// [`X25519Secret::diffie_hellman_checked`].
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, PrimitiveError> {
        if bytes == [0u8; 32] {
            return Err(PrimitiveError::InvalidPublicKey);
        }
        Ok(Self(PublicKey::from(bytes)))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        *self.0.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn rfc7748_vector() {
        let alice_secret = X25519Secret::from_bytes(hex!(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        ));
        let alice_public = alice_secret.public_key();
        assert_eq!(
            alice_public.to_bytes(),
            hex!("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );

        let bob_secret = X25519Secret::from_bytes(hex!(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
        ));
        let bob_public = bob_secret.public_key();
        assert_eq!(
            bob_public.to_bytes(),
            hex!("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );

        let shared1 = alice_secret.diffie_hellman_checked(&bob_public).unwrap();
        let shared2 = bob_secret.diffie_hellman_checked(&alice_public).unwrap();
        assert_eq!(shared1, shared2);
        assert_eq!(
            shared1,
            hex!("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        );
    }

    #[test]
    fn rejects_all_zero_public_encoding() {
        assert!(matches!(
            X25519Public::from_bytes([0u8; 32]),
            Err(PrimitiveError::InvalidPublicKey)
        ));
    }

    #[test]
    fn checked_dh_rejects_nonzero_low_order_input() {
        let secret = X25519Secret::from_bytes([7u8; 32]);
        let mut low_order = [0u8; 32];
        low_order[0] = 1;
        let low_order = X25519Public::from_bytes(low_order).unwrap();
        assert!(matches!(
            secret.diffie_hellman_checked(&low_order),
            Err(PrimitiveError::InvalidPublicKey)
        ));
        assert_eq!(secret.diffie_hellman(&low_order), [0u8; 32]);
    }
}
