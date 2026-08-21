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
        // StaticSecret clamps automatically.
        Ok(Self(StaticSecret::from(bytes)))
    }

    /// Construct from raw 32-byte scalar (clamped).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    /// Public key corresponding to this secret.
    pub fn public_key(&self) -> X25519Public {
        X25519Public(PublicKey::from(&self.0))
    }

    /// Diffie-Hellman: compute shared secret with a remote public key.
    pub fn diffie_hellman(&self, their_public: &X25519Public) -> [u8; 32] {
        *self.0.diffie_hellman(&their_public.0).as_bytes()
    }

    /// Raw bytes (use with care).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl X25519Public {
    /// Construct from 32-byte public key. Rejects the all-zero key.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, PrimitiveError> {
        if bytes == [0u8; 32] {
            return Err(PrimitiveError::InvalidPublicKey);
        }
        Ok(Self(PublicKey::from(bytes)))
    }

    /// Raw bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        *self.0.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    // RFC 7748 test vector
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

        let shared1 = alice_secret.diffie_hellman(&bob_public);
        let shared2 = bob_secret.diffie_hellman(&alice_public);
        assert_eq!(shared1, shared2);
        assert_eq!(
            shared1,
            hex!("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        );
    }

    #[test]
    fn rejects_all_zero_public() {
        let res = X25519Public::from_bytes([0u8; 32]);
        assert!(matches!(res, Err(PrimitiveError::InvalidPublicKey)));
    }

    #[test]
    fn generate_roundtrip() {
        let sk = X25519Secret::generate().unwrap();
        let pk = sk.public_key();
        let sk2 = X25519Secret::from_bytes(sk.to_bytes());
        assert_eq!(pk.to_bytes(), sk2.public_key().to_bytes());
    }
}
