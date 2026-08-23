//! AEAD wrappers (AES-256-GCM primary).

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::error::PrimitiveError;

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
/// AES-GCM authentication tag bytes appended to every sealed payload.
pub const TAG_LEN: usize = 16;

/// AES-256-GCM key. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AeadKey([u8; KEY_LEN]);

impl AeadKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// Encrypt with AES-256-GCM.
///
/// `nonce` must be unique under this key. The library does not track nonces;
/// the caller (ratchet layer) is responsible for uniqueness.
pub fn seal(
    key: &AeadKey,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, PrimitiveError> {
    let cipher =
        Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| PrimitiveError::InvalidSecretKey)?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| PrimitiveError::Internal)
}

/// Decrypt with AES-256-GCM. Fails closed on any authentication failure.
pub fn open(
    key: &AeadKey,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, PrimitiveError> {
    if ciphertext.len() < TAG_LEN {
        return Err(PrimitiveError::AeadDecryptionFailed);
    }
    let cipher =
        Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| PrimitiveError::InvalidSecretKey)?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| PrimitiveError::AeadDecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::random::fill_random;

    #[test]
    fn roundtrip() {
        let mut key_bytes = [0u8; 32];
        fill_random(&mut key_bytes).unwrap();
        let key = AeadKey::from_bytes(key_bytes);
        let nonce = [7u8; 12];
        let pt = b"VoiceChat test plaintext";
        let ad = b"VoiceChat/DR/v1/Message";

        let ct = seal(&key, &nonce, pt, ad).unwrap();
        assert_eq!(ct.len(), pt.len() + TAG_LEN);
        let recovered = open(&key, &nonce, &ct, ad).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn corrupted_tag_fails() {
        let key = AeadKey::from_bytes([9u8; 32]);
        let nonce = [1u8; 12];
        let mut ct = seal(&key, &nonce, b"data", b"ad").unwrap();
        // Flip last byte (part of tag)
        if let Some(last) = ct.last_mut() {
            *last ^= 0xff;
        }
        let res = open(&key, &nonce, &ct, b"ad");
        assert!(matches!(res, Err(PrimitiveError::AeadDecryptionFailed)));
    }

    #[test]
    fn wrong_ad_fails() {
        let key = AeadKey::from_bytes([9u8; 32]);
        let nonce = [1u8; 12];
        let ct = seal(&key, &nonce, b"data", b"correct-ad").unwrap();
        let res = open(&key, &nonce, &ct, b"wrong-ad");
        assert!(matches!(res, Err(PrimitiveError::AeadDecryptionFailed)));
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = AeadKey::from_bytes([1u8; 32]);
        let key2 = AeadKey::from_bytes([2u8; 32]);
        let nonce = [1u8; 12];
        let ct = seal(&key1, &nonce, b"data", b"ad").unwrap();
        let res = open(&key2, &nonce, &ct, b"ad");
        assert!(matches!(res, Err(PrimitiveError::AeadDecryptionFailed)));
    }

    #[test]
    fn short_ciphertext_fails() {
        let key = AeadKey::from_bytes([9u8; 32]);
        let nonce = [1u8; 12];
        let res = open(&key, &nonce, &[0u8; 8], b"ad");
        assert!(matches!(res, Err(PrimitiveError::AeadDecryptionFailed)));
    }
}
