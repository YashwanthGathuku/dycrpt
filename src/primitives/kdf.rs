//! Domain-separated HKDF and HMAC helpers.
//!
//! All labels are frozen versioned strings. Never reuse a generic label.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use zeroize::Zeroize;

use super::error::PrimitiveError;

/// Frozen domain-separated labels used throughout VoiceChat crypto.
///
/// These strings are part of the protocol definition. Changing any of them
/// requires a protocol version bump.
#[allow(non_snake_case)]
pub mod LABELS {
    /// PQXDH handshake transcript / shared secret derivation.
    pub const PQXDH_HANDSHAKE: &[u8] = b"VoiceChat/PQXDH/v1/Handshake";
    /// PQXDH associated data binding.
    pub const PQXDH_AD: &[u8] = b"VoiceChat/PQXDH/v1/AD";
    /// Double Ratchet / Triple Ratchet root key derivation.
    pub const DR_ROOT: &[u8] = b"VoiceChat/DR/v1/Root";
    /// Chain key derivation.
    pub const DR_CHAIN: &[u8] = b"VoiceChat/DR/v1/Chain";
    /// Message key derivation.
    pub const DR_MESSAGE: &[u8] = b"VoiceChat/DR/v1/Message";
    /// Header key derivation (header encryption variant).
    pub const DR_HEADER: &[u8] = b"VoiceChat/DR/v1/Header";
    /// Sparse Post-Quantum Ratchet epoch key.
    pub const SPQR_EPOCH: &[u8] = b"VoiceChat/SPQR/v1/Epoch";
    /// Triple Ratchet hybrid message-key combination.
    pub const TRIPLE_HYBRID: &[u8] = b"VoiceChat/Triple/v1/Hybrid";
    /// Attachment encryption (future use).
    pub const ATTACHMENT: &[u8] = b"VoiceChat/Attachment/v1";
    /// Voice / media frame encryption (future use).
    pub const VOICE: &[u8] = b"VoiceChat/Voice/v1";
    /// Safety fingerprint derivation.
    pub const FINGERPRINT: &[u8] = b"VoiceChat/Fingerprint/v1";
    /// Sesame-style session identifier / binding.
    pub const SESAME_SESSION: &[u8] = b"VoiceChat/Sesame/v1/Session";
    /// PQXDH HKDF info string as required by PQXDH Rev 3 §2.2:
    /// concatenation of implementer-defined parameter names separated by `_`.
    pub const PQXDH_KDF_INFO: &[u8] = b"VoiceChat_CURVE25519_SHA-256_ML-KEM-768";
    /// ML-KEM Braid PROTOCOL_INFO (implementer-defined, spec §2.2).
    pub const BRAID_PROTOCOL_INFO: &[u8] = b"VoiceChat_MLKEM768_SHA-256";
}

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// HKDF-Extract then HKDF-Expand (SHA-256) with an explicit domain-separated info label.
///
/// `info` **must** be one of the frozen `LABELS::*` constants (or a future versioned label).
pub fn hkdf_extract_expand(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    okm: &mut [u8],
) -> Result<(), PrimitiveError> {
    if okm.is_empty() || okm.len() > 255 * 32 {
        return Err(PrimitiveError::HkdfLength);
    }
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    hk.expand(info, okm).map_err(|_| PrimitiveError::HkdfLength)
}

/// Convenience: expand from already-extracted PRK material (or raw IKM treated as PRK).
pub fn hkdf_expand(prk: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), PrimitiveError> {
    hkdf_extract_expand(None, prk, info, okm)
}

/// HMAC-SHA-256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// HMAC-SHA-512.
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac =
        <HmacSha512 as Mac>::new_from_slice(key).expect("HMAC-SHA512 accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

/// SHA-256 digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    sha256_parts(&[data])
}

/// SHA-256 over multiple byte slices without first concatenating them.
///
/// This is useful for transcript/replay hashing where one component may be a
/// large ciphertext. It avoids a second attacker-sized allocation while being
/// exactly equivalent to hashing the concatenation of `parts` in order.
pub fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// PQXDH `KDF(KM)` from Rev 3 §2.2:
///
/// * IKM = F || KM  (F = 32 0xFF bytes for curve25519)
/// * salt = 32 zero bytes (SHA-256 output length)
/// * info = `VoiceChat_CURVE25519_SHA-256_ML-KEM-768`
/// * output = 32 bytes
pub fn pqxdh_kdf(km: &[u8]) -> Result<[u8; 32], PrimitiveError> {
    let mut ikm = Vec::with_capacity(32 + km.len());
    ikm.extend_from_slice(&[0xFFu8; 32]);
    ikm.extend_from_slice(km);
    let salt = [0u8; 32];
    let mut sk = [0u8; 32];
    let res = hkdf_extract_expand(Some(&salt), &ikm, LABELS::PQXDH_KDF_INFO, &mut sk);
    ikm.zeroize();
    res?;
    Ok(sk)
}

/// SHA-512 digest.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    use sha2::Digest;
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    // RFC 5869 Test Case 1 (SHA-256)
    #[test]
    fn rfc5869_case1() {
        let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex!("000102030405060708090a0b0c");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");
        let mut okm = [0u8; 42];
        hkdf_extract_expand(Some(&salt), &ikm, &info, &mut okm).unwrap();
        assert_eq!(
            okm,
            hex!(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );
    }

    #[test]
    fn domain_separated_labels_are_distinct() {
        // Sanity: the frozen labels must not collide.
        let labels = [
            LABELS::PQXDH_HANDSHAKE,
            LABELS::DR_ROOT,
            LABELS::DR_CHAIN,
            LABELS::DR_MESSAGE,
            LABELS::DR_HEADER,
            LABELS::FINGERPRINT,
        ];
        for (i, a) in labels.iter().enumerate() {
            for (j, b) in labels.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn hkdf_rejects_oversized_output() {
        let mut huge = vec![0u8; 255 * 32 + 1];
        let err = hkdf_extract_expand(None, b"ikm", LABELS::DR_ROOT, &mut huge);
        assert!(matches!(err, Err(PrimitiveError::HkdfLength)));
    }

    #[test]
    fn hmac_sha256_basic() {
        let key = b"key";
        let data = b"The quick brown fox jumps over the lazy dog";
        let mac = hmac_sha256(key, data);
        // Known value from multiple independent implementations
        assert_eq!(
            mac,
            hex!("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
        );
    }

    #[test]
    fn sha256_parts_matches_concatenation() {
        let a = b"protocol";
        let b = b"session-tag";
        let c = vec![0x5au8; 4096];
        let mut joined = Vec::new();
        joined.extend_from_slice(a);
        joined.extend_from_slice(b);
        joined.extend_from_slice(&c);
        assert_eq!(sha256_parts(&[a, b, &c]), sha256(&joined));
    }
}
