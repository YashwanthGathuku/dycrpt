//! XEd25519 signatures from the public XEdDSA specification (Revision 1,
//! 2016-10-20). Built only on curve25519-dalek + SHA-512. No curve
//! arithmetic is implemented in this crate.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

use super::error::PrimitiveError;
use super::random::fill_random;
use super::x25519::{X25519Public, X25519Secret};

/// Domain-separated hash_i from XEdDSA §2.5: SHA-512( (2^b - 1 - i) || X ).
/// For Curve25519, b = 256, so the prefix is 32 bytes.
fn hash_i(i: u8, data: &[u8]) -> [u8; 64] {
    let mut prefix = [0xFFu8; 32];
    prefix[0] = 0xFFu8.wrapping_sub(i);
    let mut hasher = Sha512::new();
    hasher.update(prefix);
    hasher.update(data);
    hasher.finalize().into()
}

fn hash_plain(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// calculate_key_pair(k) from XEdDSA §2.3.
/// Sign-bit selection is constant-time (spec §2.5 / §4).
fn calculate_key_pair(k: &Scalar) -> (CompressedEdwardsY, Scalar) {
    let e = EdwardsPoint::mul_base(k);
    let compressed = e.compress();
    let mut a_bytes = compressed.to_bytes();
    let sign = Choice::from((a_bytes[31] >> 7) & 1);
    let a = Scalar::conditional_select(k, &(-*k), sign);
    a_bytes[31] &= 0x7F;
    (CompressedEdwardsY(a_bytes), a)
}

/// convert_mont(u) from XEdDSA §2.3: Edwards point with forced sign bit 0.
fn convert_mont(u: &[u8; 32]) -> Result<EdwardsPoint, PrimitiveError> {
    MontgomeryPoint(*u)
        .to_edwards(0)
        .ok_or(PrimitiveError::InvalidPublicKey)
}

fn le_int_ge_p(bytes: &[u8; 32]) -> bool {
    // p = 2^255 - 19. Little-endian compare.
    // Any value with bit 255 set is >= 2^255 > p.
    if bytes[31] & 0x80 != 0 {
        return true;
    }
    // Compare to 2^255 - 19 = [0xED, 0xFF, ..., 0xFF, 0x7F]
    const P_LE: [u8; 32] = [
        0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x7F,
    ];
    for i in (0..32).rev() {
        if bytes[i] > P_LE[i] {
            return true;
        }
        if bytes[i] < P_LE[i] {
            return false;
        }
    }
    true // equal to p
}

/// Sign `message` under the X25519 Montgomery private key using XEd25519.
pub fn sign(secret: &X25519Secret, message: &[u8]) -> Result<[u8; 64], PrimitiveError> {
    let mut z = [0u8; 64];
    fill_random(&mut z)?;
    let sig = sign_with_nonce(secret, message, &z);
    z.zeroize();
    Ok(sig)
}

/// RFC 7748 X25519 clamping (same bits X25519 applies to the Montgomery scalar).
fn clamp_montgomery(mut s: [u8; 32]) -> [u8; 32] {
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
    s
}

fn sign_with_nonce(secret: &X25519Secret, message: &[u8], z: &[u8; 64]) -> [u8; 64] {
    let k = Scalar::from_bytes_mod_order(clamp_montgomery(secret.to_bytes()));
    let (a_comp, a) = calculate_key_pair(&k);

    let mut r_input = Vec::with_capacity(32 + message.len() + 64);
    r_input.extend_from_slice(&a.to_bytes());
    r_input.extend_from_slice(message);
    r_input.extend_from_slice(z);
    let r = Scalar::from_bytes_mod_order_wide(&hash_i(1, &r_input));
    r_input.zeroize();

    let r_point = EdwardsPoint::mul_base(&r);
    let r_bytes = r_point.compress().to_bytes();
    let a_bytes = a_comp.to_bytes();

    let mut h_input = Vec::with_capacity(32 + 32 + message.len());
    h_input.extend_from_slice(&r_bytes);
    h_input.extend_from_slice(&a_bytes);
    h_input.extend_from_slice(message);
    let h = Scalar::from_bytes_mod_order_wide(&hash_plain(&h_input));

    let s = r + (h * a);
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..].copy_from_slice(&s.to_bytes());
    sig
}

/// Verify an XEd25519 signature against a Montgomery public key.
pub fn verify(
    public: &X25519Public,
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), PrimitiveError> {
    let u = public.to_bytes();
    if le_int_ge_p(&u) {
        return Err(PrimitiveError::SignatureInvalid);
    }

    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);

    // Reject s with excess bits (s >= 2^|q|, |q| = 253).
    if s_bytes[31] & 0b1110_0000 != 0 {
        return Err(PrimitiveError::SignatureInvalid);
    }

    let a_point = convert_mont(&u)?;
    let _r_on_curve = CompressedEdwardsY(r_bytes)
        .decompress()
        .ok_or(PrimitiveError::SignatureInvalid)?;
    let s = Scalar::from_bytes_mod_order(s_bytes);

    let a_bytes = {
        let mut b = a_point.compress().to_bytes();
        b[31] &= 0x7F;
        b
    };

    let mut h_input = Vec::with_capacity(32 + 32 + message.len());
    h_input.extend_from_slice(&r_bytes);
    h_input.extend_from_slice(&a_bytes);
    h_input.extend_from_slice(message);
    let h = Scalar::from_bytes_mod_order_wide(&hash_plain(&h_input));

    let r_check = EdwardsPoint::mul_base(&s) - (h * a_point);
    let r_check_bytes = r_check.compress().to_bytes();
    if r_bytes.ct_eq(&r_check_bytes).unwrap_u8() != 1 {
        return Err(PrimitiveError::SignatureInvalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_a_matches_convert_mont() {
        let sk = X25519Secret::generate().unwrap();
        let pk = sk.public_key();
        let k = Scalar::from_bytes_mod_order(clamp_montgomery(sk.to_bytes()));
        let (a_comp, _) = calculate_key_pair(&k);
        let a_point = convert_mont(&pk.to_bytes()).expect("convert_mont");
        let mut conv = a_point.compress().to_bytes();
        conv[31] &= 0x7F;
        assert_eq!(
            a_comp.to_bytes(),
            conv,
            "calculate_key_pair A != convert_mont(u)"
        );
    }

    #[test]
    fn sign_verify_roundtrip() {
        let sk = X25519Secret::generate().unwrap();
        let pk = sk.public_key();
        let msg = b"VoiceChat prekey binding";
        let sig = sign(&sk, msg).unwrap();
        verify(&pk, msg, &sig).unwrap();
    }

    #[test]
    fn wrong_message_fails() {
        let sk = X25519Secret::generate().unwrap();
        let pk = sk.public_key();
        let sig = sign(&sk, b"correct").unwrap();
        assert!(verify(&pk, b"wrong", &sig).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let sk = X25519Secret::generate().unwrap();
        let other = X25519Secret::generate().unwrap().public_key();
        let sig = sign(&sk, b"msg").unwrap();
        assert!(verify(&other, b"msg", &sig).is_err());
    }

    #[test]
    fn tampered_signature_fails() {
        let sk = X25519Secret::generate().unwrap();
        let pk = sk.public_key();
        let mut sig = sign(&sk, b"msg").unwrap();
        sig[0] ^= 0x01;
        assert!(verify(&pk, b"msg", &sig).is_err());
    }
}
