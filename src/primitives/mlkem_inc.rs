//! Incremental ML-KEM-768 Encaps1 / Encaps2 from FIPS 203 + Braid Rev 1 §1.2.
//!
//! Encaps1 uses only (ρ, H(ek)) to produce ct1 (u) and the FO shared secret.
//! Encaps2 uses t̂ to produce ct2 (v). Concatenated ct1‖ct2 is a standard
//! FIPS 203 ciphertext and decapsulates with `ml-kem`.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Digest, Sha3_256, Sha3_512, Shake128, Shake256,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::error::PrimitiveError;
use super::kem::{MLKEM768_CIPHERTEXT_LEN, MLKEM768_PUBLIC_LEN};
use super::random::fill_random;

pub const RHO_LEN: usize = 32;
pub const HEK_LEN: usize = 32;
pub const EK_VECTOR_LEN: usize = 1152;
pub const CT1_LEN: usize = 960;
pub const CT2_LEN: usize = 128;
const Q: u32 = 3329;
const N: usize = 256;
const K: usize = 3;
const DU: u32 = 10;
const DV: u32 = 4;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EncapsSecret {
    m: [u8; 32],
    coins: [u8; 32],
    k: [u8; 32],
    rho: [u8; 32],
    hek: [u8; 32],
}

impl EncapsSecret {
    pub fn shared_secret(&self) -> [u8; 32] {
        self.k
    }

    pub fn encode(&self) -> [u8; 160] {
        let mut o = [0u8; 160];
        o[..32].copy_from_slice(&self.m);
        o[32..64].copy_from_slice(&self.coins);
        o[64..96].copy_from_slice(&self.k);
        o[96..128].copy_from_slice(&self.rho);
        o[128..].copy_from_slice(&self.hek);
        o
    }

    pub fn decode(b: &[u8; 160]) -> Self {
        let mut s = Self {
            m: [0u8; 32],
            coins: [0u8; 32],
            k: [0u8; 32],
            rho: [0u8; 32],
            hek: [0u8; 32],
        };
        s.m.copy_from_slice(&b[..32]);
        s.coins.copy_from_slice(&b[32..64]);
        s.k.copy_from_slice(&b[64..96]);
        s.rho.copy_from_slice(&b[96..128]);
        s.hek.copy_from_slice(&b[128..]);
        s
    }
}

/// Split a FIPS 203 ek (t̂ ‖ ρ) into Braid header fields.
/// Header = ρ ‖ SHA3-256(t̂ ‖ ρ) so Encaps1 has ρ and FIPS H(ek).
pub fn header_from_ek(ek: &[u8; MLKEM768_PUBLIC_LEN]) -> ([u8; 64], [u8; EK_VECTOR_LEN]) {
    let mut t = [0u8; EK_VECTOR_LEN];
    t.copy_from_slice(&ek[..EK_VECTOR_LEN]);
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek[EK_VECTOR_LEN..]);
    let hek = sha3_256(ek);
    let mut header = [0u8; 64];
    header[..32].copy_from_slice(&rho);
    header[32..].copy_from_slice(&hek);
    (header, t)
}

pub fn parse_header(header: &[u8]) -> Result<([u8; 32], [u8; 32]), PrimitiveError> {
    if header.len() != 64 {
        return Err(PrimitiveError::InvalidLength);
    }
    let mut rho = [0u8; 32];
    let mut hek = [0u8; 32];
    rho.copy_from_slice(&header[..32]);
    hek.copy_from_slice(&header[32..]);
    Ok((rho, hek))
}

/// Encaps1(ek_header, randomness) — Braid §1.2.
pub fn encaps1(header: &[u8]) -> Result<(EncapsSecret, [u8; CT1_LEN], [u8; 32]), PrimitiveError> {
    let (rho, hek) = parse_header(header)?;
    let mut m = [0u8; 32];
    fill_random(&mut m)?;
    encaps1_with_m(rho, hek, m)
}

pub fn encaps1_with_m(
    rho: [u8; 32],
    hek: [u8; 32],
    m: [u8; 32],
) -> Result<(EncapsSecret, [u8; CT1_LEN], [u8; 32]), PrimitiveError> {
    let (k, coins) = g_hash(&m, &hek);
    let ct1 = pke_encrypt_ct1(&rho, &coins, &m)?;
    let secret = EncapsSecret {
        m,
        coins,
        k,
        rho,
        hek,
    };
    Ok((secret, ct1, k))
}

/// Encaps2(encaps_secret, ek_vector) — Braid §1.2.
pub fn encaps2(secret: &EncapsSecret, ek_vector: &[u8]) -> Result<[u8; CT2_LEN], PrimitiveError> {
    if ek_vector.len() != EK_VECTOR_LEN {
        return Err(PrimitiveError::InvalidLength);
    }
    let mut ek = [0u8; MLKEM768_PUBLIC_LEN];
    ek[..EK_VECTOR_LEN].copy_from_slice(ek_vector);
    ek[EK_VECTOR_LEN..].copy_from_slice(&secret.rho);
    if sha3_256(&ek) != secret.hek {
        return Err(PrimitiveError::InvalidPublicKey);
    }
    pke_encrypt_ct2(ek_vector, &secret.coins, &secret.m)
}

pub fn join_ct(ct1: &[u8; CT1_LEN], ct2: &[u8; CT2_LEN]) -> [u8; MLKEM768_CIPHERTEXT_LEN] {
    let mut out = [0u8; MLKEM768_CIPHERTEXT_LEN];
    out[..CT1_LEN].copy_from_slice(ct1);
    out[CT1_LEN..].copy_from_slice(ct2);
    out
}

fn sha3_256(x: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, x);
    h.finalize().into()
}

fn g_hash(m: &[u8; 32], hek: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut h = Sha3_512::new();
    Digest::update(&mut h, m);
    Digest::update(&mut h, hek);
    let out = h.finalize();
    let mut k = [0u8; 32];
    let mut r = [0u8; 32];
    k.copy_from_slice(&out[..32]);
    r.copy_from_slice(&out[32..]);
    (k, r)
}

fn barrett(x: u32) -> u16 {
    (x % Q) as u16
}

fn fq_add(a: u16, b: u16) -> u16 {
    let s = u32::from(a) + u32::from(b);
    if s >= Q {
        (s - Q) as u16
    } else {
        s as u16
    }
}

fn fq_sub(a: u16, b: u16) -> u16 {
    if a >= b {
        a - b
    } else {
        (u32::from(a) + Q - u32::from(b)) as u16
    }
}

fn fq_mul(a: u16, b: u16) -> u16 {
    barrett(u32::from(a) * u32::from(b))
}

fn bitrev7(x: usize) -> usize {
    ((x >> 6) & 1)
        | (((x >> 5) & 1) << 1)
        | (((x >> 4) & 1) << 2)
        | (((x >> 3) & 1) << 3)
        | (((x >> 2) & 1) << 4)
        | (((x >> 1) & 1) << 5)
        | ((x & 1) << 6)
}

fn zeta_pow_bitrev() -> [u16; 128] {
    let mut pow = [0u16; 128];
    let mut curr = 1u32;
    for p in &mut pow {
        *p = curr as u16;
        curr = (curr * 17) % Q;
    }
    let mut out = [0u16; 128];
    for i in 0..128 {
        out[i] = pow[bitrev7(i)];
    }
    out
}

fn gamma_table() -> [u16; 128] {
    // ζ^{2 BitRev7(i) + 1}
    let mut zpow = [0u16; 256];
    let mut curr = 1u32;
    for item in zpow.iter_mut() {
        *item = curr as u16;
        curr = (curr * 17) % Q;
    }
    let mut g = [0u16; 128];
    for i in 0..128 {
        g[i] = zpow[2 * bitrev7(i) + 1];
    }
    g
}

fn ntt(f: &mut [u16; N]) {
    let z = zeta_pow_bitrev();
    let mut k = 1usize;
    let mut len = 128usize;
    while len >= 2 {
        let mut start = 0usize;
        while start < N {
            let zeta = z[k];
            k += 1;
            for j in start..(start + len) {
                let t = fq_mul(zeta, f[j + len]);
                f[j + len] = fq_sub(f[j], t);
                f[j] = fq_add(f[j], t);
            }
            start += 2 * len;
        }
        len /= 2;
    }
}

fn ntt_inv(f: &mut [u16; N]) {
    let z = zeta_pow_bitrev();
    let mut k = 127usize;
    let mut len = 2usize;
    while len <= 128 {
        let mut start = 0usize;
        while start < N {
            let zeta = z[k];
            k = k.saturating_sub(1);
            for j in start..(start + len) {
                let t = f[j];
                f[j] = fq_add(t, f[j + len]);
                f[j + len] = fq_mul(zeta, fq_sub(f[j + len], t));
            }
            start += 2 * len;
        }
        len *= 2;
    }
    for c in f.iter_mut() {
        *c = fq_mul(*c, 3303);
    }
}

fn base_mul(a0: u16, a1: u16, b0: u16, b1: u16, gamma: u16) -> (u16, u16) {
    let c0 = fq_add(fq_mul(a0, b0), fq_mul(fq_mul(a1, b1), gamma));
    let c1 = fq_add(fq_mul(a0, b1), fq_mul(a1, b0));
    (c0, c1)
}

fn multiply_ntts(a: &[u16; N], b: &[u16; N]) -> [u16; N] {
    let g = gamma_table();
    let mut out = [0u16; N];
    for i in 0..128 {
        let (c0, c1) = base_mul(a[2 * i], a[2 * i + 1], b[2 * i], b[2 * i + 1], g[i]);
        out[2 * i] = c0;
        out[2 * i + 1] = c1;
    }
    out
}

fn sample_ntt(rho: &[u8; 32], i: u8, j: u8) -> [u16; N] {
    let mut h = Shake128::default();
    Update::update(&mut h, rho);
    Update::update(&mut h, &[i, j]);
    let mut r = h.finalize_xof();
    let mut buf = [0u8; 96];
    r.read(&mut buf);
    let mut start = 0usize;
    let mut out = [0u16; N];
    let mut n = 0usize;
    while n < N {
        if start == buf.len() {
            r.read(&mut buf);
            start = 0;
        }
        let b0 = buf[start];
        let b1 = buf[start + 1];
        let b2 = buf[start + 2];
        start += 3;
        let d1 = u16::from(b0) + ((u16::from(b1) & 0xf) << 8);
        let d2 = (u16::from(b1) >> 4) + (u16::from(b2) << 4);
        if u32::from(d1) < Q {
            out[n] = d1;
            n += 1;
            if n == N {
                break;
            }
        }
        if u32::from(d2) < Q {
            out[n] = d2;
            n += 1;
        }
    }
    out
}

fn prf_eta2(s: &[u8; 32], b: u8) -> [u8; 128] {
    let mut h = Shake256::default();
    Update::update(&mut h, s);
    Update::update(&mut h, &[b]);
    let mut r = h.finalize_xof();
    let mut out = [0u8; 128];
    r.read(&mut out);
    out
}

fn sample_cbd2(buf: &[u8; 128]) -> [u16; N] {
    let mut f = [0u16; N];
    for (i, coeff) in f.iter_mut().enumerate() {
        let bit_off = 4 * i;
        let byte = buf[bit_off / 8];
        let shift = bit_off % 8;
        let bits = if shift <= 4 {
            (byte >> shift) & 0x0f
        } else {
            ((byte >> shift) | (buf[bit_off / 8 + 1] << (8 - shift))) & 0x0f
        };
        let x = (bits & 1) + ((bits >> 1) & 1);
        let y = ((bits >> 2) & 1) + ((bits >> 3) & 1);
        *coeff = fq_sub(x as u16, y as u16);
    }
    f
}

fn sample_vec_cbd(coins: &[u8; 32], start_n: u8) -> [[u16; N]; K] {
    let mut v = [[0u16; N]; K];
    for (i, slot) in v.iter_mut().enumerate() {
        let buf = prf_eta2(coins, start_n + i as u8);
        *slot = sample_cbd2(&buf);
    }
    v
}

fn compress(x: u16, d: u32) -> u16 {
    // Match ml-kem 0.3.2 (FIPS 203 eq. 4.5 via 34-bit reciprocal), so
    // Encaps1‖Encaps2 ciphertext is bit-identical to official Encrypt
    // and Decaps FO comparison always accepts.
    const DIV_SHIFT: u32 = 34;
    const DIV_MUL: u64 = (1u64 << 34) / Q as u64;
    let q_half = (u64::from(Q) + 1) >> 1;
    let y = (((u64::from(x) << d) + q_half) * DIV_MUL) >> DIV_SHIFT;
    (y as u16) & ((1u16 << d) - 1)
}

fn decompress(y: u16, d: u32) -> u16 {
    let t = (u32::from(y) * Q + (1 << (d - 1))) >> d;
    t as u16
}

fn byte_encode_d(coeffs: &[u16], d: u32) -> Vec<u8> {
    let bits = coeffs.len() * d as usize;
    let mut out = vec![0u8; bits.div_ceil(8)];
    for (i, &c) in coeffs.iter().enumerate() {
        for b in 0..d as usize {
            let bit = ((c >> b) & 1) as u8;
            let pos = i * d as usize + b;
            out[pos / 8] |= bit << (pos % 8);
        }
    }
    out
}

fn byte_decode_d(data: &[u8], d: u32, n: usize) -> Vec<u16> {
    let mut out = vec![0u16; n];
    for (i, coeff) in out.iter_mut().enumerate() {
        let mut c = 0u16;
        for b in 0..d as usize {
            let pos = i * d as usize + b;
            let bit = (data[pos / 8] >> (pos % 8)) & 1;
            c |= u16::from(bit) << b;
        }
        *coeff = c;
    }
    out
}

fn pke_encrypt_ct1(
    rho: &[u8; 32],
    coins: &[u8; 32],
    m: &[u8; 32],
) -> Result<[u8; CT1_LEN], PrimitiveError> {
    let r = sample_vec_cbd(coins, 0);
    let e1 = sample_vec_cbd(coins, K as u8);
    let mut r_hat = r;
    for p in &mut r_hat {
        ntt(p);
    }
    // u = NTT^{-1}(Â^T ◦ r̂) + e1
    let mut u = [[0u16; N]; K];
    for i in 0..K {
        let mut acc = [0u16; N];
        for (j, r_j) in r_hat.iter().enumerate() {
            // Match ml-kem matrix_sample_ntt(rho, transpose=true):
            // Â^T[i][j] = SampleNTT(XOF(ρ, i, j)).
            let a_ji = sample_ntt(rho, i as u8, j as u8);
            let prod = multiply_ntts(&a_ji, r_j);
            for (acc_t, prod_t) in acc.iter_mut().zip(prod.iter()) {
                *acc_t = fq_add(*acc_t, *prod_t);
            }
        }
        ntt_inv(&mut acc);
        for (u_t, (acc_t, e_t)) in u[i].iter_mut().zip(acc.iter().zip(e1[i].iter())) {
            *u_t = fq_add(*acc_t, *e_t);
        }
    }
    let _ = m;
    let mut packed = [0u8; CT1_LEN];
    for i in 0..K {
        let mut c = [0u16; N];
        for (c_t, u_t) in c.iter_mut().zip(u[i].iter()) {
            *c_t = compress(*u_t, DU);
        }
        let enc = byte_encode_d(&c, DU);
        packed[i * 320..(i + 1) * 320].copy_from_slice(&enc);
    }
    Ok(packed)
}

fn pke_encrypt_ct2(
    t_bytes: &[u8],
    coins: &[u8; 32],
    m: &[u8; 32],
) -> Result<[u8; CT2_LEN], PrimitiveError> {
    let r = sample_vec_cbd(coins, 0);
    let e2_buf = prf_eta2(coins, 2 * K as u8);
    let e2 = sample_cbd2(&e2_buf);
    let mut r_hat = r;
    for p in &mut r_hat {
        ntt(p);
    }
    // t̂ is already NTT-domain ByteEncode_12
    let mut t_hat = [[0u16; N]; K];
    for i in 0..K {
        let dec = byte_decode_d(&t_bytes[i * 384..(i + 1) * 384], 12, N);
        t_hat[i].copy_from_slice(&dec[..N]);
    }
    let mut acc = [0u16; N];
    for j in 0..K {
        let prod = multiply_ntts(&t_hat[j], &r_hat[j]);
        for t in 0..N {
            acc[t] = fq_add(acc[t], prod[t]);
        }
    }
    ntt_inv(&mut acc);
    let mut mu = [0u16; N];
    for i in 0..N {
        let bit = (m[i / 8] >> (i % 8)) & 1;
        mu[i] = decompress(u16::from(bit), 1);
    }
    let mut v = [0u16; N];
    for t in 0..N {
        v[t] = fq_add(fq_add(acc[t], e2[t]), mu[t]);
        v[t] = compress(v[t], DV);
    }
    let enc = byte_encode_d(&v, DV);
    let mut out = [0u8; CT2_LEN];
    out.copy_from_slice(&enc);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::kem::MlKemSecret;

    #[test]
    fn encaps1_encaps2_decaps_matches_mlkem() {
        let (sk, pk) = MlKemSecret::generate().unwrap();
        let (header, t) = header_from_ek(pk.as_bytes());
        let mut m = [0u8; 32];
        crate::primitives::random::fill_random(&mut m).unwrap();
        let (rho, hek) = parse_header(&header).unwrap();
        let (sec, ct1, ss) = encaps1_with_m(rho, hek, m).unwrap();
        let ct2 = encaps2(&sec, &t).unwrap();
        let joined = join_ct(&ct1, &ct2);

        use ml_kem::array::Array;
        use ml_kem::ml_kem_768::EncapsulationKey;
        let arr = Array::try_from(pk.as_bytes().as_slice()).unwrap();
        let ek = EncapsulationKey::new(&arr).unwrap();
        let m_arr: ml_kem::B32 = m.into();
        let (official_ct, official_ss) = ek.encapsulate_deterministic(&m_arr);
        assert_eq!(ss.as_slice(), official_ss.as_slice(), "FO shared secret");
        assert_eq!(
            joined.as_slice(),
            official_ct.as_slice(),
            "incremental ct must match official Encrypt"
        );
        let ct = crate::primitives::kem::MlKemCiphertext::from_bytes(&joined).unwrap();
        let dec = sk.decapsulate(&ct).unwrap();
        assert_eq!(dec, ss, "Decaps of incremental ct1||ct2");
    }

    #[test]
    fn encaps1_matches_official_encrypt_many() {
        for seed in 0u8..8 {
            let (sk, pk) = MlKemSecret::generate().unwrap();
            let (header, t) = header_from_ek(pk.as_bytes());
            let m = [seed.wrapping_mul(17); 32];
            let (rho, hek) = parse_header(&header).unwrap();
            let (sec, ct1, ss) = encaps1_with_m(rho, hek, m).unwrap();
            let ct2 = encaps2(&sec, &t).unwrap();
            let joined = join_ct(&ct1, &ct2);
            use ml_kem::array::Array;
            use ml_kem::ml_kem_768::EncapsulationKey;
            let arr = Array::try_from(pk.as_bytes().as_slice()).unwrap();
            let ek = EncapsulationKey::new(&arr).unwrap();
            let m_arr: ml_kem::B32 = m.into();
            let (official_ct, official_ss) = ek.encapsulate_deterministic(&m_arr);
            assert_eq!(ss.as_slice(), official_ss.as_slice(), "FO ss seed={seed}");
            assert_eq!(joined.as_slice(), official_ct.as_slice(), "CT seed={seed}");
            let ct = crate::primitives::kem::MlKemCiphertext::from_bytes(&joined).unwrap();
            assert_eq!(sk.decapsulate(&ct).unwrap(), ss, "Decaps seed={seed}");
        }
    }
}
