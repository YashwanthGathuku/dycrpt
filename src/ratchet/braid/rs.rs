//! Systematic Reed–Solomon over GF(2^16) for ML-KEM Braid chunks.
//!
//! Braid Rev 1 §2.2 recommends RS over GF(2^16)^{w/2} for chunk size `w`.
//! Primitive polynomial: x^16 + x^12 + x^3 + x + 1 (0x1100B).
//!
//! Evaluation points α_i = i+1. Systematic symbols 0..k-1 carry the message.
//! Any `k` distinct codewords recover the message (Lagrange).

use crate::primitives::error::PrimitiveError;

pub const CHUNK_DATA: usize = 32;
const INDEX_LEN: usize = 2;
pub const CHUNK_WIRE: usize = INDEX_LEN + CHUNK_DATA;
const SYMS: usize = CHUNK_DATA / 2;

const PRIM: u32 = 0x1_100B;

fn gf_mul(mut a: u16, mut b: u16) -> u16 {
    let mut r = 0u32;
    let mut aa = u32::from(a);
    while b != 0 {
        if b & 1 != 0 {
            r ^= aa;
        }
        let hi = aa & 0x8000;
        aa <<= 1;
        if hi != 0 {
            aa ^= PRIM;
        }
        b >>= 1;
    }
    (r & 0xFFFF) as u16
}

fn gf_inv(a: u16) -> u16 {
    // a^{65535-1} in GF(2^16)
    let mut exp = 0xFFFEu32;
    let mut base = a;
    let mut acc = 1u16;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = gf_mul(acc, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    acc
}

fn eval_point(idx: u16) -> u16 {
    idx.wrapping_add(1)
}

/// Encoder that yields indexed codewords.
#[derive(Clone)]
pub struct Encoder {
    /// Per-column coefficients of the degree < k interpolant (systematic).
    /// `coeffs[col][i]` = message symbol i in that 16-bit column.
    data: Vec<u16>,
    k_chunks: usize,
    next: u16,
}

impl Encoder {
    pub fn new(message: &[u8]) -> Self {
        let k_chunks = message.len().div_ceil(CHUNK_DATA).max(1);
        let mut data = vec![0u16; k_chunks * SYMS];
        for (i, chunk) in message.chunks(CHUNK_DATA).enumerate() {
            for (j, pair) in chunk.chunks(2).enumerate() {
                let hi = pair[0];
                let lo = if pair.len() > 1 { pair[1] } else { 0 };
                data[i * SYMS + j] = u16::from_be_bytes([hi, lo]);
            }
        }
        Self {
            data,
            k_chunks,
            next: 0,
        }
    }

    pub fn k_chunks(&self) -> usize {
        self.k_chunks
    }

    pub fn next_chunk(&mut self) -> Vec<u8> {
        let idx = self.next;
        self.next = self.next.wrapping_add(1);
        let payload = self.symbol_row(idx);
        let mut out = Vec::with_capacity(CHUNK_WIRE);
        out.extend_from_slice(&idx.to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&(self.k_chunks as u32).to_le_bytes());
        o.extend_from_slice(&self.next.to_le_bytes());
        o.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        for s in &self.data {
            o.extend_from_slice(&s.to_le_bytes());
        }
        o
    }

    pub fn decode(data: &[u8]) -> Result<Self, PrimitiveError> {
        if data.len() < 10 {
            return Err(PrimitiveError::InvalidLength);
        }
        let k_chunks = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let next = u16::from_le_bytes(data[4..6].try_into().unwrap());
        let n = u32::from_le_bytes(data[6..10].try_into().unwrap()) as usize;
        if data.len() != 10 + n * 2 {
            return Err(PrimitiveError::InvalidLength);
        }
        let mut symbols = Vec::with_capacity(n);
        let mut i = 10;
        for _ in 0..n {
            symbols.push(u16::from_le_bytes(data[i..i + 2].try_into().unwrap()));
            i += 2;
        }
        Ok(Self {
            data: symbols,
            k_chunks,
            next,
        })
    }

    fn symbol_row(&self, idx: u16) -> [u8; CHUNK_DATA] {
        let mut out = [0u8; CHUNK_DATA];
        if (idx as usize) < self.k_chunks {
            let base = (idx as usize) * SYMS;
            for j in 0..SYMS {
                let b = self.data[base + j].to_be_bytes();
                out[2 * j] = b[0];
                out[2 * j + 1] = b[1];
            }
            return out;
        }
        // p(α) for α = eval_point(idx), where p interpolates (α_i, data_i).
        let x = eval_point(idx);
        for col in 0..SYMS {
            let y = lagrange_eval(
                self.k_chunks,
                |i| eval_point(i as u16),
                |i| self.data[i * SYMS + col],
                x,
            );
            let b = y.to_be_bytes();
            out[2 * col] = b[0];
            out[2 * col + 1] = b[1];
        }
        out
    }
}

fn lagrange_eval(
    k: usize,
    x_at: impl Fn(usize) -> u16,
    y_at: impl Fn(usize) -> u16,
    x: u16,
) -> u16 {
    let mut acc = 0u16;
    for i in 0..k {
        let xi = x_at(i);
        let mut li = 1u16;
        for j in 0..k {
            if i == j {
                continue;
            }
            let xj = x_at(j);
            let num = x ^ xj;
            let den = xi ^ xj;
            if den == 0 {
                return 0;
            }
            li = gf_mul(li, gf_mul(num, gf_inv(den)));
        }
        acc ^= gf_mul(y_at(i), li);
    }
    acc
}

/// Decoder for a single Braid message of known byte length.
#[derive(Clone)]
pub struct Decoder {
    message_len: usize,
    k_chunks: usize,
    got: std::collections::BTreeMap<u16, [u8; CHUNK_DATA]>,
    decoded: Option<Vec<u8>>,
}

impl Decoder {
    pub fn new(message_size: usize) -> Self {
        Self {
            message_len: message_size,
            k_chunks: message_size.div_ceil(CHUNK_DATA).max(1),
            got: std::collections::BTreeMap::new(),
            decoded: None,
        }
    }

    pub fn add_chunk(&mut self, chunk: &[u8]) -> Result<(), PrimitiveError> {
        if chunk.len() != CHUNK_WIRE {
            return Err(PrimitiveError::InvalidLength);
        }
        let idx = u16::from_be_bytes([chunk[0], chunk[1]]);
        let mut payload = [0u8; CHUNK_DATA];
        payload.copy_from_slice(&chunk[2..]);
        self.got.insert(idx, payload);
        if self.got.len() >= self.k_chunks && self.decoded.is_none() {
            self.try_decode();
        }
        Ok(())
    }

    pub fn has_message(&self) -> bool {
        self.decoded.is_some()
    }

    pub fn message(&self) -> Option<&[u8]> {
        self.decoded.as_deref()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&(self.message_len as u32).to_le_bytes());
        o.extend_from_slice(&(self.k_chunks as u32).to_le_bytes());
        o.extend_from_slice(&(self.got.len() as u32).to_le_bytes());
        for (idx, payload) in &self.got {
            o.extend_from_slice(&idx.to_le_bytes());
            o.extend_from_slice(payload);
        }
        match &self.decoded {
            None => o.push(0),
            Some(m) => {
                o.push(1);
                o.extend_from_slice(&(m.len() as u32).to_le_bytes());
                o.extend_from_slice(m);
            }
        }
        o
    }

    pub fn decode(data: &[u8]) -> Result<Self, PrimitiveError> {
        if data.len() < 13 {
            return Err(PrimitiveError::InvalidLength);
        }
        let message_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let k_chunks = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
        let n = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        let mut i = 12;
        let mut got = std::collections::BTreeMap::new();
        for _ in 0..n {
            if i + 2 + CHUNK_DATA > data.len() {
                return Err(PrimitiveError::InvalidLength);
            }
            let idx = u16::from_le_bytes(data[i..i + 2].try_into().unwrap());
            i += 2;
            let mut payload = [0u8; CHUNK_DATA];
            payload.copy_from_slice(&data[i..i + CHUNK_DATA]);
            i += CHUNK_DATA;
            got.insert(idx, payload);
        }
        if i >= data.len() {
            return Err(PrimitiveError::InvalidLength);
        }
        let tag = data[i];
        i += 1;
        let decoded = match tag {
            0 => None,
            1 => {
                if i + 4 > data.len() {
                    return Err(PrimitiveError::InvalidLength);
                }
                let ln = u32::from_le_bytes(data[i..i + 4].try_into().unwrap()) as usize;
                i += 4;
                if i + ln != data.len() {
                    return Err(PrimitiveError::InvalidLength);
                }
                Some(data[i..].to_vec())
            }
            _ => return Err(PrimitiveError::InvalidLength),
        };
        Ok(Self {
            message_len,
            k_chunks,
            got,
            decoded,
        })
    }

    fn try_decode(&mut self) {
        let mut systematic = vec![0u8; self.k_chunks * CHUNK_DATA];
        let mut have_all_sys = true;
        for i in 0..self.k_chunks {
            if let Some(p) = self.got.get(&(i as u16)) {
                systematic[i * CHUNK_DATA..(i + 1) * CHUNK_DATA].copy_from_slice(p);
            } else {
                have_all_sys = false;
                break;
            }
        }
        if have_all_sys {
            systematic.truncate(self.message_len);
            self.decoded = Some(systematic);
            return;
        }
        if self.got.len() < self.k_chunks {
            return;
        }
        let pts: Vec<(u16, [u8; CHUNK_DATA])> = self
            .got
            .iter()
            .take(self.k_chunks)
            .map(|(i, p)| (*i, *p))
            .collect();
        let mut out = vec![0u8; self.k_chunks * CHUNK_DATA];
        for col in 0..SYMS {
            for i in 0..self.k_chunks {
                let xi = eval_point(i as u16);
                let y = lagrange_eval(
                    self.k_chunks,
                    |t| eval_point(pts[t].0),
                    |t| {
                        let p = &pts[t].1;
                        u16::from_be_bytes([p[2 * col], p[2 * col + 1]])
                    },
                    xi,
                );
                let b = y.to_be_bytes();
                out[i * CHUNK_DATA + 2 * col] = b[0];
                out[i * CHUNK_DATA + 2 * col + 1] = b[1];
            }
        }
        out.truncate(self.message_len);
        self.decoded = Some(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systematic_roundtrip() {
        let msg = b"hello-braid-erasure-payload-0123456789ABCDEF";
        let mut enc = Encoder::new(msg);
        let k = enc.k_chunks();
        let mut dec = Decoder::new(msg.len());
        for _ in 0..k {
            dec.add_chunk(&enc.next_chunk()).unwrap();
        }
        assert_eq!(dec.message().unwrap(), msg);
    }

    #[test]
    fn recovers_from_dropped_systematic() {
        let msg = (0u8..80).collect::<Vec<_>>();
        let mut enc = Encoder::new(&msg);
        let k = enc.k_chunks();
        // Skip first systematic chunk; take the rest + one parity.
        let mut chunks = Vec::new();
        for _ in 0..(k + 1) {
            chunks.push(enc.next_chunk());
        }
        let mut dec = Decoder::new(msg.len());
        for (i, c) in chunks.iter().enumerate() {
            if i == 0 {
                continue;
            }
            dec.add_chunk(c).unwrap();
        }
        assert!(dec.has_message());
        assert_eq!(dec.message().unwrap(), msg.as_slice());
    }

    #[test]
    fn gf_roundtrip() {
        let a = 0x1234u16;
        assert_eq!(gf_mul(a, gf_inv(a)), 1);
    }
}
