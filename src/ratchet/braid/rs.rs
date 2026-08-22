//! Systematic Reed–Solomon over GF(2^16) for ML-KEM Braid chunks.
//!
//! Braid Rev 1 §2.2 recommends RS over GF(2^16)^{w/2} for chunk size `w`.
//! Persisted codec state is treated as untrusted input and is validated before
//! multiplication, allocation, or iteration.

use crate::primitives::error::PrimitiveError;

pub const CHUNK_DATA: usize = 32;
const INDEX_LEN: usize = 2;
pub const CHUNK_WIRE: usize = INDEX_LEN + CHUNK_DATA;
const SYMS: usize = CHUNK_DATA / 2;

/// Braid currently encodes objects around 1 KiB. This generous hard ceiling
/// keeps malformed persisted state from creating unbounded codec allocations.
pub const MAX_RS_MESSAGE_BYTES: usize = 16 * 1024;
const MAX_RS_CHUNKS: usize = MAX_RS_MESSAGE_BYTES.div_ceil(CHUNK_DATA);
const MAX_STORED_CODEWORDS: usize = 1024;
const MAX_ENCODER_SYMBOLS: usize = MAX_RS_CHUNKS * SYMS;

const PRIM: u32 = 0x1_100B;

fn gf_mul(a: u16, mut b: u16) -> u16 {
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

#[derive(Clone)]
pub struct Encoder {
    data: Vec<u16>,
    k_chunks: usize,
    next: u16,
}

impl Encoder {
    pub fn new(message: &[u8]) -> Self {
        debug_assert!(message.len() <= MAX_RS_MESSAGE_BYTES);
        let k_chunks = message.len().div_ceil(CHUNK_DATA).max(1);
        let symbols = k_chunks
            .checked_mul(SYMS)
            .expect("internal Braid encoder size overflow");
        let mut data = vec![0u16; symbols];
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
        let mut out = Vec::new();
        out.extend_from_slice(&(self.k_chunks as u32).to_le_bytes());
        out.extend_from_slice(&self.next.to_le_bytes());
        out.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        for symbol in &self.data {
            out.extend_from_slice(&symbol.to_le_bytes());
        }
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, PrimitiveError> {
        if data.len() < 10 {
            return Err(PrimitiveError::InvalidLength);
        }
        let k_chunks = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let next = u16::from_le_bytes(data[4..6].try_into().unwrap());
        let n = u32::from_le_bytes(data[6..10].try_into().unwrap()) as usize;
        if k_chunks == 0 || k_chunks > MAX_RS_CHUNKS || n > MAX_ENCODER_SYMBOLS {
            return Err(PrimitiveError::LimitExceeded);
        }
        let expected_symbols = k_chunks
            .checked_mul(SYMS)
            .ok_or(PrimitiveError::LimitExceeded)?;
        if n != expected_symbols {
            return Err(PrimitiveError::InvalidLength);
        }
        let payload_len = n
            .checked_mul(2)
            .ok_or(PrimitiveError::LimitExceeded)?;
        let expected_len = 10usize
            .checked_add(payload_len)
            .ok_or(PrimitiveError::LimitExceeded)?;
        if data.len() != expected_len {
            return Err(PrimitiveError::InvalidLength);
        }

        let mut symbols = Vec::with_capacity(n);
        let mut i = 10usize;
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
                let bytes = self.data[base + j].to_be_bytes();
                out[2 * j] = bytes[0];
                out[2 * j + 1] = bytes[1];
            }
            return out;
        }
        let x = eval_point(idx);
        for col in 0..SYMS {
            let y = lagrange_eval(
                self.k_chunks,
                |i| eval_point(i as u16),
                |i| self.data[i * SYMS + col],
                x,
            );
            let bytes = y.to_be_bytes();
            out[2 * col] = bytes[0];
            out[2 * col + 1] = bytes[1];
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

#[derive(Clone)]
pub struct Decoder {
    message_len: usize,
    k_chunks: usize,
    got: std::collections::BTreeMap<u16, [u8; CHUNK_DATA]>,
    decoded: Option<Vec<u8>>,
}

impl Decoder {
    pub fn new(message_size: usize) -> Self {
        debug_assert!(message_size <= MAX_RS_MESSAGE_BYTES);
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
        let mut out = Vec::new();
        out.extend_from_slice(&(self.message_len as u32).to_le_bytes());
        out.extend_from_slice(&(self.k_chunks as u32).to_le_bytes());
        out.extend_from_slice(&(self.got.len() as u32).to_le_bytes());
        for (idx, payload) in &self.got {
            out.extend_from_slice(&idx.to_le_bytes());
            out.extend_from_slice(payload);
        }
        match &self.decoded {
            None => out.push(0),
            Some(message) => {
                out.push(1);
                out.extend_from_slice(&(message.len() as u32).to_le_bytes());
                out.extend_from_slice(message);
            }
        }
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, PrimitiveError> {
        if data.len() < 13 {
            return Err(PrimitiveError::InvalidLength);
        }
        let message_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let k_chunks = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
        let n = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        if message_len > MAX_RS_MESSAGE_BYTES || n > MAX_STORED_CODEWORDS {
            return Err(PrimitiveError::LimitExceeded);
        }
        let expected_k = message_len.div_ceil(CHUNK_DATA).max(1);
        if k_chunks != expected_k || k_chunks > MAX_RS_CHUNKS {
            return Err(PrimitiveError::InvalidLength);
        }
        let codeword_bytes = n
            .checked_mul(CHUNK_WIRE)
            .ok_or(PrimitiveError::LimitExceeded)?;
        let minimum = 12usize
            .checked_add(codeword_bytes)
            .and_then(|v| v.checked_add(1))
            .ok_or(PrimitiveError::LimitExceeded)?;
        if minimum > data.len() {
            return Err(PrimitiveError::InvalidLength);
        }

        let mut i = 12usize;
        let mut got = std::collections::BTreeMap::new();
        for _ in 0..n {
            let idx = u16::from_le_bytes(data[i..i + 2].try_into().unwrap());
            i += 2;
            let mut payload = [0u8; CHUNK_DATA];
            payload.copy_from_slice(&data[i..i + CHUNK_DATA]);
            i += CHUNK_DATA;
            if got.insert(idx, payload).is_some() {
                return Err(PrimitiveError::InvalidLength);
            }
        }

        let tag = data[i];
        i += 1;
        let decoded = match tag {
            0 => {
                if i != data.len() {
                    return Err(PrimitiveError::InvalidLength);
                }
                None
            }
            1 => {
                if i + 4 > data.len() {
                    return Err(PrimitiveError::InvalidLength);
                }
                let len = u32::from_le_bytes(data[i..i + 4].try_into().unwrap()) as usize;
                i += 4;
                if len != message_len || len > MAX_RS_MESSAGE_BYTES {
                    return Err(PrimitiveError::InvalidLength);
                }
                let end = i.checked_add(len).ok_or(PrimitiveError::LimitExceeded)?;
                if end != data.len() {
                    return Err(PrimitiveError::InvalidLength);
                }
                Some(data[i..end].to_vec())
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
        let Some(total) = self.k_chunks.checked_mul(CHUNK_DATA) else {
            return;
        };
        if total > MAX_RS_MESSAGE_BYTES.saturating_add(CHUNK_DATA) {
            return;
        }
        let mut systematic = vec![0u8; total];
        let mut have_all_sys = true;
        for i in 0..self.k_chunks {
            if let Some(payload) = self.got.get(&(i as u16)) {
                systematic[i * CHUNK_DATA..(i + 1) * CHUNK_DATA].copy_from_slice(payload);
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
            .map(|(idx, payload)| (*idx, *payload))
            .collect();
        let mut out = vec![0u8; total];
        for col in 0..SYMS {
            for i in 0..self.k_chunks {
                let xi = eval_point(i as u16);
                let y = lagrange_eval(
                    self.k_chunks,
                    |t| eval_point(pts[t].0),
                    |t| {
                        let payload = &pts[t].1;
                        u16::from_be_bytes([payload[2 * col], payload[2 * col + 1]])
                    },
                    xi,
                );
                let bytes = y.to_be_bytes();
                out[i * CHUNK_DATA + 2 * col] = bytes[0];
                out[i * CHUNK_DATA + 2 * col + 1] = bytes[1];
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
        let mut chunks = Vec::new();
        for _ in 0..(k + 1) {
            chunks.push(enc.next_chunk());
        }
        let mut dec = Decoder::new(msg.len());
        for (i, chunk) in chunks.iter().enumerate() {
            if i != 0 {
                dec.add_chunk(chunk).unwrap();
            }
        }
        assert!(dec.has_message());
        assert_eq!(dec.message().unwrap(), msg.as_slice());
    }

    #[test]
    fn gf_roundtrip() {
        let a = 0x1234u16;
        assert_eq!(gf_mul(a, gf_inv(a)), 1);
    }

    #[test]
    fn encoder_rejects_huge_serialized_symbol_count_before_allocating() {
        let mut blob = vec![0u8; 10];
        blob[0..4].copy_from_slice(&1u32.to_le_bytes());
        blob[6..10].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Encoder::decode(&blob).is_err());
    }

    #[test]
    fn decoder_rejects_noncanonical_duplicate_codeword_indexes() {
        let mut dec = Decoder::new(64);
        let mut enc = Encoder::new(&[7u8; 64]);
        let chunk = enc.next_chunk();
        dec.add_chunk(&chunk).unwrap();
        let mut blob = dec.encode();
        // Increase stored count and duplicate the sole codeword before tag.
        blob[8..12].copy_from_slice(&2u32.to_le_bytes());
        let first = blob[12..12 + CHUNK_WIRE].to_vec();
        let tag_at = 12 + CHUNK_WIRE;
        blob.splice(tag_at..tag_at, first);
        assert!(Decoder::decode(&blob).is_err());
    }
}
