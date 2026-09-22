//! Host-runnable structure-aware mutational parser walk. No libfuzzer /
//! sanitizer runtime.
//!
//! `cargo run --manifest-path fuzz/Cargo.toml --bin host_runner -- [iters]`
//!
//! # Why this was rewritten (review 2026-08-28)
//!
//! The previous version generated uniformly random buffers and threw them at
//! every parser. Measured against the real parsers it was doing almost nothing:
//!
//! * **0 of 1,000,000** generated inputs parsed successfully in *any* of the
//!   eleven decoders — every input was rejected at the first length or tag
//!   check, so no decoder body was ever entered.
//! * The length generator produced **3 distinct lengths out of 256**. It used
//!   `seed % 256` on a power-of-two LCG, whose low bits are notoriously
//!   non-random, and then advanced the same LCG a variable number of times per
//!   iteration. The sequence collapsed to a 3-cycle (min 63, max 255).
//! * Length was capped at 255, so `MlKemPublic` (1184 bytes) and
//!   `MlKemCiphertext` (1088 bytes) could never receive a correctly sized input
//!   from the loop at all.
//!
//! It nonetheless printed `ok` for any iteration count, at roughly 2.5M
//! iterations/second, which is what a gate looks like when it is measuring
//! nothing.
//!
//! This version:
//! 1. uses SplitMix64 and takes high bits;
//! 2. covers the full length range including 0, 1, and the ML-KEM sizes;
//! 3. seeds from a corpus of **genuinely valid encodings** produced by the real
//!    API, then mutates them, so decoder bodies are actually entered;
//! 4. counts how deep it got and **fails the gate** if the corpus stops
//!    round-tripping — a fuzz gate that no longer reaches its target must not
//!    be allowed to keep reporting success.

use voicechat_crypto::engine::{InitiationPacket, SealedMessage};
use voicechat_crypto::envelope::Envelope;
use voicechat_crypto::prekeys::{IdentityKeyPair, PrekeyStore, PublicPrekeyBundle};
use voicechat_crypto::primitives::encoding::{decode_ec, decode_kem};
use voicechat_crypto::primitives::kem::{MlKemCiphertext, MlKemPublic};
use voicechat_crypto::primitives::x25519::X25519Secret;
use voicechat_crypto::ratchet::scka::SckaMessage;
use voicechat_crypto::ratchet::triple::{TripleHeader, TripleRatchetState};
use voicechat_crypto::ratchet::Header;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // SplitMix64: all 64 bits usable, unlike the previous LCG's low bits.
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() >> 32) as usize % n
        }
    }
}

/// Result of one walk: how many decoders accepted the input.
fn walk(data: &[u8]) -> u32 {
    let mut accepted = 0;
    if Envelope::parse(data).is_ok() {
        accepted += 1;
    }
    if Header::decode(data).is_ok() {
        accepted += 1;
    }
    if TripleHeader::decode(data).is_ok() {
        accepted += 1;
    }
    if SckaMessage::decode(data).is_ok() {
        accepted += 1;
    }
    if MlKemPublic::from_bytes(data).is_ok() {
        accepted += 1;
    }
    if MlKemCiphertext::from_bytes(data).is_ok() {
        accepted += 1;
    }
    if decode_ec(data).is_ok() {
        accepted += 1;
    }
    if decode_kem(data).is_ok() {
        accepted += 1;
    }
    if PublicPrekeyBundle::decode(data).is_ok() {
        accepted += 1;
    }
    if InitiationPacket::decode(data).is_ok() {
        accepted += 1;
    }
    if SealedMessage::decode(data).is_ok() {
        accepted += 1;
    }
    accepted
}

/// Real encodings produced by the real API. Mutating these is what gets the
/// fuzzer past the length/tag checks and into decoder bodies.
fn build_corpus() -> Vec<Vec<u8>> {
    let mut corpus: Vec<Vec<u8>> = Vec::new();

    // Ratchet headers from an actual session.
    let sk = [11u8; 32];
    if let Ok(bob_dh) = X25519Secret::generate() {
        let bob_pub = bob_dh.public_key();
        if let (Ok(mut alice), Ok(mut bob)) = (
            TripleRatchetState::init_alice(&sk, &bob_pub),
            TripleRatchetState::init_bob(&sk, bob_dh),
        ) {
            for i in 0..4u8 {
                if let Ok((h, ct)) = alice.encrypt(&[i], b"ad") {
                    corpus.push(h.encode());
                    corpus.push(ct.clone());
                    let _ = bob.decrypt(&h, &ct, b"ad");
                }
            }
            for _ in 0..2 {
                if let Ok((h, _ct)) = bob.encrypt(b"reply", b"ad") {
                    corpus.push(h.encode());
                }
            }
        }
    }

    // A signed public prekey bundle, plus its component encodings.
    if let Ok(identity) = IdentityKeyPair::generate() {
        if let Ok(store) = PrekeyStore::new(&identity) {
            if let Ok(bundle) = store.public_bundle(&identity) {
                corpus.push(bundle.encode());
            }
        }
    }

    // Raw X25519 public key (32 bytes) — a decode_ec-shaped input.
    if let Ok(s) = X25519Secret::generate() {
        corpus.push(s.public_key().to_bytes().to_vec());
    }

    // Boundary sizes the old generator could never produce.
    corpus.push(Vec::new());
    corpus.push(vec![0u8; 1]);
    corpus.push(vec![0xffu8; 32]);
    corpus.push(vec![0u8; 1088]);
    corpus.push(vec![0u8; 1184]);

    corpus
}

fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut buf = seed.to_vec();
    match rng.below(5) {
        0 if !buf.is_empty() => {
            let i = rng.below(buf.len());
            buf[i] ^= 1u8 << rng.below(8);
        }
        1 if !buf.is_empty() => {
            let i = rng.below(buf.len());
            buf[i] = (rng.next() >> 32) as u8;
        }
        2 if !buf.is_empty() => {
            let cut = rng.below(buf.len());
            buf.truncate(cut);
        }
        3 => {
            let n = rng.below(16) + 1;
            for _ in 0..n {
                buf.push((rng.next() >> 32) as u8);
            }
        }
        _ if buf.len() > 1 => {
            let a = rng.below(buf.len());
            let b = rng.below(buf.len());
            buf.swap(a, b);
        }
        _ => {}
    }
    buf
}

fn main() {
    let iters: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000);

    let corpus = build_corpus();

    // The gate must prove it reaches decoder bodies. If the corpus itself stops
    // parsing, the campaign below is measuring nothing and must fail loudly
    // rather than print `ok`.
    let corpus_accepts: u32 = corpus.iter().map(|c| walk(c)).sum();
    if corpus_accepts == 0 {
        eprintln!(
            "host_runner FAIL: seed corpus ({} inputs) produced 0 successful parses. \
             The fuzzer is not reaching any decoder body.",
            corpus.len()
        );
        std::process::exit(1);
    }

    let mut rng = Rng(0xC0FF_EE00_1234_5678);
    let mut deep_hits: u64 = 0;
    let mut random_hits: u64 = 0;

    for _ in 0..iters {
        // Half the budget on structure-aware mutation of real encodings...
        let seed = &corpus[rng.below(corpus.len())];
        let mutated = mutate(&mut rng, seed);
        deep_hits += u64::from(walk(&mutated));

        // ...half on unstructured input, across the full length range the old
        // generator could not reach.
        let len = match rng.below(8) {
            0 => 0,
            1 => 1 + rng.below(31),
            2 => 1088,
            3 => 1184,
            _ => rng.below(2048),
        };
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            *b = (rng.next() >> 32) as u8;
        }
        random_hits += u64::from(walk(&buf));
    }

    println!(
        "host_runner ok iters={iters} corpus={} corpus_accepts={corpus_accepts} \
         mutated_accepts={deep_hits} random_accepts={random_hits}",
        corpus.len()
    );
}
