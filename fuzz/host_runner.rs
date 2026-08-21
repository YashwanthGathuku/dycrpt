//! Host-runnable mutational parser walk. No libfuzzer / sanitizer runtime.
//!
//! `cargo run --manifest-path fuzz/Cargo.toml --bin host_runner -- [iters]`

use voicechat_crypto::envelope::Envelope;
use voicechat_crypto::engine::{InitiationPacket, SealedMessage};
use voicechat_crypto::prekeys::PublicPrekeyBundle;
use voicechat_crypto::primitives::encoding::{decode_ec, decode_kem};
use voicechat_crypto::primitives::kem::{MlKemCiphertext, MlKemPublic};
use voicechat_crypto::ratchet::scka::SckaMessage;
use voicechat_crypto::ratchet::triple::TripleHeader;
use voicechat_crypto::ratchet::Header;

fn walk(data: &[u8]) {
    let _ = Envelope::parse(data);
    let _ = Header::decode(data);
    let _ = TripleHeader::decode(data);
    let _ = SckaMessage::decode(data);
    let _ = MlKemPublic::from_bytes(data);
    let _ = MlKemCiphertext::from_bytes(data);
    let _ = decode_ec(data);
    let _ = decode_kem(data);
    let _ = PublicPrekeyBundle::decode(data);
    let _ = InitiationPacket::decode(data);
    let _ = SealedMessage::decode(data);
}

fn main() {
    let iters: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000);
    let mut seed = 0xC0FFEE_u64;
    for _ in 0..iters {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let len = (seed % 256) as usize;
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (seed >> 33) as u8;
        }
        walk(&buf);
        if !buf.is_empty() {
            buf[0] ^= 0xff;
            walk(&buf);
        }
    }
    walk(&[]);
    walk(&[0xff; 1]);
    walk(&[0xff; 40]);
    walk(&[0xff; 48]);
    walk(&[0xff; 1184]);
    println!("host_runner ok iters={iters}");
}
