//! Prompt 11 — untrusted parser boundaries (libfuzzer-independent).

use crate::envelope::Envelope;
use crate::primitives::encoding::{decode_ec, decode_kem};
use crate::primitives::kem::{MlKemCiphertext, MlKemPublic};
#[cfg(feature = "hybrid")]
use crate::ratchet::scka::SckaMessage;
#[cfg(feature = "hybrid")]
use crate::ratchet::triple::TripleHeader;
use crate::ratchet::Header;

fn walk(data: &[u8]) {
    let _ = Envelope::parse(data);
    let _ = Header::decode(data);
    #[cfg(feature = "hybrid")]
    let _ = TripleHeader::decode(data);
    #[cfg(feature = "hybrid")]
    let _ = SckaMessage::decode(data);
    let _ = MlKemPublic::from_bytes(data);
    let _ = MlKemCiphertext::from_bytes(data);
    let _ = decode_ec(data);
    let _ = decode_kem(data);
    let _ = crate::prekeys::PublicPrekeyBundle::decode(data);
    let _ = crate::engine::InitiationPacket::decode(data);
    let _ = crate::engine::SealedMessage::decode(data);
}

#[test]
fn random_byte_streams_do_not_panic() {
    let mut seed = 0xA5A5_u64;
    for _ in 0..8_000 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let len = (seed % 200) as usize;
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (seed >> 33) as u8;
        }
        walk(&buf);
    }
}

#[test]
fn empty_and_boundary_inputs() {
    walk(&[]);
    walk(&[0]);
    walk(&[0xff; 1]);
    walk(&[0xff; 40]);
    walk(&[0xff; 48]);
    walk(&[0xff; 1184]);
    walk(&[0xff; 1088]);
}
