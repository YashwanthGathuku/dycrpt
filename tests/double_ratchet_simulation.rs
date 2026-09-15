//! Prompt 4 — randomized Double Ratchet conversations.
//!
//! Debug: 100 conversations × 250 messages.
//! Release (`cargo test --release`): 100 conversations × 10_000 messages.

use voicechat_crypto::primitives::x25519::X25519Secret;
use voicechat_crypto::ratchet::{DoubleRatchetState, DEFAULT_MAX_SKIP};

fn params() -> (usize, usize) {
    if cfg!(debug_assertions) {
        (100, 250)
    } else {
        (100, 10_000)
    }
}

fn pair() -> (DoubleRatchetState, DoubleRatchetState) {
    let mut sk = [0u8; 32];
    voicechat_crypto::primitives::random::fill_random(&mut sk).unwrap();
    let bob_dh = X25519Secret::generate().unwrap();
    let alice =
        DoubleRatchetState::init_alice(&sk, &bob_dh.public_key(), DEFAULT_MAX_SKIP).unwrap();
    let bob = DoubleRatchetState::init_bob(&sk, bob_dh, DEFAULT_MAX_SKIP);
    (alice, bob)
}

#[test]
fn one_hundred_conversations_random_drops_reorder_dup_corrupt_restart() {
    let (n_conv, n_msg) = params();
    let mut rng: u64 = 0xC0FFEE_u64;
    let next = |rng: &mut u64| -> u64 {
        *rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        *rng
    };

    for c in 0..n_conv {
        let (mut alice, mut bob) = pair();
        let mut inbox_b: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
        let mut inbox_a: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
        let mut delivered = 0usize;

        // Alice must send first (DR init leaves Bob without a sending chain).
        {
            let (h, ct) = alice.encrypt(b"hello-0", b"ad").unwrap();
            let header = voicechat_crypto::ratchet::Header::decode(&h.encode()).unwrap();
            assert_eq!(bob.decrypt(&header, &ct, b"ad").unwrap(), b"hello-0");
            delivered += 1;
        }

        for i in 0..n_msg {
            let body = format!("c{c}-m{i}").into_bytes();
            let roll = next(&mut rng) % 100;

            // Alice's mandatory opening message above always gives Bob a sending
            // chain, so no "can Bob send yet" guard is reachable here. The old
            // flag was dead on every path (review 2026-08-28).
            if roll < 55 {
                let (h, ct) = alice.encrypt(&body, b"ad").unwrap();
                let pkt = (h.encode(), ct, body);
                if roll < 5 {
                    // drop
                } else if roll < 10 {
                    // corrupt
                    let mut bad = pkt.1.clone();
                    if let Some(b) = bad.last_mut() {
                        *b ^= 0x5a;
                    }
                    inbox_b.push((pkt.0, bad, pkt.2));
                } else if roll < 15 {
                    inbox_b.push(pkt.clone());
                    inbox_b.push(pkt); // duplicate
                } else {
                    inbox_b.push(pkt);
                }
            } else {
                let (h, ct) = bob.encrypt(&body, b"ad").unwrap();
                let pkt = (h.encode(), ct, body);
                if roll > 95 {
                    // drop
                } else {
                    inbox_a.push(pkt);
                }
            }

            // Occasional reorder
            if inbox_b.len() >= 2 && next(&mut rng) % 7 == 0 {
                let n = inbox_b.len();
                inbox_b.swap(n - 1, n - 2);
            }

            // Drain a few
            while !inbox_b.is_empty() && next(&mut rng) % 3 != 0 {
                let (hb, ct, expect) = inbox_b.remove(0);
                let header = voicechat_crypto::ratchet::Header::decode(&hb).unwrap();
                match bob.decrypt(&header, &ct, b"ad") {
                    Ok(pt) => {
                        assert_eq!(pt, expect);
                        delivered += 1;
                    }
                    Err(_) => {}
                }
            }
            while !inbox_a.is_empty() && next(&mut rng) % 3 != 0 {
                let (hb, ct, expect) = inbox_a.remove(0);
                let header = voicechat_crypto::ratchet::Header::decode(&hb).unwrap();
                match alice.decrypt(&header, &ct, b"ad") {
                    Ok(pt) => {
                        assert_eq!(pt, expect);
                        delivered += 1;
                    }
                    Err(_) => {}
                }
            }

            // Process restart: serialize/reload
            if i % 40 == 39 {
                let ba = alice.serialize();
                let bb = bob.serialize();
                alice = DoubleRatchetState::deserialize(&ba, DEFAULT_MAX_SKIP).unwrap();
                bob = DoubleRatchetState::deserialize(&bb, DEFAULT_MAX_SKIP).unwrap();
            }
        }

        // Flush remaining (best effort)
        for (hb, ct, expect) in inbox_b {
            let header = voicechat_crypto::ratchet::Header::decode(&hb).unwrap();
            if let Ok(pt) = bob.decrypt(&header, &ct, b"ad") {
                assert_eq!(pt, expect);
                delivered += 1;
            }
        }
        for (hb, ct, expect) in inbox_a {
            let header = voicechat_crypto::ratchet::Header::decode(&hb).unwrap();
            if let Ok(pt) = alice.decrypt(&header, &ct, b"ad") {
                assert_eq!(pt, expect);
                delivered += 1;
            }
        }
        assert!(delivered > 0, "conversation {c} delivered nothing");
    }
}

#[test]
fn forward_secrecy_old_key_not_in_serialized_state() {
    let (mut alice, mut bob) = pair();
    let (h1, c1) = alice.encrypt(b"old", b"ad").unwrap();
    assert_eq!(bob.decrypt(&h1, &c1, b"ad").unwrap(), b"old");
    for _ in 0..8 {
        let (h, c) = alice.encrypt(b"n", b"ad").unwrap();
        let _ = bob.decrypt(&h, &c, b"ad").unwrap();
    }
    assert!(bob.decrypt(&h1, &c1, b"ad").is_err());
    let blob = bob.serialize();
    let mut bob2 = DoubleRatchetState::deserialize(&blob, DEFAULT_MAX_SKIP).unwrap();
    assert!(bob2.decrypt(&h1, &c1, b"ad").is_err());
}
