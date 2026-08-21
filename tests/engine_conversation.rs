//! Engine-level conversation simulation (PQXDH + selected profile + persist).
//! Complements `double_ratchet_simulation` which stresses the ratchet layer.

use voicechat_crypto::{CryptoEngineApi, CryptoProfile, DeviceConfig, VoiceChatCryptoEngine};

fn params() -> (usize, usize) {
    if cfg!(debug_assertions) {
        (20, 80)
    } else {
        (40, 400)
    }
}

fn pair(
    profile: CryptoProfile,
    tag: u8,
) -> (
    VoiceChatCryptoEngine,
    VoiceChatCryptoEngine,
    voicechat_crypto::SessionId,
    voicechat_crypto::SessionId,
) {
    let mut alice = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: vec![tag, 1],
        profile,
    })
    .unwrap();
    let mut bob = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: vec![tag, 2],
        profile,
    })
    .unwrap();
    let bundle = bob.generate_public_prekey_bundle(2).unwrap();
    let (sid_a, init) = alice
        .establish_outbound_session(&bundle, b"eng-sim", b"hello-0", b"ad")
        .unwrap();
    let (sid_b, pt0) = bob
        .process_inbound_session(&init, b"eng-sim", b"ad")
        .unwrap();
    assert_eq!(pt0, b"hello-0");
    (alice, bob, sid_a, sid_b)
}

fn run_profile(profile: CryptoProfile) {
    let (n_conv, n_msg) = params();
    let mut rng: u64 = 0xA11CE_u64;
    let next = |rng: &mut u64| -> u64 {
        *rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        *rng
    };

    for c in 0..n_conv {
        let (mut alice, mut bob, sid_a, sid_b) = pair(profile, c as u8);
        let mut inbox_b = Vec::new();
        let mut inbox_a = Vec::new();
        let mut delivered = 1usize;
        let bob_can_send = true;

        for i in 0..n_msg {
            let body = format!("c{c}-m{i}").into_bytes();
            let roll = next(&mut rng) % 100;
            if !bob_can_send || roll < 55 {
                let sealed = alice.encrypt(&sid_a, &body, b"ad").unwrap();
                if roll < 6 {
                    // drop
                } else if roll < 10 {
                    let mut bad = sealed;
                    if let Some(b) = bad.ciphertext.last_mut() {
                        *b ^= 0x3c;
                    }
                    inbox_b.push((bad, body));
                } else {
                    inbox_b.push((sealed, body));
                }
            } else {
                let sealed = bob.encrypt(&sid_b, &body, b"ad").unwrap();
                if roll > 96 {
                    // drop
                } else {
                    inbox_a.push((sealed, body));
                }
            }

            if inbox_b.len() >= 2 && next(&mut rng) % 5 == 0 {
                let n = inbox_b.len();
                inbox_b.swap(n - 1, n - 2);
            }
            while !inbox_b.is_empty() && next(&mut rng) % 3 != 0 {
                let (s, expect) = inbox_b.remove(0);
                if let Ok(pt) = bob.decrypt(&sid_b, &s, b"ad") {
                    assert_eq!(pt, expect);
                    delivered += 1;
                }
            }
            while !inbox_a.is_empty() && next(&mut rng) % 3 != 0 {
                let (s, expect) = inbox_a.remove(0);
                if let Ok(pt) = alice.decrypt(&sid_a, &s, b"ad") {
                    assert_eq!(pt, expect);
                    delivered += 1;
                }
            }
        }

        for (s, expect) in inbox_b {
            if let Ok(pt) = bob.decrypt(&sid_b, &s, b"ad") {
                assert_eq!(pt, expect);
                delivered += 1;
            }
        }
        for (s, expect) in inbox_a {
            if let Ok(pt) = alice.decrypt(&sid_a, &s, b"ad") {
                assert_eq!(pt, expect);
                delivered += 1;
            }
        }
        assert!(delivered > 0, "engine conversation {c} profile={profile:?}");
    }
}

#[test]
fn engine_conversations_classical() {
    run_profile(CryptoProfile::ClassicalV1);
}

#[cfg(feature = "hybrid")]
#[test]
fn engine_conversations_hybrid() {
    run_profile(CryptoProfile::HybridPqV1);
}
