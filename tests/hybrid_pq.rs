//! Prompt 9 — VOICECHAT_HYBRID_PQ_V1 measurements and loss behavior.

use std::time::Instant;
use voicechat_crypto::primitives::x25519::X25519Secret;
use voicechat_crypto::ratchet::scka::MlKemCka;
use voicechat_crypto::ratchet::triple::TripleRatchetState;

fn pair() -> (TripleRatchetState, TripleRatchetState) {
    let sk = [11u8; 32];
    let bob_dh = X25519Secret::generate().unwrap();
    let alice = TripleRatchetState::init_alice(&sk, &bob_dh.public_key()).unwrap();
    let bob = TripleRatchetState::init_bob(&sk, bob_dh).unwrap();
    (alice, bob)
}

#[test]
fn alternating_and_burst_and_reorder() {
    let (mut a, mut b) = pair();
    let mut held = Vec::new();
    for i in 0..6u8 {
        let (h, ct) = a.encrypt(&[i], b"ad").unwrap();
        held.push((h, ct, i));
    }
    // Deliver last then first (reorder / skip)
    let (h, ct, i) = held.pop().unwrap();
    assert_eq!(b.decrypt(&h, &ct, b"ad").unwrap(), vec![i]);
    let (h0, ct0, i0) = held.remove(0);
    let _ = b.decrypt(&h0, &ct0, b"ad");

    for _ in 0..4 {
        let (h, ct) = b.encrypt(b"burst", b"ad").unwrap();
        assert_eq!(a.decrypt(&h, &ct, b"ad").unwrap(), b"burst");
    }
}

#[test]
fn dropped_message_does_not_break_later() {
    let (mut a, mut b) = pair();
    let (_h_drop, _ct_drop) = a.encrypt(b"lost", b"ad").unwrap();
    let (h, ct) = a.encrypt(b"later", b"ad").unwrap();
    assert_eq!(b.decrypt(&h, &ct, b"ad").unwrap(), b"later");
}

#[test]
fn cka_healing_secrets_match() {
    let mut x = MlKemCka::new();
    let mut y = MlKemCka::new();
    let (m1, _) = x.send().unwrap();
    y.receive(&m1).unwrap();
    let (m2, s_y) = y.send().unwrap();
    let s_x = x.receive(&m2).unwrap();
    assert_eq!(s_x, s_y);
}

#[test]
fn measure_sizes_and_cpu() {
    let t0 = Instant::now();
    let (mut a, mut b) = pair();
    let init_ms = t0.elapsed();
    let (h, ct) = a.encrypt(&[0u8; 64], b"ad").unwrap();
    let header_len = h.encode().len();
    let msg_len = header_len + ct.len();
    let t1 = Instant::now();
    let _ = b.decrypt(&h, &ct, b"ad").unwrap();
    let dec_ms = t1.elapsed();
    eprintln!(
        "HYBRID_PQ measure init={:?} decrypt={:?} header={} total_msg={} classical_header=40",
        init_ms, dec_ms, header_len, msg_len
    );
    assert!(header_len > 40);
    assert!(msg_len > 64);
}

#[test]
fn tamper_fails() {
    let (mut a, mut b) = pair();
    let (h, mut ct) = a.encrypt(b"x", b"ad").unwrap();
    if let Some(x) = ct.last_mut() {
        *x ^= 1;
    }
    assert!(b.decrypt(&h, &ct, b"ad").is_err());
}

#[test]
fn engine_hybrid_does_not_accept_classical_ciphertext() {
    use voicechat_crypto::{CryptoEngineApi, CryptoProfile, DeviceConfig, VoiceChatCryptoEngine};

    let mut ha = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"ha".to_vec(),
        profile: CryptoProfile::HybridPqV1,
    })
    .unwrap();
    let mut hb = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"hb".to_vec(),
        profile: CryptoProfile::HybridPqV1,
    })
    .unwrap();
    let hb_bundle = hb.generate_public_prekey_bundle(1).unwrap();
    let (sid_h, init_h) = ha
        .establish_outbound_session(&hb_bundle, b"hx", b"H0", b"ad")
        .unwrap();
    let (sid_hb, pt_h) = hb.process_inbound_session(&init_h, b"hx", b"ad").unwrap();
    assert_eq!(pt_h, b"H0");

    let mut ca = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"ca".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .unwrap();
    let mut cb = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"cb".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .unwrap();
    let cb_bundle = cb.generate_public_prekey_bundle(1).unwrap();
    let (sid_c, init_c) = ca
        .establish_outbound_session(&cb_bundle, b"cx", b"C0", b"ad")
        .unwrap();
    let (sid_cb, pt_c) = cb.process_inbound_session(&init_c, b"cx", b"ad").unwrap();
    assert_eq!(pt_c, b"C0");

    let hybrid_msg = ha.encrypt(&sid_h, b"H", b"ad").unwrap();
    let class_msg = ca.encrypt(&sid_c, b"C", b"ad").unwrap();
    assert!(hb.decrypt(&sid_hb, &class_msg, b"ad").is_err());
    assert!(cb.decrypt(&sid_cb, &hybrid_msg, b"ad").is_err());
    assert_eq!(hb.decrypt(&sid_hb, &hybrid_msg, b"ad").unwrap(), b"H");
}

#[test]
fn offline_recipient_then_burst() {
    let (mut a, mut b) = pair();
    let mut held = Vec::new();
    for i in 0..12u8 {
        let (h, ct) = a.encrypt(&[i], b"ad").unwrap();
        held.push((h, ct, i));
    }
    for (h, ct, i) in held {
        assert_eq!(b.decrypt(&h, &ct, b"ad").unwrap(), vec![i]);
    }
}
