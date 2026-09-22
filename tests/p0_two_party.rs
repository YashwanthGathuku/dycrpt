//! Mandatory P0 two-party handshake + ratchet test.
//!
//! Alice PQXDH → Bob process (A1) → B1 → A2/B2 → out-of-order →
//! restart/reload → tamper failure → replay failure.
//!
//! Every success path asserts recovered plaintext exactly.

use voicechat_crypto::{CryptoEngineApi, CryptoProfile, DeviceConfig, VoiceChatCryptoEngine};

fn device(id: &[u8]) -> VoiceChatCryptoEngine {
    VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: id.to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .unwrap()
}

#[test]
fn p0_alice_bob_pqxdh_ratchet_restart_tamper_replay() {
    let alice = device(b"alice");
    let bob = device(b"bob");
    let bundle = bob.generate_public_prekey_bundle(3).unwrap();

    let (sid_a, packet) = alice
        .establish_outbound_session(&bundle, b"conv", b"A1", b"ad")
        .unwrap();
    assert!(!packet.kem_ciphertext.is_empty());
    assert_ne!(packet.sender_identity_public, [0u8; 32]);
    assert_ne!(packet.sender_ephemeral_public, [0u8; 32]);
    assert_eq!(packet.used_spk_id, bundle.signed_prekey_id);
    assert_eq!(packet.pq_prekey_id, bundle.pq_prekey_id);

    let (sid_b, a1) = bob
        .process_inbound_session(&packet, b"conv", b"ad")
        .unwrap();
    assert_eq!(a1.as_slice(), b"A1");

    let b1 = bob.encrypt(&sid_b, b"B1", b"ad").unwrap();
    assert_eq!(alice.decrypt(&sid_a, &b1, b"ad").unwrap().as_slice(), b"B1");

    let a2 = alice.encrypt(&sid_a, b"A2", b"ad").unwrap();
    let b2 = bob.encrypt(&sid_b, b"B2", b"ad").unwrap();
    let a3 = alice.encrypt(&sid_a, b"A3", b"ad").unwrap();

    assert_eq!(alice.decrypt(&sid_a, &b2, b"ad").unwrap().as_slice(), b"B2");
    assert_eq!(bob.decrypt(&sid_b, &a3, b"ad").unwrap().as_slice(), b"A3");
    assert_eq!(bob.decrypt(&sid_b, &a2, b"ad").unwrap().as_slice(), b"A2");

    alice.simulate_crash_reload().unwrap();
    bob.simulate_crash_reload().unwrap();

    let a4 = alice.encrypt(&sid_a, b"A4", b"ad").unwrap();
    assert_eq!(bob.decrypt(&sid_b, &a4, b"ad").unwrap().as_slice(), b"A4");
    let b3 = bob.encrypt(&sid_b, b"B3", b"ad").unwrap();
    assert_eq!(alice.decrypt(&sid_a, &b3, b"ad").unwrap().as_slice(), b"B3");

    let mut tampered = alice.encrypt(&sid_a, b"TAMPER", b"ad").unwrap();
    if let Some(byte) = tampered.ciphertext.last_mut() {
        *byte ^= 0xff;
    }
    assert!(bob.decrypt(&sid_b, &tampered, b"ad").is_err());

    let good = alice.encrypt(&sid_a, b"A5", b"ad").unwrap();
    assert_eq!(bob.decrypt(&sid_b, &good, b"ad").unwrap().as_slice(), b"A5");
    assert!(bob.decrypt(&sid_b, &good, b"ad").is_err());
}
