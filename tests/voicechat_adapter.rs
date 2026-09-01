//! Prompt 14 — VoiceChat application adapter behavioral tests.
//! Parent VoiceChat app is not in this workspace; these tests cover the
//! `CryptoEngineApi` contract that the app must use.

use voicechat_crypto::{
    CryptoEngineApi, CryptoError, CryptoProfile, DeviceConfig, VoiceChatCryptoEngine,
};

fn engine(id: &[u8], profile: CryptoProfile) -> VoiceChatCryptoEngine {
    VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: id.to_vec(),
        profile,
    })
    .unwrap()
}

#[test]
fn adapter_full_lifecycle_text_and_voice() {
    let alice = engine(b"alice-phone", CryptoProfile::ClassicalV1);
    let bob = engine(b"bob-phone", CryptoProfile::ClassicalV1);
    let bundle = bob.generate_public_prekey_bundle(4).unwrap();
    let (sid_a, init) = alice
        .establish_outbound_session(&bundle, b"thread-1", b"hello", b"type=text")
        .unwrap();
    let (sid_b, pt0) = bob
        .process_inbound_session(&init, b"thread-1", b"type=text")
        .unwrap();
    assert_eq!(pt0, b"hello");

    let voice = alice
        .encrypt_voice_payload(&sid_a, b"opus-frame-bytes", b"codec=opus")
        .unwrap();
    assert_eq!(
        bob.decrypt(&sid_b, &voice, b"codec=opus").unwrap(),
        b"opus-frame-bytes"
    );

    assert!(alice
        .encrypt_voice_payload(&sid_a, b"x", b"voice_profile=owner")
        .is_err());

    let fa = alice
        .safety_fingerprint(&bob.local_identity_public(), Some(b"bob-phone"))
        .unwrap();
    let fb = bob
        .safety_fingerprint(&alice.local_identity_public(), Some(b"alice-phone"))
        .unwrap();
    assert_eq!(fa.binary, fb.binary);

    alice
        .acknowledge_identity_change(&bob.local_identity_public(), Some(b"bob-phone"))
        .unwrap();
    assert!(alice.has_session(&sid_a));
    alice.delete_session(&sid_a).unwrap();
    assert!(!alice.has_session(&sid_a));
    assert_eq!(
        alice.encrypt(&sid_a, b"x", b"ad"),
        Err(CryptoError::NoSession)
    );
}

#[cfg(feature = "hybrid")]
#[test]
fn adapter_hybrid_profile_is_not_classical() {
    let alice = engine(b"a", CryptoProfile::HybridPqV1);
    let bob = engine(b"b", CryptoProfile::HybridPqV1);
    let bundle = bob.generate_public_prekey_bundle(2).unwrap();
    let (sid_a, init) = alice
        .establish_outbound_session(&bundle, b"h", b"pq", b"ad")
        .unwrap();
    let (sid_b, pt) = bob.process_inbound_session(&init, b"h", b"ad").unwrap();
    assert_eq!(pt, b"pq");
    let sealed = alice.encrypt(&sid_a, b"pq", b"ad").unwrap();
    assert!(sealed.header.len() > 40);
    assert_eq!(bob.decrypt(&sid_b, &sealed, b"ad").unwrap(), b"pq");
}

#[test]
fn adapter_replenish_prekeys_and_delete_all() {
    let alice = engine(b"a", CryptoProfile::ClassicalV1);
    let bob = engine(b"b", CryptoProfile::ClassicalV1);
    let _ = bob.replenish_prekeys(2).unwrap();
    let bundle = bob.generate_public_prekey_bundle(2).unwrap();
    let (sid, _init) = alice
        .establish_outbound_session(&bundle, b"c", b"A0", b"ad")
        .unwrap();
    alice.delete_all_sessions().unwrap();
    assert!(!alice.has_session(&sid));
}
