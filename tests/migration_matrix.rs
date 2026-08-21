//! Prompt 15 — migration matrix (security behavior, not ciphertext identity).

#![cfg(test)]

use voicechat_crypto::{CryptoEngineApi, CryptoProfile, DeviceConfig, VoiceChatCryptoEngine};

fn alice() -> VoiceChatCryptoEngine {
    VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"alice-dev".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .unwrap()
}

fn bob() -> VoiceChatCryptoEngine {
    VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"bob-dev".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .unwrap()
}

fn linked() -> (
    VoiceChatCryptoEngine,
    VoiceChatCryptoEngine,
    voicechat_crypto::SessionId,
    voicechat_crypto::SessionId,
) {
    let mut a = alice();
    let mut b = bob();
    let bundle = b.generate_public_prekey_bundle(4).unwrap();
    let (sid_a, init) = a
        .establish_outbound_session(&bundle, b"conv", b"A0", b"ad")
        .unwrap();
    let (sid_b, pt) = b.process_inbound_session(&init, b"conv", b"ad").unwrap();
    assert_eq!(pt, b"A0");
    (a, b, sid_a, sid_b)
}

#[test]
fn matrix_initial_session() {
    let (a, _b, sid, sid_b) = linked();
    assert!(a.has_session(&sid));
    let _ = sid_b;
}

#[test]
fn matrix_sequential_messages() {
    let (mut a, mut b, sid_a, sid_b) = linked();
    for i in 0..8u8 {
        let s = a.encrypt(&sid_a, &[i], b"ad").unwrap();
        assert_eq!(b.decrypt(&sid_b, &s, b"ad").unwrap(), vec![i]);
    }
}

#[test]
fn matrix_bidirectional_ratchet() {
    let (mut a, mut b, sid_a, sid_b) = linked();
    let s = a.encrypt(&sid_a, b"A", b"ad").unwrap();
    assert_eq!(b.decrypt(&sid_b, &s, b"ad").unwrap(), b"A");
    let s = b.encrypt(&sid_b, b"B", b"ad").unwrap();
    assert_eq!(a.decrypt(&sid_a, &s, b"ad").unwrap(), b"B");
}

#[test]
fn matrix_out_of_order() {
    let (mut a, mut b, sid_a, sid_b) = linked();
    let s1 = a.encrypt(&sid_a, b"1", b"ad").unwrap();
    let s2 = a.encrypt(&sid_a, b"2", b"ad").unwrap();
    let s3 = a.encrypt(&sid_a, b"3", b"ad").unwrap();
    assert_eq!(b.decrypt(&sid_b, &s1, b"ad").unwrap(), b"1");
    assert_eq!(b.decrypt(&sid_b, &s3, b"ad").unwrap(), b"3");
    assert_eq!(b.decrypt(&sid_b, &s2, b"ad").unwrap(), b"2");
}

#[test]
fn matrix_dropped_messages() {
    let (mut a, mut b, sid_a, sid_b) = linked();
    let _dropped = a.encrypt(&sid_a, b"lost", b"ad").unwrap();
    let s = a.encrypt(&sid_a, b"kept", b"ad").unwrap();
    assert_eq!(b.decrypt(&sid_b, &s, b"ad").unwrap(), b"kept");
}

#[test]
fn matrix_tamper_rejection() {
    let (mut a, mut b, sid_a, sid_b) = linked();
    let mut s = a.encrypt(&sid_a, b"m", b"ad").unwrap();
    if let Some(x) = s.ciphertext.last_mut() {
        *x ^= 0xff;
    }
    assert!(b.decrypt(&sid_b, &s, b"ad").is_err());
}

#[test]
fn matrix_replay_rejection() {
    let (mut a, mut b, sid_a, sid_b) = linked();
    let s = a.encrypt(&sid_a, b"m", b"ad").unwrap();
    assert_eq!(b.decrypt(&sid_b, &s, b"ad").unwrap(), b"m");
    assert!(b.decrypt(&sid_b, &s, b"ad").is_err());
}

#[test]
fn matrix_restart_persistence() {
    let (mut a, mut b, sid_a, sid_b) = linked();
    let s = a.encrypt(&sid_a, b"before", b"ad").unwrap();
    assert_eq!(b.decrypt(&sid_b, &s, b"ad").unwrap(), b"before");
    a.simulate_crash_reload().unwrap();
    b.simulate_crash_reload().unwrap();
    let s2 = a.encrypt(&sid_a, b"after", b"ad").unwrap();
    assert_eq!(b.decrypt(&sid_b, &s2, b"ad").unwrap(), b"after");
}

#[test]
fn matrix_prekey_depletion() {
    let mut b = bob();
    let bundle = b.generate_public_prekey_bundle(1).unwrap();
    let mut a1 = alice();
    let mut a2 = alice();
    let (_s1, init1) = a1
        .establish_outbound_session(&bundle, b"c1", b"A0", b"ad")
        .unwrap();
    let (_sid_b, pt) = b.process_inbound_session(&init1, b"c1", b"ad").unwrap();
    assert_eq!(pt, b"A0");
    // Alice can still encapsulate to the published one-time PQ public, but Bob
    // must reject a second consume of that one-time identifier.
    let (_s2, init2) = a2
        .establish_outbound_session(&bundle, b"c2", b"A1", b"ad")
        .unwrap();
    assert!(b.process_inbound_session(&init2, b"c2", b"ad").is_err());
}

#[test]
fn matrix_identity_and_fingerprint() {
    let a = alice();
    let b = bob();
    let fa = a
        .safety_fingerprint(&b.local_identity_public(), Some(b"bob-dev"))
        .unwrap();
    let fb = b
        .safety_fingerprint(&a.local_identity_public(), Some(b"alice-dev"))
        .unwrap();
    assert_eq!(fa.binary, fb.binary);
}

#[test]
fn matrix_wrong_session() {
    let (mut a, mut b, sid_a, sid_b) = linked();
    let s = a.encrypt(&sid_a, b"x", b"ad").unwrap();
    a.delete_session(&sid_a).unwrap();
    assert!(!a.has_session(&sid_a));
    assert!(a.decrypt(&sid_a, &s, b"ad").is_err());
    let _ = sid_b;
    let _ = b;
}

#[test]
fn matrix_large_voice_payload() {
    let (mut a, mut b, sid_a, sid_b) = linked();
    let payload = vec![7u8; 64 * 1024];
    let s = a
        .encrypt_voice_payload(&sid_a, &payload, b"ok-meta")
        .unwrap();
    assert_eq!(b.decrypt(&sid_b, &s, b"ok-meta").unwrap(), payload);
}

#[test]
fn matrix_voice_profile_forbidden() {
    let (mut a, _b, sid_a, _sid_b) = linked();
    assert!(a
        .encrypt_voice_payload(&sid_a, b"audio", b"voice_profile=x")
        .is_err());
}

#[test]
fn matrix_crash_recovery_stronger() {
    use voicechat_crypto::storage::{MemoryStorage, StateBlob, TransactionalStorage};
    let mut store = MemoryStorage::default();
    let tx = store.begin().unwrap();
    store.put(tx, b"s", &StateBlob(b"v1".to_vec())).unwrap();
    store.commit(tx).unwrap();
    let tx = store.begin().unwrap();
    store.put(tx, b"s", &StateBlob(b"v2".to_vec())).unwrap();
    store.abort(tx).unwrap();
    assert_eq!(store.get(b"s").unwrap().unwrap().0, b"v1");
}

#[test]
fn matrix_rollback_attempt_stronger() {
    use voicechat_crypto::{RollbackGuard, StorageEpoch};
    let mut g = RollbackGuard::default();
    g.observe(StorageEpoch(5)).unwrap();
    assert!(g.observe(StorageEpoch(1)).is_err());
}

#[test]
fn matrix_downgrade_attempt_stronger() {
    assert!(CryptoProfile::from_u8(99).is_err());
    assert!(voicechat_crypto::enforce_profile(
        CryptoProfile::ClassicalV1,
        CryptoProfile::ClassicalV1
    )
    .is_ok());
}

#[cfg(feature = "hybrid")]
#[test]
fn matrix_hybrid_session_and_bidirectional() {
    let mut a = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"alice-h".to_vec(),
        profile: CryptoProfile::HybridPqV1,
    })
    .unwrap();
    let mut b = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"bob-h".to_vec(),
        profile: CryptoProfile::HybridPqV1,
    })
    .unwrap();
    let bundle = b.generate_public_prekey_bundle(2).unwrap();
    let (sid_a, init) = a
        .establish_outbound_session(&bundle, b"hy", b"A", b"ad")
        .unwrap();
    let (sid_b, pt) = b.process_inbound_session(&init, b"hy", b"ad").unwrap();
    assert_eq!(pt, b"A");
    let s = a.encrypt(&sid_a, b"A", b"ad").unwrap();
    assert_eq!(b.decrypt(&sid_b, &s, b"ad").unwrap(), b"A");
    let s = b.encrypt(&sid_b, b"B", b"ad").unwrap();
    assert_eq!(a.decrypt(&sid_a, &s, b"ad").unwrap(), b"B");
}

#[cfg(feature = "header-encrypt")]
#[test]
fn matrix_header_encrypt_session() {
    let mut a = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"alice-he".to_vec(),
        profile: CryptoProfile::ClassicalHeV1,
    })
    .unwrap();
    let mut b = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"bob-he".to_vec(),
        profile: CryptoProfile::ClassicalHeV1,
    })
    .unwrap();
    let bundle = b.generate_public_prekey_bundle(2).unwrap();
    let (sid_a, init) = a
        .establish_outbound_session(&bundle, b"he", b"hid", b"ad")
        .unwrap();
    let (sid_b, pt) = b.process_inbound_session(&init, b"he", b"ad").unwrap();
    assert_eq!(pt, b"hid");
    let s = a.encrypt(&sid_a, b"hid", b"ad").unwrap();
    assert_eq!(b.decrypt(&sid_b, &s, b"ad").unwrap(), b"hid");
}

#[test]
fn matrix_identity_replacement() {
    use voicechat_crypto::primitives::x25519::X25519Secret;
    use voicechat_crypto::{IdentityMaterial, IdentityState, IdentityTracker};
    let old = IdentityMaterial {
        identity_key: X25519Secret::generate().unwrap().public_key(),
        device_id: Some(b"phone".to_vec()),
    };
    let new = IdentityMaterial {
        identity_key: X25519Secret::generate().unwrap().public_key(),
        device_id: Some(b"phone".to_vec()),
    };
    let t = IdentityTracker::with_acknowledged(old);
    assert!(matches!(
        t.observe(&new),
        IdentityState::IdentityChanged { .. }
    ));
}
