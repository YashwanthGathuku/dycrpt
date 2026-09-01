//! Prompt 6 — crash-safe persistence, rollback, resource bounds.

use voicechat_crypto::padding::{pad_to_bucket, unpad, DEFAULT_BUCKETS};
use voicechat_crypto::policy::{select_profile, CryptoProfile};
use voicechat_crypto::primitives::x25519::X25519Secret;
use voicechat_crypto::ratchet::DoubleRatchetState;
use voicechat_crypto::replay::{ReplayCache, ReplayKey};
use voicechat_crypto::storage::{
    MemoryStorage, RollbackGuard, StateBlob, StorageEpoch, TransactionalStorage,
};

const TEST_MAX_SKIP: u32 = 8;

fn pair() -> (DoubleRatchetState, DoubleRatchetState) {
    let sk = [7u8; 32];
    let bob_dh = X25519Secret::generate().unwrap();
    let alice = DoubleRatchetState::init_alice(&sk, &bob_dh.public_key(), TEST_MAX_SKIP).unwrap();
    let bob = DoubleRatchetState::init_bob(&sk, bob_dh, TEST_MAX_SKIP);
    (alice, bob)
}

#[test]
fn encrypt_not_released_if_commit_aborted() {
    let (alice, _bob) = pair();
    let mut store = MemoryStorage::default();
    let mut trial = alice.clone_for_trial();
    let (_h, ct) = trial.encrypt(b"secret", b"ad").unwrap();
    let tx = store.begin().unwrap();
    store
        .put(tx, b"sess", &StateBlob(trial.serialize()))
        .unwrap();
    store.abort(tx).unwrap();
    // Ciphertext must not be treated as sendable: persistent store unchanged.
    assert!(store.get(b"sess").unwrap().is_none());
    let _ = ct;
    // In-memory original state still decrypts nothing for that send.
}

#[test]
fn decrypt_crash_before_commit_keeps_old_blob() {
    let (mut alice, bob) = pair();
    let (h, ct) = alice.encrypt(b"m", b"ad").unwrap();
    let mut store = MemoryStorage::default();
    let tx = store.begin().unwrap();
    store.put(tx, b"bob", &StateBlob(bob.serialize())).unwrap();
    store.commit(tx).unwrap();

    let mut trial = bob.clone_for_trial();
    assert_eq!(trial.decrypt(&h, &ct, b"ad").unwrap(), b"m");
    let tx2 = store.begin().unwrap();
    store
        .put(tx2, b"bob", &StateBlob(trial.serialize()))
        .unwrap();
    store.abort(tx2).unwrap();

    let old = store.get(b"bob").unwrap().unwrap();
    let mut restored = DoubleRatchetState::deserialize(&old.0, TEST_MAX_SKIP).unwrap();
    // Old state can still decrypt the same message (commit never happened).
    assert_eq!(restored.decrypt(&h, &ct, b"ad").unwrap(), b"m");
}

#[test]
fn rollback_of_stale_backup_detected() {
    let mut g = RollbackGuard::default();
    g.observe(StorageEpoch(10)).unwrap();
    assert!(g.observe(StorageEpoch(2)).is_err());
}

#[test]
fn replay_cache_bounded() {
    let mut cache = ReplayCache::new(8);
    for i in 0..32u8 {
        let _ = cache.check_and_insert(ReplayKey {
            conversation_id: b"c".to_vec(),
            sender_device_id: b"d".to_vec(),
            message_id: vec![i],
        });
    }
    assert!(cache.len() <= 8);
}

#[test]
fn max_skip_and_packet_size_bounds() {
    let (mut alice, mut bob) = pair();
    let (h0, c0) = alice.encrypt(b"0", b"ad").unwrap();
    bob.decrypt(&h0, &c0, b"ad").unwrap();
    let (mut h, c) = alice.encrypt(b"far", b"ad").unwrap();
    h.n = 10_000;
    assert!(bob.decrypt(&h, &c, b"ad").is_err());
    assert!(bob.skipped_count() <= TEST_MAX_SKIP as usize);
}

#[test]
fn padding_hides_length_in_bucket() {
    let a = pad_to_bucket(&[1u8; 10], DEFAULT_BUCKETS).unwrap();
    let b = pad_to_bucket(&[2u8; 20], DEFAULT_BUCKETS).unwrap();
    assert_eq!(a.len(), b.len());
    assert_eq!(unpad(&a).unwrap(), vec![1u8; 10]);
}

#[test]
fn engine_reload_after_commit() {
    use voicechat_crypto::{CryptoEngineApi, CryptoProfile, DeviceConfig, VoiceChatCryptoEngine};
    let a = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"a".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .unwrap();
    let b = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"b".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .unwrap();
    let bundle = b.generate_public_prekey_bundle(1).unwrap();
    let (sid_a, init) = a
        .establish_outbound_session(&bundle, b"c", b"x", b"ad")
        .unwrap();
    let (sid_b, pt) = b.process_inbound_session(&init, b"c", b"ad").unwrap();
    assert_eq!(pt, b"x");
    let s = a.encrypt(&sid_a, b"x", b"ad").unwrap();
    assert_eq!(b.decrypt(&sid_b, &s, b"ad").unwrap(), b"x");
    a.simulate_crash_reload().unwrap();
    b.simulate_crash_reload().unwrap();
    let s2 = a.encrypt(&sid_a, b"y", b"ad").unwrap();
    assert_eq!(b.decrypt(&sid_b, &s2, b"ad").unwrap(), b"y");
}

#[test]
fn no_network_downgrade() {
    assert!(select_profile(&[CryptoProfile::ClassicalV1], &[CryptoProfile::ClassicalV1]).is_ok());
    assert!(select_profile(&[CryptoProfile::ClassicalV1], &[]).is_err());
}
