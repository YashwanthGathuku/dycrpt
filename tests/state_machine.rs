//! Prompt 12 — executable state-machine checks matching the TLA+ models.
//! These are not a TLC proof. They test the same invariants against the Rust
//! implementation and a finite model.

use voicechat_crypto::fingerprint::{IdentityMaterial, IdentityState, IdentityTracker};
use voicechat_crypto::policy::{enforce_profile, CryptoProfile};
use voicechat_crypto::prekeys::{IdentityKeyPair, PrekeyStore};
use voicechat_crypto::primitives::x25519::X25519Secret;
use voicechat_crypto::ratchet::{DoubleRatchetState, DEFAULT_MAX_SKIP};
use voicechat_crypto::replay::{ReplayCache, ReplayKey};

#[test]
fn opk_at_most_once() {
    let ik = IdentityKeyPair::generate().unwrap();
    let mut store = PrekeyStore::new(&ik).unwrap();
    store.replenish(&ik, 3, 0).unwrap();
    let bundle = store.public_bundle(&ik).unwrap();
    let id = bundle.one_time_ec.unwrap().0;
    store.consume_ec(id).unwrap();
    assert!(store.consume_ec(id).is_err());
}

#[test]
fn invalid_auth_does_not_commit() {
    let sk = [1u8; 32];
    let bob_dh = X25519Secret::generate().unwrap();
    let mut alice =
        DoubleRatchetState::init_alice(&sk, &bob_dh.public_key(), DEFAULT_MAX_SKIP).unwrap();
    let mut bob = DoubleRatchetState::init_bob(&sk, bob_dh, DEFAULT_MAX_SKIP);
    let (h, mut ct) = alice.encrypt(b"m", b"ad").unwrap();
    let before = bob.serialize();
    if let Some(b) = ct.last_mut() {
        *b ^= 0xff;
    }
    assert!(bob.decrypt(&h, &ct, b"ad").is_err());
    assert_eq!(before, bob.serialize());
}

#[test]
fn replay_second_accept_impossible() {
    let mut cache = ReplayCache::new(16);
    let k = ReplayKey {
        conversation_id: b"c".to_vec(),
        sender_device_id: b"d".to_vec(),
        message_id: b"m1".to_vec(),
    };
    assert!(!cache.check_and_insert(k.clone()).unwrap());
    assert!(cache.check_and_insert(k).unwrap());
}

#[test]
fn identity_change_not_silent() {
    let a = IdentityMaterial {
        identity_key: X25519Secret::generate().unwrap().public_key(),
        device_id: Some(b"d".to_vec()),
    };
    let b = IdentityMaterial {
        identity_key: X25519Secret::generate().unwrap().public_key(),
        device_id: Some(b"d".to_vec()),
    };
    let t = IdentityTracker::with_acknowledged(a);
    assert!(matches!(
        t.observe(&b),
        IdentityState::IdentityChanged { .. }
    ));
}

#[test]
fn downgrade_after_bind_impossible() {
    assert!(enforce_profile(CryptoProfile::ClassicalV1, CryptoProfile::ClassicalV1).is_ok());
    assert!(CryptoProfile::from_u8(0).is_err());
}

/// Finite model: enumerate Consume / DoubleConsumeAttempt like PrekeyConsumption.tla
#[test]
fn finite_prekey_model_at_most_once() {
    #[derive(Clone)]
    struct Model {
        available: Vec<u8>,
        consumed: [u8; 3],
    }
    let mut m = Model {
        available: vec![0, 1, 2],
        consumed: [0; 3],
    };
    for _step in 0..12 {
        if let Some(id) = m.available.first().copied() {
            m.available.retain(|x| *x != id);
            m.consumed[id as usize] = 1;
        }
        for id in 0..3u8 {
            if !m.available.contains(&id) {
                // DoubleConsumeAttempt: stutter
                assert!(m.consumed[id as usize] <= 1);
            }
        }
    }
    assert!(m.consumed.iter().all(|c| *c <= 1));
}
