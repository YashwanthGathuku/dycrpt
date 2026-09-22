use std::sync::{Arc, Barrier};
use std::thread;

use voicechat_crypto::{
    CryptoEngineApi, CryptoProfile, DeviceConfig, SessionId, VoiceChatCryptoEngine,
};

fn engine(id: &[u8]) -> VoiceChatCryptoEngine {
    VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: id.to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .unwrap()
}

fn sessions(
    alice: &VoiceChatCryptoEngine,
    bob: &VoiceChatCryptoEngine,
    count: usize,
) -> Vec<(SessionId, SessionId)> {
    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        let bundle = bob.generate_public_prekey_bundle(2).unwrap();
        let conversation = format!("parallel-conversation-{i}").into_bytes();
        let (sid_a, init) = alice
            .establish_outbound_session(&bundle, &conversation, b"first", b"ad")
            .unwrap();
        let (sid_b, first) = bob
            .process_inbound_session(&init, &conversation, b"ad")
            .unwrap();
        assert_eq!(first, b"first");
        result.push((sid_a, sid_b));
    }
    result
}

#[test]
fn different_sessions_can_use_one_shared_engine_without_outer_mutex() {
    const N: usize = 12;
    let alice = Arc::new(engine(b"parallel-alice"));
    let bob = Arc::new(engine(b"parallel-bob"));
    let pairs = sessions(&alice, &bob, N);
    let barrier = Arc::new(Barrier::new(N));

    let mut workers = Vec::with_capacity(N);
    for (i, (sid_a, sid_b)) in pairs.into_iter().enumerate() {
        let alice = alice.clone();
        let bob = bob.clone();
        let barrier = barrier.clone();
        workers.push(thread::spawn(move || {
            barrier.wait();
            let plaintext = format!("parallel-message-{i}").into_bytes();
            let sealed = alice.encrypt(&sid_a, &plaintext, b"ad").unwrap();
            let recovered = bob.decrypt(&sid_b, &sealed, b"ad").unwrap();
            assert_eq!(recovered, plaintext);
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn same_session_concurrent_senders_are_serialized_without_key_reuse() {
    const N: usize = 32;
    let alice = Arc::new(engine(b"same-session-alice"));
    let bob = Arc::new(engine(b"same-session-bob"));
    let (sid_a, sid_b) = sessions(&alice, &bob, 1).pop().unwrap();
    let barrier = Arc::new(Barrier::new(N));

    let mut workers = Vec::with_capacity(N);
    for i in 0..N {
        let alice = alice.clone();
        let barrier = barrier.clone();
        let sid = sid_a.clone();
        workers.push(thread::spawn(move || {
            barrier.wait();
            let plaintext = format!("same-session-{i}").into_bytes();
            let sealed = alice.encrypt(&sid, &plaintext, b"ad").unwrap();
            (plaintext, sealed)
        }));
    }

    // Join order is intentionally unrelated to ratchet order. The receiver's
    // skipped-key mechanism must still recover every message exactly once.
    for worker in workers {
        let (plaintext, sealed) = worker.join().unwrap();
        assert_eq!(bob.decrypt(&sid_b, &sealed, b"ad").unwrap(), plaintext);
    }
}

#[test]
fn concurrent_duplicate_delivery_has_single_winner() {
    let alice = Arc::new(engine(b"replay-race-alice"));
    let bob = Arc::new(engine(b"replay-race-bob"));
    let (sid_a, sid_b) = sessions(&alice, &bob, 1).pop().unwrap();
    let sealed = Arc::new(alice.encrypt(&sid_a, b"deliver-once", b"ad").unwrap());
    let barrier = Arc::new(Barrier::new(2));

    let mut workers = Vec::new();
    for _ in 0..2 {
        let bob = bob.clone();
        let sealed = sealed.clone();
        let barrier = barrier.clone();
        let sid = sid_b.clone();
        workers.push(thread::spawn(move || {
            barrier.wait();
            bob.decrypt(&sid, &sealed, b"ad")
        }));
    }
    let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(voicechat_crypto::CryptoError::Replay)))
            .count(),
        1
    );
}
