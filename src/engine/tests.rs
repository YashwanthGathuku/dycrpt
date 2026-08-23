use super::*;
use crate::policy::CryptoProfile;
use crate::storage::{MemoryStorage, StorageEpoch, TransactionId, TransactionalStorage};

fn cfg() -> DeviceConfig {
    DeviceConfig {
        device_id: b"device-1".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    }
}

fn handshake(
    alice: &mut VoiceChatCryptoEngine,
    bob: &mut VoiceChatCryptoEngine,
    conv: &[u8],
    first: &[u8],
    ad: &[u8],
) -> (SessionId, SessionId) {
    let bob_bundle = bob.generate_public_prekey_bundle(3).unwrap();
    let (sid_a, init) = alice
        .establish_outbound_session(&bob_bundle, conv, first, ad)
        .unwrap();
    let (sid_b, pt) = bob.process_inbound_session(&init, conv, ad).unwrap();
    assert_eq!(pt, first);
    (sid_a, sid_b)
}

fn linked_pair() -> (
    VoiceChatCryptoEngine,
    VoiceChatCryptoEngine,
    SessionId,
    SessionId,
) {
    let mut alice = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
    let mut bob = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"device-2".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .unwrap();
    let (sid_a, sid_b) = handshake(&mut alice, &mut bob, b"conv-1", b"A0", b"ad");
    (alice, bob, sid_a, sid_b)
}

#[test]
fn outbound_encrypt_decrypt_roundtrip() {
    let (mut alice, mut bob, sid_a, sid_b) = linked_pair();
    let sealed = alice.encrypt(&sid_a, b"hello", b"ad").unwrap();
    assert_eq!(bob.decrypt(&sid_b, &sealed, b"ad").unwrap(), b"hello");
    let reply = bob.encrypt(&sid_b, b"hi-alice", b"ad").unwrap();
    assert_eq!(alice.decrypt(&sid_a, &reply, b"ad").unwrap(), b"hi-alice");
}

#[test]
fn wrong_conversation_ad_fails() {
    let (mut alice, mut bob, sid_a, sid_b) = linked_pair();
    let sealed = alice.encrypt(&sid_a, b"hello", b"ad").unwrap();
    assert!(bob.decrypt(&sid_b, &sealed, b"other-ad").is_err());
}

#[test]
fn voice_profile_forbidden_in_ad() {
    let mut eng = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
    let mut remote = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"r".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .unwrap();
    let remote_bundle = remote.generate_public_prekey_bundle(1).unwrap();
    let (sid, _) = eng
        .establish_outbound_session(&remote_bundle, b"c", b"A0", b"ad")
        .unwrap();
    assert_eq!(
        eng.encrypt_voice_payload(&sid, b"opus-bytes", b"voice_profile=secret"),
        Err(CryptoError::VoiceProfileForbidden)
    );
}

#[test]
fn voice_payload_ok_without_profile_metadata() {
    let mut eng = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
    let mut remote = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"r".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .unwrap();
    let remote_bundle = remote.generate_public_prekey_bundle(1).unwrap();
    let (sid, _) = eng
        .establish_outbound_session(&remote_bundle, b"c", b"A0", b"ad")
        .unwrap();
    assert!(!eng
        .encrypt_voice_payload(&sid, b"opus-audio-payload", b"msg-meta")
        .unwrap()
        .ciphertext
        .is_empty());
}

#[test]
fn recommended_config_uses_preference_head() {
    let c = DeviceConfig::recommended(b"dev".to_vec());
    assert_eq!(c.profile, crate::policy::PROFILE_PREFERENCE[0]);
}

#[test]
fn fingerprint_symmetric_via_engine() {
    let a = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
    let b = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"other".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .unwrap();
    let fa = a
        .safety_fingerprint(&b.local_identity_public(), Some(b"other"))
        .unwrap();
    let fb = b
        .safety_fingerprint(&a.local_identity_public(), Some(b"device-1"))
        .unwrap();
    assert_eq!(fa.binary, fb.binary);
}

#[test]
fn initiation_packet_encode_decode_roundtrip() {
    let mut alice = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
    let mut bob = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"bob".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .unwrap();
    let bundle = bob.generate_public_prekey_bundle(1).unwrap();
    let (_, packet) = alice
        .establish_outbound_session(&bundle, b"c", b"A0", b"ad")
        .unwrap();
    let decoded = InitiationPacket::decode(&packet.encode()).unwrap();
    assert_eq!(
        decoded.sender_identity_public,
        packet.sender_identity_public
    );
    assert_eq!(decoded.kem_ciphertext, packet.kem_ciphertext);
    assert_eq!(decoded.used_spk_id, packet.used_spk_id);
    let (_, pt) = bob.process_inbound_session(&decoded, b"c", b"ad").unwrap();
    assert_eq!(pt, b"A0");
}

#[test]
fn delete_session_removes_and_stays_deleted() {
    let (mut alice, _bob, sid_a, _sid_b) = linked_pair();
    alice.delete_session(&sid_a).unwrap();
    assert!(!alice.has_session(&sid_a));
    alice.simulate_crash_reload().unwrap();
    assert!(!alice.has_session(&sid_a));
}

#[test]
fn replay_rejected() {
    let mut eng = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
    let mut remote = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"r".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .unwrap();
    let bundle = remote.generate_public_prekey_bundle(1).unwrap();
    let (_, init) = eng
        .establish_outbound_session(&bundle, b"c", b"x", b"ad")
        .unwrap();
    let (sid_b, pt0) = remote.process_inbound_session(&init, b"c", b"ad").unwrap();
    assert_eq!(pt0, b"x");
    assert_eq!(
        remote.decrypt(&sid_b, &init.first_message, b"ad"),
        Err(CryptoError::Replay)
    );
}

#[test]
fn initiation_replay_without_one_time_prekeys_is_rejected() {
    let mut alice = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
    let mut bob = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"bob".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .unwrap();
    let bundle = bob.generate_public_prekey_bundle(0).unwrap();
    assert!(bundle.one_time_ec.is_none());
    assert!(!bundle.is_pq_one_time);
    let (_, init) = alice
        .establish_outbound_session(&bundle, b"replay-conv", b"hello", b"ad")
        .unwrap();
    let (_, pt) = bob
        .process_inbound_session(&init, b"replay-conv", b"ad")
        .unwrap();
    assert_eq!(pt, b"hello");
    assert_eq!(
        bob.process_inbound_session(&init, b"replay-conv", b"ad")
            .unwrap_err(),
        CryptoError::Replay
    );
}

#[test]
fn handshake_opk_and_session_atomic_across_reload() {
    let mut alice = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
    let mut bob = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"bob".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .unwrap();
    let bundle = bob.generate_public_prekey_bundle(1).unwrap();
    let (sid_a, init) = alice
        .establish_outbound_session(&bundle, b"c", b"hello", b"ad")
        .unwrap();
    let (sid_b, pt) = bob.process_inbound_session(&init, b"c", b"ad").unwrap();
    assert_eq!(pt, b"hello");
    bob.simulate_crash_reload().unwrap();
    assert_eq!(
        bob.process_inbound_session(&init, b"c", b"ad").unwrap_err(),
        CryptoError::Replay
    );
    assert_eq!(
        bob.decrypt(&sid_b, &init.first_message, b"ad").unwrap_err(),
        CryptoError::Replay
    );
    let s = alice.encrypt(&sid_a, b"more", b"ad").unwrap();
    assert_eq!(bob.decrypt(&sid_b, &s, b"ad").unwrap(), b"more");
}

#[test]
fn delayed_initiation_survives_signed_and_last_resort_rotation() {
    let mut alice = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
    let mut bob = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"bob".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .unwrap();

    // No OPKs: the delayed packet depends on the signed EC + LR-PQ pair.
    let old_bundle = bob.generate_public_prekey_bundle(0).unwrap();
    let (_, delayed) = alice
        .establish_outbound_session(&old_bundle, b"delay", b"queued", b"ad")
        .unwrap();

    bob.rotate_signed_prekey(1).unwrap();
    bob.rotate_last_resort_pq(1).unwrap();

    let (_, pt) = bob
        .process_inbound_session(&delayed, b"delay", b"ad")
        .unwrap();
    assert_eq!(pt, b"queued");
}

#[test]
fn stable_peer_binding_blocks_identity_replacement() {
    let mut alice = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
    let mut bob = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"bob-device".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .unwrap();
    let bob_bundle = bob.generate_public_prekey_bundle(1).unwrap();
    let peer = b"account-42/device-1";

    let _ = alice
        .establish_outbound_session_for_peer(
            peer,
            Some(b"bob-device"),
            &bob_bundle,
            b"c1",
            b"hello",
            b"ad",
        )
        .unwrap();
    alice
        .acknowledge_peer_identity(peer, &bob.local_identity_public(), Some(b"bob-device"), 123)
        .unwrap();

    let mut impostor = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"bob-device".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .unwrap();
    let impostor_bundle = impostor.generate_public_prekey_bundle(1).unwrap();
    assert_eq!(
        alice
            .establish_outbound_session_for_peer(
                peer,
                Some(b"bob-device"),
                &impostor_bundle,
                b"c2",
                b"attack",
                b"ad",
            )
            .unwrap_err(),
        CryptoError::IdentityChanged
    );
}

#[test]
fn peer_binding_survives_crash_reload() {
    let mut alice = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
    let bob = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"bob".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .unwrap();
    let peer = b"peer-stable";
    alice
        .acknowledge_peer_identity(peer, &bob.local_identity_public(), Some(b"bob"), 9)
        .unwrap();
    alice.simulate_crash_reload().unwrap();
    assert_eq!(
        alice
            .peer_identity_state(peer, &bob.local_identity_public(), Some(b"bob"))
            .unwrap(),
        IdentityState::Verified
    );
}

#[test]
fn trust_not_implied_by_session_until_ack() {
    let mut alice = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
    let mut bob = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"bob".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .unwrap();
    let bundle = bob.generate_public_prekey_bundle(1).unwrap();
    let (_, init) = alice
        .establish_outbound_session(&bundle, b"c", b"x", b"ad")
        .unwrap();
    let _ = bob.process_inbound_session(&init, b"c", b"ad").unwrap();
    let alice_ik = alice.local_identity_public();
    assert_eq!(
        bob.remote_identity_state(&alice_ik, None).unwrap(),
        IdentityState::Unknown
    );
    bob.acknowledge_identity_change(&alice_ik, None).unwrap();
    bob.simulate_crash_reload().unwrap();
    assert_eq!(
        bob.remote_identity_state(&alice_ik, None).unwrap(),
        IdentityState::Verified
    );
}

#[test]
fn delete_all_sessions_preserves_device_state() {
    let (mut alice, _bob, sid_a, _sid_b) = linked_pair();
    let identity_before = alice.local_identity_public();
    alice.delete_all_sessions().unwrap();
    assert!(!alice.has_session(&sid_a));
    alice.simulate_crash_reload().unwrap();
    assert!(!alice.has_session(&sid_a));
    assert_eq!(alice.local_identity_public(), identity_before);
}

#[test]
fn crash_reload_rejects_reused_one_time_prekey() {
    let mut alice = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
    let mut bob = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"device-2".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .unwrap();
    let bundle = bob.generate_public_prekey_bundle(1).unwrap();
    let (_, init) = alice
        .establish_outbound_session(&bundle, b"c1", b"A0", b"ad")
        .unwrap();
    let (_, pt) = bob.process_inbound_session(&init, b"c1", b"ad").unwrap();
    assert_eq!(pt, b"A0");
    bob.simulate_crash_reload().unwrap();
    let mut alice2 = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
    let (_, init2) = alice2
        .establish_outbound_session(&bundle, b"c2", b"A1", b"ad")
        .unwrap();
    assert!(bob.process_inbound_session(&init2, b"c2", b"ad").is_err());
}

#[test]
fn crash_reload_classical_continues() {
    let (mut alice, mut bob, sid_a, sid_b) = linked_pair();
    let s = alice.encrypt(&sid_a, b"pre", b"ad").unwrap();
    assert_eq!(bob.decrypt(&sid_b, &s, b"ad").unwrap(), b"pre");
    alice.simulate_crash_reload().unwrap();
    bob.simulate_crash_reload().unwrap();
    let s2 = alice.encrypt(&sid_a, b"post", b"ad").unwrap();
    assert_eq!(bob.decrypt(&sid_b, &s2, b"ad").unwrap(), b"post");
    let s3 = bob.encrypt(&sid_b, b"reply", b"ad").unwrap();
    assert_eq!(alice.decrypt(&sid_a, &s3, b"ad").unwrap(), b"reply");
}

/// Storage that deliberately fails the second commit. The first commit is
/// device initialization; the next mutating crypto operation must poison the
/// engine after the monotonic counter advanced.
struct FailSecondCommitStorage {
    inner: MemoryStorage,
    commits: usize,
}

impl FailSecondCommitStorage {
    fn new() -> Self {
        Self {
            inner: MemoryStorage::default(),
            commits: 0,
        }
    }
}

impl TransactionalStorage for FailSecondCommitStorage {
    fn begin(&mut self) -> Result<TransactionId, PrimitiveError> {
        self.inner.begin()
    }

    fn put(
        &mut self,
        tx: TransactionId,
        key: &[u8],
        value: &StateBlob,
    ) -> Result<(), PrimitiveError> {
        self.inner.put(tx, key, value)
    }

    fn delete(&mut self, tx: TransactionId, key: &[u8]) -> Result<(), PrimitiveError> {
        self.inner.delete(tx, key)
    }

    fn commit(&mut self, tx: TransactionId) -> Result<(), PrimitiveError> {
        self.commits += 1;
        if self.commits == 2 {
            let _ = self.inner.abort(tx);
            return Err(PrimitiveError::Internal);
        }
        self.inner.commit(tx)
    }

    fn abort(&mut self, tx: TransactionId) -> Result<(), PrimitiveError> {
        self.inner.abort(tx)
    }

    fn get(&self, key: &[u8]) -> Result<Option<StateBlob>, PrimitiveError> {
        self.inner.get(key)
    }

    fn keys(&self) -> Result<Vec<Vec<u8>>, PrimitiveError> {
        TransactionalStorage::keys(&self.inner)
    }

    fn epoch(&self) -> Result<StorageEpoch, PrimitiveError> {
        self.inner.epoch()
    }

    fn advance_epoch(&mut self) -> Result<StorageEpoch, PrimitiveError> {
        self.inner.advance_epoch()
    }
}

#[test]
fn uncertain_storage_commit_poisons_engine() {
    let mut engine = VoiceChatCryptoEngine::initialize_device_with_backends(
        cfg(),
        Box::new(FailSecondCommitStorage::new()),
        Box::new(MemoryCounter::default()),
    )
    .unwrap();
    assert_eq!(
        engine.generate_public_prekey_bundle(1).unwrap_err(),
        CryptoError::Storage
    );
    assert_eq!(
        engine.generate_public_prekey_bundle(1).unwrap_err(),
        CryptoError::Storage
    );
}

#[cfg(any(feature = "hybrid", feature = "header-encrypt"))]
fn linked_with(
    profile: CryptoProfile,
) -> (
    VoiceChatCryptoEngine,
    VoiceChatCryptoEngine,
    SessionId,
    SessionId,
) {
    let mut alice = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"device-1".to_vec(),
        profile,
    })
    .unwrap();
    let mut bob = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"device-2".to_vec(),
        profile,
    })
    .unwrap();
    let (sid_a, sid_b) = handshake(&mut alice, &mut bob, b"conv-1", b"A0", b"ad");
    (alice, bob, sid_a, sid_b)
}

#[cfg(feature = "hybrid")]
#[test]
fn hybrid_engine_roundtrip_and_no_classical_mix() {
    let (mut alice, mut bob, sid_a, sid_b) = linked_with(CryptoProfile::HybridPqV1);
    let sealed = alice.encrypt(&sid_a, b"hybrid", b"ad").unwrap();
    assert!(sealed.header.len() > 40);
    assert_eq!(bob.decrypt(&sid_b, &sealed, b"ad").unwrap(), b"hybrid");
    let reply = bob.encrypt(&sid_b, b"ok", b"ad").unwrap();
    assert_eq!(alice.decrypt(&sid_a, &reply, b"ad").unwrap(), b"ok");

    let (mut c_alice, mut c_bob, c_sid_a, c_sid_b) = linked_with(CryptoProfile::ClassicalV1);
    let classical = c_alice.encrypt(&c_sid_a, b"class", b"ad").unwrap();
    assert!(bob.decrypt(&sid_b, &classical, b"ad").is_err());
    assert!(c_bob.decrypt(&c_sid_b, &sealed, b"ad").is_err());
}

#[cfg(feature = "header-encrypt")]
#[test]
fn header_encrypt_engine_roundtrip_and_reload() {
    let (mut alice, mut bob, sid_a, sid_b) = linked_with(CryptoProfile::ClassicalHeV1);
    let sealed = alice.encrypt(&sid_a, b"hidden-hdr", b"ad").unwrap();
    assert_eq!(bob.decrypt(&sid_b, &sealed, b"ad").unwrap(), b"hidden-hdr");
    alice.simulate_crash_reload().unwrap();
    bob.simulate_crash_reload().unwrap();
    let reply = bob.encrypt(&sid_b, b"back", b"ad").unwrap();
    assert_eq!(alice.decrypt(&sid_a, &reply, b"ad").unwrap(), b"back");
}

#[cfg(feature = "hybrid")]
#[test]
fn crash_reload_hybrid_continues() {
    let (mut alice, mut bob, sid_a, sid_b) = linked_with(CryptoProfile::HybridPqV1);
    let s = alice.encrypt(&sid_a, b"hy-pre", b"ad").unwrap();
    assert_eq!(bob.decrypt(&sid_b, &s, b"ad").unwrap(), b"hy-pre");
    alice.simulate_crash_reload().unwrap();
    bob.simulate_crash_reload().unwrap();
    let s2 = bob.encrypt(&sid_b, b"hy-post", b"ad").unwrap();
    assert_eq!(alice.decrypt(&sid_a, &s2, b"ad").unwrap(), b"hy-post");
}
