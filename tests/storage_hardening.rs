use std::sync::{Arc, Mutex};

use voicechat_crypto::primitives::error::PrimitiveError;
use voicechat_crypto::storage::monotonic::{MemoryCounter, MonotonicCounter};
use voicechat_crypto::storage::{
    MemoryStorage, StateBlob, StorageEpoch, TransactionId, TransactionalStorage,
};
use voicechat_crypto::{
    CryptoEngineApi, CryptoError, CryptoProfile, DeviceConfig, VoiceChatCryptoEngine,
};

#[derive(Clone, Default)]
struct SharedStorage {
    inner: Arc<Mutex<MemoryStorage>>,
}

impl SharedStorage {
    fn put_committed_raw(&self, key: &[u8], value: &[u8]) {
        let mut storage = self.inner.lock().unwrap();
        let tx = TransactionalStorage::begin(&mut *storage).unwrap();
        TransactionalStorage::put(&mut *storage, tx, key, &StateBlob(value.to_vec())).unwrap();
        TransactionalStorage::commit(&mut *storage, tx).unwrap();
    }

    fn delete_committed_raw(&self, key: &[u8]) {
        let mut storage = self.inner.lock().unwrap();
        let tx = TransactionalStorage::begin(&mut *storage).unwrap();
        TransactionalStorage::delete(&mut *storage, tx, key).unwrap();
        TransactionalStorage::commit(&mut *storage, tx).unwrap();
    }

    fn get_raw(&self, key: &[u8]) -> Vec<u8> {
        let storage = self.inner.lock().unwrap();
        let mut blob = TransactionalStorage::get(&*storage, key).unwrap().unwrap();
        std::mem::take(&mut blob.0)
    }
}

impl TransactionalStorage for SharedStorage {
    fn begin(&mut self) -> Result<TransactionId, PrimitiveError> {
        TransactionalStorage::begin(&mut *self.inner.lock().unwrap())
    }

    fn put(
        &mut self,
        tx: TransactionId,
        key: &[u8],
        value: &StateBlob,
    ) -> Result<(), PrimitiveError> {
        TransactionalStorage::put(&mut *self.inner.lock().unwrap(), tx, key, value)
    }

    fn delete(&mut self, tx: TransactionId, key: &[u8]) -> Result<(), PrimitiveError> {
        TransactionalStorage::delete(&mut *self.inner.lock().unwrap(), tx, key)
    }

    fn commit(&mut self, tx: TransactionId) -> Result<(), PrimitiveError> {
        TransactionalStorage::commit(&mut *self.inner.lock().unwrap(), tx)
    }

    fn abort(&mut self, tx: TransactionId) -> Result<(), PrimitiveError> {
        TransactionalStorage::abort(&mut *self.inner.lock().unwrap(), tx)
    }

    fn get(&self, key: &[u8]) -> Result<Option<StateBlob>, PrimitiveError> {
        TransactionalStorage::get(&*self.inner.lock().unwrap(), key)
    }

    fn keys(&self) -> Result<Vec<Vec<u8>>, PrimitiveError> {
        TransactionalStorage::keys(&*self.inner.lock().unwrap())
    }

    fn epoch(&self) -> Result<StorageEpoch, PrimitiveError> {
        TransactionalStorage::epoch(&*self.inner.lock().unwrap())
    }

    fn advance_epoch(&mut self) -> Result<StorageEpoch, PrimitiveError> {
        TransactionalStorage::advance_epoch(&mut *self.inner.lock().unwrap())
    }
}

#[derive(Clone, Default)]
struct SharedCounter {
    inner: Arc<Mutex<MemoryCounter>>,
}

impl MonotonicCounter for SharedCounter {
    fn current(&self) -> Result<u64, PrimitiveError> {
        MonotonicCounter::current(&*self.inner.lock().unwrap())
    }

    fn increment(&mut self) -> Result<u64, PrimitiveError> {
        MonotonicCounter::increment(&mut *self.inner.lock().unwrap())
    }
}

fn config(device: &[u8]) -> DeviceConfig {
    DeviceConfig {
        device_id: device.to_vec(),
        profile: CryptoProfile::ClassicalV1,
    }
}

#[test]
fn restore_rejects_different_device_configuration() {
    let storage = SharedStorage::default();
    let counter = SharedCounter::default();
    let engine = VoiceChatCryptoEngine::initialize_device_with_backends(
        config(b"device-a"),
        Box::new(storage.clone()),
        Box::new(counter.clone()),
    )
    .unwrap();
    let original_identity = engine.local_identity_public();
    drop(engine);

    let wrong = VoiceChatCryptoEngine::restore_device_with_backends(
        config(b"device-b"),
        Box::new(storage.clone()),
        Box::new(counter.clone()),
    );
    assert!(matches!(wrong, Err(CryptoError::Storage)));

    let restored = VoiceChatCryptoEngine::restore_device_with_backends(
        config(b"device-a"),
        Box::new(storage),
        Box::new(counter),
    )
    .unwrap();
    assert_eq!(restored.local_identity_public(), original_identity);
}

#[test]
fn malformed_reload_is_atomic_and_poisons_engine() {
    let storage = SharedStorage::default();
    let counter = SharedCounter::default();
    let alice = VoiceChatCryptoEngine::initialize_device_with_backends(
        config(b"atomic-alice"),
        Box::new(storage.clone()),
        Box::new(counter),
    )
    .unwrap();
    let bob = VoiceChatCryptoEngine::initialize_device(config(b"atomic-bob")).unwrap();
    let bundle = bob.generate_public_prekey_bundle(1).unwrap();
    let (sid, _) = alice
        .establish_outbound_session(&bundle, b"atomic", b"first", b"ad")
        .unwrap();
    let identity_before = alice.local_identity_public();
    assert!(alice.has_session(&sid));

    // Simulate post-commit storage corruption without changing the separately
    // stored anti-rollback epoch. The loader must parse into temporary state and
    // must not partially replace live identity/session state before failure.
    storage.put_committed_raw(b"trust", b"corrupt-trust-state");
    assert_eq!(
        alice.simulate_crash_reload().unwrap_err(),
        CryptoError::Storage
    );
    assert_eq!(alice.local_identity_public(), identity_before);
    assert!(alice.has_session(&sid));
    assert_eq!(
        alice.generate_public_prekey_bundle(1).unwrap_err(),
        CryptoError::Storage
    );
}

#[test]
fn duplicate_persisted_session_tags_are_rejected_on_reload() {
    let storage = SharedStorage::default();
    let counter = SharedCounter::default();
    let alice = VoiceChatCryptoEngine::initialize_device_with_backends(
        config(b"tag-alice"),
        Box::new(storage.clone()),
        Box::new(counter),
    )
    .unwrap();
    let bob = VoiceChatCryptoEngine::initialize_device(config(b"tag-bob")).unwrap();

    let bundle1 = bob.generate_public_prekey_bundle(3).unwrap();
    let (sid1, init1) = alice
        .establish_outbound_session(&bundle1, b"tag-1", b"one", b"ad")
        .unwrap();
    let (bob_sid1, _) = bob
        .process_inbound_session(&init1, b"tag-1", b"ad")
        .unwrap();
    let ack1 = bob.encrypt(&bob_sid1, b"ack-1", b"ad").unwrap();
    alice.decrypt(&sid1, &ack1, b"ad").unwrap();

    let bundle2 = bob.generate_public_prekey_bundle(3).unwrap();
    let (sid2, init2) = alice
        .establish_outbound_session(&bundle2, b"tag-2", b"two", b"ad")
        .unwrap();
    let (bob_sid2, _) = bob
        .process_inbound_session(&init2, b"tag-2", b"ad")
        .unwrap();
    let ack2 = bob.encrypt(&bob_sid2, b"ack-2", b"ad").unwrap();
    alice.decrypt(&sid2, &ack2, b"ad").unwrap();

    let first_blob = storage.get_raw(&sid1.0);
    let mut second_blob = storage.get_raw(&sid2.0);
    assert_eq!(&first_blob[..8], b"VCSESS02");
    assert_eq!(&second_blob[..8], b"VCSESS02");

    // VCSESS02: magic(8) + version(2) + local sid(16) + profile(1), then tag(16).
    let tag_start = 8 + 2 + 16 + 1;
    let tag_end = tag_start + 16;
    second_blob[tag_start..tag_end].copy_from_slice(&first_blob[tag_start..tag_end]);
    storage.put_committed_raw(&sid2.0, &second_blob);

    assert_eq!(
        alice.simulate_crash_reload().unwrap_err(),
        CryptoError::Storage
    );
    assert!(alice.has_session(&sid1));
    assert!(alice.has_session(&sid2));
    assert_eq!(
        alice.generate_public_prekey_bundle(1).unwrap_err(),
        CryptoError::Storage
    );
}

fn poison_reload_preserves_live_sessions(key: &[u8], corrupt: &[u8], device: &[u8]) {
    let storage = SharedStorage::default();
    let counter = SharedCounter::default();
    let alice = VoiceChatCryptoEngine::initialize_device_with_backends(
        config(device),
        Box::new(storage.clone()),
        Box::new(counter),
    )
    .unwrap();
    let bob = VoiceChatCryptoEngine::initialize_device(config(b"reload-bob")).unwrap();
    let bundle = bob.generate_public_prekey_bundle(1).unwrap();
    let (sid, _) = alice
        .establish_outbound_session(&bundle, b"reload", b"first", b"ad")
        .unwrap();
    let identity_before = alice.local_identity_public();
    assert!(alice.has_session(&sid));

    storage.put_committed_raw(key, corrupt);
    assert_eq!(
        alice.simulate_crash_reload().unwrap_err(),
        CryptoError::Storage
    );
    assert_eq!(alice.local_identity_public(), identity_before);
    assert!(alice.has_session(&sid));
    assert_eq!(
        alice.generate_public_prekey_bundle(1).unwrap_err(),
        CryptoError::Storage
    );
}

#[test]
fn corrupt_prekeys_reload_leaves_live_sessions_unchanged() {
    poison_reload_preserves_live_sessions(b"prekeys", b"corrupt-prekeys-state", b"prekey-alice");
}

#[test]
fn corrupt_replay_reload_leaves_live_sessions_unchanged() {
    poison_reload_preserves_live_sessions(b"replay", b"corrupt-replay-state", b"replay-alice");
}

#[test]
fn malformed_persisted_session_does_not_remove_valid_sessions() {
    let storage = SharedStorage::default();
    let counter = SharedCounter::default();
    let alice = VoiceChatCryptoEngine::initialize_device_with_backends(
        config(b"sess-alice"),
        Box::new(storage.clone()),
        Box::new(counter),
    )
    .unwrap();
    let bob = VoiceChatCryptoEngine::initialize_device(config(b"sess-bob")).unwrap();

    let bundle1 = bob.generate_public_prekey_bundle(3).unwrap();
    let (sid1, init1) = alice
        .establish_outbound_session(&bundle1, b"s1", b"one", b"ad")
        .unwrap();
    let (bob_sid1, _) = bob.process_inbound_session(&init1, b"s1", b"ad").unwrap();
    alice
        .decrypt(
            &sid1,
            &bob.encrypt(&bob_sid1, b"ack-1", b"ad").unwrap(),
            b"ad",
        )
        .unwrap();

    let bundle2 = bob.generate_public_prekey_bundle(3).unwrap();
    let (sid2, init2) = alice
        .establish_outbound_session(&bundle2, b"s2", b"two", b"ad")
        .unwrap();
    let (bob_sid2, _) = bob.process_inbound_session(&init2, b"s2", b"ad").unwrap();
    alice
        .decrypt(
            &sid2,
            &bob.encrypt(&bob_sid2, b"ack-2", b"ad").unwrap(),
            b"ad",
        )
        .unwrap();

    let mut blob = storage.get_raw(&sid2.0);
    assert_eq!(&blob[..8], b"VCSESS02");
    let last = blob.len() - 1;
    blob[last] ^= 0xff;
    storage.put_committed_raw(&sid2.0, &blob);

    assert_eq!(
        alice.simulate_crash_reload().unwrap_err(),
        CryptoError::Storage
    );
    assert!(alice.has_session(&sid1));
    assert!(alice.has_session(&sid2));
    assert_eq!(
        alice.generate_public_prekey_bundle(1).unwrap_err(),
        CryptoError::Storage
    );
}

#[test]
fn corrupt_session_magic_fails_without_dropping_live_sessions() {
    let storage = SharedStorage::default();
    let counter = SharedCounter::default();
    let alice = VoiceChatCryptoEngine::initialize_device_with_backends(
        config(b"magic-alice"),
        Box::new(storage.clone()),
        Box::new(counter),
    )
    .unwrap();
    let bob = VoiceChatCryptoEngine::initialize_device(config(b"magic-bob")).unwrap();
    let bundle = bob.generate_public_prekey_bundle(1).unwrap();
    let (sid, _) = alice
        .establish_outbound_session(&bundle, b"magic", b"first", b"ad")
        .unwrap();
    assert!(alice.has_session(&sid));

    let mut blob = storage.get_raw(&sid.0);
    blob[..8].copy_from_slice(b"XXXXXXXX");
    storage.put_committed_raw(&sid.0, &blob);

    assert_eq!(
        alice.simulate_crash_reload().unwrap_err(),
        CryptoError::Storage
    );
    assert!(alice.has_session(&sid));
}

#[test]
fn successful_reload_replaces_live_sessions_from_storage() {
    let storage = SharedStorage::default();
    let counter = SharedCounter::default();
    let alice = VoiceChatCryptoEngine::initialize_device_with_backends(
        config(b"ok-alice"),
        Box::new(storage.clone()),
        Box::new(counter),
    )
    .unwrap();
    let bob = VoiceChatCryptoEngine::initialize_device(config(b"ok-bob")).unwrap();
    let bundle = bob.generate_public_prekey_bundle(1).unwrap();
    let (sid, init) = alice
        .establish_outbound_session(&bundle, b"ok", b"first", b"ad")
        .unwrap();
    let (bob_sid, _) = bob.process_inbound_session(&init, b"ok", b"ad").unwrap();
    alice
        .decrypt(&sid, &bob.encrypt(&bob_sid, b"ack", b"ad").unwrap(), b"ad")
        .unwrap();
    assert!(alice.has_session(&sid));

    storage.delete_committed_raw(&sid.0);
    alice.simulate_crash_reload().unwrap();
    assert!(!alice.has_session(&sid));
    alice.generate_public_prekey_bundle(1).unwrap();
}
