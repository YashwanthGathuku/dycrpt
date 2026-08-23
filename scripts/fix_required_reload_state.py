#!/usr/bin/env python3
from pathlib import Path

ENGINE = Path('src/engine/mod.rs')
TESTS = Path('tests/storage_hardening.rs')

old = '''    let replay = match storage
        .get(VoiceChatCryptoEngine::KEY_REPLAY)
        .map_err(|_| CryptoError::Storage)?
    {
        Some(blob) => ReplayCache::deserialize(&blob.0).map_err(|_| CryptoError::Storage)?,
        None => ReplayCache::new(DEFAULT_REPLAY_CACHE_SIZE),
    };
    let trust = match storage
        .get(VoiceChatCryptoEngine::KEY_TRUST)
        .map_err(|_| CryptoError::Storage)?
    {
        Some(blob) => TrustStore::deserialize(&blob.0).map_err(|_| CryptoError::Storage)?,
        None => TrustStore::new(),
    };
    let peer_identities = match storage
        .get(VoiceChatCryptoEngine::KEY_PEER_IDENTITIES)
        .map_err(|_| CryptoError::Storage)?
    {
        Some(blob) => PeerIdentityStore::deserialize(&blob.0).map_err(|_| CryptoError::Storage)?,
        None => PeerIdentityStore::new(),
    };
'''

new = '''    // These security-critical stores are created and durably written at device
    // initialization. Their absence on a v2 restore is corruption/tampering, not
    // an empty-state migration: silently recreating them would erase replay
    // history or identity bindings. Any future legacy migration must be explicit
    // and versioned rather than weakening this fail-closed restore path.
    let replay_blob = storage
        .get(VoiceChatCryptoEngine::KEY_REPLAY)
        .map_err(|_| CryptoError::Storage)?
        .ok_or(CryptoError::Storage)?;
    let replay = ReplayCache::deserialize(&replay_blob.0).map_err(|_| CryptoError::Storage)?;
    let trust_blob = storage
        .get(VoiceChatCryptoEngine::KEY_TRUST)
        .map_err(|_| CryptoError::Storage)?
        .ok_or(CryptoError::Storage)?;
    let trust = TrustStore::deserialize(&trust_blob.0).map_err(|_| CryptoError::Storage)?;
    let peers_blob = storage
        .get(VoiceChatCryptoEngine::KEY_PEER_IDENTITIES)
        .map_err(|_| CryptoError::Storage)?
        .ok_or(CryptoError::Storage)?;
    let peer_identities =
        PeerIdentityStore::deserialize(&peers_blob.0).map_err(|_| CryptoError::Storage)?;
'''

engine = ENGINE.read_text()
if new in engine:
    print('already fixed: required persisted replay/trust/peer state')
elif old in engine:
    ENGINE.write_text(engine.replace(old, new, 1))
    print('fixed: required persisted replay/trust/peer state')
else:
    raise SystemExit('expected reload-state block missing in src/engine/mod.rs')

marker = '''#[test]
fn corrupt_prekeys_reload_leaves_live_sessions_unchanged() {
'''
addition = r'''fn missing_required_reload_state_is_fail_closed(key: &[u8], device: &[u8]) {
    let storage = SharedStorage::default();
    let counter = SharedCounter::default();
    let alice = VoiceChatCryptoEngine::initialize_device_with_backends(
        config(device),
        Box::new(storage.clone()),
        Box::new(counter),
    )
    .unwrap();
    let bob = VoiceChatCryptoEngine::initialize_device(config(b"missing-state-bob")).unwrap();
    let bundle = bob.generate_public_prekey_bundle(1).unwrap();
    let (sid, _) = alice
        .establish_outbound_session(&bundle, b"missing-state", b"first", b"ad")
        .unwrap();
    let identity_before = alice.local_identity_public();
    assert!(alice.has_session(&sid));

    storage.delete_committed_raw(key);
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
fn missing_replay_state_fails_closed_without_dropping_live_sessions() {
    missing_required_reload_state_is_fail_closed(b"replay", b"missing-replay-alice");
}

#[test]
fn missing_trust_state_fails_closed_without_dropping_live_sessions() {
    missing_required_reload_state_is_fail_closed(b"trust", b"missing-trust-alice");
}

#[test]
fn missing_peer_identity_state_fails_closed_without_dropping_live_sessions() {
    missing_required_reload_state_is_fail_closed(
        b"peer-identities-v1",
        b"missing-peer-state-alice",
    );
}

'''

tests = TESTS.read_text()
if 'missing_replay_state_fails_closed_without_dropping_live_sessions' in tests:
    print('already added: required-state deletion regressions')
elif marker in tests:
    TESTS.write_text(tests.replace(marker, addition + marker, 1))
    print('added: required-state deletion regressions')
else:
    raise SystemExit('test insertion marker missing in tests/storage_hardening.rs')
