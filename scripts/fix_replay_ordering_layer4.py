#!/usr/bin/env python3
from pathlib import Path

ENGINE = Path("src/engine/mod.rs")
TESTS = Path("src/engine/tests.rs")

engine = ENGINE.read_text()

old = '''        self.ensure_storage_healthy()?;
        self.ensure_session_capacity()?;
        validate_context_lengths(conversation_context, associated_data)?;
        validate_ciphertext_len(message.first_message.ciphertext.len())?;
        if message.protocol_version != PROTOCOL_VERSION
            || message.profile != self.profile
            || message.first_message.protocol_version != PROTOCOL_VERSION
            || message.first_message.profile != self.profile
            || message.first_message.session_tag.is_zero()
        {
            return Err(CryptoError::CryptoFailure);
        }
        if message.kem_ciphertext.len() > MAX_KEM_CIPHERTEXT_LEN
            || message.first_message.header.len() > MAX_HEADER_LEN
        {
            return Err(CryptoError::LimitExceeded);
        }
        if self.session_tag_in_use(message.first_message.session_tag)? {
            return Err(CryptoError::CryptoFailure);
        }
        let should_record_peer = match &peer {
            Some((peer_id, material)) => self.check_peer(peer_id, material)?,
            None => false,
        };
        let initiation_replay = Self::initiation_replay_key(message, conversation_context);
        {
            let replay = self.mutex(&self.replay)?;
            if replay.cache.contains(&initiation_replay)
                || replay.pending.contains(&initiation_replay)
            {
                return Err(CryptoError::Replay);
            }
        }
'''

new = '''        self.ensure_storage_healthy()?;
        validate_context_lengths(conversation_context, associated_data)?;
        validate_ciphertext_len(message.first_message.ciphertext.len())?;
        if message.protocol_version != PROTOCOL_VERSION
            || message.profile != self.profile
            || message.first_message.protocol_version != PROTOCOL_VERSION
            || message.first_message.profile != self.profile
            || message.first_message.session_tag.is_zero()
        {
            return Err(CryptoError::CryptoFailure);
        }
        if message.kem_ciphertext.len() > MAX_KEM_CIPHERTEXT_LEN
            || message.first_message.header.len() > MAX_HEADER_LEN
        {
            return Err(CryptoError::LimitExceeded);
        }
        let should_record_peer = match &peer {
            Some((peer_id, material)) => self.check_peer(peer_id, material)?,
            None => false,
        };

        // Exact whole-initiation replays must be classified before admission
        // checks that naturally become true after the first successful handshake
        // (session-tag occupancy and session capacity). Otherwise a durable replay
        // can be misreported as CryptoFailure/LimitExceeded after reload or OPK use.
        let initiation_replay = Self::initiation_replay_key(message, conversation_context);
        {
            let replay = self.mutex(&self.replay)?;
            if replay.cache.contains(&initiation_replay)
                || replay.pending.contains(&initiation_replay)
            {
                return Err(CryptoError::Replay);
            }
        }
        self.ensure_session_capacity()?;
        if self.session_tag_in_use(message.first_message.session_tag)? {
            return Err(CryptoError::CryptoFailure);
        }
'''

if new in engine:
    print("already fixed: inbound initiation replay precedence")
elif old in engine:
    ENGINE.write_text(engine.replace(old, new, 1))
    print("fixed: inbound initiation replay precedence")
else:
    raise SystemExit("expected process_inbound_impl ordering block not found")

tests = TESTS.read_text()
marker = '''#[test]
fn handshake_opk_and_session_atomic_across_reload() {
'''
regression = '''#[test]
fn modified_initiation_reusing_live_session_tag_is_not_replay() {
    let alice = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
    let bob = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"bob".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .unwrap();
    let bundle = bob.generate_public_prekey_bundle(1).unwrap();
    let (_, init) = alice
        .establish_outbound_session(&bundle, b"collision-conv", b"hello", b"ad")
        .unwrap();
    let (_, plaintext) = bob
        .process_inbound_session(&init, b"collision-conv", b"ad")
        .unwrap();
    assert_eq!(plaintext, b"hello");

    let mut modified = init.clone();
    let last = modified
        .first_message
        .ciphertext
        .last_mut()
        .expect("AEAD ciphertext is non-empty");
    *last ^= 1;

    // Only the exact persisted initiation is a Replay. A distinct packet that
    // collides with an already-live session tag remains a cryptographic failure.
    assert_eq!(
        bob.process_inbound_session(&modified, b"collision-conv", b"ad")
            .unwrap_err(),
        CryptoError::CryptoFailure
    );
}

'''

if regression in tests:
    print("already fixed: modified-session-tag replay regression")
elif marker in tests:
    TESTS.write_text(tests.replace(marker, regression + marker, 1))
    print("added: modified-session-tag replay regression")
else:
    raise SystemExit("test insertion marker not found")

print("Layer-4 replay ordering fix applied.")
