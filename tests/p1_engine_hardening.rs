use voicechat_crypto::{
    CryptoEngineApi, CryptoError, CryptoProfile, DeviceConfig, InitiationPacket, SealedMessage,
    VoiceChatCryptoEngine, PROTOCOL_VERSION,
};

fn engine(device: &[u8]) -> VoiceChatCryptoEngine {
    VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: device.to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .unwrap()
}

fn pair() -> (
    VoiceChatCryptoEngine,
    VoiceChatCryptoEngine,
    voicechat_crypto::SessionId,
    voicechat_crypto::SessionId,
    InitiationPacket,
) {
    let mut alice = engine(b"alice-v2");
    let mut bob = engine(b"bob-v2");
    let bundle = bob.generate_public_prekey_bundle(2).unwrap();
    let (sid_a, init) = alice
        .establish_outbound_session(&bundle, b"conv-v2", b"first", b"ad")
        .unwrap();
    let (sid_b, first) = bob
        .process_inbound_session(&init, b"conv-v2", b"ad")
        .unwrap();
    assert_eq!(first, b"first");
    (alice, bob, sid_a, sid_b, init)
}

#[test]
fn v2_wire_roundtrip_binds_version_profile_and_tag() {
    let (mut alice, mut bob, sid_a, sid_b, init) = pair();
    assert_eq!(init.protocol_version, PROTOCOL_VERSION);
    assert_eq!(init.first_message.protocol_version, PROTOCOL_VERSION);
    assert_eq!(init.profile, CryptoProfile::ClassicalV1);
    assert_eq!(init.first_message.profile, CryptoProfile::ClassicalV1);

    let reply = bob.encrypt(&sid_b, b"reply", b"ad").unwrap();
    assert_eq!(reply.session_tag, init.first_message.session_tag);
    assert_eq!(alice.decrypt(&sid_a, &reply, b"ad").unwrap(), b"reply");
}

#[test]
fn session_tag_relabel_fails_before_ratchet_and_original_still_decrypts() {
    let (mut alice, mut bob, sid_a, sid_b, _init) = pair();
    let sealed = alice.encrypt(&sid_a, b"tag-bound", b"ad").unwrap();
    let mut relabeled = sealed.clone();
    relabeled.session_tag.0[0] ^= 0x80;

    assert_eq!(
        bob.decrypt(&sid_b, &relabeled, b"ad").unwrap_err(),
        CryptoError::CryptoFailure
    );
    assert_eq!(bob.decrypt(&sid_b, &sealed, b"ad").unwrap(), b"tag-bound");
}

#[test]
fn protocol_relabel_fails_before_ratchet_and_original_still_decrypts() {
    let (mut alice, mut bob, sid_a, sid_b, _init) = pair();
    let sealed = alice.encrypt(&sid_a, b"version-bound", b"ad").unwrap();
    let mut relabeled = sealed.clone();
    relabeled.protocol_version = PROTOCOL_VERSION - 1;

    assert_eq!(
        bob.decrypt(&sid_b, &relabeled, b"ad").unwrap_err(),
        CryptoError::CryptoFailure
    );
    assert_eq!(
        bob.decrypt(&sid_b, &sealed, b"ad").unwrap(),
        b"version-bound"
    );
}

#[test]
fn pending_initiation_survives_crash_byte_for_byte() {
    let mut alice = engine(b"alice-pending");
    let mut bob = engine(b"bob-pending");
    let bundle = bob.generate_public_prekey_bundle(1).unwrap();
    let (sid_a, packet) = alice
        .establish_outbound_session(&bundle, b"pending", b"first", b"ad")
        .unwrap();

    let pending = alice
        .pending_outbound_initiation(&sid_a)
        .unwrap()
        .unwrap();
    assert_eq!(pending.encode(), packet.encode());

    alice.simulate_crash_reload().unwrap();
    let restored = alice
        .pending_outbound_initiation(&sid_a)
        .unwrap()
        .unwrap();
    assert_eq!(restored.encode(), packet.encode());

    let (sid_b, _) = bob
        .process_inbound_session(&restored, b"pending", b"ad")
        .unwrap();
    let reply = bob.encrypt(&sid_b, b"ack", b"ad").unwrap();
    assert_eq!(alice.decrypt(&sid_a, &reply, b"ad").unwrap(), b"ack");
    assert!(alice.pending_outbound_initiation(&sid_a).unwrap().is_none());
}

#[test]
fn explicit_pending_ack_is_durable() {
    let mut alice = engine(b"alice-ack");
    let mut bob = engine(b"bob-ack");
    let bundle = bob.generate_public_prekey_bundle(1).unwrap();
    let (sid, _) = alice
        .establish_outbound_session(&bundle, b"ack", b"first", b"ad")
        .unwrap();
    assert!(alice.pending_outbound_initiation(&sid).unwrap().is_some());
    alice.acknowledge_outbound_initiation(&sid).unwrap();
    alice.simulate_crash_reload().unwrap();
    assert!(alice.pending_outbound_initiation(&sid).unwrap().is_none());
}

#[test]
fn v1_wire_magics_are_not_accepted_as_v2() {
    assert!(SealedMessage::decode(b"VCSEAL01legacy").is_err());
    assert!(InitiationPacket::decode(b"VCINIT01legacy").is_err());
}
