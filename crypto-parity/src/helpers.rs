//! Shared VoiceChatCrypto helpers for scenarios.

use voicechat_crypto::engine::{
    CryptoEngineApi, CryptoError, DeviceConfig, SessionId, VoiceChatCryptoEngine,
};
use voicechat_crypto::policy::CryptoProfile;
use voicechat_crypto::pqxdh::{
    alice_initiate, bob_process, AliceInitiation, BobPrivateMaterial, PqxdhSharedSecret,
};
use voicechat_crypto::prekeys::{IdentityKeyPair, PrekeyStore};
use voicechat_crypto::primitives::x25519::X25519Secret;
use voicechat_crypto::ratchet::{DoubleRatchetState, DEFAULT_MAX_SKIP};

pub fn pqxdh_pair(
    ec_opk: bool,
    pq_opk: bool,
) -> Result<
    (
        AliceInitiation,
        PqxdhSharedSecret,
        PrekeyStore,
        IdentityKeyPair,
    ),
    String,
> {
    let alice_ik = IdentityKeyPair::generate().map_err(|e| format!("{e}"))?;
    let bob_ik = IdentityKeyPair::generate().map_err(|e| format!("{e}"))?;
    let mut store = PrekeyStore::new(&bob_ik).map_err(|e| format!("{e}"))?;
    let nec = if ec_opk { 1 } else { 0 };
    let npq = if pq_opk { 1 } else { 0 };
    store
        .replenish(&bob_ik, nec, npq)
        .map_err(|e| format!("{e}"))?;
    let bundle = store.public_bundle(&bob_ik).map_err(|e| format!("{e}"))?;
    let alice = alice_initiate(&alice_ik, &bundle).map_err(|e| format!("{e}"))?;

    let opk;
    let opk_ref = if let Some(id) = alice.used_ec_opk_id {
        opk = store.consume_ec(id).map_err(|e| format!("{e}"))?;
        Some(&opk)
    } else {
        None
    };

    let bob = if bundle.is_pq_one_time {
        let consumed = store
            .consume_pq(alice.used_pq_prekey_id)
            .map_err(|e| format!("{e}"))?;
        let pq_secret = consumed.secret.clone();
        let pq_public = pq_secret.public_key().map_err(|e| format!("{e}"))?;
        let mat = BobPrivateMaterial {
            identity: &bob_ik,
            signed_prekey: &store.signed,
            one_time_ec: opk_ref,
            pq_secret: &pq_secret,
            pq_public: &pq_public,
            pq_prekey_id: alice.used_pq_prekey_id,
        };
        bob_process(
            &mat,
            &alice_ik.public(),
            &alice.ephemeral_public,
            &alice.kem_ciphertext,
            alice.used_ec_opk_id,
        )
        .map_err(|e| format!("{e}"))?
    } else {
        let pq_public = store.last_resort_pq.public().map_err(|e| format!("{e}"))?;
        let mat = BobPrivateMaterial {
            identity: &bob_ik,
            signed_prekey: &store.signed,
            one_time_ec: opk_ref,
            pq_secret: &store.last_resort_pq.secret,
            pq_public: &pq_public,
            pq_prekey_id: alice.used_pq_prekey_id,
        };
        bob_process(
            &mat,
            &alice_ik.public(),
            &alice.ephemeral_public,
            &alice.kem_ciphertext,
            alice.used_ec_opk_id,
        )
        .map_err(|e| format!("{e}"))?
    };
    Ok((alice, bob, store, bob_ik))
}

pub fn dr_pair() -> Result<(DoubleRatchetState, DoubleRatchetState), String> {
    let sk = [7u8; 32];
    let bob_dh = X25519Secret::generate().map_err(|e| format!("{e}"))?;
    let alice = DoubleRatchetState::init_alice(&sk, &bob_dh.public_key(), DEFAULT_MAX_SKIP)
        .map_err(|e| format!("{e}"))?;
    let bob = DoubleRatchetState::init_bob(&sk, bob_dh, DEFAULT_MAX_SKIP);
    Ok((alice, bob))
}

pub fn engine() -> Result<VoiceChatCryptoEngine, String> {
    VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: b"dev".to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .map_err(|e| format!("{e:?}"))
}

pub fn engine_named(id: &[u8]) -> Result<VoiceChatCryptoEngine, String> {
    VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: id.to_vec(),
        profile: CryptoProfile::ClassicalV1,
    })
    .map_err(|e| format!("{e:?}"))
}

pub fn engine_handshake(
    alice: &mut VoiceChatCryptoEngine,
    bob: &mut VoiceChatCryptoEngine,
) -> Result<(SessionId, SessionId), String> {
    let bundle = bob
        .generate_public_prekey_bundle(2)
        .map_err(|e| format!("{e:?}"))?;
    let (sid_a, init) = alice
        .establish_outbound_session(&bundle, b"conv", b"hello", b"ad")
        .map_err(|e| format!("{e:?}"))?;
    let (sid_b, pt) = bob
        .process_inbound_session(&init, b"conv", b"ad")
        .map_err(|e| format!("{e:?}"))?;
    if pt != b"hello" {
        return Err("first plaintext mismatch".into());
    }
    let _ = init;
    Ok((sid_a, sid_b))
}

pub fn map_engine_err(e: &CryptoError) -> &'static str {
    match e {
        CryptoError::Replay => "REJECT_REPLAY",
        CryptoError::IdentityChanged => "REJECT_IDENTITY",
        CryptoError::LimitExceeded => "REJECT_LIMIT",
        CryptoError::InvalidArgument => "REJECT_MALFORMED",
        CryptoError::VoiceProfileForbidden => "REJECT_VOICE",
        CryptoError::CryptoFailure | CryptoError::NoSession => "REJECT_AUTH",
        CryptoError::Storage | CryptoError::Internal => "REJECT_INTERNAL",
    }
}
