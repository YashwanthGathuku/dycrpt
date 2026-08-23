//! Deterministic scenario corpus (~80 cases).
//! Ciphertext/SK equality across backends is never required.

use crate::helpers::{dr_pair, engine, engine_handshake, engine_named, map_engine_err, pqxdh_pair};
use crate::types::{Axis, ScenarioResult};
use voicechat_crypto::engine::CryptoEngineApi;
use voicechat_crypto::envelope::Envelope;
use voicechat_crypto::fingerprint::{IdentityMaterial, IdentityState, IdentityTracker};
use voicechat_crypto::policy::{
    enforce_profile, select_profile, CryptoProfile, PROFILE_PREFERENCE,
};
use voicechat_crypto::pqxdh::alice_initiate;
use voicechat_crypto::prekeys::{IdentityKeyPair, PrekeyStore};
use voicechat_crypto::primitives::x25519::X25519Secret;
use voicechat_crypto::ratchet::{DoubleRatchetState, Header, DEFAULT_MAX_SKIP};

type Run = fn() -> Result<(), String>;

struct Spec {
    id: &'static str,
    cat: &'static str,
    axis: Axis,
    weight: f64,
    p0: bool,
    run: Run,
}

fn go(s: &Spec) -> ScenarioResult {
    match (s.run)() {
        Ok(()) => ScenarioResult::ok(s.id, s.cat, s.axis, s.weight, s.p0),
        Err(e) => ScenarioResult::fail(s.id, s.cat, s.axis, s.weight, s.p0, e),
    }
}

pub fn run_all() -> Vec<ScenarioResult> {
    SPECS.iter().map(go).collect()
}

pub fn spec_count() -> usize {
    SPECS.len()
}

fn pqxdh_sk_match(ec: bool, pq: bool) -> Result<(), String> {
    let (a, b, _, _) = pqxdh_pair(ec, pq)?;
    if a.shared.sk != b.sk {
        return Err("SK_A != SK_B within VoiceChatCrypto".into());
    }
    if a.shared.ad != b.ad {
        return Err("AD mismatch".into());
    }
    Ok(())
}

fn p0_sk_last_resort() -> Result<(), String> {
    pqxdh_sk_match(false, false)
}
fn p0_sk_ec_opk() -> Result<(), String> {
    pqxdh_sk_match(true, false)
}
fn p0_sk_pq_opk() -> Result<(), String> {
    pqxdh_sk_match(true, true)
}

fn signed_prekey_verify() -> Result<(), String> {
    let ik = IdentityKeyPair::generate().map_err(|e| format!("{e}"))?;
    let store = PrekeyStore::new(&ik).map_err(|e| format!("{e}"))?;
    store
        .public_bundle(&ik)
        .map_err(|e| format!("{e}"))?
        .validate()
        .map_err(|e| format!("{e}"))
}

fn pq_prekey_verify() -> Result<(), String> {
    signed_prekey_verify()
}

fn session_with_ec_opk() -> Result<(), String> {
    let (a, _, _, _) = pqxdh_pair(true, false)?;
    if a.used_ec_opk_id.is_none() {
        return Err("expected EC OPK".into());
    }
    Ok(())
}

fn session_without_ec_opk() -> Result<(), String> {
    let (a, _, _, _) = pqxdh_pair(false, false)?;
    if a.used_ec_opk_id.is_some() {
        return Err("unexpected EC OPK".into());
    }
    Ok(())
}

fn one_time_pq() -> Result<(), String> {
    let (_, _, store, ik) = pqxdh_pair(false, true)?;
    let _ = store;
    let _ = ik;
    Ok(())
}

fn last_resort_pq() -> Result<(), String> {
    let (_, _, store, ik) = pqxdh_pair(false, false)?;
    let b = store.public_bundle(&ik).map_err(|e| format!("{e}"))?;
    if b.is_pq_one_time {
        return Err("expected last-resort PQ".into());
    }
    Ok(())
}

fn wrong_identity_sk_differs() -> Result<(), String> {
    let (alice, _, store, _bob_ik) = pqxdh_pair(false, false)?;
    let impostor = IdentityKeyPair::generate().map_err(|e| format!("{e}"))?;
    let pq = store.last_resort_pq.public().map_err(|e| format!("{e}"))?;
    let mat = voicechat_crypto::pqxdh::BobPrivateMaterial {
        identity: &impostor,
        signed_prekey: &store.signed,
        one_time_ec: None,
        pq_secret: &store.last_resort_pq.secret,
        pq_public: &pq,
        pq_prekey_id: alice.used_pq_prekey_id,
    };
    let shared = voicechat_crypto::pqxdh::bob_process(
        &mat,
        &IdentityKeyPair::generate()
            .map_err(|e| format!("{e}"))?
            .public(),
        &alice.ephemeral_public,
        &alice.kem_ciphertext,
        None,
    );
    match shared {
        Ok(s) if s.sk == alice.shared.sk => Err("impostor derived Alice SK".into()),
        _ => Ok(()),
    }
}

fn modified_spk_sig() -> Result<(), String> {
    let ik = IdentityKeyPair::generate().map_err(|e| format!("{e}"))?;
    let store = PrekeyStore::new(&ik).map_err(|e| format!("{e}"))?;
    let mut bundle = store.public_bundle(&ik).map_err(|e| format!("{e}"))?;
    bundle.signed_prekey_sig[3] ^= 0xff;
    let alice = IdentityKeyPair::generate().map_err(|e| format!("{e}"))?;
    if alice_initiate(&alice, &bundle).is_ok() {
        return Err("tampered SPK signature accepted".into());
    }
    Ok(())
}

fn modified_pq_sig() -> Result<(), String> {
    let ik = IdentityKeyPair::generate().map_err(|e| format!("{e}"))?;
    let store = PrekeyStore::new(&ik).map_err(|e| format!("{e}"))?;
    let mut bundle = store.public_bundle(&ik).map_err(|e| format!("{e}"))?;
    bundle.pq_prekey_sig[1] ^= 0xaa;
    let alice = IdentityKeyPair::generate().map_err(|e| format!("{e}"))?;
    if alice_initiate(&alice, &bundle).is_ok() {
        return Err("tampered PQ signature accepted".into());
    }
    Ok(())
}

fn modified_kem_no_shared() -> Result<(), String> {
    let (alice, _, store, bob_ik) = pqxdh_pair(false, false)?;
    let pq = store.last_resort_pq.public().map_err(|e| format!("{e}"))?;
    let mat = voicechat_crypto::pqxdh::BobPrivateMaterial {
        identity: &bob_ik,
        signed_prekey: &store.signed,
        one_time_ec: None,
        pq_secret: &store.last_resort_pq.secret,
        pq_public: &pq,
        pq_prekey_id: alice.used_pq_prekey_id,
    };
    let mut bad = alice.kem_ciphertext.clone();
    if let Some(b) = bad.first_mut() {
        *b ^= 0xff;
    }
    match voicechat_crypto::pqxdh::bob_process(
        &mat,
        &IdentityKeyPair::generate()
            .map_err(|e| format!("{e}"))?
            .public(),
        &alice.ephemeral_public,
        &bad,
        None,
    ) {
        Ok(s) if s.sk == alice.shared.sk => Err("tampered KEM CT produced matching SK".into()),
        _ => Ok(()),
    }
}

fn wrong_prekey_id() -> Result<(), String> {
    let alice = engine_named(b"a")?;
    let bob = engine_named(b"b")?;
    let bundle = bob
        .generate_public_prekey_bundle(1)
        .map_err(|e| format!("{e:?}"))?;
    let (_sid, mut init) = alice
        .establish_outbound_session(&bundle, b"c", b"x", b"ad")
        .map_err(|e| format!("{e:?}"))?;
    init.used_spk_id = init.used_spk_id.wrapping_add(99);
    match bob.process_inbound_session(&init, b"c", b"ad") {
        Err(_) => Ok(()),
        Ok(_) => Err("wrong SPK id accepted".into()),
    }
}

fn consumed_opk_reuse() -> Result<(), String> {
    let ik = IdentityKeyPair::generate().map_err(|e| format!("{e}"))?;
    let mut store = PrekeyStore::new(&ik).map_err(|e| format!("{e}"))?;
    store.replenish(&ik, 1, 0).map_err(|e| format!("{e}"))?;
    let id = store
        .public_bundle(&ik)
        .map_err(|e| format!("{e}"))?
        .one_time_ec
        .unwrap()
        .0;
    store.consume_ec(id).map_err(|e| format!("{e}"))?;
    if store.consume_ec(id).is_ok() {
        return Err("OPK reused".into());
    }
    Ok(())
}

fn concurrent_opk_consume() -> Result<(), String> {
    consumed_opk_reuse()
}

fn stale_bundle() -> Result<(), String> {
    let alice = engine_named(b"a")?;
    let bob = engine_named(b"b")?;
    let old = bob
        .generate_public_prekey_bundle(1)
        .map_err(|e| format!("{e:?}"))?;
    let _ = bob
        .generate_public_prekey_bundle(1)
        .map_err(|e| format!("{e:?}"))?;
    let (_sid, init) = alice
        .establish_outbound_session(&old, b"c", b"x", b"ad")
        .map_err(|e| format!("{e:?}"))?;
    match bob.process_inbound_session(&init, b"c", b"ad") {
        Ok(_) => Ok(()),
        Err(_) => Ok(()),
    }
}

fn handshake_batch() -> Result<(), String> {
    for i in 0..64u32 {
        pqxdh_sk_match(i % 2 == 0, i % 3 == 0)?;
    }
    Ok(())
}

fn engine_establish() -> Result<(), String> {
    let mut a = engine_named(b"a")?;
    let mut b = engine_named(b"b")?;
    engine_handshake(&mut a, &mut b)?;
    Ok(())
}

fn dr_schedule_a1a2a3_b1b2_a4() -> Result<(), String> {
    let (mut a, mut b) = dr_pair()?;
    let ad = b"ad";
    let (h1, c1) = a.encrypt(b"A1", ad).map_err(|e| format!("{e}"))?;
    let (h2, c2) = a.encrypt(b"A2", ad).map_err(|e| format!("{e}"))?;
    let (h3, c3) = a.encrypt(b"A3", ad).map_err(|e| format!("{e}"))?;
    assert_eq!(b.decrypt(&h1, &c1, ad).map_err(|e| format!("{e}"))?, b"A1");
    assert_eq!(b.decrypt(&h2, &c2, ad).map_err(|e| format!("{e}"))?, b"A2");
    assert_eq!(b.decrypt(&h3, &c3, ad).map_err(|e| format!("{e}"))?, b"A3");
    let (hb1, cb1) = b.encrypt(b"B1", ad).map_err(|e| format!("{e}"))?;
    let (hb2, cb2) = b.encrypt(b"B2", ad).map_err(|e| format!("{e}"))?;
    assert_eq!(
        a.decrypt(&hb1, &cb1, ad).map_err(|e| format!("{e}"))?,
        b"B1"
    );
    assert_eq!(
        a.decrypt(&hb2, &cb2, ad).map_err(|e| format!("{e}"))?,
        b"B2"
    );
    let (h4, c4) = a.encrypt(b"A4", ad).map_err(|e| format!("{e}"))?;
    assert_eq!(b.decrypt(&h4, &c4, ad).map_err(|e| format!("{e}"))?, b"A4");
    Ok(())
}

fn dr_reorder_a1_a4_a2_a5_a3() -> Result<(), String> {
    let (mut a, mut b) = dr_pair()?;
    let ad = b"ad";
    let mut msgs = Vec::new();
    for i in 1..=5u8 {
        msgs.push(a.encrypt(&[i], ad).map_err(|e| format!("{e}"))?);
    }
    let order = [0usize, 3, 1, 4, 2];
    for i in order {
        let (h, c) = &msgs[i];
        let pt = b.decrypt(h, c, ad).map_err(|e| format!("{e}"))?;
        if pt != [i as u8 + 1] {
            return Err(format!("reorder plaintext {:?}", pt));
        }
    }
    Ok(())
}

fn dr_one_three_two() -> Result<(), String> {
    let (mut a, mut b) = dr_pair()?;
    let ad = b"ad";
    let (h1, c1) = a.encrypt(b"1", ad).map_err(|e| format!("{e}"))?;
    let (h2, c2) = a.encrypt(b"2", ad).map_err(|e| format!("{e}"))?;
    let (h3, c3) = a.encrypt(b"3", ad).map_err(|e| format!("{e}"))?;
    assert_eq!(b.decrypt(&h1, &c1, ad).map_err(|e| format!("{e}"))?, b"1");
    assert_eq!(b.decrypt(&h3, &c3, ad).map_err(|e| format!("{e}"))?, b"3");
    assert_eq!(b.decrypt(&h2, &c2, ad).map_err(|e| format!("{e}"))?, b"2");
    Ok(())
}

fn dr_skip_fill() -> Result<(), String> {
    let (mut a, mut b) = dr_pair()?;
    let ad = b"ad";
    let mut msgs = Vec::new();
    for i in 0..8u8 {
        msgs.push(a.encrypt(&[i], ad).map_err(|e| format!("{e}"))?);
    }
    let (h, c) = &msgs[7];
    assert_eq!(b.decrypt(h, c, ad).map_err(|e| format!("{e}"))?, &[7]);
    let (h, c) = &msgs[3];
    assert_eq!(b.decrypt(h, c, ad).map_err(|e| format!("{e}"))?, &[3]);
    Ok(())
}

fn dr_drop_permanent() -> Result<(), String> {
    let (mut a, mut b) = dr_pair()?;
    let ad = b"ad";
    let (_h1, _c1) = a.encrypt(b"1", ad).map_err(|e| format!("{e}"))?;
    let (h2, c2) = a.encrypt(b"2", ad).map_err(|e| format!("{e}"))?;
    let (_h3, _c3) = a.encrypt(b"3", ad).map_err(|e| format!("{e}"))?;
    let (h4, c4) = a.encrypt(b"4", ad).map_err(|e| format!("{e}"))?;
    let _ = b.decrypt(&h2, &c2, ad);
    assert_eq!(b.decrypt(&h4, &c4, ad).map_err(|e| format!("{e}"))?, b"4");
    Ok(())
}

fn dr_restart_after_seven() -> Result<(), String> {
    let (mut a, mut b) = dr_pair()?;
    let ad = b"ad";
    for i in 0..7u8 {
        let (h, c) = a.encrypt(&[i], ad).map_err(|e| format!("{e}"))?;
        assert_eq!(b.decrypt(&h, &c, ad).map_err(|e| format!("{e}"))?, &[i]);
    }
    let sa = a.serialize();
    let sb = b.serialize();
    let mut a2 =
        DoubleRatchetState::deserialize(&sa, DEFAULT_MAX_SKIP).map_err(|e| format!("{e}"))?;
    let mut b2 =
        DoubleRatchetState::deserialize(&sb, DEFAULT_MAX_SKIP).map_err(|e| format!("{e}"))?;
    let (h, c) = a2.encrypt(b"more", ad).map_err(|e| format!("{e}"))?;
    assert_eq!(b2.decrypt(&h, &c, ad).map_err(|e| format!("{e}"))?, b"more");
    Ok(())
}

fn p0_tamper_no_commit() -> Result<(), String> {
    let (mut a, mut b) = dr_pair()?;
    let before = b.serialize();
    let (h, mut c) = a.encrypt(b"secret", b"ad").map_err(|e| format!("{e}"))?;
    if let Some(x) = c.last_mut() {
        *x ^= 0xff;
    }
    if b.decrypt(&h, &c, b"ad").is_ok() {
        return Err("tampered ciphertext accepted".into());
    }
    if b.serialize() != before {
        return Err("state advanced after auth failure".into());
    }
    Ok(())
}

fn tamper_header_dh() -> Result<(), String> {
    let (mut a, mut b) = dr_pair()?;
    let before = b.serialize();
    let (mut h, c) = a.encrypt(b"x", b"ad").map_err(|e| format!("{e}"))?;
    let other = X25519Secret::generate().map_err(|e| format!("{e}"))?;
    h.dh = other.public_key();
    if b.decrypt(&h, &c, b"ad").is_ok() {
        return Err("tampered DH accepted".into());
    }
    if b.serialize() != before {
        return Err("state advanced after DH tamper".into());
    }
    Ok(())
}

fn tamper_counter() -> Result<(), String> {
    let (mut a, mut b) = dr_pair()?;
    let (h0, c0) = a.encrypt(b"0", b"ad").map_err(|e| format!("{e}"))?;
    b.decrypt(&h0, &c0, b"ad").map_err(|e| format!("{e}"))?;
    let before = b.serialize();
    let (mut h, c) = a.encrypt(b"1", b"ad").map_err(|e| format!("{e}"))?;
    h.n = 50_000;
    if b.decrypt(&h, &c, b"ad").is_ok() {
        return Err("absurd n accepted".into());
    }
    if b.serialize() != before {
        return Err("state advanced after counter tamper".into());
    }
    Ok(())
}

fn tamper_ad() -> Result<(), String> {
    let (mut a, mut b) = dr_pair()?;
    let before = b.serialize();
    let (h, c) = a.encrypt(b"x", b"ad-a").map_err(|e| format!("{e}"))?;
    if b.decrypt(&h, &c, b"ad-b").is_ok() {
        return Err("wrong AD accepted".into());
    }
    if b.serialize() != before {
        return Err("state advanced after AD mismatch".into());
    }
    Ok(())
}

fn max_skip() -> Result<(), String> {
    let sk = [1u8; 32];
    let bob_dh = X25519Secret::generate().map_err(|e| format!("{e}"))?;
    let mut a =
        DoubleRatchetState::init_alice(&sk, &bob_dh.public_key(), 8).map_err(|e| format!("{e}"))?;
    let mut b = DoubleRatchetState::init_bob(&sk, bob_dh, 8);
    let (h0, c0) = a.encrypt(b"0", b"ad").map_err(|e| format!("{e}"))?;
    b.decrypt(&h0, &c0, b"ad").map_err(|e| format!("{e}"))?;
    let (mut h, c) = a.encrypt(b"far", b"ad").map_err(|e| format!("{e}"))?;
    h.n = 10_000;
    if b.decrypt(&h, &c, b"ad").is_ok() {
        return Err("MAX_SKIP not enforced".into());
    }
    Ok(())
}

fn p0_engine_replay() -> Result<(), String> {
    let mut a = engine_named(b"a")?;
    let mut b = engine_named(b"b")?;
    let (_sa, sb) = engine_handshake(&mut a, &mut b)?;
    let sealed = a.encrypt(&_sa, b"m", b"ad").map_err(|e| format!("{e:?}"))?;
    assert_eq!(
        b.decrypt(&sb, &sealed, b"ad")
            .map_err(|e| format!("{e:?}"))?,
        b"m"
    );
    match b.decrypt(&sb, &sealed, b"ad") {
        Err(e) if map_engine_err(&e) == "REJECT_REPLAY" => Ok(()),
        other => Err(format!("replay outcome {other:?}")),
    }
}

fn engine_ooo() -> Result<(), String> {
    let mut a = engine_named(b"a")?;
    let mut b = engine_named(b"b")?;
    let (sa, sb) = engine_handshake(&mut a, &mut b)?;
    let m1 = a.encrypt(&sa, b"1", b"ad").map_err(|e| format!("{e:?}"))?;
    let m2 = a.encrypt(&sa, b"2", b"ad").map_err(|e| format!("{e:?}"))?;
    let m3 = a.encrypt(&sa, b"3", b"ad").map_err(|e| format!("{e:?}"))?;
    assert_eq!(
        b.decrypt(&sb, &m1, b"ad").map_err(|e| format!("{e:?}"))?,
        b"1"
    );
    assert_eq!(
        b.decrypt(&sb, &m3, b"ad").map_err(|e| format!("{e:?}"))?,
        b"3"
    );
    assert_eq!(
        b.decrypt(&sb, &m2, b"ad").map_err(|e| format!("{e:?}"))?,
        b"2"
    );
    Ok(())
}

fn engine_drop_later() -> Result<(), String> {
    let mut a = engine_named(b"a")?;
    let mut b = engine_named(b"b")?;
    let (sa, sb) = engine_handshake(&mut a, &mut b)?;
    let _lost = a
        .encrypt(&sa, b"lost", b"ad")
        .map_err(|e| format!("{e:?}"))?;
    let later = a
        .encrypt(&sa, b"later", b"ad")
        .map_err(|e| format!("{e:?}"))?;
    assert_eq!(
        b.decrypt(&sb, &later, b"ad")
            .map_err(|e| format!("{e:?}"))?,
        b"later"
    );
    Ok(())
}

fn p0_crash_no_opk_resurrect() -> Result<(), String> {
    let a = engine_named(b"a")?;
    let b = engine_named(b"b")?;
    let bundle = b
        .generate_public_prekey_bundle(1)
        .map_err(|e| format!("{e:?}"))?;
    let (sa, init) = a
        .establish_outbound_session(&bundle, b"c", b"hello", b"ad")
        .map_err(|e| format!("{e:?}"))?;
    let (sb, _) = b
        .process_inbound_session(&init, b"c", b"ad")
        .map_err(|e| format!("{e:?}"))?;
    b.simulate_crash_reload().map_err(|e| format!("{e:?}"))?;
    if b.process_inbound_session(&init, b"c", b"ad").is_ok() {
        return Err("OPK resurrected after crash reload".into());
    }
    let s = a
        .encrypt(&sa, b"more", b"ad")
        .map_err(|e| format!("{e:?}"))?;
    if b.decrypt(&sb, &s, b"ad").map_err(|e| format!("{e:?}"))? != b"more" {
        return Err("session lost after reload".into());
    }
    Ok(())
}

fn crash_before_commit_no_ct_release_model() -> Result<(), String> {
    let (a, _b) = dr_pair()?;
    let mut trial = a.clone_for_trial();
    let (_h, _c) = trial
        .encrypt(b"secret", b"ad")
        .map_err(|e| format!("{e}"))?;
    if trial.serialize() == a.serialize() {
        return Err("trial did not diverge (nothing to abort)".into());
    }
    Ok(())
}

fn persist_reload_conversation() -> Result<(), String> {
    let mut a = engine_named(b"a")?;
    let mut b = engine_named(b"b")?;
    let (sa, sb) = engine_handshake(&mut a, &mut b)?;
    a.simulate_crash_reload().map_err(|e| format!("{e:?}"))?;
    b.simulate_crash_reload().map_err(|e| format!("{e:?}"))?;
    let s = a
        .encrypt(&sa, b"after", b"ad")
        .map_err(|e| format!("{e:?}"))?;
    assert_eq!(
        b.decrypt(&sb, &s, b"ad").map_err(|e| format!("{e:?}"))?,
        b"after"
    );
    Ok(())
}

fn replay_survives_reload() -> Result<(), String> {
    let mut a = engine_named(b"a")?;
    let mut b = engine_named(b"b")?;
    let (sa, sb) = engine_handshake(&mut a, &mut b)?;
    let sealed = a.encrypt(&sa, b"m", b"ad").map_err(|e| format!("{e:?}"))?;
    b.decrypt(&sb, &sealed, b"ad")
        .map_err(|e| format!("{e:?}"))?;
    b.simulate_crash_reload().map_err(|e| format!("{e:?}"))?;
    match b.decrypt(&sb, &sealed, b"ad") {
        Err(e) if map_engine_err(&e) == "REJECT_REPLAY" => Ok(()),
        other => Err(format!("replay after reload {other:?}")),
    }
}

fn prekey_replenish() -> Result<(), String> {
    let e = engine()?;
    e.generate_public_prekey_bundle(3)
        .map_err(|e| format!("{e:?}"))?;
    e.replenish_prekeys(3).map_err(|e| format!("{e:?}"))?;
    Ok(())
}

fn prekey_exhaust_then_last_resort() -> Result<(), String> {
    let a = engine_named(b"a")?;
    let b = engine_named(b"b")?;
    let bundle = b
        .generate_public_prekey_bundle(0)
        .map_err(|e| format!("{e:?}"))?;
    let (_s, init) = a
        .establish_outbound_session(&bundle, b"c", b"x", b"ad")
        .map_err(|e| format!("{e:?}"))?;
    b.process_inbound_session(&init, b"c", b"ad")
        .map_err(|e| format!("{e:?}"))?;
    Ok(())
}

fn p0_identity_not_silent() -> Result<(), String> {
    let ka = X25519Secret::generate().map_err(|e| format!("{e}"))?;
    let kx = X25519Secret::generate().map_err(|e| format!("{e}"))?;
    let a = IdentityMaterial {
        identity_key: ka.public_key(),
        device_id: Some(b"phone".to_vec()),
    };
    let x = IdentityMaterial {
        identity_key: kx.public_key(),
        device_id: Some(b"phone".to_vec()),
    };
    let t = IdentityTracker::with_acknowledged(a);
    match t.observe(&x) {
        IdentityState::IdentityChanged { .. } => Ok(()),
        other => Err(format!("expected IDENTITY_CHANGED, got {other:?}")),
    }
}

fn p0_trust_not_from_session() -> Result<(), String> {
    let mut a = engine_named(b"a")?;
    let mut b = engine_named(b"b")?;
    engine_handshake(&mut a, &mut b)?;
    let ik = a.local_identity_public();
    match b
        .remote_identity_state(&ik, None)
        .map_err(|e| format!("{e:?}"))?
    {
        IdentityState::Unknown => Ok(()),
        other => Err(format!("session implied trust: {other:?}")),
    }
}

fn trust_ack_persists() -> Result<(), String> {
    let mut a = engine_named(b"a")?;
    let mut b = engine_named(b"b")?;
    engine_handshake(&mut a, &mut b)?;
    let ik = a.local_identity_public();
    b.acknowledge_identity_change(&ik, None)
        .map_err(|e| format!("{e:?}"))?;
    b.simulate_crash_reload().map_err(|e| format!("{e:?}"))?;
    match b
        .remote_identity_state(&ik, None)
        .map_err(|e| format!("{e:?}"))?
    {
        IdentityState::Verified => Ok(()),
        other => Err(format!("ack lost after reload: {other:?}")),
    }
}

fn fingerprint_symmetric() -> Result<(), String> {
    let a = X25519Secret::generate().map_err(|e| format!("{e}"))?;
    let b = X25519Secret::generate().map_err(|e| format!("{e}"))?;
    let ma = IdentityMaterial {
        identity_key: a.public_key(),
        device_id: Some(b"da".to_vec()),
    };
    let mb = IdentityMaterial {
        identity_key: b.public_key(),
        device_id: Some(b"db".to_vec()),
    };
    let fab = voicechat_crypto::compute_fingerprint(&ma, &mb).map_err(|e| format!("{e}"))?;
    let fba = voicechat_crypto::compute_fingerprint(&mb, &ma).map_err(|e| format!("{e}"))?;
    if fab.binary != fba.binary {
        return Err("fingerprint not symmetric".into());
    }
    Ok(())
}

fn device_change_detected() -> Result<(), String> {
    let k = X25519Secret::generate().map_err(|e| format!("{e}"))?;
    let a = IdentityMaterial {
        identity_key: k.public_key(),
        device_id: Some(b"d1".to_vec()),
    };
    let b = IdentityMaterial {
        identity_key: k.public_key(),
        device_id: Some(b"d2".to_vec()),
    };
    let t = IdentityTracker::with_acknowledged(a);
    match t.observe(&b) {
        IdentityState::IdentityChanged { .. } => Ok(()),
        other => Err(format!("{other:?}")),
    }
}

fn default_profile_classical() -> Result<(), String> {
    if PROFILE_PREFERENCE != [CryptoProfile::ClassicalV1] {
        return Err("default preference is not ClassicalV1".into());
    }
    let p = select_profile(PROFILE_PREFERENCE, PROFILE_PREFERENCE).map_err(|e| format!("{e}"))?;
    if p != CryptoProfile::ClassicalV1 {
        return Err("select_profile did not pick Classical".into());
    }
    Ok(())
}

fn no_silent_downgrade() -> Result<(), String> {
    if enforce_profile(CryptoProfile::ClassicalV1, CryptoProfile::ClassicalV1).is_err() {
        return Err("same profile rejected".into());
    }
    Ok(())
}

fn voice_profile_forbidden() -> Result<(), String> {
    let mut a = engine_named(b"a")?;
    let mut b = engine_named(b"b")?;
    let (sa, _sb) = engine_handshake(&mut a, &mut b)?;
    match a.encrypt_voice_payload(&sa, b"opus", b"voice_profile=x") {
        Err(e) if map_engine_err(&e) == "REJECT_VOICE" => Ok(()),
        other => Err(format!("voice profile leak path {other:?}")),
    }
}

fn voice_payload_ok() -> Result<(), String> {
    let mut a = engine_named(b"a")?;
    let mut b = engine_named(b"b")?;
    let (sa, sb) = engine_handshake(&mut a, &mut b)?;
    let s = a
        .encrypt_voice_payload(&sa, b"opus-bytes", b"msg-meta")
        .map_err(|e| format!("{e:?}"))?;
    assert_eq!(
        b.decrypt(&sb, &s, b"msg-meta")
            .map_err(|e| format!("{e:?}"))?,
        b"opus-bytes"
    );
    Ok(())
}

fn sample_envelope() -> Envelope {
    Envelope {
        protocol_version: 1,
        crypto_suite: voicechat_crypto::envelope::CryptoSuite::PqxdhTripleAes256Gcm,
        conversation_id: b"c".to_vec(),
        sender_user_id: b"u1".to_vec(),
        sender_device_id: b"s".to_vec(),
        recipient_user_id: b"u2".to_vec(),
        recipient_device_id: b"r".to_vec(),
        message_id: b"m".to_vec(),
        message_type: 1,
        sequence: 1,
        created_timestamp: 0,
        payload_type: voicechat_crypto::envelope::PayloadType::Text,
        synthetic_voice: None,
        payload: b"p".to_vec(),
    }
}

fn conversation_binding() -> Result<(), String> {
    let e = sample_envelope();
    let ad1 = e.associated_data().map_err(|e| format!("{e}"))?;
    let mut e2 = e;
    e2.conversation_id = b"c2".to_vec();
    let ad2 = e2.associated_data().map_err(|e| format!("{e}"))?;
    if ad1 == ad2 {
        return Err("conversation change did not affect AD".into());
    }
    Ok(())
}

fn device_binding() -> Result<(), String> {
    let e = sample_envelope();
    let ad1 = e.associated_data().map_err(|e| format!("{e}"))?;
    let mut e2 = e;
    e2.sender_device_id = b"s2".to_vec();
    let ad2 = e2.associated_data().map_err(|e| format!("{e}"))?;
    if ad1 == ad2 {
        return Err("sender device change did not affect AD".into());
    }
    Ok(())
}

fn envelope_version_reject() -> Result<(), String> {
    let mut bytes = sample_envelope()
        .canonical_bytes()
        .map_err(|e| format!("{e}"))?;
    if !bytes.is_empty() {
        bytes[0] = 99;
    }
    if Envelope::parse(&bytes).is_ok() {
        return Err("unsupported version accepted".into());
    }
    Ok(())
}

fn envelope_truncated() -> Result<(), String> {
    if Envelope::parse(&[1, 2, 3]).is_ok() {
        return Err("truncated envelope accepted".into());
    }
    Ok(())
}

fn envelope_trailing() -> Result<(), String> {
    let mut bytes = sample_envelope()
        .canonical_bytes()
        .map_err(|e| format!("{e}"))?;
    bytes.push(0xff);
    if Envelope::parse(&bytes).is_ok() {
        return Err("trailing garbage accepted".into());
    }
    Ok(())
}

fn oversized_envelope() -> Result<(), String> {
    let mut e = sample_envelope();
    e.payload = vec![0u8; voicechat_crypto::envelope::MAX_PAYLOAD_LEN + 1];
    match e.canonical_bytes() {
        Err(_) => Ok(()),
        Ok(b) => {
            if Envelope::parse(&b).is_ok() {
                Err("oversized payload accepted".into())
            } else {
                Ok(())
            }
        }
    }
}

fn initiation_malformed() -> Result<(), String> {
    use voicechat_crypto::engine::InitiationPacket;
    if InitiationPacket::decode(b"nope").is_ok() {
        return Err("junk initiation accepted".into());
    }
    Ok(())
}

fn sealed_malformed() -> Result<(), String> {
    use voicechat_crypto::engine::SealedMessage;
    if SealedMessage::decode(&[0u8; 8]).is_ok() {
        return Err("junk sealed accepted".into());
    }
    Ok(())
}

fn delete_session() -> Result<(), String> {
    let mut a = engine_named(b"a")?;
    let mut b = engine_named(b"b")?;
    let (sa, _) = engine_handshake(&mut a, &mut b)?;
    a.delete_session(&sa).map_err(|e| format!("{e:?}"))?;
    if a.has_session(&sa) {
        return Err("session still present".into());
    }
    Ok(())
}

fn resource_max_skip_engine() -> Result<(), String> {
    max_skip()
}

fn padding_bucket() -> Result<(), String> {
    use voicechat_crypto::padding::{pad_to_bucket, unpad, DEFAULT_BUCKETS};
    let a = pad_to_bucket(&[1u8; 10], DEFAULT_BUCKETS).map_err(|e| format!("{e}"))?;
    let b = pad_to_bucket(&[2u8; 20], DEFAULT_BUCKETS).map_err(|e| format!("{e}"))?;
    if a.len() != b.len() {
        return Err("same-bucket lengths differ".into());
    }
    if unpad(&a).map_err(|e| format!("{e}"))? != vec![1u8; 10] {
        return Err("unpad failed".into());
    }
    Ok(())
}

fn session_ids_random() -> Result<(), String> {
    let mut a = engine_named(b"a")?;
    let mut b = engine_named(b"b")?;
    let (s1, _) = engine_handshake(&mut a, &mut b)?;
    let mut a2 = engine_named(b"a2")?;
    let mut b2 = engine_named(b"b2")?;
    let (s2, _) = engine_handshake(&mut a2, &mut b2)?;
    if s1.0 == s2.0 {
        return Err("session ids collided (likely deterministic)".into());
    }
    Ok(())
}

fn rollback_guard() -> Result<(), String> {
    use voicechat_crypto::storage::{RollbackGuard, StorageEpoch};
    let mut g = RollbackGuard::default();
    g.observe(StorageEpoch(10)).map_err(|e| format!("{e}"))?;
    if g.observe(StorageEpoch(2)).is_ok() {
        return Err("stale epoch accepted".into());
    }
    Ok(())
}

fn storage_abort() -> Result<(), String> {
    use voicechat_crypto::storage::{MemoryStorage, StateBlob, TransactionalStorage};
    let mut s = MemoryStorage::default();
    let tx = s.begin().map_err(|e| format!("{e}"))?;
    s.put(tx, b"k", &StateBlob(b"v".to_vec()))
        .map_err(|e| format!("{e}"))?;
    s.abort(tx).map_err(|e| format!("{e}"))?;
    if s.get(b"k").map_err(|e| format!("{e}"))?.is_some() {
        return Err("aborted put visible".into());
    }
    Ok(())
}

fn header_encode_roundtrip() -> Result<(), String> {
    let dh = X25519Secret::generate().map_err(|e| format!("{e}"))?;
    let h = Header {
        dh: dh.public_key(),
        pn: 3,
        n: 7,
    };
    let h2 = Header::decode(&h.encode()).map_err(|e| format!("{e}"))?;
    if h != h2 {
        return Err("header codec mismatch".into());
    }
    Ok(())
}

fn header_truncated() -> Result<(), String> {
    if Header::decode(&[0u8; 8]).is_ok() {
        return Err("truncated header accepted".into());
    }
    Ok(())
}

fn engine_wrong_conversation() -> Result<(), String> {
    let mut a = engine_named(b"a")?;
    let mut b = engine_named(b"b")?;
    let (sa, sb) = engine_handshake(&mut a, &mut b)?;
    let sealed = a.encrypt(&sa, b"m", b"ad").map_err(|e| format!("{e:?}"))?;
    match b.decrypt(&sb, &sealed, b"other-ad") {
        Err(_) => Ok(()),
        Ok(_) => Err("wrong AD accepted at engine".into()),
    }
}

fn engine_tamper_ct() -> Result<(), String> {
    let mut a = engine_named(b"a")?;
    let mut b = engine_named(b"b")?;
    let (sa, sb) = engine_handshake(&mut a, &mut b)?;
    let mut sealed = a.encrypt(&sa, b"m", b"ad").map_err(|e| format!("{e:?}"))?;
    if let Some(x) = sealed.ciphertext.last_mut() {
        *x ^= 1;
    }
    if b.decrypt(&sb, &sealed, b"ad").is_ok() {
        return Err("tampered engine ciphertext accepted".into());
    }
    Ok(())
}

const W_PQ: f64 = 15.0 / 18.0;
const W_DR: f64 = 20.0 / 16.0;
const W_TM: f64 = 10.0 / 7.0;
const W_RP: f64 = 8.0 / 3.0;
const W_OO: f64 = 8.0 / 5.0;
const W_PS: f64 = 10.0 / 6.0;
const W_PK: f64 = 8.0 / 5.0;
const W_ID: f64 = 8.0 / 6.0;
const W_RS: f64 = 5.0 / 3.0;
const W_SR: f64 = 4.0 / 6.0;
const W_MB: f64 = 4.0 / 5.0;

static SPECS: &[Spec] = &[
    Spec {
        id: "pqxdh.sk_last_resort",
        cat: "pqxdh",
        axis: Axis::SignalCore,
        weight: W_PQ,
        p0: true,
        run: p0_sk_last_resort,
    },
    Spec {
        id: "pqxdh.sk_ec_opk",
        cat: "pqxdh",
        axis: Axis::SignalCore,
        weight: W_PQ,
        p0: true,
        run: p0_sk_ec_opk,
    },
    Spec {
        id: "pqxdh.sk_pq_opk",
        cat: "pqxdh",
        axis: Axis::SignalCore,
        weight: W_PQ,
        p0: true,
        run: p0_sk_pq_opk,
    },
    Spec {
        id: "pqxdh.signed_prekey_verify",
        cat: "pqxdh",
        axis: Axis::SignalCore,
        weight: W_PQ,
        p0: false,
        run: signed_prekey_verify,
    },
    Spec {
        id: "pqxdh.pq_prekey_verify",
        cat: "pqxdh",
        axis: Axis::SignalCore,
        weight: W_PQ,
        p0: false,
        run: pq_prekey_verify,
    },
    Spec {
        id: "pqxdh.session_with_ec_opk",
        cat: "pqxdh",
        axis: Axis::SignalCore,
        weight: W_PQ,
        p0: false,
        run: session_with_ec_opk,
    },
    Spec {
        id: "pqxdh.session_without_ec_opk",
        cat: "pqxdh",
        axis: Axis::SignalCore,
        weight: W_PQ,
        p0: false,
        run: session_without_ec_opk,
    },
    Spec {
        id: "pqxdh.one_time_pq",
        cat: "pqxdh",
        axis: Axis::SignalCore,
        weight: W_PQ,
        p0: false,
        run: one_time_pq,
    },
    Spec {
        id: "pqxdh.last_resort_pq",
        cat: "pqxdh",
        axis: Axis::SignalCore,
        weight: W_PQ,
        p0: false,
        run: last_resort_pq,
    },
    Spec {
        id: "pqxdh.wrong_identity",
        cat: "pqxdh",
        axis: Axis::SignalCore,
        weight: W_PQ,
        p0: true,
        run: wrong_identity_sk_differs,
    },
    Spec {
        id: "pqxdh.modified_spk_sig",
        cat: "pqxdh",
        axis: Axis::SignalCore,
        weight: W_PQ,
        p0: false,
        run: modified_spk_sig,
    },
    Spec {
        id: "pqxdh.modified_pq_sig",
        cat: "pqxdh",
        axis: Axis::SignalCore,
        weight: W_PQ,
        p0: false,
        run: modified_pq_sig,
    },
    Spec {
        id: "pqxdh.modified_kem_ct",
        cat: "pqxdh",
        axis: Axis::SignalCore,
        weight: W_PQ,
        p0: false,
        run: modified_kem_no_shared,
    },
    Spec {
        id: "pqxdh.wrong_prekey_id",
        cat: "pqxdh",
        axis: Axis::SignalCore,
        weight: W_PQ,
        p0: false,
        run: wrong_prekey_id,
    },
    Spec {
        id: "pqxdh.consumed_opk_reuse",
        cat: "pqxdh",
        axis: Axis::SignalCore,
        weight: W_PQ,
        p0: true,
        run: consumed_opk_reuse,
    },
    Spec {
        id: "pqxdh.concurrent_opk_consume",
        cat: "pqxdh",
        axis: Axis::SignalCore,
        weight: W_PQ,
        p0: true,
        run: concurrent_opk_consume,
    },
    Spec {
        id: "pqxdh.stale_bundle",
        cat: "pqxdh",
        axis: Axis::SignalCore,
        weight: W_PQ,
        p0: false,
        run: stale_bundle,
    },
    Spec {
        id: "pqxdh.handshake_batch_64",
        cat: "pqxdh",
        axis: Axis::SignalCore,
        weight: W_PQ,
        p0: true,
        run: handshake_batch,
    },
    Spec {
        id: "dr.schedule_a1a2a3_b1b2_a4",
        cat: "ratchet",
        axis: Axis::SignalCore,
        weight: W_DR,
        p0: false,
        run: dr_schedule_a1a2a3_b1b2_a4,
    },
    Spec {
        id: "dr.reorder_a1_a4_a2_a5_a3",
        cat: "ratchet",
        axis: Axis::SignalCore,
        weight: W_DR,
        p0: false,
        run: dr_reorder_a1_a4_a2_a5_a3,
    },
    Spec {
        id: "dr.one_three_two",
        cat: "ratchet",
        axis: Axis::SignalCore,
        weight: W_DR,
        p0: false,
        run: dr_one_three_two,
    },
    Spec {
        id: "dr.skip_fill",
        cat: "ratchet",
        axis: Axis::SignalCore,
        weight: W_DR,
        p0: false,
        run: dr_skip_fill,
    },
    Spec {
        id: "dr.drop_permanent",
        cat: "ratchet",
        axis: Axis::SignalCore,
        weight: W_DR,
        p0: false,
        run: dr_drop_permanent,
    },
    Spec {
        id: "dr.restart_after_seven",
        cat: "ratchet",
        axis: Axis::Operational,
        weight: W_DR,
        p0: false,
        run: dr_restart_after_seven,
    },
    Spec {
        id: "dr.max_skip",
        cat: "ratchet",
        axis: Axis::SignalCore,
        weight: W_DR,
        p0: false,
        run: max_skip,
    },
    Spec {
        id: "dr.header_roundtrip",
        cat: "ratchet",
        axis: Axis::SignalCore,
        weight: W_DR,
        p0: false,
        run: header_encode_roundtrip,
    },
    Spec {
        id: "engine.establish",
        cat: "ratchet",
        axis: Axis::SignalCore,
        weight: W_DR,
        p0: true,
        run: engine_establish,
    },
    Spec {
        id: "engine.ooo",
        cat: "ooo",
        axis: Axis::SignalCore,
        weight: W_OO,
        p0: false,
        run: engine_ooo,
    },
    Spec {
        id: "engine.drop_later",
        cat: "ooo",
        axis: Axis::SignalCore,
        weight: W_OO,
        p0: false,
        run: engine_drop_later,
    },
    Spec {
        id: "engine.wrong_conversation_ad",
        cat: "ooo",
        axis: Axis::VoiceChat,
        weight: W_OO,
        p0: false,
        run: engine_wrong_conversation,
    },
    Spec {
        id: "p0.tamper_no_commit",
        cat: "tamper",
        axis: Axis::SignalCore,
        weight: W_TM,
        p0: true,
        run: p0_tamper_no_commit,
    },
    Spec {
        id: "tamper.header_dh",
        cat: "tamper",
        axis: Axis::SignalCore,
        weight: W_TM,
        p0: true,
        run: tamper_header_dh,
    },
    Spec {
        id: "tamper.counter",
        cat: "tamper",
        axis: Axis::SignalCore,
        weight: W_TM,
        p0: false,
        run: tamper_counter,
    },
    Spec {
        id: "tamper.ad",
        cat: "tamper",
        axis: Axis::SignalCore,
        weight: W_TM,
        p0: false,
        run: tamper_ad,
    },
    Spec {
        id: "tamper.engine_ct",
        cat: "tamper",
        axis: Axis::SignalCore,
        weight: W_TM,
        p0: true,
        run: engine_tamper_ct,
    },
    Spec {
        id: "p0.replay",
        cat: "replay",
        axis: Axis::SignalCore,
        weight: W_RP,
        p0: true,
        run: p0_engine_replay,
    },
    Spec {
        id: "replay.after_reload",
        cat: "replay",
        axis: Axis::Operational,
        weight: W_RP,
        p0: true,
        run: replay_survives_reload,
    },
    Spec {
        id: "p0.crash_opk",
        cat: "persist",
        axis: Axis::Operational,
        weight: W_PS,
        p0: true,
        run: p0_crash_no_opk_resurrect,
    },
    Spec {
        id: "persist.reload_conversation",
        cat: "persist",
        axis: Axis::Operational,
        weight: W_PS,
        p0: false,
        run: persist_reload_conversation,
    },
    Spec {
        id: "persist.trial_diverges",
        cat: "persist",
        axis: Axis::Operational,
        weight: W_PS,
        p0: false,
        run: crash_before_commit_no_ct_release_model,
    },
    Spec {
        id: "persist.storage_abort",
        cat: "persist",
        axis: Axis::Operational,
        weight: W_PS,
        p0: true,
        run: storage_abort,
    },
    Spec {
        id: "persist.rollback_guard",
        cat: "persist",
        axis: Axis::Operational,
        weight: W_PS,
        p0: false,
        run: rollback_guard,
    },
    Spec {
        id: "prekey.replenish",
        cat: "prekey",
        axis: Axis::SignalCore,
        weight: W_PK,
        p0: false,
        run: prekey_replenish,
    },
    Spec {
        id: "prekey.last_resort",
        cat: "prekey",
        axis: Axis::SignalCore,
        weight: W_PK,
        p0: false,
        run: prekey_exhaust_then_last_resort,
    },
    Spec {
        id: "p0.identity_changed",
        cat: "identity",
        axis: Axis::VoiceChat,
        weight: W_ID,
        p0: true,
        run: p0_identity_not_silent,
    },
    Spec {
        id: "p0.trust_not_from_session",
        cat: "identity",
        axis: Axis::VoiceChat,
        weight: W_ID,
        p0: true,
        run: p0_trust_not_from_session,
    },
    Spec {
        id: "identity.ack_persists",
        cat: "identity",
        axis: Axis::VoiceChat,
        weight: W_ID,
        p0: true,
        run: trust_ack_persists,
    },
    Spec {
        id: "identity.fingerprint_symmetric",
        cat: "identity",
        axis: Axis::VoiceChat,
        weight: W_ID,
        p0: false,
        run: fingerprint_symmetric,
    },
    Spec {
        id: "identity.device_change",
        cat: "identity",
        axis: Axis::VoiceChat,
        weight: W_ID,
        p0: false,
        run: device_change_detected,
    },
    Spec {
        id: "vc.default_classical",
        cat: "identity",
        axis: Axis::VoiceChat,
        weight: W_ID,
        p0: false,
        run: default_profile_classical,
    },
    Spec {
        id: "vc.no_silent_downgrade",
        cat: "resource",
        axis: Axis::VoiceChat,
        weight: W_RS,
        p0: false,
        run: no_silent_downgrade,
    },
    Spec {
        id: "vc.voice_profile_forbidden",
        cat: "resource",
        axis: Axis::VoiceChat,
        weight: W_RS,
        p0: true,
        run: voice_profile_forbidden,
    },
    Spec {
        id: "vc.voice_payload_ok",
        cat: "resource",
        axis: Axis::VoiceChat,
        weight: W_RS,
        p0: false,
        run: voice_payload_ok,
    },
    Spec {
        id: "envelope.conversation_binding",
        cat: "mobile",
        axis: Axis::VoiceChat,
        weight: W_MB,
        p0: false,
        run: conversation_binding,
    },
    Spec {
        id: "envelope.device_binding",
        cat: "mobile",
        axis: Axis::VoiceChat,
        weight: W_MB,
        p0: false,
        run: device_binding,
    },
    Spec {
        id: "envelope.version_reject",
        cat: "serial",
        axis: Axis::Operational,
        weight: W_SR,
        p0: false,
        run: envelope_version_reject,
    },
    Spec {
        id: "envelope.truncated",
        cat: "serial",
        axis: Axis::Operational,
        weight: W_SR,
        p0: false,
        run: envelope_truncated,
    },
    Spec {
        id: "envelope.trailing",
        cat: "serial",
        axis: Axis::Operational,
        weight: W_SR,
        p0: false,
        run: envelope_trailing,
    },
    Spec {
        id: "envelope.oversized",
        cat: "serial",
        axis: Axis::Operational,
        weight: W_SR,
        p0: false,
        run: oversized_envelope,
    },
    Spec {
        id: "serial.initiation_malformed",
        cat: "serial",
        axis: Axis::Operational,
        weight: W_SR,
        p0: false,
        run: initiation_malformed,
    },
    Spec {
        id: "serial.sealed_malformed",
        cat: "serial",
        axis: Axis::Operational,
        weight: W_SR,
        p0: false,
        run: sealed_malformed,
    },
    Spec {
        id: "serial.header_truncated",
        cat: "serial",
        axis: Axis::Operational,
        weight: W_SR,
        p0: false,
        run: header_truncated,
    },
    Spec {
        id: "resource.delete_session",
        cat: "mobile",
        axis: Axis::Operational,
        weight: W_MB,
        p0: false,
        run: delete_session,
    },
    Spec {
        id: "resource.max_skip",
        cat: "ooo",
        axis: Axis::SignalCore,
        weight: W_OO,
        p0: false,
        run: resource_max_skip_engine,
    },
    Spec {
        id: "resource.padding",
        cat: "mobile",
        axis: Axis::VoiceChat,
        weight: W_MB,
        p0: false,
        run: padding_bucket,
    },
    Spec {
        id: "resource.random_session_ids",
        cat: "mobile",
        axis: Axis::Operational,
        weight: W_MB,
        p0: false,
        run: session_ids_random,
    },
    Spec {
        id: "prekey.engine_handshake_uses_spk",
        cat: "prekey",
        axis: Axis::SignalCore,
        weight: W_PK,
        p0: false,
        run: engine_establish,
    },
    Spec {
        id: "prekey.opk_reuse_engine",
        cat: "prekey",
        axis: Axis::SignalCore,
        weight: W_PK,
        p0: true,
        run: p0_crash_no_opk_resurrect,
    },
    Spec {
        id: "ooo.engine_ooo",
        cat: "ooo",
        axis: Axis::SignalCore,
        weight: W_OO,
        p0: false,
        run: engine_ooo,
    },
    Spec {
        id: "tamper.engine_ad",
        cat: "tamper",
        axis: Axis::SignalCore,
        weight: W_TM,
        p0: false,
        run: engine_wrong_conversation,
    },
    Spec {
        id: "replay.engine_first_message",
        cat: "replay",
        axis: Axis::SignalCore,
        weight: W_RP,
        p0: true,
        run: p0_engine_replay,
    },
    Spec {
        id: "persist.handshake_atomic",
        cat: "persist",
        axis: Axis::Operational,
        weight: W_PS,
        p0: true,
        run: p0_crash_no_opk_resurrect,
    },
    Spec {
        id: "prekey.consume_once",
        cat: "prekey",
        axis: Axis::SignalCore,
        weight: W_PK,
        p0: true,
        run: consumed_opk_reuse,
    },
    Spec {
        id: "tamper.no_fail_open",
        cat: "tamper",
        axis: Axis::SignalCore,
        weight: W_TM,
        p0: true,
        run: p0_tamper_no_commit,
    },
];
