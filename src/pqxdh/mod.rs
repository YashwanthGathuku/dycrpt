//! PQXDH key agreement — implemented from the public specification
//! (Revision 3, 2023-05-24, last updated 2024-01-23).
//!
//! No libsignal code, names, or structures were consulted.

use crate::prekeys::{
    EcPrekeyId, IdentityKeyPair, OneTimeEcPrekey, PqPrekeyId, PublicPrekeyBundle, SignedPrekey,
};
use crate::primitives::encoding::{encode_ec, encode_kem};
use crate::primitives::error::PrimitiveError;
use crate::primitives::kdf::pqxdh_kdf;
use crate::primitives::kem::{MlKemCiphertext, MlKemPublic, MlKemSecret};
use crate::primitives::x25519::{X25519Public, X25519Secret};
use zeroize::{Zeroize, Zeroizing};

/// Result of a successful PQXDH run (both sides obtain the same SK).
#[derive(Zeroize)]
pub struct PqxdhSharedSecret {
    pub sk: [u8; 32],
    /// Associated data that must be used with the first AEAD message.
    pub ad: Vec<u8>,
}

impl Drop for PqxdhSharedSecret {
    fn drop(&mut self) {
        self.sk.zeroize();
        self.ad.zeroize();
    }
}

pub struct AliceInitiation {
    pub ephemeral_public: X25519Public,
    pub shared: PqxdhSharedSecret,
    pub kem_ciphertext: Vec<u8>,
    pub used_ec_opk_id: Option<EcPrekeyId>,
    pub used_pq_prekey_id: PqPrekeyId,
}

/// Perform Alice's side of PQXDH against a validated public bundle.
///
/// Every X25519 term uses contributory-behavior validation: a nonzero low-order
/// peer input that yields an all-zero shared secret is rejected before it can be
/// included in the PQXDH KDF.
pub fn alice_initiate(
    alice_ik: &IdentityKeyPair,
    bob_bundle: &PublicPrekeyBundle,
) -> Result<AliceInitiation, PrimitiveError> {
    bob_bundle.validate()?;

    let eka = X25519Secret::generate()?;
    let pq_pk = MlKemPublic::from_bytes(&bob_bundle.pq_prekey_public)?;
    let (ss_raw, kem_ct) = pq_pk.encapsulate()?;
    let ss = Zeroizing::new(ss_raw);

    let dh1 = Zeroizing::new(
        alice_ik
            .secret
            .diffie_hellman_checked(&bob_bundle.signed_prekey)?,
    );
    let dh2 = Zeroizing::new(eka.diffie_hellman_checked(&bob_bundle.identity_key)?);
    let dh3 = Zeroizing::new(eka.diffie_hellman_checked(&bob_bundle.signed_prekey)?);

    let mut km = Zeroizing::new(Vec::with_capacity(32 * 5));
    km.extend_from_slice(&*dh1);
    km.extend_from_slice(&*dh2);
    km.extend_from_slice(&*dh3);

    let used_ec_opk_id = if let Some((id, opk_pub)) = &bob_bundle.one_time_ec {
        let dh4 = Zeroizing::new(eka.diffie_hellman_checked(opk_pub)?);
        km.extend_from_slice(&*dh4);
        Some(*id)
    } else {
        None
    };
    km.extend_from_slice(&*ss);

    let sk = pqxdh_kdf(&km)?;
    let mut ad = Vec::new();
    ad.extend_from_slice(&encode_ec(&alice_ik.public()));
    ad.extend_from_slice(&encode_ec(&bob_bundle.identity_key));
    ad.extend_from_slice(&encode_kem(&pq_pk));

    let ephemeral_public = eka.public_key();
    Ok(AliceInitiation {
        ephemeral_public,
        shared: PqxdhSharedSecret { sk, ad },
        kem_ciphertext: kem_ct.as_bytes().to_vec(),
        used_ec_opk_id,
        used_pq_prekey_id: bob_bundle.pq_prekey_id,
    })
}

pub struct BobPrivateMaterial<'a> {
    pub identity: &'a IdentityKeyPair,
    pub signed_prekey: &'a SignedPrekey,
    pub one_time_ec: Option<&'a OneTimeEcPrekey>,
    pub pq_secret: &'a MlKemSecret,
    pub pq_public: &'a MlKemPublic,
    pub pq_prekey_id: PqPrekeyId,
}

/// Process Alice's initiation message (Bob side). Spec §3.4.
pub fn bob_process(
    bob: &BobPrivateMaterial<'_>,
    alice_ik: &X25519Public,
    alice_ek: &X25519Public,
    kem_ct: &[u8],
    used_ec_opk_id: Option<EcPrekeyId>,
) -> Result<PqxdhSharedSecret, PrimitiveError> {
    let ct = MlKemCiphertext::from_bytes(kem_ct)?;
    let ss = Zeroizing::new(bob.pq_secret.decapsulate(&ct)?);

    let dh1 = Zeroizing::new(bob.signed_prekey.secret.diffie_hellman_checked(alice_ik)?);
    let dh2 = Zeroizing::new(bob.identity.secret.diffie_hellman_checked(alice_ek)?);
    let dh3 = Zeroizing::new(bob.signed_prekey.secret.diffie_hellman_checked(alice_ek)?);

    let mut km = Zeroizing::new(Vec::with_capacity(32 * 5));
    km.extend_from_slice(&*dh1);
    km.extend_from_slice(&*dh2);
    km.extend_from_slice(&*dh3);

    if let Some(id) = used_ec_opk_id {
        let opk = bob.one_time_ec.ok_or(PrimitiveError::InvalidSecretKey)?;
        if opk.id != id {
            return Err(PrimitiveError::InvalidSecretKey);
        }
        let dh4 = Zeroizing::new(opk.secret.diffie_hellman_checked(alice_ek)?);
        km.extend_from_slice(&*dh4);
    }
    km.extend_from_slice(&*ss);

    let sk = pqxdh_kdf(&km)?;
    let mut ad = Vec::new();
    ad.extend_from_slice(&encode_ec(alice_ik));
    ad.extend_from_slice(&encode_ec(&bob.identity.public()));
    ad.extend_from_slice(&encode_kem(bob.pq_public));
    Ok(PqxdhSharedSecret { sk, ad })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prekeys::PrekeyStore;

    fn handshake_pair(
        with_opk: bool,
    ) -> (
        IdentityKeyPair,
        IdentityKeyPair,
        PrekeyStore,
        AliceInitiation,
        PqxdhSharedSecret,
    ) {
        let alice_ik = IdentityKeyPair::generate().unwrap();
        let bob_ik = IdentityKeyPair::generate().unwrap();
        let mut store = PrekeyStore::new(&bob_ik).unwrap();
        if with_opk {
            store.replenish(&bob_ik, 1, 1).unwrap();
        }
        let bundle = store.public_bundle(&bob_ik).unwrap();
        let alice = alice_initiate(&alice_ik, &bundle).unwrap();

        let opk;
        let opk_ref = if let Some(id) = alice.used_ec_opk_id {
            opk = store.consume_ec(id).unwrap();
            Some(&opk)
        } else {
            None
        };

        let pq_public;
        if bundle.is_pq_one_time {
            let consumed = store.consume_pq(alice.used_pq_prekey_id).unwrap();
            let pq_secret = consumed.secret.clone();
            let pq_public = pq_secret.public_key().unwrap();
            let bob_mat = BobPrivateMaterial {
                identity: &bob_ik,
                signed_prekey: &store.signed,
                one_time_ec: opk_ref,
                pq_secret: &pq_secret,
                pq_public: &pq_public,
                pq_prekey_id: alice.used_pq_prekey_id,
            };
            let bob_shared = bob_process(
                &bob_mat,
                &alice_ik.public(),
                &alice.ephemeral_public,
                &alice.kem_ciphertext,
                alice.used_ec_opk_id,
            )
            .unwrap();
            return (alice_ik, bob_ik, store, alice, bob_shared);
        }

        pq_public = store.last_resort_pq.public().unwrap();
        let bob_mat = BobPrivateMaterial {
            identity: &bob_ik,
            signed_prekey: &store.signed,
            one_time_ec: opk_ref,
            pq_secret: &store.last_resort_pq.secret,
            pq_public: &pq_public,
            pq_prekey_id: alice.used_pq_prekey_id,
        };
        let bob_shared = bob_process(
            &bob_mat,
            &alice_ik.public(),
            &alice.ephemeral_public,
            &alice.kem_ciphertext,
            alice.used_ec_opk_id,
        )
        .unwrap();
        (alice_ik, bob_ik, store, alice, bob_shared)
    }

    #[test]
    fn alice_bob_shared_secret_equal() {
        let (_a, _b, _s, alice, bob_shared) = handshake_pair(false);
        assert_eq!(alice.shared.sk, bob_shared.sk);
        assert_eq!(&alice.shared.ad, &bob_shared.ad);
    }

    #[test]
    fn alice_bob_with_one_time_ec() {
        let (_a, _b, _s, alice, bob_shared) = handshake_pair(true);
        assert!(alice.used_ec_opk_id.is_some());
        assert_eq!(alice.shared.sk, bob_shared.sk);
    }

    #[test]
    fn bob_rejects_noncontributory_alice_identity() {
        let alice_ik = IdentityKeyPair::generate().unwrap();
        let bob_ik = IdentityKeyPair::generate().unwrap();
        let store = PrekeyStore::new(&bob_ik).unwrap();
        let bundle = store.public_bundle(&bob_ik).unwrap();
        let alice = alice_initiate(&alice_ik, &bundle).unwrap();
        let pq_public = store.last_resort_pq.public().unwrap();
        let bob_mat = BobPrivateMaterial {
            identity: &bob_ik,
            signed_prekey: &store.signed,
            one_time_ec: None,
            pq_secret: &store.last_resort_pq.secret,
            pq_public: &pq_public,
            pq_prekey_id: bundle.pq_prekey_id,
        };
        let mut low_order = [0u8; 32];
        low_order[0] = 1;
        let low_order = X25519Public::from_bytes(low_order).unwrap();
        assert!(matches!(
            bob_process(
                &bob_mat,
                &low_order,
                &alice.ephemeral_public,
                &alice.kem_ciphertext,
                None,
            ),
            Err(PrimitiveError::InvalidPublicKey)
        ));
    }

    #[test]
    fn modified_signed_prekey_sig_fails() {
        let bob_ik = IdentityKeyPair::generate().unwrap();
        let store = PrekeyStore::new(&bob_ik).unwrap();
        let mut bundle = store.public_bundle(&bob_ik).unwrap();
        bundle.signed_prekey_sig[3] ^= 0xff;
        let alice_ik = IdentityKeyPair::generate().unwrap();
        assert!(alice_initiate(&alice_ik, &bundle).is_err());
    }

    #[test]
    fn modified_pq_prekey_fails() {
        let bob_ik = IdentityKeyPair::generate().unwrap();
        let store = PrekeyStore::new(&bob_ik).unwrap();
        let mut bundle = store.public_bundle(&bob_ik).unwrap();
        bundle.pq_prekey_sig[1] ^= 0xaa;
        let alice_ik = IdentityKeyPair::generate().unwrap();
        assert!(alice_initiate(&alice_ik, &bundle).is_err());
    }

    #[test]
    fn malformed_kem_ciphertext_rejected_or_changes_secret() {
        let alice_ik = IdentityKeyPair::generate().unwrap();
        let bob_ik = IdentityKeyPair::generate().unwrap();
        let store = PrekeyStore::new(&bob_ik).unwrap();
        let bundle = store.public_bundle(&bob_ik).unwrap();
        let alice = alice_initiate(&alice_ik, &bundle).unwrap();
        let pq_public = store.last_resort_pq.public().unwrap();
        let bob_mat = BobPrivateMaterial {
            identity: &bob_ik,
            signed_prekey: &store.signed,
            one_time_ec: None,
            pq_secret: &store.last_resort_pq.secret,
            pq_public: &pq_public,
            pq_prekey_id: bundle.pq_prekey_id,
        };
        let mut bad = alice.kem_ciphertext.clone();
        if let Some(byte) = bad.first_mut() {
            *byte ^= 0xff;
        }
        match bob_process(
            &bob_mat,
            &alice_ik.public(),
            &alice.ephemeral_public,
            &bad,
            None,
        ) {
            Ok(shared) => assert_ne!(shared.sk, alice.shared.sk),
            Err(_) => {}
        }
    }

    #[test]
    fn wrong_recipient_identity_produces_different_sk() {
        let alice_ik = IdentityKeyPair::generate().unwrap();
        let bob_ik = IdentityKeyPair::generate().unwrap();
        let store = PrekeyStore::new(&bob_ik).unwrap();
        let bundle = store.public_bundle(&bob_ik).unwrap();
        let alice = alice_initiate(&alice_ik, &bundle).unwrap();

        let impostor = IdentityKeyPair::generate().unwrap();
        let pq_public = store.last_resort_pq.public().unwrap();
        let bob_mat = BobPrivateMaterial {
            identity: &impostor,
            signed_prekey: &store.signed,
            one_time_ec: None,
            pq_secret: &store.last_resort_pq.secret,
            pq_public: &pq_public,
            pq_prekey_id: bundle.pq_prekey_id,
        };
        let shared = bob_process(
            &bob_mat,
            &alice_ik.public(),
            &alice.ephemeral_public,
            &alice.kem_ciphertext,
            None,
        )
        .unwrap();
        assert_ne!(shared.sk, alice.shared.sk);
    }

    #[test]
    fn consumed_opk_cannot_be_consumed_twice() {
        let bob_ik = IdentityKeyPair::generate().unwrap();
        let mut store = PrekeyStore::new(&bob_ik).unwrap();
        store.replenish(&bob_ik, 1, 0).unwrap();
        let id = store.public_bundle(&bob_ik).unwrap().one_time_ec.unwrap().0;
        store.consume_ec(id).unwrap();
        assert!(store.consume_ec(id).is_err());
    }

    #[test]
    fn ten_thousand_randomized_handshakes() {
        for i in 0..10_000u32 {
            let with_opk = i % 3 != 0;
            let (_a, _b, _s, alice, bob_shared) = handshake_pair(with_opk);
            assert_eq!(alice.shared.sk, bob_shared.sk);
            assert_eq!(&alice.shared.ad, &bob_shared.ad);
        }
    }
}
