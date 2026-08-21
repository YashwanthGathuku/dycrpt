# SPEC_TRACE.md — public spec → code

For an **independent** reviewer. This is not a verification proof.

## PQXDH Rev 3 (https://signal.org/docs/specifications/pqxdh/)

| Spec | Code |
| ---- | ---- |
| §2.1 EncodeEC / EncodeKEM | `src/primitives/encoding.rs` |
| §2.2 KDF(F\|\|KM), salt zeros, info `_` concat | `pqxdh_kdf` / `LABELS::PQXDH_KDF_INFO` |
| §2.4 same IK for DH + XEdDSA | `IdentityKeyPair` |
| §3.2 publish SPK + PQ signed by IK | `PrekeyStore::public_bundle` |
| §3.3 verify then DH1–4 + KEM | `alice_initiate` |
| §3.3 AD = EncodeEC(IKA)\|\|EncodeEC(IKB) [+\|EncodeKEM] | `alice_initiate` AD |
| §3.3 initial AEAD | `InitiationPacket.first_message` |
| §3.4 Bob DH + decaps + consume OPK | `bob_process` + engine consume |

## Double Ratchet Rev 4 (https://signal.org/docs/specifications/doubleratchet/)

| Spec | Code |
| ---- | ---- |
| §3.3 InitAlice / InitBob | `DoubleRatchetState::init_alice/init_bob` |
| §7.1 Bob DH = SPK_B | engine `init_bob_ratchet` |
| §7.2 KDF_CK HMAC 0x01/0x02 | `kdf_ck` |
| §3.5 Skip / DHRatchet | `src/ratchet/mod.rs` |
| §4 Header encryption | `src/ratchet/header_encrypt/` (`header-encrypt`) |
| §5–6 SPQR / Triple | `spqr/`, `triple/` |
| §8.8 Braid as SCKA | `src/ratchet/braid/` (Encaps1/Encaps2 + RS chunks; see KNOWN_LIMITATIONS) |

## XEdDSA Rev 1

| Spec | Code |
| ---- | ---- |
| §3 xeddsa_sign / verify | `src/primitives/xeddsa.rs` |
| §4 VXEdDSA | **not implemented** (not required by PQXDH) |

## Sesame Rev 2

| Spec | Code |
| ---- | ---- |
| §3.1 records | `src/session/mod.rs` |
| §3.3 send loop | `src/session/sesame.rs` (**not production**; `feature = "sesame"` / tests only) |
| §3.4 receive + activate | `sesame::receive_all` (same; hardcoded SK in retry path) |
| §4.1 retry / receipts | `MailboxBody::RetryRequest` / `DeliveryReceipt` |
| Server | `mailbox::Directory` (in-memory; real server is the app) |

## ML-KEM Braid Rev 1

| Spec | Code |
| ---- | ---- |
| §2.2 RS GF(2^16) | `src/ratchet/braid/rs.rs` |
| §2.3 message types | `BraidMessage` |
| §2.4 authenticator | `braid/auth.rs` |
| §2.5 states / Send / Receive | `BraidScka` |
| Encaps1 from header only | `src/primitives/mlkem_inc.rs` Encaps1(ρ‖H(ek)) → ct1; Encaps2(t̂) → ct2. Joined CT matches `ml-kem` Encrypt |
