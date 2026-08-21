# PQXDH_IMPLEMENTATION.md

**Project:** voicechat-crypto  
**Specification:** The PQXDH Key Agreement Protocol, Revision 3 (2023-05-24), last updated 2024-01-23  
**Source:** https://signal.org/docs/specifications/pqxdh/ (public domain)  
**Implementation date:** 2026-08-17 (amended when real ML-KEM-768 + XEd25519 were wired)  
**Status:** Protocol logic implemented from the public specification only. No libsignal code consulted.

## Mapping of Specification Sections → Implementation

| Spec Section / Concept | Implementation Location | Notes |
|------------------------|--------------------------|-------|
| §2 Parameters (curve, hash, info, pqkem, aead, Encode*) | `primitives/` + `LABELS::PQXDH_*` | X25519, SHA-256/HKDF, ML-KEM-768 profile, AES-256-GCM. Domain-separated info strings frozen. |
| Identity Key (IK) | `prekeys::IdentityKeyPair` | X25519 long-term. |
| Signed Prekey (SPK) | `prekeys::SignedPrekey` | Medium-term, signature under identity. |
| One-time EC Prekey (OPK) | `prekeys::OneTimeEcPrekey` | Explicit model; consumption is atomic via storage (to be completed with Storage trait). |
| Last-resort PQ Prekey / One-time PQ Prekey | `prekeys::LastResortPqPrekey`, `OneTimePqPrekey` | Explicit distinction; `is_pq_one_time` flag on bundle. |
| Prekey identifiers | `EcPrekeyId`, `PqPrekeyId` | Opaque u32. Wrong-ID lookup rejected in `bob_process`. |
| Signatures (XEdDSA) | `primitives::xeddsa` + `PublicPrekeyBundle::validate` | XEd25519 from the public XEdDSA spec (Rev 1), using dalek + SHA-512. |
| Bundle validation | `PublicPrekeyBundle::validate` | Rejects invalid signatures, all-zero keys, structural problems. |
| Alice initiation | `pqxdh::alice_initiate` | Exactly follows the ordered DH + KEM steps of the public spec. |
| Bob processing | `pqxdh::bob_process` | Symmetric recomputation of SK and AD. |
| Associated Data construction | Inside both `alice_initiate` and `bob_process` | `EncodeEC(IKA) \|\| EncodeEC(IKB) \|\| EncodeKEM(PQPKB)`. PQPK binding included to mitigate the re-encapsulation attack described in the public specification. |
| Shared-secret derivation | `primitives::kdf::pqxdh_kdf` | Spec §2.2: IKM = F \|\| KM, salt = 32 zero bytes, info = `VoiceChat_CURVE25519_SHA-256_ML-KEM-768`. |
| Prekey consumption | Explicit models + future transactional Storage | One-time prekeys must be marked consumed before SK is returned (ATOMIC-STATE). |
| Secure deletion | `Zeroize` / `ZeroizeOnDrop` on all secret types; explicit zeroize of DH intermediates | |
| Rejection behavior | Typed `PrimitiveError` variants | InvalidPublicKey, SignatureInvalid, InvalidKemCiphertext, InvalidSecretKey (wrong ID), etc. |
| KEM re-encapsulation mitigation | AD always binds `pq_prekey_public` | Matches the public-spec recommendation for generic KEMs and is safe for ML-KEM as well. |

## Test Coverage (from the public requirements)

| Property / Attack | Test |
|-------------------|------|
| Alice.SK == Bob.SK for valid sessions | `alice_bob_shared_secret_equal`, `alice_bob_with_one_time_ec` |
| Modified signed-prekey / PQ-prekey signature | `modified_signed_prekey_sig_fails`, `modified_pq_prekey_fails` |
| Malformed / corrupted KEM ciphertext | `malformed_kem_ciphertext_rejected` (implicit rejection ⇒ SK mismatch) |
| Wrong recipient identity | `wrong_recipient_identity_produces_different_sk` |
| Consumed OPK cannot be reused | `consumed_opk_cannot_be_consumed_twice` + `PrekeyStore::consume_ec` |
| 10 000 randomized handshake trials | `ten_thousand_randomized_handshakes` — **passed this session** (551.20s) |

## Security Invariants Enforced at this Layer

- KEY-SEPARATION — distinct labels and key types.
- IDENTITY-BINDING — IKs and PQPK appear in AD / KDF.
- DOWNGRADE-RESISTANCE — suite is implicit in the frozen labels and will be authenticated at the session layer.
- FAIL-CLOSED — any signature, KEM, or structural failure aborts without producing an SK.
- ATOMIC-STATE — one-time prekey consumption is designed to be transactional; the Storage trait (next) will guarantee it.

## Known Limitations of the Current Snapshot

1. **ML-KEM crate** — `ml-kem` 0.3.2 is linked (Apache-2.0 OR MIT). The crate itself is **not independently audited** (upstream warning).
2. **Transactional persistence** — `PrekeyStore` consumption is in-memory atomic; durable crash-safe storage is the `TransactionalStorage` trait + `MemoryStorage` tests, not a mobile DB.
3. **Not production-ready** until independent expert review.

This implementation is a direct transcription of the public PQXDH specification into safe Rust. No proprietary or AGPL source was examined.

This implementation is a direct, readable transcription of the public PQXDH specification into safe Rust. No proprietary or AGPL source was examined.