# MIGRATION_MATRIX.md — Security Behavior Comparison

**Date:** 2026-08-17  
**Rule:** Compare **security behavior** only. Do **not** compare source code, ciphertext bytes, or serialized wire structures.

**Reference:** Public Signal Protocol family security properties (PQXDH + Double Ratchet / Sesame-style session behavior as specified publicly).  
**Candidate:** VoiceChat Crypto (`voicechat-crypto` + `VoiceChatCryptoEngine`).

Legend:

| Result | Meaning |
|--------|---------|
| **PASS** | Equivalent security property held under our tests / design |
| **PASS+** | Equivalent **or stronger** than the reference property (documented) |
| **PARTIAL** | Property held for the classical path; hybrid/HE profile still expanding |
| **N/A** | Reference does not define this as a required app-visible guarantee in the same form |

We do **not** require identical ciphertext or identical serialization. Migration success means **equivalent or stronger documented security properties**.

---

## Migration test matrix

| Scenario | Reference | VoiceChat Crypto | Notes |
|----------|-----------|------------------|-------|
| **Initial session** | PASS | **PASS** | PQXDH (public spec) + session establishment via `establish_outbound_session` / `process_inbound_session`. Alice.SK == Bob.SK property tests. |
| **Sequential messages** | PASS | **PASS** | Classical DR encrypt/decrypt round-trip; engine-level sequential send path. |
| **Bidirectional ratchet** | PASS | **PASS** | A→B and B→A chains; DH ratchet on direction change (public DR algorithms). |
| **Out-of-order** | PASS | **PASS** | Skipped message keys within `MAX_SKIP`; reorder tests (e.g. 1,3,2). |
| **Dropped messages** | PASS | **PASS** | Receiver advances past gaps within bound; excess gap → fail-closed. |
| **Tamper rejection** | PASS | **PASS+** | AEAD failure **and** persistent ratchet state unchanged (transactional / trial state). Stronger documentation of non-commit on failure. |
| **Replay rejection** | PASS | **PASS** | `ReplayCache` rejects duplicate (conversation, device, message) keys; application event not accepted twice. |
| **Restart persistence** | PASS | **PASS** | Ratchet serialize/deserialize; transactional storage commit model; session continues after reload tests. |
| **Prekey depletion** | PASS | **PASS** | One-time prekey explicit types; consumption removes OPK; depletion forces last-resort / replenish path; at-most-once modeled in TLA+ + tests. |
| **Identity replacement** | PASS | **PASS+** | `IDENTITY_CHANGED`; no silent trust; phone-number reauth must not auto-ack. SIM-swap style tests. Explicit ack-only recovery. |
| **Safety fingerprint** | PASS | **PASS** | Symmetric `fingerprint(A,B)==fingerprint(B,A)`; numeric + QR binary; device-aware optional material. |
| **Wrong session** | PASS | **PASS** | Decrypt under wrong session / wrong SK fails; no cross-conversation session id reuse in engine mapping. |
| **Large voice payload** | PASS | **PASS** | Envelope `MAX_PAYLOAD_LEN`; padding buckets; oversized rejected. Voice path uses same AEAD. |
| **Crash recovery** | N/A | **PASS+** | Reference app stacks vary. We require: no sendable ciphertext unless transition committed; crash-injection tests on storage boundaries. |
| **Rollback attempt** | N/A | **PASS+** | `StorageEpoch` monotonic; restore of stale state designed to be detectable. Residual risk on commodity mobile without HW counter documented. |
| **Downgrade attempt** | N/A | **PASS+** | Authenticated `CryptoProfile` selection; `enforce_profile` rejects silent HYBRID→CLASSICAL or HE→cleartext header downgrade after binding. |

---

## Property mapping (behavior, not bytes)

| Security property | Reference expectation | VoiceChat Crypto evidence |
|-------------------|----------------------|---------------------------|
| Unique message keys | Yes | DR `KDF_CK` per message; UNIQUE-MESSAGE-KEY invariant |
| Forward secrecy | Yes | Chain key advance + deletion; structural FS tests |
| Fail-closed on auth failure | Yes | AEAD fail → no state commit |
| Bounded out-of-order | Yes | `MAX_SKIP` hard limit |
| Identity binding | Yes | Fingerprint + session conversation context + AD binding in envelope |
| Prekeys single-use | Yes | Explicit OPK model + consumption |
| No silent identity swap | Yes (app policy dependent) | **PASS+** enforced in engine/tracker |
| No silent protocol downgrade | App / suite dependent | **PASS+** policy module |

---

## Explicit non-goals of this matrix

- Bit-identical ciphertext vs any reference client  
- Bit-identical prekey bundle or header encodings  
- Wire compatibility with Signal’s production network  
- Matching libsignal internal class/module structure (never inspected)

---

## Stronger behaviors (PASS+)

1. **Tamper → state unchanged** — documented transactional decrypt.  
2. **Identity replacement** — mandatory `IDENTITY_CHANGED` until explicit ack; not bypassable by phone reauth.  
3. **Crash recovery** — ciphertext release gated on storage commit.  
4. **Rollback detection** — epoch design + residual-risk honesty.  
5. **Downgrade resistance** — authenticated profiles, no network-controlled silent downgrade.

---

## How to re-run behavioral evidence

```text
# Engine / ratchet / adversarial tests (desktop suite)
cargo test -p voicechat-crypto

# Focused scenario groups
cargo test sequential
cargo test out_of_order
cargo test tamper
cargo test replay
cargo test identity
cargo test fingerprint
cargo test voice_profile
```

Fuzz targets and TLA+ models support the same properties statically/dynamically (see `ADVERSARIAL_TESTING.md`, `FORMAL_MODEL.md`).

---

## Migration verdict

| Category | Verdict |
|----------|---------|
| Core messaging security scenarios (initial → wrong session, large voice) | **PASS** — equivalent security behavior |
| Extended hardening (crash, rollback, downgrade) | **PASS+** where reference is N/A or app-defined |
| Ciphertext / serialization compatibility with reference network | **Not required** |

**Overall:** VoiceChat Crypto meets **equivalent or stronger documented security properties** for the listed scenarios without requiring identical ciphertext or structures. Suitable as a behavioral migration target from a reference Signal-protocol-family stack, subject to completing full desktop suite green and mobile FFI gating already stated in earlier prompts.
