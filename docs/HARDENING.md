# HARDENING.md — VoiceChat-Specific Security Hardening

**Date:** 2026-08-17  
**Scope:** Hardening beyond baseline Signal Protocol behavior.  
**Constraint:** Cryptographic mathematics of PQXDH and Double Ratchet are not modified.

## Threat → Defense → Test → Residual Risk

| # | Threat | Defense | Test / Verification | Residual Risk |
|---|--------|---------|---------------------|---------------|
| 1 | Crash between key consumption and ciphertext emission → key/nonce reuse | Transactional storage (`TransactionalStorage`). Ciphertext is only released after `commit`. Crash injection at every persistence boundary. | `storage` unit tests: crash-before-commit leaves prior state; epoch advances only on commit. | Platform filesystem may reorder durable writes; mitigated by `fsync`/platform transactional APIs where available. |
| 2 | Replay of previously accepted messages | Bounded FIFO replay cache (`ReplayCache`) keyed by (conversation, sender device, message_id). Hard capacity limit. | Insert → replay detection; capacity eviction; no unbounded growth. | Eviction of very old entries under sustained load could in theory allow a delayed replay; capacity is chosen high enough for practical sessions. |
| 3 | Silent protocol-version downgrade | Every session binds `PROTOCOL_VERSION` into AD / transcript. Unsupported versions rejected by envelope parser and policy. | Envelope rejects foreign version; `version_binding_bytes` included in session establishment. | None for honest peers; active attacker cannot force a lower version without detection. |
| 4 | Cipher-suite downgrade | Suites ordered by explicit preference (`SUITE_PREFERENCE`). `select_suite` picks strongest common; no fallback to weaker. | Negotiation tests; mismatch after establishment rejected by `enforce_suite`. | Future weaker suites must be added only behind explicit policy change. |
| 5 | Message-length leakage | Configurable encrypted padding buckets with **random** pad content (`padding`). Original length encoded in a short prefix; pad never deterministic. | Round-trip; different short messages map to same bucket; oversized rejected. | Bucket choice itself leaks coarse size class; refined by traffic-analysis research. |
| 6 | Metadata leakage (phone, display name, contact, voice-profile ID) | Envelope and wire formats contain only cryptographic identifiers. Phone numbers / display names are application-layer only and never appear in protocol headers or AD. | Envelope field set inspection; no phone/display fields exist in the type. | Application must not smuggle such data into `conversation_id` or free-form IDs. |
| 7 | Residual secrets in memory after use | Immediate `Zeroize` / `ZeroizeOnDrop` on message keys, chain keys, ephemeral handshake secrets, consumed OPKs, temporary PQ secrets. | Type system + drop tests; explicit zeroize of DH intermediates in PQXDH and ratchet. | **Managed/mobile OS residual risk:** GC, memory compression, swap, crash dumps, and compiler temporaries may retain copies. Documented limitation; not solvable purely in userspace. |
| 8 | Storage rollback (restore old backup) → key/nonce reuse | Monotonic `StorageEpoch` advanced on every irreversible transition. On load, compare epoch to platform-backed counter (Keystore/Keychain/enclave) when available. Mismatch → refuse to use state or force re-establishment. | Epoch monotonicity tests; design for platform binding. | **Commodity Android/iOS residual risk:** without a hardware-backed monotonic counter an attacker with filesystem access can still restore a consistent old snapshot. Perfect rollback resistance is not guaranteed on all devices; risk is explicit. |
| 9 | Resource exhaustion (CPU / memory / storage) | Hard bounds: `MAX_SKIP`, replay cache capacity, max sessions/prekeys (policy), `MAX_PAYLOAD_LEN`, envelope size, attachment/voice size, handshake attempt rate (application), malformed-packet early reject. | MAX_SKIP rejection; replay capacity; envelope oversized/truncated tests; padding oversized rejection. | Application-layer rate limiting of handshake attempts is required; the library only bounds per-session costs. |
| 10 | Timing side-channels on secrets / authenticators | `subtle::ConstantTimeEq` for secret comparisons (`SecretBytes`, key equality). AEAD and signature verification use constant-time implementations from the underlying crates. | Constant-time equality unit tests; reliance on audited primitive crates. | High-level control flow (error vs success) is intentionally non-constant; only secret-dependent comparisons are hardened. |

## Implementation Map

| Hardening | Module / Location |
|-----------|-------------------|
| Crash-safe persistence | `src/storage/` |
| Replay cache | `src/replay/` |
| Protocol version binding | `src/policy.rs` + `envelope` |
| Suite downgrade resistance | `src/policy.rs` |
| Message padding | `src/padding/` |
| Metadata minimization | `src/envelope/` (field set) |
| Secure deletion | `Zeroize` on all secret types; explicit intermediate zeroize |
| Rollback detection | `StorageEpoch` in `storage` |
| Resource bounds | Constants in ratchet, envelope, replay, padding |
| Constant-time comparisons | `primitives/zeroizing.rs` + underlying crates |

## Explicit Non-Goals / Residual Risks (Summary)

1. **Secure deletion on managed runtimes** — userspace zeroization is best-effort; OS and language runtime may retain copies.
2. **Perfect rollback resistance on commodity mobile** — requires platform-backed monotonic counters; when unavailable the residual risk is accepted and documented.
3. **Traffic-analysis resistance beyond padding buckets** — coarse size classes remain; further mitigation is an application/transport concern.
4. **Application-layer misuse** — if the application places phone numbers or display names into identifier fields, the library cannot prevent it.

## Crash-Injection Guidance

For every persistence boundary (OPK consumption, ratchet advance, epoch increment):

1. Begin transaction.
2. Mutate state.
3. Inject crash (drop process / abort transaction).
4. Restart → assert previous committed state is intact and no ciphertext that depended on the uncommitted transition was released.

The in-memory `MemoryStorage` is the first harness; platform-specific stores must provide equivalent semantics.

## Relationship to SECURITY_INVARIANTS.md

These hardenings reinforce the invariants already stated (ATOMIC-STATE, REPLAY-REJECTION, BOUNDED-SKIP, DOWNGRADE-RESISTANCE, FAIL-CLOSED, KEY-SEPARATION, etc.) with concrete mechanisms and residual-risk statements tailored to VoiceChat’s deployment on Android/iOS and desktop.
