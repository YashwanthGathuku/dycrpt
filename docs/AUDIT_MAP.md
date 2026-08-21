# AUDIT_MAP.md — Protocol Requirement → Module → Test → Formal Property

**Date:** 2026-08-17  
**Rule:** No status may read VERIFIED until independent external review. Compilation ≠ evidence upgrade.

## Status summary (pre-external-audit)

| Area | Status |
|------|--------|
| Clean-room boundary | PARTIALLY VERIFIED |
| PQXDH lifecycle | PARTIALLY VERIFIED |
| Classical Double Ratchet | PARTIALLY VERIFIED |
| Header Encryption profile | PARTIALLY VERIFIED |
| Hybrid PQ / SPQR / Braid | PARTIALLY VERIFIED (in-repo Encaps1/Triple tests) |
| Envelope binding | PARTIALLY VERIFIED |
| Replay / identity / downgrade | PARTIALLY VERIFIED |
| Storage transactions / epoch | PARTIALLY VERIFIED |
| Zeroization policy | PARTIALLY VERIFIED |
| FFI secret boundary | PARTIALLY VERIFIED (design) |
| Fuzz continuous runs | UNVERIFIED |
| TLA+ TLC machine-checked | UNVERIFIED (models exist) |
| Production readiness | **BLOCKED** (external audit required) |

---

## Map

| Protocol / security requirement | Source module(s) | Test / evidence | Formal / model property |
|---------------------------------|------------------|-----------------|-------------------------|
| PQXDH shared secret agreement | `pqxdh/`, `prekeys/` | SK equality; malformed KEM CT; randomized handshakes | — |
| OPK single-use | `prekeys/`, `storage/`, `engine/` | Consumption retain/delete; migration matrix | `PrekeyConsumption.tla` **AtMostOnce** |
| Classical DR encrypt/decrypt | `ratchet/mod.rs` | Round-trip; A1…A4 style; bidirectional | `RatchetState.tla` transitions |
| Tamper → fail + no state commit | `ratchet/` decrypt trial | `tamper_message_leaves_state_unchanged`; adversarial | `NoCommitOnFailure` |
| Bounded skip | `ratchet/` MAX_SKIP | Extreme N rejected | Counters / skip bounds (approx) |
| Replay ≠ second accept | `replay/`, `engine/` | ReplayCache tests; matrix | `ReplayAndIdentity.tla` **NoDuplicateAccept** |
| Identity change not silent | `fingerprint/`, `engine/` | SIM-swap style; ack-only | `NoSilentIdentitySuccess` |
| Safety fingerprint symmetry | `fingerprint/` | `fingerprint_is_symmetric` | — |
| Envelope conversation/device binding | `envelope/` | AD differs on conv/device change | — |
| Fail-closed parse | `envelope/`, headers | Truncation, trailing, version | — |
| Authenticated profile / no downgrade | `policy.rs` | `enforce_profile` rejects mismatch | `DowngradeAttempt` stutter |
| Transactional persistence | `storage/` | Crash-before-commit leaves old state | Assumption A3 in formal README |
| Zeroize secrets after use | `primitives/zeroizing`, ratchet MK wipe | zeroize unit tests | — |
| Voice profile never leaves device | `engine/` `encrypt_voice_payload` | `VoiceProfileForbidden` | — |
| Hybrid MK composition | `ratchet/triple/`, `spqr/`, `braid/` | Encaps1 CT match; Triple epoch + incrementality tests | `BraidEpoch.tla` |
| Header encryption optional | `ratchet/header_encrypt/` | HE module tests; demux limitation documented | — |
| FFI no raw key export | `ffi/` | API surface review | — |
| Sesame-style limits | `session/` | Device limit enforcement tests | — |

---

## Document index for auditors

| Document | Purpose |
|----------|---------|
| `AUDIT_SCOPE.md` | Scope, labels, out-of-scope |
| `PROTOCOL.md` | Protocol surface |
| `THREAT_MODEL.md` | Adversaries and assets |
| `SECURITY_INVARIANTS.md` | Named invariants |
| `PQXDH_IMPLEMENTATION.md` | Spec → code map |
| `RATCHET_IMPLEMENTATION.md` | DR / HE / Triple map |
| `POST_QUANTUM_PROFILE.md` | Hybrid claims and non-claims |
| `WIRE_PROTOCOL.md` | On-the-wire objects |
| `STORAGE_SECURITY.md` | Persistence security |
| `FUZZING.md` | Fuzz targets and policy |
| `TEST_EVIDENCE.md` | What internal tests cover |
| `LICENSE_AUDIT.md` | Dependency licenses |
| `KNOWN_LIMITATIONS.md` | Honest gaps |
| `SOURCE_BOUNDARY.md` | Clean-room rules |
| `AUDIT_MAP.md` | This file |
| `formal/README.md` | TLA+ assumptions and how to check |

---

## Production readiness gate

```
PRODUCTION_READY :=
    external_cryptography_audit_passed
    AND all BLOCKED items cleared
    AND hybrid claims scoped to POST_QUANTUM_PROFILE non-claims
    AND mobile FFI interop evidence recorded (if shipping mobile)
```

**Current value: false (BLOCKED).**
