# AUDIT_SCOPE.md — Independent Cryptography Audit Scope

**Project:** voicechat-crypto  
**Date:** 2026-08-17  
**Audience:** External cryptography / protocol security reviewers

## Status preamble (mandatory)

This implementation is **not** declared production-ready.  
Code compilation, internal tests, and design documents are **not** substitutes for independent expert review.  
Evidence levels in this package are never upgraded merely because the project builds.

Final status labels used throughout:

| Label | Meaning |
|-------|---------|
| **VERIFIED** | Independent external review has confirmed the claim (none yet) |
| **PARTIALLY VERIFIED** | Internal tests and/or formal models support the claim; external review pending |
| **UNVERIFIED** | Designed or implemented but lacking sufficient evidence |
| **BLOCKED** | Cannot be claimed until a dependency, toolchain, or review gate is cleared |

Until an external audit completes, **no item may be marked VERIFIED**.

## In scope

1. Clean-room alignment with **public** Signal Protocol family specifications (PQXDH, Double Ratchet Rev 4 classical + HE variant, SPQR/Triple Ratchet concepts, Sesame-style session management concepts, XEdDSA where used).
2. Security invariants listed in `SECURITY_INVARIANTS.md`.
3. Threat model in `THREAT_MODEL.md`.
4. Primitive selection and license compatibility (`LICENSE_AUDIT.md`, `PRIMITIVES.md`).
5. State-machine behavior: prekey consumption, ratchet transitions, replay, identity change, profile downgrade resistance.
6. Envelope binding, padding, storage transactional semantics, zeroization policy.
7. FFI secret boundary (no raw key export to Dart).
8. Fuzz targets and adversarial test design.
9. Formal TLA+ models (properties modeled, not externally proven).
10. Known limitations and residual risks.

## Out of scope

- Review of any AGPL Signal application or libsignal **source** (we did not use it; auditors should not need it for clean-room validation).
- Production operational security of a full VoiceChat deployment (servers, push, account system).
- Side-channel laboratory evaluation (timing, power, EM) beyond constant-time comparison usage.
- Formal proofs of underlying primitives (X25519, ML-KEM, AES-GCM, HKDF).
- Bit-compatibility with Signal’s production network.

## Deliverables for auditors

See index in `docs/AUDIT_MAP.md`. Primary entry points:

- `PROTOCOL.md` — protocol surface
- `THREAT_MODEL.md`
- `SECURITY_INVARIANTS.md`
- Implementation maps: `PQXDH_IMPLEMENTATION.md`, `RATCHET_IMPLEMENTATION.md`, `POST_QUANTUM_PROFILE.md`
- `WIRE_PROTOCOL.md`, `STORAGE_SECURITY.md`, `FUZZING.md`, `TEST_EVIDENCE.md`
- `LICENSE_AUDIT.md`, `KNOWN_LIMITATIONS.md`
- `SOURCE_BOUNDARY.md` — clean-room rules

## Suggested audit questions

1. Does PQXDH follow the public specification’s DH/KEM/AD construction without silent weakening?
2. Is decrypt-failure non-commit of ratchet state enforced everywhere?
3. Are one-time prekeys truly single-use under crash?
4. Is profile/suite negotiation authenticated against downgrade?
5. Are residual risks (secure deletion, mobile rollback, HE demux) accurately stated?
6. Is the FFI boundary free of secret leakage to managed language heaps?
