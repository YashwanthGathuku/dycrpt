# SAFETY_NUMBERS.md — Cryptographic Identity Verification

**Date:** 2026-08-17

## Principles

- A mobile / phone number is **never** a cryptographic identity.
- Safety fingerprints are derived only from long-term public keys and (optionally) device identifiers.
- `fingerprint(A, B) == fingerprint(B, A)`.
- Identity or device changes transition the conversation to `IDENTITY_CHANGED`.
- The only way out of `IDENTITY_CHANGED` is explicit user acknowledgement / verification.
- Phone-number reauthentication must **not** call `acknowledge` automatically.

## Representations

| Form | Description |
|------|-------------|
| Binary (32 bytes) | QR-compatible, stable |
| Numeric (60 digits) | Human comparison, grouped by 5 |
| Display | Numeric with spaces |

## SIM-Swap Scenario

Same phone number + different cryptographic identity key → `IdentityState::IdentityChanged` with reason `IdentityKeyChanged`. The conversation remains untrusted until the user explicitly verifies the new safety number.

## API

- `compute_fingerprint(party_a, party_b)`
- `IdentityTracker::observe` → `Unknown` | `Verified` | `IdentityChanged`
- `IdentityTracker::acknowledge` — sole path to clear a change
