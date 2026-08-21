# AUDIT_HANDOFF.md

This file is the packet for an **external** cryptography reviewer.
Completing this file is **not** an audit.

For a new implementer/session (Antigravity, etc.): start at [`HANDOFF.md`](HANDOFF.md) and [`NEXT_STEPS.md`](NEXT_STEPS.md).

## Scope to review

1. PQXDH + XEd25519 + classical Double Ratchet (default profile).
2. Optional header-encryption and hybrid Triple (full ML-KEM CKA + Braid SCKA module).
3. Sesame mailbox algorithm as implemented (no Signal server).
4. FFI secret boundary (`vc_establish_outbound` / `vc_process_inbound`).

## Out of scope for the reviewer (unless contracted)

- Parent VoiceChat UI
- Physical TEE attacks
- libsignal wire compatibility (not claimed)

## How to run

```
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
```

## Required reviewer outputs

- Written opinion: ship / ship-with-fixes / do-not-ship
- Findings with spec citations (PQXDH / DR / XEdDSA / Braid / Sesame)
- Confirmation that no AGPL code was observed

## Known unreviewed dependencies

`ml-kem` 0.3.2 states it has never been independently audited.
