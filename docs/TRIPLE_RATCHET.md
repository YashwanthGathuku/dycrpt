# TRIPLE_RATCHET.md — Hybrid Post-Quantum Profile

**Date:** 2026-08-17  
**Specifications:** Double Ratchet Algorithm Revision 4 (public); ML-KEM Braid (public)  
**Profiles:** `VOICECHAT_CLASSICAL_V1` | `VOICECHAT_HYBRID_PQ_V1`

## Construction

```
Classical Double Ratchet  ──┐
                            ├─ KDF_HYBRID ─→ message encryption key
Sparse Post-Quantum Ratchet ┘
        (ML-KEM Braid SCKA)
```

Classical implementation is **not** replaced. Both profiles coexist; suite selection is authenticated.

## Authenticated Profile Selection

- Preference order: HybridPqV1 > ClassicalV1
- `select_profile` chooses the strongest mutually supported profile
- After establishment, `enforce_profile` rejects any other profile
- **No network-controlled downgrade** from HYBRID_PQ to CLASSICAL

## What Post-Quantum Guarantees Are Provided

| Guarantee | Status under HYBRID_PQ_V1 |
|-----------|---------------------------|
| Confidentiality against a future quantum adversary who recorded ciphertext (HNDL) after PQ healing | Aimed for via SPQR epoch secrets (ML-KEM) mixed into message keys |
| Post-compromise security that includes a quantum-safe component | Yes, after SPQR epoch advance injects fresh ML-KEM entropy |
| Classical security properties of the Double Ratchet | Retained (hybrid still requires breaking classical *or* PQ path for full break in the intended model) |
| Authentication / signatures against a quantum adversary | **Not** provided — identity authentication still relies on classical assumptions in this revision (as with PQXDH’s public statement) |
| “Quantum proof” / unconditional quantum security | **Not claimed** |

## What Is Explicitly Not Claimed

- This is **not** “quantum proof.”
- Active quantum adversaries that can break discrete log / forge classical signatures are outside the intended PQ guarantees (consistent with the public PQXDH security discussion).
- Incremental Encaps1/Encaps2, GF(2^16) RS chunking, and Braid Send/Receive states are implemented (`src/primitives/mlkem_inc.rs`, `src/ratchet/braid/`). Joined Encaps1‖Encaps2 matches `ml-kem` Encrypt in-repo. Independent review has not been done. Do not call the stack “quantum proof.”
- `MlKemCka` in `scka.rs` remains as a bandwidth-heavy CKA test stand-in; production Triple uses `BraidScka`.

## Measurements (scaffolding)

| Metric | Classical | Hybrid (design target) |
|--------|-----------|------------------------|
| Handshake size | PQXDH (EC + KEM CT) | Same PQXDH |
| Message header | 40 bytes (DH + pn + n) | + 8 bytes (epoch + n) |
| State size | classical DR state | classical + SPQR root/chains/skipped |
| CPU / RAM | baseline | + ML-KEM ops on epoch advance; + hybrid KDF per message |
| Bandwidth | baseline | modest header growth; braid chunks when full SCKA is active |
| Healing | classical DH ratchet | classical + PQ epoch advance |
| Message loss | MAX_SKIP | MAX_SKIP + SPQR epoch bounds |

## Vulnerable Message Set Tests (scenarios)

The following scenarios must be exercised for the hybrid profile:

- Alternating conversation (A/B/A/B…)
- One-sided bursts
- Offline recipient then catch-up
- Dropped messages within skip bounds
- Reordered messages within skip bounds

Expected: confidentiality of messages outside the vulnerable set relative to the last PQ epoch advance; no unbounded state growth.

## Module Map

| Component | Path |
|-----------|------|
| Profile policy | `src/policy.rs` |
| SPQR | `src/ratchet/spqr/` |
| Triple Ratchet | `src/ratchet/triple/` |
| Classical DR (unchanged) | `src/ratchet/mod.rs` |
