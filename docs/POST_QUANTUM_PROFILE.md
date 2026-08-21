# POST_QUANTUM_PROFILE.md

**Status:** PARTIALLY VERIFIED (design + classical coexistence + incremental Braid Encaps1/Encaps2 in-repo tests). **Not** independently reviewed. **Not** quantum-proof.

## Profile

`VOICECHAT_HYBRID_PQ_V1` = PQXDH + Triple Ratchet (classical DR ‖ SPQR).

## Claims allowed

- Design intent: continuous PQ contribution to message keys after SPQR epoch advance (ML-KEM-based SCKA).  
- Classical DR properties retained in parallel.  
- Authenticated selection; no silent downgrade to classical-only after hybrid bound.

## Claims forbidden

- “Quantum proof” / unconditional quantum security  
- Quantum-safe authentication (identity still classical-assumption based in this revision, consistent with public PQXDH discussion)

## Evidence

- `src/policy.rs` profile enum + enforce  
- `src/ratchet/spqr/`, `triple/`  
- `docs/TRIPLE_RATCHET.md`  

External review required before any production hybrid claim.
