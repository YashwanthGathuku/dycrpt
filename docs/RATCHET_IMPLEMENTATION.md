# RATCHET_IMPLEMENTATION.md

**Status:** PARTIALLY VERIFIED (classical path tests); hybrid/HE PARTIALLY VERIFIED / UNVERIFIED in places

## Classical Double Ratchet

Source: `src/ratchet/mod.rs`  
Spec: public Double Ratchet Rev 4 algorithms (RatchetEncrypt/Decrypt, DHRatchet, SkipMessageKeys, TrySkippedMessageKeys, InitAlice/InitBob).

| Spec construct | Module |
|----------------|--------|
| State variables | `DoubleRatchetState` |
| HEADER / CONCAT | `Header`, `concat_ad` |
| MAX_SKIP | `DEFAULT_MAX_SKIP` + reject path |
| Transactional decrypt | trial clone; commit only on AEAD success |

Tests: sequential, bidirectional, reorder, MAX_SKIP, tamper non-commit, serialize/reload (`DOUBLE_RATCHET_IMPLEMENTATION.md`).

## Header Encryption variant

Source: `src/ratchet/header_encrypt/`  
Spec: public HE section (HKs/HKr/NHKs/NHKr, HENCRYPT/HDECRYPT, DHRatchetHE).  
Status: implemented as optional profile; multi-device demux complexity documented — **not default**.

## Triple Ratchet / SPQR

Source: `src/ratchet/spqr/`, `src/ratchet/triple/`  
Spec: public Rev 4 Triple Ratchet composition + ML-KEM Braid as preferred SCKA.  
Status: classical DR ‖ SPQR ‖ Braid SCKA with incremental Encaps1/Encaps2. Encaps1‖Encaps2 matches `ml-kem` Encrypt in-repo. Not independently reviewed (`TRIPLE_RATCHET.md`, `POST_QUANTUM_PROFILE.md`).
