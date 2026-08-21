# DOUBLE_RATCHET_IMPLEMENTATION.md

**Specification:** The Double Ratchet Algorithm, Revision 4 (public, signal.org)  
**Scope:** Classical (elliptic-curve) Double Ratchet only  
**Date:** 2026-08-17

## Spec → Code Mapping

| Public Spec Construct | Implementation |
|-----------------------|----------------|
| State: DHs, DHr, RK, CKs, CKr, Ns, Nr, PN, MKSKIPPED | `DoubleRatchetState` |
| GENERATE_DH / DH | `X25519Secret::generate` / `diffie_hellman` |
| KDF_RK | `kdf_rk` using `LABELS::DR_ROOT` |
| KDF_CK | `kdf_ck` using `LABELS::DR_CHAIN` + `DR_MESSAGE` |
| ENCRYPT / DECRYPT | `aead::seal` / `aead::open` (AES-256-GCM) |
| HEADER / CONCAT | `Header` + `concat_ad` |
| RatchetEncrypt | `DoubleRatchetState::encrypt` |
| RatchetDecrypt | `DoubleRatchetState::decrypt` (transactional) |
| TrySkippedMessageKeys | `try_skipped_message_keys` |
| SkipMessageKeys | `skip_message_keys` with hard `max_skip` |
| DHRatchet | `dh_ratchet` |
| RatchetInitAlice / InitBob | `init_alice` / `init_bob` |
| MAX_SKIP | `DEFAULT_MAX_SKIP = 1000`, configurable per state |

## Required Invariants Enforced

- **decrypt(tampered) = failure ∧ state unchanged**  
  Implemented by speculative trial state; only committed after AEAD success.

- **Bounded skip**  
  `skip_message_keys` rejects any `until` that would exceed `max_skip` steps or stored keys. Protects against CPU / memory / skipped-key explosion.

- **Forward secrecy**  
  After a message key is used it is deleted from `MKSKIPPED` (or never stored). Structural test confirms old ciphertexts become undecryptable.

- **Secure deletion**  
  `Zeroize` / `ZeroizeOnDrop` on all secret fields; intermediates zeroized.

- **Transactional state**  
  No durable mutation before authentication succeeds.

## Tests Present

- Classic A1 → A2 → A3 → B1 → B2 → A4 sequence.
- Tampered ciphertext leaves state identical.
- MAX_SKIP rejection of enormous message numbers.
- Out-of-order delivery within bound.
- Forward-secrecy structural check.
- Serialize → deserialize → continue session after every major transition.

## Randomized Simulation Guidance

A full 100 × 10 000-message stress harness (drops, delays, reorders, restarts, duplicates, corruption) is expressed as a configurable integration test. On a modern toolchain it can be enabled with:

```rust
// tests/ratchet_stress.rs (to be expanded)
proptest / loop over conversations with controlled drop/reorder probability.
```

The unit tests already exercise the critical safety properties; the stress harness validates liveness and bound enforcement under load.

## Notes

- Header encryption variant and SPQR / Triple Ratchet are deliberately out of scope for this prompt; they build on the same state machine.
- All KDF labels remain the frozen VoiceChat domain-separated strings.
- No libsignal code, naming, or binary formats were used.
