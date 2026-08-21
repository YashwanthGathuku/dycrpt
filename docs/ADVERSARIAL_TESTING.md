# ADVERSARIAL_TESTING.md — Property Tests, Fuzzing, Adversarial Simulation

**Date:** 2026-08-17

## Core properties (must always hold)

| Property | Test |
|----------|------|
| `decrypt(encrypt(m)) == m` | `core_properties::decrypt_encrypt_roundtrip` |
| Valid sender/receiver only | wrong-session decrypt fails |
| `decrypt(tamper(c)) == failure` | `decrypt_tamper_fails_and_state_unchanged` |
| `decrypt(c, wrong_session) == failure` | `decrypt_wrong_session_fails` |
| `replay(c) != second_valid_application_message` | `replay_not_accepted_twice_by_cache` |
| `identity_change != silent_success` | `identity_change_not_silent_success` |
| `failed_decryption does_not_commit_ratchet_state` | `failed_decryption_does_not_commit_ratchet_state` |

## Adversarial simulations mapped

| Attack | Coverage |
|--------|----------|
| MITM | Fingerprint mismatch on substituted identity |
| Replay / packet duplication | ReplayCache second insert = true |
| Packet modification | AEAD failure |
| Packet truncation | AEAD / length failure |
| Malformed serialization | Envelope parse reject |
| Invalid curves / public keys | Zero-key / wrapper validation |
| Malformed ML-KEM data | KEM ciphertext reject (PQXDH layer) |
| Stale signed prekeys | Signature validation fail (prekeys) |
| Reused one-time prekeys | Consumption + replay model |
| Prekey exhaustion | Device/session limits |
| Reordered messages | Out-of-order within MAX_SKIP |
| Extreme skipped-message indexes | MAX_SKIP rejection |
| Identity replacement | IDENTITY_CHANGED |
| Session-state rollback | StorageEpoch monotonicity |
| Corrupted database | Deserialize / epoch checks |
| Crash during encrypt / decrypt / ratchet update | Transactional storage + trial state |
| Simultaneous sends | Independent message keys |
| Simultaneous session establishment | Session manager limits |
| Malicious oversized messages | MAX_PAYLOAD_LEN reject |
| Random byte input | Parse no-panic |

## Fuzz targets (every external parser)

| Target | Parser |
|--------|--------|
| `envelope_parse` | `Envelope::parse` |
| `header_decode` | `Header::decode` |
| `triple_header_decode` | `TripleHeader::decode` |

```bash
cargo fuzz run envelope_parse
cargo fuzz run header_decode
cargo fuzz run triple_header_decode
```

## Property-based / long sequences

- Alternating 200-message conversations
- One-sided 50-message bursts then reply
- On a modern toolchain, expand with `proptest` to millions of state-machine sequences (see PQXDH 10k handshake trials pattern)

## Failure seed registry

`testing::adversarial::KNOWN_FAILURE_SEEDS` — append every discovered bug seed permanently. Each seed gets a dedicated regression test that must never be deleted.

## Sanitizers / memory safety

| Tool | Use |
|------|-----|
| Rust safe subset (`#![deny(unsafe_code)]`) | Default |
| `cargo +nightly miri` | Interpreter checks for UB on critical paths |
| AddressSanitizer / LeakSanitizer | `RUSTFLAGS="-Zsanitizer=address" cargo test` (nightly) |
| `cargo fuzz` + libFuzzer | Continuous parser fuzzing |
| `zeroize` drop tests | Secret residual checks |

## Permanent regression rule

Every cryptographic or state-machine bug found in simulation or fuzzing:

1. Record exact seed in `KNOWN_FAILURE_SEEDS`
2. Add a named `#[test]` that reproduces the failure mode and asserts the fixed behavior
3. Never remove that test
