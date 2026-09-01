# TEST_EVIDENCE.md

**Status:** PARTIALLY VERIFIED (internal). **Not VERIFIED** by independent auditors.  
P0 handshake/storage remediations executed. **Not production-ready.** Not formally verified. Not quantum-proof. Hybrid/SPQR/HE are **optional Cargo features** and are **not** in `PROFILE_PREFERENCE` (default advertised = ClassicalV1).

Host: rustc 1.96, `stable-x86_64-pc-windows-gnu` via `rust-lld`, `CARGO_INCREMENTAL=0`.  
OpenJDK 21.0.12 + TLC2 2026.08.11.125311 (`formal/tools/tla2tools.jar`).

## This session (crypto-parity harness)

Isolated `crypto-parity` crate. libsignal **not** linked (AGPL). Property corpus, not byte-equality.

```
cargo run -p crypto-parity
    VoiceChatCrypto corpus (74 scenarios); libsignal=NotLinked
    Signal-Core 100.0% (44/44)
    Operational 100.0% (17/17)
    VoiceChat invariants 100.0% (13/13)
    P0 failures: 0
    Randomized transitions: 10128 (violations 0)
    Malformed inputs: 33 (panics 0)
    process exit 0
```

`--full` (1M DR events / 10k PQXDH) not run this session. Pin of VoiceChat’s libsignal revision: **UNVERIFIED** (app not in workspace).

## Prior (reviewer hardening cycle)

Independent review of the source ZIP. In-repo fixes for items 1–10 of the recommended order. **Not production-ready.**

| Command | Result |
| ------- | ------ |
| `cargo fmt --all -- --check` | exit 0 |
| `clippy --all-targets --all-features --offline -- -D warnings` | `Finished dev profile … in 6.68s` exit 0 |
| `cargo test --all-targets --all-features --offline -- --skip ten_thousand` | **0 failed.** lib `ok. 160 passed; … 1 filtered; 3.35s`. crash 8; DR 2 (45.94s); engine 2 (68.98s); hybrid 7; matrix 19; p0 1; state 6; adapter 3 |

New tests: `handshake_opk_and_session_atomic_across_reload`, `trust_not_implied_by_session_until_ack`, `trust_store_roundtrip_does_not_imply_ack`, `serialize_reload_preserves_entries`.

## Prior (production-engineering pass)

`PRODUCTION_READY` remains **false** (external audit required). Engineering gates after last source edit:

| Command | Result |
| ------- | ------ |
| `cargo fmt --all -- --check` | exit 0 |
| `clippy --all-targets --all-features --offline -- -D warnings` | exit 0 (`Finished dev profile … in 5.19s`) |
| `cargo test --all-targets --all-features --offline -- --skip ten_thousand` | **0 failed.** lib `ok. 156 passed; … 1 filtered out; finished in 3.09s`. crash 8; DR 2 (27.67s); engine 2 (46.89s); hybrid 7; matrix 19; p0 1; state 6; adapter 3 |

New tests: `two_current_peers_select_strongest`, `classical_only_peer_is_not_upgraded`, `recommended_config_uses_preference_head`.

## Prior session (production Triple + full Braid incrementality)

Host: rustc 1.96, `stable-x86_64-pc-windows-gnu` via `rust-lld`, `CARGO_INCREMENTAL=0`. After last source edit.

| Command | Result (verbatim) |
| ------- | ----------------- |
| `cargo fmt --all -- --check` | exit 0 |
| `clippy --all-targets --all-features --offline -- -D warnings` | `Finished dev profile … in 4.99s` exit 0 |
| `cargo test --lib encaps1` | `ok. 2 passed` — `encaps1_encaps2_decaps_matches_mlkem`, `encaps1_matches_official_encrypt_many` (8 seeds, CT = official Encrypt) |
| `cargo test --lib braid` | `ok. 9 passed` including `braid_alice_bob_keys_match`, `incremental_ct1_before_ek`, `serialize_reload_mid_handshake`, Triple epoch tests |
| `cargo test --all-targets --all-features --offline -- --skip ten_thousand` | **0 failed.** lib `ok. 154 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 1.99s`. crash 8; DR sim 2 (20.91s); engine 2 (39.66s); hybrid 7; matrix 19; p0 1; state 6; adapter 3 |

Total this invocation: **154 + 8 + 2 + 2 + 7 + 19 + 1 + 6 + 3 = 202**. One filtered (`ten_thousand`).

## Prior leftover close (Braid-in-Triple, Sesame e2e, TLC)

| Command | Result |
| ------- | ------ |
| `clippy --all-targets --all-features --offline -- -D warnings` | exit 0 |
| `cargo test --all-targets --all-features --offline -- --skip ten_thousand` | lib **149 passed**, 1 filtered; crash 8; DR 2; engine 2; hybrid 7; matrix 19; p0 1; state 6; adapter 3 — **0 failed** |
| TLC `SesameMailbox` | No error. 216 gen / 70 distinct / depth 9 |
| TLC `BraidEpoch` | No error. 33 gen / 20 distinct / depth 8 |

## Prior (Braid / Sesame / profiles / audit packet)

| Command | Result |
| ------- | ------ |
| `cargo fmt` + `clippy --all-targets --all-features --offline -- -D warnings` | exit 0 |
| `cargo test --all-targets --all-features --offline -- --skip ten_thousand` | lib **147 passed**, 1 filtered; crash 8; DR sim 2; engine 2; hybrid 7; matrix 19; p0 1; state 6; adapter 3 — **0 failed** |
| `cargo test --lib braid` | `braid_alice_bob_keys_match`, RS systematic + drop recovery **ok** |

## Prior session (FFI + host fuzz finish)

No crate source edits after these runs.

| Command | Result (verbatim) |
| ------- | ----------------- |
| `cargo fmt --check` | exit 0 (no diff) |
| `cargo clippy --all-targets --all-features --offline -- -D warnings` | `Finished dev profile … in 4.72s` exit 0 |
| `CARGO_INCREMENTAL=0 cargo test --all-targets --all-features --offline -- --skip ten_thousand` | **0 failed.** lib `ok. 140 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 2.37s` (includes `alice_bob_ffi_pqxdh_no_secrets_cross`, `initiation_packet_encode_decode_roundtrip`) |
| crash_hardening | `ok. 8 passed` |
| double_ratchet_simulation | `ok. 2 passed … 33.46s` |
| engine_conversation | `ok. 2 passed … 21.13s` |
| hybrid_pq | `ok. 7 passed` |
| migration_matrix | `ok. 19 passed` |
| p0_two_party | `ok. 1 passed` |
| state_machine | `ok. 6 passed` |
| voicechat_adapter | `ok. 3 passed` |
| `cargo build --manifest-path fuzz/Cargo.toml --offline` | **exit 0** (`Finished dev profile … in 8.30s`) — default bins only; no `libfuzzer` feature |
| `cargo run --manifest-path fuzz/Cargo.toml --offline --bin host_runner -- 20000` | `host_runner ok iters=20000` |

## Prior P0 command evidence (unfiltered suite, same project)

Same-task-family logs from before the FFI rewrite. PQXDH / ratchet math was not changed in the FFI pass.

| Command | Result (verbatim from logs) |
| ------- | --------------------------- |
| `CARGO_INCREMENTAL=0 cargo test --all-targets --all-features --offline` | **0 failed**. lib `ok. 140 passed … finished in 554.65s` including `ten_thousand` |
| `cargo test --lib ten_thousand` | `ok. 1 passed; 0 failed; … 119 filtered out; finished in 690.15s` |
| `cargo build --manifest-path fuzz/Cargo.toml` (old, with required libfuzzer-sys) | **FAILED** — `libfuzzer-sys` `FuzzerExtFunctionsWindows.cpp` / `__pragma`. Replaced by optional `--features libfuzzer` + `host_runner`. |

### Unfiltered suite breakdown

`cargo test --all-targets --all-features --offline` (`Finished test profile … in 6.65s`):

| Crate / binary | Verbatim `test result` |
| -------------- | ---------------------- |
| lib (`src/lib.rs`, 140 tests, includes `ten_thousand_randomized_handshakes`) | `ok. 140 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 554.65s` |
| `tests/crash_hardening.rs` | `ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s` |
| `tests/double_ratchet_simulation.rs` | `ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 19.98s` |
| `tests/engine_conversation.rs` | `ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 15.73s` |
| `tests/hybrid_pq.rs` | `ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.37s` |
| `tests/migration_matrix.rs` | `ok. 19 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.50s` |
| `tests/p0_two_party.rs` | `ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.11s` |
| `tests/state_machine.rs` | `ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s` |
| `tests/voicechat_adapter.rs` | `ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.27s` |

Total passing tests in that unfiltered invocation: **140 + 8 + 2 + 2 + 7 + 19 + 1 + 6 + 3 = 188**. Zero ignored. Zero filtered on the unfiltered command.

## Earlier same-task / historical command evidence

| Command | Result |
| ------- | ------ |
| `cargo test --all-targets --all-features -- --skip ten_thousand` | lib **137 passed**; crash 8; DR sim 2; engine conv 2; hybrid 7; matrix 19; **p0_two_party 1**; state 6; adapter 3 |
| `cargo test --lib serialize_reload_preserves_consumed_set` | **ok** |
| `cargo test --lib crash_reload` | **3 passed** including `crash_reload_rejects_reused_one_time_prekey` |
| `cargo test --features ffi --lib -- --skip ten_thousand` | `ok. 137 passed; 0 failed; 1 filtered out; finished in 2.25s` |
| `cargo test --test crash_hardening` | `ok. 8 passed` |
| `cargo test --test hybrid_pq` | `ok. 7 passed` (hybrid header=1236 B vs classical 40) |
| `cargo test --test migration_matrix` | `ok. 19 passed` |
| `cargo test --test state_machine` | `ok. 6 passed` |
| `cargo test --test voicechat_adapter` | `ok. 3 passed` |
| `cargo test --test engine_conversation` | `ok. 2 passed` (20×80 classical + hybrid, 29.71s) |
| `cargo test --test double_ratchet_simulation` (debug) | `ok. 2 passed` — **100 conversations × 250 messages**, 31.89s |
| `cargo test --release --test double_ratchet_simulation` | `ok. 2 passed` — **100 conversations × 10_000 messages**, 155.22s |
| TLC `PrekeyConsumption` | No error. 289 gen / 64 distinct / depth 4 |
| TLC `RatchetState` | No error. 1824 gen / 840 distinct / depth 29 |
| TLC `ReplayAndIdentity` | No error. 4225 gen / 576 distinct / depth 10 |
| `cargo test --lib ten_thousand` (older run) | `ten_thousand_randomized_handshakes ... ok` — **10_000 SK-equality** in **928.10s** |

## Prompt status (honest)

| Prompt | Status | Evidence |
| ------ | ------ | -------- |
| 0 Source boundary | Done | `docs/SOURCE_BOUNDARY.md` — official specs only; no libsignal |
| 1 Architecture | Done | `docs/ARCHITECTURE.md` + crate modules |
| 2 Primitives | Tested | RFC 7748 / RFC 5869 / AEAD / real ML-KEM / XEd25519 in lib tests |
| 3 PQXDH | Tested | SK-equality + unfiltered 10k handshake; bundle/sig/OPK negatives |
| 4 Double Ratchet | Tested | Unit A1…A4 + **100×10_000 release sim passed** |
| 5 Envelope | Tested | Binding, version, overflow, synthetic-voice |
| 6 Hardening | Tested | Crash/rollback/replay/padding/downgrade + **engine `simulate_crash_reload`** for classical and hybrid |
| 7 Safety numbers | Tested | Commutative fingerprint + identity-change |
| 8 Sesame manager | **Not production** | `SessionManager` records tested. `sesame` module gated; retry path uses hardcoded SK |
| 9 Triple / hybrid | Tested + incremental Braid | Encaps1/Encaps2 + RS chunks. `braid_completes_epoch_and_ct1_precedes_ek`, `serialize_mid_braid_then_finish_epoch`, `serialize_reload` + hybrid_pq **ok** |
| 10 Header encryption | Tested (optional) | Engine `ClassicalHeV1` roundtrip + serialize/crash-reload; not default |
| 11 Adversarial | Tested | `src/testing/adversarial.rs` + fuzz parsers; **cargo-fuzz host build FAILED**; not millions of sequences / not continuous CI |
| 12 Formal model | TLC finite instances | See above. **Library is not formally verified** |
| 13 FFI | Rust C-ABI tested | Alice↔Bob PQXDH via `vc_establish_outbound`/`vc_process_inbound` (no SK/DH arguments). **No physical Android/iOS devices** |
| 14 VoiceChat adapter | In-repo tested | `CryptoEngineApi` lifecycle + voice-profile refuse. **Parent app not in workspace** |
| 15 Migration matrix | Tested | 19 behavioral scenarios PASS (properties, not ciphertext-identical to Signal) |
| 16 Audit package | Packaged | Docs present. Independent expert review **not done** |

## Suites

| Suite | Location | Evidence |
| ----- | -------- | -------- |
| Primitives | `src/primitives/` | RFC 7748, RFC 5869, AEAD negatives, real ML-KEM |
| XEd25519 | `src/primitives/xeddsa.rs` | Roundtrip + tamper |
| PQXDH | `src/pqxdh/` | SK equality + 10k real ML-KEM handshakes |
| Double Ratchet | `src/ratchet/` + `tests/double_ratchet_simulation.rs` | A1…A4, MAX_SKIP, 100×10k release |
| Triple + CKA | `src/ratchet/triple/`, `scka.rs`, `tests/hybrid_pq.rs` | Hybrid keys + matching ML-KEM CKA |
| Engine profiles | `src/engine/` | Classical, HE, Hybrid dispatch; full-session persist + crash reload |
| Envelope / parsers | `src/envelope/`, `testing/fuzz_parsers.rs` | Binding + random streams |
| FFI | `src/ffi/` (`--features ffi`) | Identity, size-query (no key consume), Alice/Bob interop, fingerprint |
| Crash / rollback | `tests/crash_hardening.rs` | Abort-before-commit, epoch rollback |
| Formal (exec) | `tests/state_machine.rs` | Same invariants as TLA+ against Rust |
| Formal (TLC) | `formal/tla/*.cfg` | Finite-state checks recorded |
| Migration matrix | `tests/migration_matrix.rs` | Required scenarios PASS or stronger |
| Adapter | `tests/voicechat_adapter.rs` | App-facing API |
| P0 two-party | `tests/p0_two_party.rs` | A1→B1→A2/B2→OOO→reload→tamper→replay |

## Failure seeds

`testing::adversarial::KNOWN_FAILURE_SEEDS` — empty until bugs found.

## Remaining (not claimed / not done)

- Production-ready
- Formally verified (TLC checked **finite models**, not the crypto)
- Quantum-proof
- Independent review of Encaps1/Braid (in-repo tests only; lattice code is ours + `ml-kem` 0.3.2)
- Physical Android/iOS device interop
- Independent security review
- Ciphertext / wire compatibility with libsignal
- `cargo-fuzz` / `libfuzzer-sys` **on this Windows GNU host** (optional feature; `host_runner` **does** build and ran 20_000 iters)
- Parent VoiceChat app (not in this workspace)

## Assurance run — 2026-08-28 (review branch `hardening/f1-f4-review-fixes-2026-08-28`)

Toolchain: rustc 1.85.0 (per `rust-toolchain.toml`), x86_64-unknown-linux-gnu.

| Gate | Command | Result |
|---|---|---|
| Format | `cargo fmt --all -- --check` | clean |
| Lint (default) | `cargo clippy --all-targets -- -D warnings` | 0 |
| Lint (all features) | `cargo clippy --all-targets --all-features -- -D warnings` | 0 |
| Lint (release bin) | `cargo build --release --bin ct_timing` | 0 warnings |
| Tests | `cargo test --tests --all-features -- --skip ten_thousand` | 318 passed, 0 failed |
| 10k handshakes | `cargo test --release --all-features ten_thousand` | 1 passed, 11.66 s |
| Parity | `cargo run -p crypto-parity --bin crypto-parity` | P0=0 core=100.0 ops=100.0 vc=100.0 |
| Fuzz (CI) | `cargo run --manifest-path fuzz/Cargo.toml --bin host_runner -- 100000` | ok; corpus_accepts=9 mutated_accepts=27073 random_accepts=12599 |
| Fuzz (long) | `host_runner 5000000` | ok, 38 s; mutated_accepts=1361211 random_accepts=627561 |
| Timing | `ct_timing --samples 500000` | samples=500000 welch_t=0.7675 max_abs_t=10 passed=true |

Patch series verified by `git am` onto a clean checkout of
`hardening/p0-audit-fixes-2026-08-22`: applies without conflict, 318 tests pass.

### Gate caveats recorded for the auditor

1. **`ct_timing` argument form.** It parses `--samples N`. A positional argument
   is silently ignored and the 250,000 default is used. A CI line reading
   `ct_timing 500000` measures half the intended sample count and still reports
   `passed: true`.
2. **`ct_timing` probe coverage.** One probe only: `x25519-secret-class`. It does
   not cover AEAD tag comparison, wire decoders, skipped-message-key lookup, or
   XEdDSA scalar decoding. A green timing gate is evidence about X25519 secret
   handling and nothing else.
3. **`host_runner` is not a coverage-guided fuzzer.** It is a structure-aware
   mutational walk with no instrumentation feedback. The `libfuzzer` targets in
   `fuzz/fuzz_targets/` remain the real fuzzing surface and still require
   `cargo-fuzz` on nightly; CI builds them but does not run them.
4. **Prior fuzz history is void.** Before this branch, `fuzz/Cargo.toml` lacked a
   `[workspace]` table, so every CI fuzz invocation exited non-zero at manifest
   resolution before compiling. Any earlier green fuzz run in this repository's
   history should be treated as no evidence at all.

## Mutation testing — first run, 2026-08-28

Tool: `cargo-mutants` 26.0.0 (27.x requires rustc >= 1.88; this repo pins 1.85).

`cargo-mutants` injects a small fault per run — flip a comparison, replace a return value — and
reruns the suite. A mutant that survives is a fault the test suite provably cannot detect. This
is the general form of the F1 finding: F1 was one real, undetectable fault, and the mutation
score says how many more there are.

### Practical blocker found first

The initial run reported an unusable cycle time: **55s build + 539s test per mutant**, i.e. ~7
hours for 45 mutants on one file. Cause: the `ten_thousand` randomized handshake gate takes
11.7s in release and ~533s in debug, which is 99% of the debug lib-suite runtime. Every other
lib test totals 6s.

`.cargo/mutants.toml` now skips that one test inside mutation runs only. It is **not** disabled —
it still runs in release via its own CI step. Cycle time went from ~10 minutes to ~1 minute per
mutant.

### Result: src/primitives/xeddsa.rs

| Run | Caught | Missed | Unviable | Score |
|---|---|---|---|---|
| Before | 37 | 4 | 4 | 90.2% |
| After killing tests | 41 | 0 | 4 | **100%** |

All four survivors were in input validation and domain separation, in the same file that produced
the F1 signature-malleability finding:

1. `replace le_int_ge_p -> bool with false` — the XEdDSA 2.5 requirement to reject `u >= p` was
   **never exercised**. A build accepting every public-key encoding would have passed the entire
   suite.
2. `replace < with <= in le_int_ge_p` — the canonicality boundary was untested at `p - 1` / `p` /
   `p + 1`.
3, 4. `replace hash_i -> [u8; 64] with [0; 64]` / `with [1; 64]` — domain separation between
   `hash_1` (nonce derivation) and the plain challenge hash was never asserted. A constant `hash_i`
   passed every test.

Each is now killed by a test asserting the specific property. Note the pattern: every survivor
was on a *rejecting* path. The existing tests covered what the code accepts and almost nothing
about what it must refuse.

### Remaining work

Only one file of ~50 has been measured. The v1 exit criterion is >= 85% across
`src/primitives/`, `src/ratchet/`, `src/pqxdh/`, `src/replay/` and `src/storage/`, with every
survivor either killed or justified in `KNOWN_LIMITATIONS.md`.

```bash
cargo install cargo-mutants --version 26.0.0 --locked
cargo mutants --file 'src/primitives/**' --file 'src/ratchet/**' -- --lib
```

Budget hours, not minutes: each mutant rebuilds the crate. Run it on a machine you can leave.

## Mutation testing — Double Ratchet, 2026-09-01

Command (this machine: GNU 1.85 + gcc linker, `cargo-mutants` 26.0.0, `-j 2`):

```text
cargo mutants -f src/ratchet/mod.rs -j 2 -o mutants-ratchet.out -- --lib
```

```text
Found 89 mutants to test
ok       Unmutated baseline in 69s build + 8s test
89 mutants tested in 17m: 14 missed, 59 caught, 16 unviable
```

Score: **59 / (59 + 14) = 80.8%**. Below the v1 ≥ 85% bar for `src/ratchet/`.

Fourteen survivors, all on wipe/count/rejection/unused-API paths — same shape as F1 and the XEdDSA 90.2% run. Full classification and the killing-test list: `docs/MUTATION_TESTING.md`.

XEdDSA unit tests after the four killing tests, this session:

```text
cargo +1.85.0-x86_64-pc-windows-gnu test --offline --lib -- xeddsa::
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 200 filtered out; finished in 3.76s
```
