# Mutation testing findings — 2026-09-01

**Tool:** `cargo-mutants` 26.0.0 (prebuilt `x86_64-pc-windows-msvc` binary). 27.x needs rustc ≥ 1.88; this repo pins 1.85.
**Crate compile:** `1.85.0-x86_64-pc-windows-gnu` with `CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=gcc` (MSVC `link.exe` is not present on this machine).
**Config:** `.cargo/mutants.toml` skips `ten_thousand` inside mutation runs only. Baseline on this host: 69s build + 8s test; ~20s per mutant with `-j 2`.
**Score formula:** caught ÷ (caught + missed). Unviable mutants are not in the denominator.

v1 exit criterion (from `docs/dycrpt-v1-scope-and-comparison.md` Gate 3): **≥ 85%** on `src/primitives/`, `src/ratchet/`, `src/pqxdh/`, `src/replay/`, and `src/storage/`. Every survivor is either killed with a new test or justified in `KNOWN_LIMITATIONS.md`.

This file records two measured files. It is not a v1 Gate 3 pass.

---

## 1. `src/primitives/xeddsa.rs` — 100%

First measured score (review 2026-08-28, before killing tests): **90.2%** (37 caught, 4 missed, 4 unviable).

All four survivors were on rejecting / domain-separation paths, in the same file that produced F1 (canonical-`s` malleability):

| # | Mutant | Why it survived |
|---|---|---|
| 1 | `replace le_int_ge_p -> bool with false` | XEdDSA §2.5 `u >= p` rejection was never exercised. A build that accepted every public-key encoding would have passed the entire suite. |
| 2 | `replace < with <= in le_int_ge_p` | Canonicality boundary untested at `p-1` / `p` / `p+1`. |
| 3 | `replace hash_i -> [u8; 64] with [0; 64]` | Domain separation between `hash_1` (nonce derivation) and the plain challenge hash was never asserted. |
| 4 | `replace hash_i -> [u8; 64] with [1; 64]` | Same. A constant `hash_i` passed every existing test. |

Four tests added, one per property. After the tests, the review re-run was 41 caught, 0 missed = **100%**.

### XEdDSA tests that pass on this tree (this session)

Command:

```text
cargo +1.85.0-x86_64-pc-windows-gnu test --offline --lib -- xeddsa::
```

```text
running 10 tests
test primitives::xeddsa::tests::le_int_ge_p_boundary_is_exact ... ok
test primitives::xeddsa::tests::hash_i_is_domain_separated_and_prefix_dependent ... ok
test primitives::xeddsa::tests::public_a_matches_convert_mont ... ok
test primitives::xeddsa::tests::non_canonical_public_key_u_ge_p_is_rejected ... ok
test primitives::xeddsa::tests::tampered_signature_fails ... ok
test primitives::xeddsa::tests::s_equal_to_order_is_rejected ... ok
test primitives::xeddsa::tests::wrong_message_fails ... ok
test primitives::xeddsa::tests::wrong_key_fails ... ok
test primitives::xeddsa::tests::sign_verify_roundtrip ... ok
test primitives::xeddsa::tests::non_canonical_s_plus_order_is_rejected ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 200 filtered out; finished in 3.76s
```

Happy-path and obvious-failure tests (`sign_verify_roundtrip`, `wrong_key`, `wrong_message`, `tampered_signature`) were already present. They did not kill the four survivors. The killing tests are the four rejection/domain tests.

This session did **not** re-run `cargo mutants --file src/primitives/xeddsa.rs` after the killing tests. The 100% figure is the review re-run recorded in the 2026-09-01 patch, not a second measurement here.

---

## 2. `src/ratchet/mod.rs` (Double Ratchet state machine) — 80.8%

This is the v1 Classical Double Ratchet. Hybrid / header-encrypt / SPQR / braid modules are feature-gated and were **not** measured in this pass (`src/ratchet/**` is 835 mutants; this file is 89).

Command:

```text
cargo mutants -f src/ratchet/mod.rs -j 2 -o mutants-ratchet.out -- --lib
```

```text
Found 89 mutants to test
ok       Unmutated baseline in 69s build + 8s test
89 mutants tested in 17m: 14 missed, 59 caught, 16 unviable
```

| | Count |
|---|---|
| Examined | 89 |
| Caught | 59 |
| Missed | 14 |
| Unviable | 16 |
| Timeout | 0 |
| **Score** | **59 / (59 + 14) = 80.8%** |

Below the v1 85% bar.

### Existing Double Ratchet tests (what the suite already covers)

These 11 tests in `src/ratchet/mod.rs` are the coverage the mutants ran against (plus the rest of `--lib`, with `ten_thousand` skipped):

| Test | What it checks |
|---|---|
| `alice_init_rejects_noncontributory_peer_dh` | `init_alice` rejects low-order peer DH |
| `low_order_ratchet_header_fails_without_state_change` | decrypt of low-order header fails; state unchanged |
| `sequence_a1_a2_a3_b1_b2_a4` | happy-path bidirectional encrypt/decrypt |
| `tampered_message_leaves_state_unchanged` | AEAD fail does not commit |
| `tampered_out_of_order_message_restores_skipped_map` | failed skip-ahead decrypt rolls back skipped keys |
| `max_skip_protects_against_explosion` | `header.n = 10_000` with `max_skip = 5` is rejected; `skipped_count() <= 5` |
| `serialize_reload_preserves_session` | serialize/deserialize round-trip continues the conversation |
| `out_of_order_within_bound` | decrypt 1, 3, then 2 |
| `deserialize_rejects_noncanonical_presence_tag` | presence tag `2` is rejected |
| `deserialize_rejects_max_skip_mismatch` | stored max_skip ≠ caller max_skip |
| `deserialize_rejects_trailing_bytes` | extra trailing byte rejected |

Happy-path, tamper, and a few deserialize rejections are present. Several *other* rejection and hygiene paths are not independently asserted. That is the same shape as F1 and as the XEdDSA survivors.

### 14 survivors (the list to kill)

Grouped. These are the mutants the suite cannot see.

#### A. Secret wipe / Drop — 3

Hygiene, not functional correctness. Tests never observe whether skipped message keys are zeroized.

```
src/ratchet/mod.rs:81:9: replace <impl Zeroize for SkippedKeys>::zeroize with ()
src/ratchet/mod.rs:90:9: replace <impl Drop for SkippedKeys>::drop with ()
src/ratchet/mod.rs:156:9: replace <impl Drop for SkippedMutationJournal>::drop with ()
```

`SkippedKeys::drop` only calls `zeroize()`, so those two are the same untested wipe. `SkippedMutationJournal::drop` wipes a removed message key on rollback.

#### B. Skipped-key accessors never read — 5

`len`, `iter`, and `skipped_count` are unused by assertions except `max_skip_protects_against_explosion`, which only checks `skipped_count() <= 5`. Returning `0` or `1` still satisfies `<= 5` when the skip is rejected before insertion.

```
src/ratchet/mod.rs:109:9: replace SkippedKeys::len -> usize with 0
src/ratchet/mod.rs:109:9: replace SkippedKeys::len -> usize with 1
src/ratchet/mod.rs:113:9: replace SkippedKeys::iter -> impl Iterator<...> with ::std::iter::empty()
src/ratchet/mod.rs:535:9: replace DoubleRatchetState::skipped_count -> usize with 0
src/ratchet/mod.rs:535:9: replace DoubleRatchetState::skipped_count -> usize with 1
```

A test that actually skips (out-of-order decrypt of message 3 after 1) and asserts `skipped_count() == 1` (or inspects `iter`) would kill all five.

#### C. Outer skip bound is redundant with the inner bound — 2

```
src/ratchet/mod.rs:352:18: replace < with == in DoubleRatchetState::skip_message_keys_journaled
src/ratchet/mod.rs:352:18: replace < with <= in DoubleRatchetState::skip_message_keys_journaled
```

`skip_message_keys_journaled` has two LimitExceeded checks:

```rust
if limit < until {                // line 352 — OUTER, untested independently
    return Err(LimitExceeded);
}
while self.nr < until {
    if self.mkskipped.len() as u32 >= self.max_skip {  // line 357 — INNER, caught
        return Err(LimitExceeded);
    }
    ...
}
```

`max_skip_protects_against_explosion` still fails via the inner loop when the outer comparison is mutated, so the outer bound is dead as far as the suite is concerned. Need a case that trips `limit < until` *without* entering the inner `len >= max_skip` path (or that distinguishes `==` / `<=` from `<`).

The inner `>=` → `<` mutant **was** caught (unviable/caught list includes it as unviable actually — `replace >= with <` is in unviable, meaning it did not compile or the tests failed at build? Unviable = does not compile. Wait, unviable is compile failure. Caught would be tests fail.

Looking at unviable list: `replace >= with < in skip_message_keys_journaled` is unviable. So flipping that comparison didn't even compile? Unusual. Anyway the outer `<` mutants missed.

#### D. Deserialize skipped-count ceiling untested — 2

```
src/ratchet/mod.rs:499:18: replace > with == in DoubleRatchetState::deserialize
src/ratchet/mod.rs:499:18: replace > with >= in DoubleRatchetState::deserialize
```

```rust
let count = read_u32(data, &mut i)? as usize;
if count > max_skip as usize {   // line 499
    return Err(PrimitiveError::LimitExceeded);
}
```

Existing deserialize tests cover presence-tag, max_skip field mismatch, and trailing bytes. None construct a blob whose skipped-entry *count* exceeds `max_skip`. A crafted snapshot with `count = max_skip + 1` (and matching payload length) would kill these.

#### E. Triple-Ratchet key-export API unused by default tests — 2

```
src/ratchet/mod.rs:299:9: replace DoubleRatchetState::receive_message_key -> Result<[u8; 32], PrimitiveError> with Ok([0; 32])
src/ratchet/mod.rs:299:9: replace DoubleRatchetState::receive_message_key -> Result<[u8; 32], PrimitiveError> with Ok([1; 32])
```

`receive_message_key` is documented as the Triple Ratchet transactional path. Default-feature `--lib` tests only call `encrypt` / `decrypt`. Returning a constant key is invisible. Either call this API from a Classical test that decrypts with the derived key, or accept it as untested because Triple Ratchet is v1-out-of-scope (feature-gated `hybrid`) — in that case record it in `KNOWN_LIMITATIONS.md` rather than leaving a silent hole on a `pub` method that still compiles in Classical.

### Unviable (16) — compile-time, not a coverage hole

These did not produce a compilable mutant. They do not affect the 80.8% score.

```
Header::decode -> Ok(Default::default())
SkippedKeys::iter -> once(([0;32])) / once(([1;32]))
RatchetScalarSnapshot::capture -> Default::default()
init_alice -> Ok(Default::default())
init_bob -> Default::default()
encrypt -> Ok((Default::default(), vec![] / [0] / [1]))
send_message_key -> Ok((Default::default(), [0;32] / [1;32]))
skip_message_keys_journaled: replace >= with <
clone_for_trial -> Default::default()
deserialize -> Ok(Default::default())
aead_from_mk -> Ok((Default::default(), [0;12] / [1;12]))
```

Most are `Default::default()` substitutions on types that are not `Default`.

---

## 3. The pattern (actual finding)

Same as F1 and as the XEdDSA 90.2% run:

**The suite covers what the code accepts, and almost nothing about what it must refuse — or wipe, or count.**

| File | Score | Survivor cluster |
|---|---|---|
| `src/primitives/xeddsa.rs` (after killing tests) | 100% (review re-run) | Were: input validation + domain separation |
| `src/ratchet/mod.rs` (this session) | **80.8%** | Secret wipe, unused accessors, redundant skip bound, deserialize count ceiling, unused Triple key-export API |

Round-trip, tamper, and a handful of deserialize tests are all present and all passing. They do not pin the outer skip bound, the skipped-count ceiling, skipped-key cardinality after a real skip, or zeroization.

When the rest of `src/ratchet/**` (835 mutants, including hybrid/header-encrypt), `src/pqxdh/`, `src/replay/`, and `src/storage/` are measured, expect the same clustering on validation and rejection paths.

---

## 4. Not measured this session

| Target | Mutants listed | Status |
|---|---|---|
| `src/ratchet/**` (braid, header_encrypt, scka, spqr, triple) | 835 | Not run. Hybrid/header-encrypt are v1-out-of-scope feature gates. |
| `src/primitives/` except xeddsa | — | Not run |
| `src/pqxdh/`, `src/replay/`, `src/storage/` | — | Not run |
| Re-measure of xeddsa after killing tests | 45-ish | Not re-run here; 100% is the review figure |

Reproduce Double Ratchet:

```bash
# rustc 1.85, cargo-mutants 26.0.0
cargo mutants -f src/ratchet/mod.rs -j 2 -- --lib
```

Raw outcome files from this run: `mutants-ratchet.out/mutants.out/{caught,missed,unviable}.txt`.
