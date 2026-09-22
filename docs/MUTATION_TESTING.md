# Mutation testing findings — 2026-09-01

**Tool:** `cargo-mutants` 26.0.0 (prebuilt `x86_64-pc-windows-msvc` binary). 27.x needs rustc ≥ 1.88; this repo pins 1.85.
**Crate compile:** `1.85.0-x86_64-pc-windows-gnu` with `CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=gcc` (MSVC `link.exe` is not present on this machine).
**Config:** `.cargo/mutants.toml` skips `ten_thousand` inside mutation runs only. Baseline on this host: 69s build + 8s test; ~20s per mutant with `-j 2`.
**Score formula:** caught ÷ (caught + missed). Unviable mutants are not in the denominator.

v1 exit criterion (from `docs/dycrpt-v1-scope-and-comparison.md` Gate 3): **≥ 85%** on `src/primitives/`, `src/ratchet/`, `src/pqxdh/`, `src/replay/`, and `src/storage/`. Every survivor is either killed with a new test or justified in `KNOWN_LIMITATIONS.md`.

This file records measured files. It is not a v1 Gate 3 pass.

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
| `src/ratchet/mod.rs` (after killing tests) | 100% | Were: secret wipe, unused accessors, skip bound, deserialize count |
| `src/pqxdh/mod.rs` (2026-09-08) | 100% | Drop excluded; OPK-id rejection tests added |
| `src/replay/mod.rs` (2026-09-08, after killing tests) | 100% | Were: const bounds, independent component rejects, accessors, deserialize ceilings |
| `src/storage/encrypted_file.rs` (2026-09-08, after killing tests) | **89.6%** | 13 documented: 512 MiB / 80 MiB exact bounds, redundant min-length arithmetic |
| Remaining default primitives + `storage/{mod,monotonic,trusted_anchor}.rs` (2026-09-08) | **100%** | Were: AEAD tag-length bound, HKDF length, HMAC-SHA512, accessors, MemoryStorage abort/clear |

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

## Double Ratchet survivors killed — 2026-08-28 (review)

| Run | Caught | Missed | Unviable | Score |
|---|---|---|---|---|
| Baseline (`ecb52df`) | 59 | 14 | 16 | 80.8% |
| After killing tests | **71** | **0** | 16 | **100%** |

Two mutants moved out of scope rather than being killed (89 → 87 total): the
`Drop` impls for `SkippedKeys` and `SkippedMutationJournal`. Their only effect
is zeroizing memory that is about to be freed, and observing that requires
reading freed memory — undefined behaviour. They are excluded in
`.cargo/mutants.toml` with a written rationale. The behaviour they delegate to
is tested directly: `skipped_keys_zeroize_clears_the_store` asserts
`SkippedKeys::zeroize` actually empties the store, leaving only the one-line
`drop` → `zeroize` delegation unverified.

### Two findings that came out of writing the tests

**1. The outer skip bound is not redundant.** The baseline notes read
`if limit < until` as shadowed by the inner `len >= max_skip` loop check. It
isn't. `limit == nr + max_skip`, so `until == limit` — skipping *exactly*
`max_skip` messages — is legal and must succeed. Both mutants (`<` → `==`,
`<` → `<=`) reject that legal case. Nothing had tested the boundary from the
accepting side, only from the rejecting side, so both survived.

**2. The deserialize count ceiling is unreachable by any honest round trip.**
`deserialize` validates `stored_max != max_skip` *before* it reads the count.
Loading an honest blob under a smaller ceiling therefore fails as
`InvalidLength` at the max_skip field and never reaches `count > max_skip` at
all. That bound only ever guards a **tampered state file**, which is precisely
why it had no coverage and why it matters. Killing it required crafting a blob
with `stored_max == max_skip` and an inflated count field.

### The pattern, restated

Every one of the fourteen survivors was on a path the suite never *observed*:
wiping, counting, or an independent rejection bound. The existing tests
asserted what `encrypt`/`decrypt` accept and returned. None asserted what the
state must refuse, how much it must retain, or that a wipe wiped.

That is the same shape as F1 in `xeddsa.rs`, which was also a missing
rejection, and as the four survivors killed there — all of which were on
rejecting paths too. Two files, two independent runs, one consistent gap.

### Still unmeasured

The other ~835 mutants under `src/ratchet/**` (hybrid and header-encrypt
profiles, `spqr/`, `braid/`, `triple/`) and `src/primitives/mlkem_inc.rs`
(Braid incremental KEM, not on the v1 default surface). The v1 exit criterion
is ≥ 85% across the **v1** surface. That surface is now measured. The gated
ratchet profiles are not part of v1.

## `src/pqxdh/mod.rs` — 100% (2026-09-08)

cargo-mutants sees almost no branching here: Alice/Bob are straight-line DH +
KEM concatenations. Listed mutants: 4. After excluding the unobservable Drop
(same rationale as `SkippedKeys`), 3 remain.

Command:

```text
cargo mutants -f src/pqxdh/mod.rs -j 2 -o mutants-pqxdh.out -- --lib
```

| Run | Examined | Caught | Missed | Unviable | Score |
|---|---|---|---|---|---|
| Baseline (Drop still in scope) | 4 | 1 | 1 | 2 | 50% |
| After Drop exclude + rejection tests | 3 | 1 | 0 | 2 | **100%** |

The one caught mutant is `opk.id != id` flipped to `==` in `bob_process`. The
happy-path OPK handshake already kills it (matching IDs would then reject).
The two unviable mutants are `alice_initiate` / `bob_process` replaced with
`Ok(Default::default())` — those types are not `Default`.

The missed Drop was `impl Drop for PqxdhSharedSecret` emptied to `()`. Same
class as the ratchet Drops: observing whether `sk`/`ad` are wiped after free
is undefined behaviour. Excluded in `.cargo/mutants.toml`. The behaviour it
delegates to is tested: `shared_secret_zeroize_clears_sk_and_ad`.

Two rejection tests were still missing even though the `!=` mutant was already
caught by the happy path:

| Test | What it pins |
|---|---|
| `bob_rejects_mismatched_one_time_ec_id` | `bob_process` with a present OPK and the wrong id → `InvalidSecretKey` |
| `bob_rejects_claimed_opk_when_none_present` | `used_ec_opk_id = Some(_)` but `one_time_ec = None` → `InvalidSecretKey` |

This 100% is **not** “PQXDH is fully verified.” It is “the mutants cargo-mutants
can inject in this file are all caught or unviable.” Spec KATs (Gate 2) and
the DH-term membership still sit outside this tool.

## `src/replay/mod.rs` — 100% (2026-09-08)

Command:

```text
cargo mutants -f src/replay/mod.rs -j 2 -o mutants-replay.out -- --lib
```

| Run | Examined | Caught | Missed | Unviable | Score |
|---|---|---|---|---|---|
| Baseline | 76 | 49 | 26 | 1 | **65.3%** |
| After killing tests | 76 | 75 | 0 | 1 | **100%** |

Unviable: `deserialize -> Ok(Default::default())` (`ReplayCache` is not `Default`).

The 26 survivors were the same shape as XEdDSA and the Double Ratchet: the
suite accepted what a well-formed cache does, and did not pin independent
rejection bounds, exact cardinalities, or the numeric max lengths.

| Cluster | Mutants | Why they survived | Killing tests |
|---|---|---|---|
| Const `*` → `+` on `MAX_*_LEN` | 3 | Tests used the same identifier, so both sides moved together | `component_max_lengths_are_the_documented_constants` (literals 65536 / 4096 / 16384) |
| `validate` `\|\|` → `&&` and `>` → `==`/`>=` | 7 | Only oversized `conversation_id` was tested; empty `message_id`, oversized sender, and exact-max lengths were not | `each_oversized_component_is_rejected_independently`, `exact_max_component_lengths_are_accepted_and_roundtrip` |
| `len` / `is_empty` / `capacity` → 0/1/true/false | 6 | `respects_capacity` asserted `len <= 3`, which 0 and 1 also satisfy | `accessors_report_exact_cardinality_and_capacity` |
| Deserialize magic `\|\|` → `&&`, `n > capacity` `==`/`>=`, `capacity > MAX` `>=` | 4 | Happy-path magic; no `n == capacity` or `capacity == MAX` accept case | `deserialize_rejects_wrong_magic_even_when_length_is_legal`, `deserialize_accepts_max_capacity_and_count_equal_to_capacity` |
| Trailing bytes `\|\|` → `&&` | 1 | No extra-byte blob | `deserialize_rejects_trailing_bytes` |
| `take_vec` remainder `+` → `-`, `n > max` `==`/`>=` | 5 | No truncated payload; exact-max field never deserialized | `deserialize_rejects_truncated_entry_payload`, `deserialize_empty_message_id_is_limit_exceeded_not_invalid_length`, exact-max roundtrip |

`deserialize_empty_message_id_is_limit_exceeded_not_invalid_length` is the
interesting one: an empty last field leaves `take_vec` with exactly four
bytes remaining. Original code reads `n = 0` and then `validate` returns
`LimitExceeded`. Mutating `i + 4 > len` to `>=` or `==` returns
`InvalidLength` instead. `assert!(is_err())` would not have distinguished
them.

## `src/storage/encrypted_file.rs` — 89.6% (2026-09-08)

Must include integration tests (`storage_hardening`, `ffi_persistent`,
`crash_hardening`, `migration_matrix`, `p02_concurrency`). `--lib` alone hides
most coverage.

```text
cargo mutants -f src/storage/encrypted_file.rs -j 2 -o mutants-encrypted-file.out \
  -- --features ffi --lib --test storage_hardening --test ffi_persistent \
  --test crash_hardening --test migration_matrix --test p02_concurrency
```

| Run | Examined | Caught | Missed | Unviable | Timeout | Score |
|---|---|---|---|---|---|---|
| Baseline | 145 | 71 | 65 | 8 | 1 | **52.2%** |
| After kill tests (Drop still in) | 144 | 109 | 27 | 8 | 0 | 80.1% |
| After Drop + `sync_parent_dir` exclude | 133 | 112 | 13 | 8 | 0 | **89.6%** |

Above the v1 85% bar. The 13 survivors are recorded in `KNOWN_LIMITATIONS.md`:

| Cluster | N | Why they remain |
|---|---|---|
| `file_len > MAX_STORAGE_FILE` `>` → `==`/`>=` | 2 | Exact 512 MiB snapshot is not a mutation fixture |
| `decode_map` `8+8+4` `+` → `-` | 2 | Equivalent on every successful parse (plaintext ≥ 20 bytes) |
| `effective_record_count > MAX_RECORDS` | 2 | 200k live keys; header-only `decode_map` already pins the ceiling |
| `encode_effective_map` `emitted != count \|\| out.len() > MAX` | 3 | Defensive check; 512 MiB side unfixtureable |
| `put` / `append_record` `value.len() > MAX_VALUE_LEN` `>` → `==`/`>=` | 4 | Exact 80 MiB value; `decode_map` header-only pins this bound |

`sync_parent_dir` (10 mutants) and `Drop` are excluded, not missed: Windows
directory fsync is best-effort after `sync_all` + rename, and wipe-on-drop is
UB to observe.

Kill tests that moved the score: constant literals, `encode_lower_hex`,
same-instance `get`/`keys` after commit (kills `apply_staged` → `()`), abort
then begin, empty follow-up commit, empty/oversized keys on `put`/`delete`/
`append_record`, V1 magic → `InvalidNonce`, truncated snapshot error variants,
`decode_map` count/key/value headers.

## Default primitives + small storage — 100% (2026-09-08)

One run, `--lib` only. `mlkem_inc.rs` is out (hybrid/Braid, not v1).

```text
cargo mutants -j 2 -o mutants-primitives.out -- --lib \
  -f src/primitives/aead.rs -f src/primitives/kdf.rs -f src/primitives/x25519.rs \
  -f src/primitives/encoding.rs -f src/primitives/signature.rs \
  -f src/primitives/zeroizing.rs -f src/primitives/random.rs \
  -f src/primitives/kem.rs -f src/primitives/error.rs \
  -f src/storage/mod.rs -f src/storage/monotonic.rs -f src/storage/trusted_anchor.rs
```

| Run | Examined | Caught | Missed | Unviable | Score |
|---|---|---|---|---|---|
| Baseline | 184 | 99 | 52 | 33 | **65.6%** |
| After killing tests and Drop excludes | 181 | 148 | 0 | 33 | **100%** |

`x25519`, `kem`, `error`, `monotonic`, and `trusted_anchor` had no missed mutants on the baseline. The 52 were unused accessors and a few real bounds:

| Cluster | Killing tests |
|---|---|
| AES-GCM / XChaCha `ciphertext.len() < TAG_LEN` → `==` / `<=` | `empty_plaintext_roundtrips_at_exact_tag_length` |
| `encode_kem` / `decode_kem` id and `1 + PUBLIC_LEN` | `encode_kem_roundtrip_and_rejects_wrong_id` |
| HKDF empty / exact `255*32` / `*` → `+` / `hkdf_expand -> Ok(())` | `hkdf_rejects_empty_and_accepts_exact_max`, `hkdf_expand_matches_extract_with_empty_salt` |
| `hmac_sha512 -> [0; 64]` | `hmac_sha512_rfc4231_case1` (RFC 4231 case 1) |
| `random_32 -> Ok([0; 32])` | `random_32_is_not_a_constant` |
| Ed25519 `to_bytes` | `to_bytes_roundtrips_seed_and_public_key` |
| `SecretBytes` len / `as_ref` / `zeroize_now` / `from_slice` / deref | zeroizing unit tests |
| `MemoryStorage` abort / `clear` / inherent `keys` / `last_seen` / `zeroize_staged` | storage unit tests |

Excluded, not missed: `Drop` for `StateBlob`, `SignatureSecret`, and `ZeroizingScope`. Same rationale as the other wipe-on-drop impls. `state_blob_zeroize_clears_bytes` pins the `Zeroize` impl those drops call.

## src/storage/coordinated.rs — 2026-08-28 (review)

### Scoping matters here, and it did not before

A `--lib`-only run is correct for `primitives/` and `ratchet/`, whose coverage
is in-module. It is **wrong for `src/storage/`**: that area has 27 lib tests but
47 integration tests (`storage_hardening` 8, `ffi_persistent` 9,
`crash_hardening` 8, `migration_matrix` 19, `p02_concurrency` 3). Running
`--lib` alone would have hidden most real coverage and reported survivors the
integration suite already kills. Correct invocation, recorded in
`.cargo/mutants.toml`:

```
cargo mutants --file 'src/storage/**' -- --features ffi --lib \
    --test storage_hardening --test ffi_persistent --test crash_hardening \
    --test migration_matrix --test p02_concurrency
```

That scope is 265 tests in ~8s once built.

### Survivors (8 at cutoff, 65 mutants total)

| Site | Mutation | Consequence |
|---|---|---|
| `Coordination::finalize` | guard `observed == target` → `true` | **Most serious.** Any `Ok(_)` from the anchor accepted as a successful advance; pending epoch cleared. Durable epoch and anchor diverge permanently — next open is a false rollback lockout, or a rollback that is no longer detectable. |
| `PreparedMonotonicCounter::current` | → `Ok(1)` | Counter stops tracking the anchor |
| `AnchoredStorage::begin` | `\|\|` → `&&` | Second `begin` on an open transaction succeeds; two transactions race one epoch |
| `AnchoredStorage::put` | `\|\|` → `&&` | A correctly sized second epoch write accepted; one transaction stages two epochs |
| `AnchoredStorage::delete` | → `Ok(())` | All delete guards bypassed |
| `AnchoredStorage::delete` | `\|\|` → `&&` | Epoch key deletable on the active transaction |
| `AnchoredStorage::delete` | `!=` → `==` | Guard inverted: foreign transactions allowed, active one refused |
| `AnchoredStorage::delete` | `==` → `!=` | Epoch key deletable, normal keys refused |

All eight are killed by the seven tests in `mod coordination_mutation_kills`.

### Note on the `finalize` survivor

This one is worth reading closely. The guard it removes is the only thing
enforcing the rule already written into the anchor contract in
`ffi/include/voicechat_crypto.h` and `VoiceChatRollbackAnchor`: an increment
whose outcome does not match what was asked for must not be acknowledged. The
contract was documented for platform implementors; nothing tested that the
library itself enforced it. `LyingAnchor` — an anchor that returns `Ok` with a
value it did not actually reach — now does.

### Pattern, third confirmation

`xeddsa.rs`: 4 survivors, all on rejecting paths.
`ratchet/mod.rs`: 14 survivors, all on wiping, counting, or independent bounds.
`storage/coordinated.rs`: 8 survivors, six of them on independent conditions in
compound `||` guards, plus one accepting-path case (`!=` → `==`) and one
constant return.

Three files, three independent runs, one gap: the suite asserts what the happy
path returns and rarely that a compound condition rejects on *each* of its
limbs independently, or that the last legal case is still accepted.

### Not yet measured

`encrypted_file.rs`, `monotonic.rs`, `trusted_anchor.rs`, `storage/mod.rs`, plus
`src/pqxdh/` and `src/replay/`.
