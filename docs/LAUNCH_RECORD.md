# Launch record — 2026-09-08

Branch: `hardening/p0-audit-fixes-2026-08-22`  
Remote: `https://github.com/YashwanthGathuku/dycrpt.git`  
`PRODUCTION_READY` is still **false**. `publish` is still **false**. `patches/` was never committed.

This file is the session record for Step 0 and Step 1 of `docs/PUBLIC_LAUNCH.md`. Step 2 is recorded in `docs/KAT.md` after the known-answer suite exists. It does not replace `docs/MUTATION_TESTING.md` (the score tables) or `docs/V1_SCOPE.md` (the freeze).

Toolchain for every mutation run in this session:

- `cargo-mutants` 26.0.0 (prebuilt Windows binary). 27.x needs rustc ≥ 1.88.
- `RUSTUP_TOOLCHAIN=1.85.0-x86_64-pc-windows-gnu`
- `CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=gcc` because MSVC `link.exe` is not installed.
- Score = caught ÷ (caught + missed). Unviable mutants are not in the denominator.
- `.cargo/mutants.toml` skips the `ten_thousand` handshake inside mutation runs only.

---

## Step 0 — license and speech

**Commit:** `551537b` — `docs: add MIT/Apache-2.0 license files and freeze v1 scope`

| File | What it is |
|---|---|
| `LICENSE` | MIT. Copyright (c) 2026 YashwanthGathuku. Matches `Cargo.toml` `license = "MIT OR Apache-2.0"`. |
| `LICENSE-APACHE` | Apache License 2.0, official terms. Appendix copyright line filled in as `Copyright 2026 YashwanthGathuku`. |
| `docs/V1_SCOPE.md` | v1 freeze. In: 1:1 `ClassicalV1`, one device, encrypted persistent storage with fail-closed restore, one platform FFI (not chosen), dual license, no libsignal in this crate. Out: groups, sealed sender, attachments, sesame, hybrid-as-default, header-encrypt-as-default, a second OS, Signal wire. `PRODUCTION_READY` stays false until an independent audit. |
| `README.md` | Policy section links `docs/V1_SCOPE.md`. |
| `docs/PUBLIC_LAUNCH.md` | Step 0 items 1, 2, and 4 marked done. The “until LICENSE files exist” sentence was removed. |
| `docs/LIBSIGNAL_COMPARISON.md` | The “license files are missing” gap was replaced with a pointer at the two license files and `V1_SCOPE.md`. |

Not done in Step 0: making the GitHub repository public. That is still a human choice. Public is not v1.0.0.

Earlier commits already on this branch, not repeated here: `01f0385` (public-launch process and README non-affiliation), `d43b060` (clean-room identifier check; `signal` keyword removed from `Cargo.toml`), `b2cc0e6` (libsignal comparison).

---

## Step 1 — mutation, module by module

The v1 default surface was measured. Gated hybrid / header-encrypt / Braid code under `src/ratchet/**` (about 835 mutants) and `src/primitives/mlkem_inc.rs` were **not** measured. They are outside the v1 audit surface.

### Already on the branch before this session’s continuation

| Commit | What |
|---|---|
| `db27748` | XEdDSA kill tests. 90.2% → **100%** (41 caught, 0 missed). Survivors were the canonical-`s` bound and `hash_i` domain separation. |
| `ecb52df` | Recorded Double Ratchet `src/ratchet/mod.rs` baseline **80.8%** (59 caught, 14 missed, 16 unviable, 89 examined). |
| `d8237b0` | Killed 12 of those 14. The other 2 are `Drop` on `SkippedKeys` and `SkippedMutationJournal`, excluded because observing a wipe after free is undefined behaviour. Re-run **100%**. |
| `a8cedf4` | `src/storage/coordinated.rs` kill tests (8 survivors, including a lying rollback anchor). |

### This session

#### `src/pqxdh/mod.rs` — 100%

cargo-mutants lists only 4 mutants. Alice and Bob are straight-line DH and KEM calls.

| Run | Examined | Caught | Missed | Unviable | Score |
|---|---|---|---|---|---|
| Baseline | 4 | 1 | 1 | 2 | 50% |
| After Drop exclude | 3 | 1 | 0 | 2 | **100%** |

- Caught: `opk.id != id` flipped to `==`. The happy-path one-time handshake already kills it.
- Unviable: `alice_initiate` / `bob_process` replaced with `Ok(Default::default())`. Those types are not `Default`.
- Missed, then excluded: `impl Drop for PqxdhSharedSecret` emptied. Same class as the ratchet drops.
- Tests added: `shared_secret_zeroize_clears_sk_and_ad` (the wipe `Drop` delegates to), `bob_rejects_mismatched_one_time_ec_id`, `bob_rejects_claimed_opk_when_none_present`.

#### `src/replay/mod.rs` — 65.3% → 100%

| Run | Examined | Caught | Missed | Unviable | Score |
|---|---|---|---|---|---|
| Baseline | 76 | 49 | 26 | 1 | **65.3%** |
| After kill tests | 76 | 75 | 0 | 1 | **100%** |

Unviable: `deserialize -> Ok(Default::default())`.

The 26 survivors were constants, independent reject bounds, exact accessors, and deserialize ceilings. Tests added:

- `component_max_lengths_are_the_documented_constants` (literals 65536 / 4096 / 16384, so `*` → `+` cannot move with the test)
- `accessors_report_exact_cardinality_and_capacity`
- `each_oversized_component_is_rejected_independently`
- `exact_max_component_lengths_are_accepted_and_roundtrip`
- `deserialize_accepts_max_capacity_and_count_equal_to_capacity`
- `deserialize_rejects_wrong_magic_even_when_length_is_legal`
- `deserialize_rejects_short_header`
- `deserialize_rejects_trailing_bytes`
- `deserialize_rejects_truncated_entry_payload`
- `deserialize_empty_message_id_is_limit_exceeded_not_invalid_length` — an empty last field leaves `take_vec` with exactly four bytes left. Original code returns `LimitExceeded`. `>` → `>=` or `==` returns `InvalidLength`. `assert!(is_err())` would not have told them apart.

**Commit:** `0d2a16f` — `test: kill PQXDH and replay mutation survivors (both 100%)`

#### `src/storage/encrypted_file.rs` — 52.2% → 89.6%

Integration tests were included (`--features ffi --lib --test storage_hardening --test ffi_persistent --test crash_hardening --test migration_matrix --test p02_concurrency`). `--lib` alone would have hidden that coverage.

| Run | Examined | Caught | Missed | Unviable | Timeout | Score |
|---|---|---|---|---|---|---|
| Baseline | 145 | 71 | 65 | 8 | 1 | **52.2%** |
| After the first kill tests | 144 | 109 | 27 | 8 | 0 | 80.1% |
| After Drop and `sync_parent_dir` excludes | 133 | 112 | 13 | 8 | 0 | **89.6%** |

Above the 85% bar. The 13 remaining mutants are written in `docs/KNOWN_LIMITATIONS.md`:

| Cluster | N | Why they remain |
|---|---|---|
| `file_len > MAX_STORAGE_FILE` `>` → `==` / `>=` | 2 | Exact 512 MiB snapshot is not a per-mutant fixture. The constant itself is pinned to `536_870_912`. |
| `decode_map` `8+8+4` `+` → `-` | 2 | Every successful map is at least 20 bytes. A 12–19 byte blob fails as `InvalidLength` either way. |
| `effective_record_count > MAX_RECORDS` | 2 | 200_000 live keys. Header-only `decode_map` already pins the ceiling. |
| `encode_effective_map` `emitted != count \|\| out.len() > MAX` | 3 | Defensive check. The 512 MiB side is not fixtureable. |
| `put` / `append_record` `value.len() > MAX_VALUE_LEN` `>` → `==` / `>=` | 4 | Exact 80 MiB value. `decode_map` header-only pins the same bound. |

Excluded, not missed:

- `impl Drop for EncryptedFileStorage` — wipe-on-drop, unobservable without reading freed memory.
- `sync_parent_dir` — Windows directory fsync is best-effort after the snapshot file is `sync_all`’d and renamed. Tests cannot inject a directory-handle failure. On this host `PermissionDenied` / raw os error 5 already returns `Ok(())`.

Tests added: documented constants, `encode_lower_hex`, same-instance `get`/`keys` after commit (kills `apply_staged` → `()`), abort-then-begin, empty follow-up commit, empty and oversized keys on `put` / `delete` / `append_record`, V1 magic → `InvalidNonce`, truncated snapshot error variants, `decode_map` count and record-header ceilings.

**Commit:** `b653db2` — `test: kill EncryptedFileStorage mutation survivors (52.2% to 89.6%)`

#### Remaining default primitives and small storage — 65.6% → 100%

One `cargo mutants` invocation, `--lib` only:

`src/primitives/{aead,kdf,x25519,encoding,signature,zeroizing,random,kem,error}.rs` and `src/storage/{mod,monotonic,trusted_anchor}.rs`.

| Run | Examined | Caught | Missed | Unviable | Score |
|---|---|---|---|---|---|
| Baseline | 184 | 99 | 52 | 33 | **65.6%** |
| After kill tests and three more Drop excludes | 181 | 148 | 0 | 33 | **100%** |

`x25519`, `kem`, `error`, `monotonic`, and `trusted_anchor` had **no** missed mutants on the baseline. The 52 were unused accessors and a few real bounds.

| Cluster | Tests that killed them |
|---|---|
| AES-GCM and XChaCha `ciphertext.len() < TAG_LEN` → `==` / `<=` | `empty_plaintext_roundtrips_at_exact_tag_length` |
| `encode_kem` / `decode_kem` id and `1 + PUBLIC_LEN` | `encode_kem_roundtrip_and_rejects_wrong_id` |
| HKDF empty output, exact `255*32` (8160), `*` → `+`, `hkdf_expand -> Ok(())` | `hkdf_rejects_empty_and_accepts_exact_max`, `hkdf_expand_matches_extract_with_empty_salt` |
| `hmac_sha512` replaced with a constant | `hmac_sha512_rfc4231_case1` (RFC 4231 test case 1, 20-byte `0x0b` key, data `Hi There`) |
| `random_32 -> Ok([0;32])` / `Ok([1;32])` | `random_32_is_not_a_constant` |
| Ed25519 `to_bytes` | `to_bytes_roundtrips_seed_and_public_key` |
| `SecretBytes` / `SecretBytes32` length, `as_ref`, `zeroize_now`, `from_slice`, deref | zeroizing unit tests |
| `MemoryStorage` abort, wrong transaction id, `clear`, inherent `keys`, `RollbackGuard::last_seen`, `zeroize_staged` | storage unit tests |
| `StateBlob` `Zeroize` (not the Drop) | `state_blob_zeroize_clears_bytes` |

Excluded with the same wipe-on-drop rationale: `impl Drop for StateBlob`, `impl Drop for SignatureSecret` (that Drop only wipes a stack copy of `to_bytes()`), `impl Drop for ZeroizingScope`.

**Commit:** `8b92482` — `test: kill remaining v1 primitive and storage mutation survivors (65.6% to 100%)`

Lab output directories (`mutants-pqxdh.out`, `mutants-replay.out`, `mutants-encrypted-file.out`, `mutants-primitives.out`) are gitignored. They were not committed.

### v1 Gate 3 scoreboard after Step 1

| Surface | Score | Notes |
|---|---|---|
| `src/primitives/xeddsa.rs` | 100% | |
| `src/ratchet/mod.rs` (classical) | 100% | Drop excludes for skipped-key journals |
| `src/pqxdh/mod.rs` | 100% | Drop exclude |
| `src/replay/mod.rs` | 100% | |
| `src/storage/coordinated.rs` | killed in `a8cedf4` | See `MUTATION_TESTING.md` |
| `src/storage/encrypted_file.rs` | **89.6%** | 13 survivors documented |
| Default primitives + `storage/{mod,monotonic,trusted_anchor}.rs` | 100% | |
| `src/ratchet/**` hybrid, header-encrypt, SPQR, Braid | not measured | Not v1 |
| `src/primitives/mlkem_inc.rs` | not measured | Braid incremental KEM, not v1 |

Gate 3’s ≥ 85% bar is met on the measured v1 surface. It is not “the crate is fully verified.”

---

## What Step 1 did not do

- No groups, sealed sender, attachments, or “AI ratchet.”
- No change to `PRODUCTION_READY`.
- No crates.io publish.
- No hardware run.
- No libsignal differential (that stays in a separate AGPL tree if it is ever done).
- `patches/` left untracked.
