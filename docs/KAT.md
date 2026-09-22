# Known-answer vectors — Step 2 (2026-09-08)

`PRODUCTION_READY` is still false. These tests show the primitive wrappers match published vectors. They are not an audit.

## Command

```text
cargo test kat
```

That name selects `tests/kat.rs`. On this machine (rustc 1.85 GNU, debug) the suite finished as two runs of the same binary:

| Filter | Result | Time |
|---|---|---|
| Wycheproof + RFC 5869 + RFC 7748 §5.2/§6.1 | 5 passed | 0.34s |
| RFC 7748 §5.2 iteration (1, 1,000, and 1,000,000) | 1 passed | **661.15s** |

Almost all of the 661 seconds is the one-million X25519 iteration. Debug `x25519-dalek` is slow. The vector is required by RFC 7748 §5.2, so it is not ignored.

## What ran

| Source | Vectors executed | Result |
|---|---|---|
| RFC 7748 §5.2 two direct X25519 calls | 2 | pass |
| RFC 7748 §5.2 iterations (1, 1,000, 1,000,000) | 3 | pass |
| RFC 7748 §6.1 Alice/Bob public keys and shared secret (both directions) | 4 checks | pass |
| RFC 5869 appendix A.1, A.2, A.3 HKDF-SHA256, PRK and OKM | 6 | pass |
| Wycheproof `x25519_test.json` (C2SP `testvectors_v1`, 518 tests, curve25519 only) | 518 | pass |
| Wycheproof `hmac_sha256_test.json` (174 tests, full and truncated tags) | 174 | pass |
| Wycheproof `hmac_sha512_test.json` (174 tests, full and truncated tags) | 174 | pass |

Wycheproof files are unmodified under `testdata/kat/`. Provenance is in `testdata/kat/README.md`. Downloaded 2026-09-08 from `https://github.com/C2SP/wycheproof` `main` `testvectors_v1`. Apache-2.0.

External vectors executed: **881** (866 Wycheproof + 15 RFC checks). Gate 2 asks for at least 100. That bar is met.

## How a vector is judged

**X25519.** `X25519Secret::diffie_hellman` is the raw RFC function (scalar clamping is inside dalek, as RFC 7748 requires). `X25519Public::from_bytes` rejects the all-zero encoding.

- Wycheproof `valid`: the public key must be accepted and the shared secret must match.
- Wycheproof `acceptable` (low-order, twist, non-canonical, zero shared secret): RFC 7748 allows an implementation to reject an all-zero public or an all-zero shared secret. If this crate computes a shared secret, those bytes must equal the vector. If `from_bytes` rejects the public key, the vector is not a failure. Every acceptable vector in this file either matched or was rejected that way; the test passed.

**HMAC.** `hmac_sha256` / `hmac_sha512` always return the full tag (32 or 64 bytes). Wycheproof groups with `tagSize` 128 compare the leading 16 bytes. `valid` must match that prefix. `invalid` must not.

**HKDF-SHA256.** A.3 uses a zero-length salt (`Some(&[])`), which is not the same as an omitted salt (HashLen zero bytes). Both PRK (`HMAC(salt, IKM)`) and OKM (`hkdf_extract_expand`) are checked.

## What did not run

| Spec text | Why it is not in `cargo test kat` |
|---|---|
| RFC 7748 X448 (§5.2 and §6.2) | This crate has no X448. v1 Gate 2, as written in `docs/dycrpt-v1-scope-and-comparison.md`, asks for the X25519 vectors. |
| RFC 5869 A.4–A.7 (HKDF-SHA1) | This crate has no HKDF-SHA1. The v1 gate asks for the HKDF-SHA256 cases. |
| NIST ACVP ML-KEM-768 | Stays out until `hybrid` is ungated. `docs/V1_SCOPE.md` keeps hybrid off the default build. |

Calling this “the whole of RFC 7748 and RFC 5869” would be false. It is every X25519 vector in RFC 7748 and every HKDF-SHA256 vector in RFC 5869, plus the Wycheproof X25519 and HMAC-SHA256/SHA512 files.

## Code

- `tests/kat.rs` — the suite.
- `Cargo.toml` dev-dependencies: `serde`, `serde_json` (parse the JSON only in tests).
- `Cargo.lock` updated for those crates.

No production algorithm changed. The wrappers that already existed matched the vectors.

---

## Next phases

Still the only queue. Do not start groups, sealed sender, attachments, or a new ratchet.

### Step 3 — one real device

One operating system, not two. Two devices. At least 1,000 messages, reorder, kill the app, restore an old backup. The restore must surface `VC_STATE_LOST` and must not crash. That is the demo. Kotlin/Swift/JNI in this tree have not been compiled against a device SDK.

### Step 4 — external audit

Pay for a review of the v1 surface only: ClassicalV1, persistent encrypted storage, one FFI. `PRODUCTION_READY` stays false until that review. crates.io stays `publish = false` until then.

### Other gates that are still open

| Gate | State |
|---|---|
| 1. Scope freeze | Done. `docs/V1_SCOPE.md`. |
| 2. Known-answer vectors | Done for X25519, HKDF-SHA256, and the Wycheproof files above. Not X448, not HKDF-SHA1, not ML-KEM ACVP. |
| 3. Mutation ≥ 85% on the v1 surface | Measured. See `docs/LAUNCH_RECORD.md` and `docs/MUTATION_TESTING.md`. Encrypted-file storage is 89.6% with 13 documented survivors. Hybrid / header-encrypt / Braid ratchet code and `mlkem_inc` are not measured and are not v1. |
| 4. Differential vs libsignal | Not started. If it is ever done, it is a separate AGPL test binary, not a dependency of this crate. |
| 5. Adversarial | `host_runner`, cargo-fuzz, `ct_timing`, and the 10k handshake gate are specified in `docs/ADVERSARIAL_TESTING.md` / `docs/FUZZING.md`. Not re-run as a Gate 5 pass in this session. |
| 6. One real device | Not run. |
| 7. Independent audit | Not done. |

Making the GitHub repository public is still a separate choice. Public is not a 1.0.0 tag.

The sentence that is allowed in public:

> Clean-room implementation of the public-domain PQXDH, Double Ratchet, and XEdDSA specifications, plus FIPS 203 ML-KEM, under MIT OR Apache-2.0. Not affiliated with Signal. Not a port of libsignal. Not compatible with the Signal network.
