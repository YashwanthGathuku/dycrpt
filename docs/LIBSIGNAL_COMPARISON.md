# dycrpt vs libsignal — verification, gaps, and how to find remaining bugs

**Date:** 2026-09-08  
**This tree:** `a8cedf4` (`hardening/p0-audit-fixes-2026-08-22`), ~17,965 lines of Rust in `src/`  
**libsignal checked:** `github.com/signalapp/libsignal` `main` (retrieved 2026-09-08; rust tree SHA prefix `b3f7ecc`)  
**License of libsignal (verbatim from their LICENSE / README):** GNU AGPLv3, Copyright 2020–2026 Signal Messenger, LLC. Use outside Signal is unsupported.

This is not a legal opinion and not a security audit. It is a capability and assurance comparison of **this library** against **libsignal’s protocol crate**, plus a testing plan that actually finds the class of bugs already seen here.

Related living docs: `PRODUCTION.md`, `KNOWN_LIMITATIONS.md`, `MUTATION_TESTING.md`, `dycrpt-v1-scope-and-comparison.md`.

---

## Verdict (short)

| Question | Answer |
|---|---|
| Did you need to reimplement instead of linking libsignal? | **Yes**, if VoiceChat must stay MIT/Apache-2.0. libsignal is AGPL-3.0. Linking it would copyleft the app. |
| Are you “closer” to libsignal on 1:1 messaging crypto? | **Yes — roughly at protocol-core parity.** PQXDH, Double Ratchet, Triple Ratchet (gated), ML-KEM, identity, safety numbers, sessions are present. |
| Are you “more advanced” than libsignal overall? | **No.** libsignal has groups, sealed sender, attachments, production bindings, audits, and ~15 years of traffic. You are ahead in a few *library-layer* designs (rollback-resistant storage, permissive license, in-tree TLA+/mutation work). |
| What decides whether anyone should ship this? | **Assurance, not features.** Green tests are not an audit. `PRODUCTION_READY` is still false. |

Do not try to “match libsignal the repository.” libsignal is ~18 Rust crates. Most of them are Signal’s product (private groups, CDSI, SVR, key transparency, chat websocket, media sanitizer). Matching those would be building Signal’s service, not a messenger crypto engine.

The honest fight is: **`libsignal` `rust/protocol` vs this crate’s `src/`.**

---

## 1. Why libsignal cannot be used here

Evidence:

- libsignal README (2026): “Licensed under the GNU AGPLv3.”
- libsignal LICENSE is the full AGPLv3 text.
- This crate: `Cargo.toml` `license = "MIT OR Apache-2.0"`. `docs/LICENSE_AUDIT.md` forbids AGPL/GPL/LGPL runtime deps. `crypto-parity/backends/libsignal/PIN.md` says libsignal must not be a dependency; a real differential belongs in a **separate AGPL-licensed repo**.

Clean-room from **public specs** (PQXDH, Double Ratchet Rev 4, XEdDSA, FIPS 203) is the correct path for a permissive VoiceChat engine. Byte-for-byte Signal network interop is **not** claimed and is not required for VoiceChat.

**Gap even on the license story:** `Cargo.toml` says MIT OR Apache-2.0, but there are **no `LICENSE` / `LICENSE-APACHE` files in the tree**. That is a v1 Gate 1 item. Add the actual files before any public tag.

---

## 2. Protocol core — like for like

libsignal `rust/protocol/src` (2026-09-08 listing) vs this `src/`:

| Capability | libsignal | dycrpt | Status |
|---|---|---|---|
| PQXDH | `pqxdh.rs` | `pqxdh/` | Have |
| Double Ratchet | `double_ratchet.rs` | `ratchet/mod.rs` | Have (ClassicalV1 default) |
| Triple Ratchet / PQ ratchet | `triple_ratchet.rs` | `ratchet/triple/`, `spqr/`, `braid/` | Have, **feature-gated `hybrid`**, not default |
| ML-KEM | `kem.rs`, `kem/` | `primitives/kem.rs`, `mlkem_inc.rs` | Have, gated; `ml-kem` 0.3.2 is **unaudited upstream** |
| Identity | `identity_key.rs` | `identity/` | Have |
| Safety numbers | `fingerprint.rs` | `fingerprint/` | Have |
| Sessions | `session.rs`, `session_management.rs`, `state/` | `engine/`, `session/` | Have |
| Primitives | `crypto.rs` | `primitives/` | Have |
| Wire format | protobuf (`proto/`) | custom `wire/` + `envelope/` | **Divergent — no Signal interop** |
| Group messaging | `sender_keys.rs`, `group_cipher.rs` | — | **Missing** |
| Sealed sender (metadata) | `sealed_sender.rs` | — | **Missing** |
| Attachment / streaming MAC | `incremental_mac.rs` | — | **Missing** |
| Multi-device (Sesame) | `session_management.rs` | `session/sesame.rs` | Prototype, **feature-gated off** |
| Language bindings | Java, Swift, Node, **used in production** | C ABI + JNI/Swift/Kotlin, **never run on hardware** | Partial |

Default advertised profile here is **ClassicalV1** (PQXDH + classical Double Ratchet). Hybrid and header-encryption exist but are experimental and must not be auto-selected.

### Where this library is ahead of libsignal’s *protocol crate* (not the whole product)

1. **Rollback-resistant persistence inside the library.** libsignal gives the app store traits. This crate ships `EncryptedFileStorage` (XChaCha20-Poly1305, `VCENCST2`), a monotonic-epoch contract, a trusted-anchor interface, typed fail-closed restore (`RollbackDetected`, `StateLost`), and engine poisoning on an unknown write. That is a real design contribution — and it is also extra surface that must be tested on devices.
2. **Permissive license on a PQXDH + Double Ratchet stack.** libsignal is AGPL-3.0. That is the market reason this crate exists.
3. **In-tree TLA+ models, a parity harness (behavioral, not wire), a constant-time binary, and mutation testing.** libsignal’s assurance is production + published analyses, not this exact toolbox.
4. **Header-encryption profile** (`ratchet/header_encrypt/`) — beyond the public Signal spec. Keep it gated for v1.

Ahead on those four does **not** mean “more advanced than libsignal.” It means a different product shape: a library that owns storage/rollback instead of delegating it.

---

## 3. Missing vs needed vs later

Three lists. Mixing them is how the project never ships.

### A. Missing vs libsignal `rust/protocol` (real messenger features)

| Missing | Needed for VoiceChat v1 1:1? | When to add |
|---|---|---|
| Sender keys / group cipher | No | v2, if VoiceChat does groups |
| Sealed sender | No (metadata protection is a product choice) | v2 |
| Incremental MAC / attachment streaming | Only if you send large files through this crate | v2 |
| Signal protobuf wire | No — VoiceChat has its own envelope | Never, unless you need Signal network interop |
| Sesame multi-device | No for single-device v1 | v2; keep `sesame` off until redesigned |
| Java/Swift/Node generated bridges at Signal quality | One **working** binding is enough for v1 | Second platform after the first is proven on hardware |

### B. Needed to add **before v1** (not features — proof)

These are not “more Signal.” They are why the code you already have is not shippable.

| Need | Why | Done? |
|---|---|---|
| Actual `LICENSE` + `LICENSE-APACHE` files | Cargo.toml claims MIT OR Apache-2.0; files are absent | **No** |
| `docs/V1_SCOPE.md` freeze | Audit is priced by surface; hybrid/HE/Sesame must stay gated | Partial (`dycrpt-v1-scope-and-comparison.md` exists) |
| Known-answer vectors (Wycheproof + full RFC 7748 + RFC 5869) | Today: RFC 7748 one vector + RFC 5869 case 1 | **No** |
| Mutation score ≥ 85% on primitives, ratchet, pqxdh, replay, storage | Measured: xeddsa 100% (review), ratchet/mod.rs 100% after kill tests, coordinated.rs kill tests added; rest unmeasured | **Incomplete** |
| Isolated AGPL differential vs libsignal | `crypto-parity` reports `NOT_LINKED` | **No** |
| Fuzz targets **run**, not only built | `fuzz/fuzz_targets/` exist; CI historically failed to even compile fuzz until `[workspace]` was added | **Not run at scale here** |
| `ct_timing` with multiple probes at 500k samples | One probe (`x25519-secret-class`); `--samples` vs positional-arg pitfall documented | **Incomplete** |
| One platform on **physical hardware** | JNI/Swift/Kotlin written; never compiled with NDK/Xcode, never two-device | **No** |
| Independent crypto audit, v1 surface only | `PRODUCTION_READY` rule | **No** |
| Server-held rollback anchor (or accept Keystore/Keychain limits) | Device-local sealed counters do not stop a rooted attacker who restores counter+state together | Product decision, unstarted |

### C. What you *can* add later (v2+) — only after v1 is audited

- Group messaging (sender keys), if VoiceChat needs groups.
- Sealed sender / padded metadata, if the threat model includes a curious relay.
- Attachment chunk MAC, if large media goes through this crate.
- Hybrid PQ as default — **not** before NIST ACVP KATs and an audit of `mlkem_inc.rs` (highest-risk code in the tree).
- Header encryption as default.
- Second platform binding.
- Multi-device Sesame with real SessionTag semantics (current module is explicitly not production).

### D. What you should **never** add just to “match libsignal”

From libsignal’s rust tree (2026-09-08): `zkgroup`, `zkcredential`, `poksho`, `attest`, `svrb`, `account-keys`, `keytrans`, `net`, `media`, `message-backup`, `usernames`, `device-transfer`, `cli-utils`, `debug`.

Those exist because Signal runs a global service. Building them would spend years on AGPL-shaped product infrastructure you do not operate.

---

## 4. Assurance: the only category that decides adoption

| | libsignal | this crate |
|---|---|---|
| Independent audits | Multiple, public (Signal’s history) | **Zero** |
| Formal crypto analysis of PQXDH | Published ProVerif/CryptoVerif work on the *spec* | TLA+ **state** models (different thing; not a crypto proof) |
| Production exposure | Signal clients/servers, years of traffic | Zero |
| Device bindings | Java / Swift / Node in production | Written, **untested on hardware** |
| Known-answer vectors | Extensive | Two RFC cases |
| Mutation testing | Not their primary story | Started: 3 files, rejection-path holes found and (mostly) killed |
| License for a closed-source or MIT app | AGPL — cannot use | MIT OR Apache-2.0 (files still missing) |

Bugs already found in **this** project were not “wrong algorithm” bugs. They were **verification** bugs:

| Finding | What it was | Why tests missed it |
|---|---|---|
| F1 | XEdDSA `s + q` still verified (malleable encoding) | Spec check was literal `s >= 2^253`; decode reduced mod q |
| F2 | `fill_random` could never return `Err` (RNG panic) | Result type was structurally unreachable |
| F3 | Crate-wide unused-lint allows hid dead test branches | Lint policy, not crypto |
| F4 | AES-GCM random 96-bit nonce on unrotated storage key | Format never bounded |
| Fuzz gate | `fuzz/Cargo.toml` had no `[workspace]` | CI never compiled fuzz |
| Android Kotlin | `external fun` with **zero JNI symbols** | Facade compiled; first native call would `UnsatisfiedLinkError` |
| Mutation (xeddsa) | `u >= p` never tested | Happy-path + wrong-key + tamper only |
| Mutation (ratchet) | Skip bound, skip count, deserialize ceiling, unused `receive_message_key` | Encrypt/decrypt round-trips |
| Mutation (storage) | `finalize` accepting any `Ok(_)` from the anchor | Documented contract, untested library enforcement |

That pattern is the project’s actual risk: **the suite asserts what the code accepts, not what it must refuse.**

---

## 5. Real-time testing — how to keep finding those bugs

“Real-time” here means **continuous, automated, and on devices**, not a one-off `cargo test` before a tag.

### Layer 0 — every PR (already partly in CI)

```
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --features ffi -- --skip ten_thousand
cargo test --release --lib -- ten_thousand
cargo test --features ffi --test ffi_persistent --test storage_hardening --test crash_hardening
```

Do not treat `--skip ten_thousand` as “the suite passed.” That test is the handshake soak; run it in **release** on a schedule.

### Layer 1 — mutation testing (finds untested rejections)

Tool: `cargo-mutants` **26.0.0** (27.x needs rustc ≥ 1.88; MSRV is 1.85).

```
# Protocol core (lib tests are enough)
cargo mutants --file 'src/primitives/**' --file 'src/ratchet/mod.rs' --file 'src/pqxdh/**' --file 'src/replay/**' -- --lib

# Storage MUST include integration tests (lib-only hides coverage)
cargo mutants --file 'src/storage/**' -- --features ffi --lib \
  --test storage_hardening --test ffi_persistent --test crash_hardening \
  --test migration_matrix --test p02_concurrency
```

Pass: ≥ 85% on each of those trees; every survivor killed or written into `KNOWN_LIMITATIONS.md`.

Measured so far:

| File | Score | Note |
|---|---|---|
| `src/primitives/xeddsa.rs` | 100% (review re-run after kill tests) | 4 rejection tests |
| `src/ratchet/mod.rs` | 100% after 7 kill tests; 2 Drop impls excluded (UB to observe) | Baseline was 80.8% |
| `src/storage/coordinated.rs` | Kill tests added; re-run not executed in this session | 8 survivors targeted |
| Rest of primitives / pqxdh / replay / encrypted_file | **Not measured** | Next |

Overnight job, not a 10-minute CI step.

### Layer 2 — fuzzing that actually runs

Targets: `envelope_parse`, `header_decode`, `prekey_bundle`, `state_decoders`, `engine_wire`, `triple_header_decode`.

```
# nightly + cargo-fuzz
cargo fuzz run envelope_parse -- -max_total_time=3600
# repeat per target
```

Plus `fuzz/host_runner.rs` at ≥ 10M iterations, corpus self-check, zero panics.

A **build** of fuzz is not evidence. Before 2026-08-28 the fuzz crate was not even a workspace root.

### Layer 3 — differential testing vs libsignal (isolated)

Keep AGPL out of this repo.

1. Separate repository, AGPL-licensed, never published as part of VoiceChat.
2. Implement the `crypto-parity` `Backend` against a **pinned** libsignal commit.
3. Replay the same `crypto-parity/scenarios/*.yaml` IDs.
4. Pass: ≥ 10,000 randomized transcripts, **zero divergences** where the public spec requires agreement (shared secrets, not protobuf bytes).

Until that exists, `libsignal backend: NOT_LINKED` means “we implemented the spec,” not “we match the reference.”

### Layer 4 — known-answer vectors

Wire Project Wycheproof (X25519, HMAC) + all RFC 7748 X25519 vectors + all RFC 5869 HKDF-SHA256 cases as `cargo test kat`. Target ≥ 100 external vectors.

Do **not** ungating hybrid until NIST ACVP ML-KEM-768 KATs exist for `mlkem_inc.rs`.

### Layer 5 — timing / side channels

```
cargo run --release --bin ct_timing -- --samples 500000
```

Required probes (today only X25519 secret-class is covered):

- X25519 secret class
- AEAD tag comparison
- Skipped-message-key lookup
- XEdDSA scalar canonicality (the F1 path)

Confirm the CLI actually honors `--samples N`. A positional `500000` was documented as silently ignored.

### Layer 6 — real devices, real time (the missing “does it work” test)

Pick **one** platform first (v1 rule). Android is further along (JNI exists) but **has never been built with the NDK or run on a phone.**

Minimum hardware campaign:

| Test | What it catches |
|---|---|
| Two physical devices, 1,000+ messages | Session, padding, replay, crash-reload |
| Airplane-mode / delayed delivery / reorder | Skip-key path (the mutation hole) |
| Kill app mid-send, relaunch | Persist/restore, `VC_STATE_LOST` |
| Restore an old backup of the state file | Must fail closed (`RollbackDetected` / `StateLost`), app must not crash |
| Concurrent send/receive | `VcRollbackAnchorCallbacks` `Send + Sync` is asserted, not proven |
| `nativeLiveAnchorCount` create/destroy loop | JNI `GlobalRef` leaks |
| User removes Android lock screen (Keystore invalidation) | Permanent `VC_STATE_LOST` — intended, needs UX |
| iOS before first unlock after boot | `VC_ANCHOR_UNAVAILABLE` is **transient**, must not be treated as rollback |

Without this layer, FFI and storage are lab artifacts.

### Layer 7 — soak / “real time” in CI

- Nightly: release `ten_thousand` handshake + host_runner 10M + one fuzz target for 1 hour.
- Weekly: mutation of one unmeasured directory.
- Before any “v1” tag: full Gate 2–6 list, then external audit (Gate 7).

---

## 6. Recommended order (do this, not “more Signal features”)

1. Add `LICENSE` and `LICENSE-APACHE`. Freeze `docs/V1_SCOPE.md`.
2. Finish mutation on `pqxdh`, `replay`, `encrypted_file`, remaining primitives. Kill or document survivors.
3. Wycheproof + full RFC KATs.
4. Isolated libsignal differential (separate repo).
5. Run fuzz for hours, not compile-only.
6. One phone, two installs, 1,000 messages + backup/restore.
7. External audit of the **ClassicalV1 + storage + one FFI** surface only.

Then tag v1. Groups, sealed sender, hybrid-default, and the second OS are v2.

---

## 7. What not to claim

Forbidden until an external reviewer writes ship / ship-with-fixes (`PRODUCTION.md`):

- “Production-ready”
- “More secure than Signal”
- “Quantum-proof”
- “Formally verified”
- “Independently audited”
- “Compatible with the Signal network”

Accurate claims you *can* make today:

- Clean-room implementation of public PQXDH + Double Ratchet specs, MIT/Apache-2.0 intended, no libsignal linkage.
- 1:1 protocol core is present; group/sealed-sender/attachments are not.
- Library-layer rollback storage is a differentiator and is still hardware-unproven.
- Tests and mutation work have already found real, previously invisible faults; that work is unfinished.

---

## Sources for this verification

- This repository: `Cargo.toml`, `src/` layout, `docs/PRODUCTION.md`, `KNOWN_LIMITATIONS.md`, `LICENSE_AUDIT.md`, `MUTATION_TESTING.md`, `crypto-parity/backends/libsignal/PIN.md`, commits through `a8cedf4`.
- [signalapp/libsignal](https://github.com/signalapp/libsignal) README + LICENSE (AGPLv3) and `rust/` + `rust/protocol/src/` listings retrieved 2026-09-08.
- Public specs (not re-derived here): Signal PQXDH, Double Ratchet, XEdDSA; FIPS 203.

**Confidence on the capability table:** high — both trees were listed.  
**Confidence on “no other permissive PQXDH impl exists”:** not re-verified in this pass; treat as unverified marketing until searched again.  
**Confidence on audit history of libsignal:** medium — public Signal research exists; this note does not inventory every audit report.  
**Confidence on hardware status of this crate:** high — `KNOWN_LIMITATIONS.md` and the JNI commit message state untested on device; no contrary evidence in-tree.
