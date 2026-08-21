# HANDOFF — continue in Antigravity (or any new session)

**Date:** 2026-08-19  
**Repo:** `voicechat-crypto`  
**Start here, then read [`NEXT_STEPS.md`](NEXT_STEPS.md).**

This is a clean-room Rust crypto engine for the VoiceChat app. It is **not** production-ready and **not** a libsignal replacement yet. Do not mark VERIFIED / production-ready / quantum-proof / formally verified without new independent evidence.

---

## Binding rules (do not waive)

| Doc | Rule |
|-----|------|
| [`FINAL_SECURITY_RULE.md`](FINAL_SECURITY_RULE.md) | Security beats convenience. No invented algorithms. No silent PQXDH/profile downgrade. No key reuse. No private keys through FFI. |
| [`SOURCE_BOUNDARY.md`](SOURCE_BOUNDARY.md) | Public Signal specs + FIPS 203 + RFCs **only**. **Never** clone, browse, or copy `libsignal` (AGPL). |
| [`LICENSE_AUDIT.md`](LICENSE_AUDIT.md) | No AGPL/GPL/LGPL runtime deps in this workspace. |
| [`AUDIT_SCOPE.md`](AUDIT_SCOPE.md) | `PRODUCTION_READY` stays false until an **external** crypto review. |

If a task needs libsignal as a reference, keep that adapter in a **separate AGPL repo**. Do not add it to this crate. See [`../crypto-parity/backends/libsignal/PIN.md`](../crypto-parity/backends/libsignal/PIN.md).

---

## What this crate is

Clean-room implementation of:

- **PQXDH Rev 3** + real **ML-KEM-768** (`ml-kem` 0.3.2)
- **XEd25519** (same identity key as X25519)
- **Classical Double Ratchet Rev 4**
- Optional **header encryption** (`--features header-encrypt`)
- Optional **Triple = DR ‖ SPQR ‖ ML-KEM Braid** (`--features hybrid`)
- Engine + secret-free FFI
- **crypto-parity** property harness (behavioral, not wire-compatible)

Default advertised profile is **ClassicalV1 only**. Hybrid/HE compile only when featured and are **never auto-selected**.

Integrator API: `VoiceChatCryptoEngine` / `CryptoEngineApi`. App code must not import ratchet internals.

---

## Layout

| Path | Role |
|------|------|
| `src/engine/mod.rs` | App-facing engine. Atomic inbound handshake persist. Random session IDs. |
| `src/pqxdh/mod.rs` | PQXDH. SK = KDF(F‖KM), AD = EncodeEC(IKA)‖EncodeEC(IKB)‖EncodeKEM(PQPKB). |
| `src/prekeys/mod.rs` | Signed SPK + PQ, one-time consume, last-resort PQ. |
| `src/primitives/xeddsa.rs` | XEd25519. `calculate_key_pair` uses **constant-time** `conditional_select`. |
| `src/primitives/kem.rs` | `ml-kem` wrapper. |
| `src/primitives/mlkem_inc.rs` | FIPS 203 Encaps1/Encaps2 (our lattice). CT matches official Encrypt in tests. **Unaudited.** |
| `src/ratchet/mod.rs` | Classical DR. `checked_inc`. Skipped-key zeroize. Trial decrypt. |
| `src/ratchet/triple/` | Hybrid MK = KDF_HYBRID(ec_mk, pq_mk). SPQR advances only when **both** have SCKA key. |
| `src/ratchet/braid/` | Incremental Encaps1 on header, Encaps2 after ek+ack. Persist `VCBRAID3`. |
| `src/ratchet/spqr/` | Epoch chains from SCKA secrets. |
| `src/ratchet/header_encrypt/` | Optional HE. Counters are `checked_inc`. |
| `src/session/sesame.rs` | **Not production.** `#[cfg(any(test, feature = "sesame"))]`. Retry uses hardcoded `[9u8; 32]`. |
| `src/fingerprint/mod.rs` | Safety numbers + `TrustStore` (session ≠ user trust). |
| `src/replay/mod.rs` | Bounded cache; durable serialize `VCREPL01`. |
| `src/ffi/` | C ABI. No SK/DH args. Handle exhaust fail-closed. |
| `crypto-parity/` | Workspace member. 74 property scenarios. libsignal **NOT_LINKED**. |
| `docs/` | Specs, audit packet, this handoff. |
| `formal/tla/` | TLC finite models. Not a crypto proof. |

Workspace: `[workspace] members = [".", "crypto-parity"]`.

---

## Toolchain

- MSRV **1.85** (`ml-kem`).
- This machine: **rustc 1.96**, `stable_x86_64-pc-windows-gnu`, **rust-lld** (`rust-toolchain.toml`). Host MSVC often has no `link.exe`.
- Use `CARGO_INCREMENTAL=0` on this Windows GNU host if incremental acts up.
- `cargo test` filter accepts **one** TESTNAME only.
- Fuzz: `host_runner` works. `libfuzzer-sys` **fails** on GNU Windows (`__pragma`). Linux CI can build libfuzzer.

---

## Last verified commands (2026-08-19)

Do not treat this as still-true after you edit. Re-run.

```
cargo fmt --all -- --check                          # exit 0 after last rustfmt
clippy --all-targets --all-features -- -D warnings  # exit 0
cargo test --all-targets --all-features -- --skip ten_thousand
    lib 160 + crash 8 + DR 2 + engine 2 + hybrid 7 + matrix 19 + p0 1 + state 6 + adapter 3
    = 208 passed, 0 failed

cargo run -p crypto-parity
    74 scenarios; P0=0
    Signal-Core 100% (44/44)
    Operational 100% (17/17)
    VoiceChat 100% (13/13)
    random transitions 10128 / violations 0
    malformed 33 / panics 0
```

**Not re-run this cycle:** `cargo test --lib ten_thousand` (historically ~10k PQXDH SK-equality, many minutes).  
**Not run:** `cargo run -p crypto-parity -- --full` (200×5000 DR events).

Evidence log: [`TEST_EVIDENCE.md`](TEST_EVIDENCE.md). Scorecard: [`../crypto-parity/reports/SCORECARD.md`](../crypto-parity/reports/SCORECARD.md).

---

## Hardening already landed (do not redo)

1. XEdDSA `calculate_key_pair` — `Scalar::conditional_select` (no `if sign == 1`).
2. First inbound: in-memory decrypt → consume OPKs → **one** persist of session + prekeys + identity + replay + trust. Test: `handshake_opk_and_session_atomic_across_reload`.
3. `PROFILE_PREFERENCE = [ClassicalV1]`. `default = ["std"]`.
4. HE / SPQR / Braid epoch counters: `checked_add` → `LimitExceeded`. RS chunk indices still wrap (field indices, not ratchet counters).
5. `TrustStore` persisted separately. Session existence ≠ acknowledged identity. `remote_identity_state`.
6. Replay cache durable; keys bind conversation + device + version + header/ct prefix.
7. Sesame unexported unless `feature = "sesame"` or tests.
8. Session IDs: 128-bit CSPRNG (`fill_random`).
9. FFI handle/size bounds fail closed.
10. Encaps1 compress matches `ml-kem` 34-bit reciprocal; joined CT == official Encrypt in tests.
11. Triple does **not** advance SPQR at Encaps1-only (would break Alice decrypt).

---

## Known sharp edges

- **Encaps1** (`mlkem_inc.rs`) is security-critical lattice code we wrote. Tests match `ml-kem` Encrypt; no independent review; not lab-CT.
- **Hybrid** is real but experimental. Do not put it first in `PROFILE_PREFERENCE` again.
- **Sesame retry** is fake (`[9u8; 32]`). Leave disabled.
- **`ml-kem` 0.3.2** unaudited upstream.
- **Bob DH = `SPK_B`** (`engine` ~signed.secret → `init_bob_ratchet`). Do not “simplify” to a fresh DH.
- **Do not compare** VoiceChatCrypto ciphertext to libsignal ciphertext. Different encodings. Goal is security-property parity.
- `PRODUCTION.md` / `AUDIT_SCOPE.md` define `PRODUCTION_READY := external audit ∧ …`. Green tests do not flip it.
- Parent VoiceChat app is **not** in this workspace. Physical Android/iOS **not** run. libsignal revision VoiceChat uses is **UNVERIFIED** — do not invent a SHA.

---

## How to verify after any edit

```
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features -- --skip ten_thousand
cargo run -p crypto-parity
```

Touched hybrid/Braid/Encaps1: also `cargo test --lib encaps1` and `--features hybrid` ratchet/triple tests.  
Touched PQXDH: consider `cargo test --lib ten_thousand` (slow).

---

## Honest status line (use this)

> VoiceChat Crypto is a substantial clean-room engine: real PQXDH, classical Double Ratchet, XEd25519, ML-KEM-768, plus experimental SPQR/Braid/Triple. ClassicalV1 is approaching experimental app integration quality. It is **not** production-ready: no independent audit, no physical device interop, Hybrid unaudited, Sesame disabled, libsignal differential not linked.

---

## Related docs

| File | Use |
|------|-----|
| [`NEXT_STEPS.md`](NEXT_STEPS.md) | Ordered work queue for Antigravity |
| [`PRODUCTION.md`](PRODUCTION.md) | What is / is not shippable |
| [`AUDIT_HANDOFF.md`](AUDIT_HANDOFF.md) | External reviewer packet |
| [`SPEC_TRACE.md`](SPEC_TRACE.md) | Spec → file map |
| [`../crypto-parity/README.md`](../crypto-parity/README.md) | Property harness |
