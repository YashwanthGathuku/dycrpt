# V1 scope freeze

**Date:** 2026-09-08  
**Crate:** `voicechat_crypto` (`voicechat-crypto`)  
**License:** MIT OR Apache-2.0 (`LICENSE`, `LICENSE-APACHE`)  
**Status:** `PRODUCTION_READY` is **false**. This freeze is Gate 1 of v1, not a 1.0.0 tag.

This file is the product definition. Anything not listed under **In scope** is refused for v1, even if code for it already exists behind a feature flag.

Public sentence (do not substitute):

> Clean-room implementation of the **public-domain** PQXDH, Double Ratchet, and XEdDSA specifications, plus FIPS 203 ML-KEM, under MIT OR Apache-2.0. Not affiliated with Signal. Not a port of libsignal. Not compatible with the Signal network.

Related: `PUBLIC_LAUNCH.md` (speech and process), `PRODUCTION.md` (why the ready bit is still false), `SOURCE_BOUNDARY.md` (clean-room rule), `dycrpt-v1-scope-and-comparison.md` (how this freeze was derived).

---

## In scope

| Item | Meaning |
|---|---|
| One-to-one sessions | Two identities, one session each direction as the engine already models. No groups. |
| `ClassicalV1` only | PQXDH + classical Double Ratchet. Default advertised profile. Never auto-select another profile. |
| Single device per identity | No Sesame multi-device for v1. |
| Persistent encrypted storage | `EncryptedFileStorage` (XChaCha20-Poly1305, `VCENCST2`) with monotonic-epoch restore. Fail closed: `RollbackDetected` / `StateLost`. |
| One platform binding | C ABI plus **one** of Android JNI or iOS, on real hardware. Not both. Platform not yet selected. |
| Dual licence | MIT OR Apache-2.0. No libsignal (AGPL) linkage in this crate. |

Default `cargo build` / `cargo test` is the v1 surface: feature `std` only.

---

## Out of scope (defend this list)

Every item below is a legitimate later candidate. None of it is in the v1 audit surface.

| Item | How it stays out |
|---|---|
| Group messaging / sender keys | Absent. Do not add. |
| Sealed sender / metadata protection | Absent. Do not add. |
| Attachment or streaming encryption | Absent. Do not add. |
| Multi-device (Sesame) | Feature `sesame` — off by default, not advertised. |
| Hybrid PQ (`HybridPqV1`, Triple / SPQR / Braid) | Feature `hybrid` — compiled only when requested; never auto-selected. |
| Header encryption (`ClassicalHeV1`) | Feature `header-encrypt` — experimental opt-in. |
| Second OS binding | Forbidden until the first platform has hardware evidence. |
| Signal network wire / protobuf `SessionStructure` | Not claimed. Custom `wire/` + `envelope/` only. |
| libsignal as a dependency | Forbidden in this repo. Any differential belongs in a **separate AGPL-licensed** test repo. |

`ffi` and `android` are opt-in build features. Shipping v1 still means **one** of those bindings proven on a device, not enabling every flag.

---

## Default-feature check (Gate 1)

With default features, the advertised profile is `ClassicalV1`. Hybrid, header-encrypt, and sesame must not be on.

```
cargo build
```

Pass: the crate builds; `Cargo.toml` `[features]` keeps `hybrid`, `header-encrypt`, and `sesame` off the default list.

---

## What still has to be true before a v1.0.0 tag

This freeze does **not** make the crate shippable. Remaining gates from `dycrpt-v1-scope-and-comparison.md`:

| Gate | Pass condition |
|---|---|
| 2. Known-answer vectors | `cargo test kat` runs ≥ 100 external vectors (Wycheproof X25519/HMAC, full RFC 7748, full RFC 5869). |
| 3. Mutation | ≥ 85% on `src/primitives/`, `src/ratchet/`, `src/pqxdh/`, `src/replay/`, `src/storage/`. Survivors killed or recorded in `KNOWN_LIMITATIONS.md`. |
| 4. Isolated differential | libsignal linked only in a separate AGPL test binary; ≥ 10,000 transcripts, zero spec-required divergences. |
| 5. Adversarial | host_runner, cargo-fuzz, `ct_timing`, 10k handshake gate as specified there. |
| 6. One real device | Two devices, ≥ 1,000 messages, reorder, kill-app, restore-old-backup → `VC_STATE_LOST` without crash. |
| 7. External audit | Independent review of this v1 surface. **`PRODUCTION_READY` stays false until this.** |

crates.io stays `publish = false` until Gate 7.

---

## Forbidden claims while this freeze holds

- “Production-ready”, “quantum-proof”, “formally verified”, “independently audited”
- “We replicated / cloned / forked libsignal”
- “Drop-in replacement for libsignal” / “Signal-compatible”
- Ungating hybrid, header-encrypt, or sesame as the default
- Adding groups, sealed sender, or a second OS to the v1 audit packet
