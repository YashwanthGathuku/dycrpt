# LICENSE_AUDIT.md

**Repository:** voicechat-crypto  
**Audit date:** 2026-08-17 (amended after `ml-kem` 0.3.2 was linked)  
**Goal:** Ensure the final library is permissively licensable (MIT / Apache-2.0 dual or equivalent). Reject any AGPL, GPL, LGPL, or other reciprocal license unless explicitly approved in writing.

## Summary Decision

**Status:** Gate open. Runtime dependencies in `Cargo.toml` are MIT / Apache-2.0 / BSD-3-Clause.  
No AGPL/GPL/LGPL runtime dependency is present.

## Audit Table

| Component | Purpose | License | Runtime? | Acceptable? |
| --------- | ------- | ------- | -------- | ----------- |
| `ml-kem` 0.3.2 | FIPS 203 ML-KEM-768 | Apache-2.0 OR MIT | Yes | **Yes** |
| `x25519-dalek` 2.0.0 | X25519 (RFC 7748) | BSD-3-Clause | Yes | **Yes** |
| `curve25519-dalek` 4.1.1 | Edwards ops for XEd25519 | BSD-3-Clause | Yes | **Yes** |
| `ed25519-dalek` 2.1.0 | Ed25519 helper (non-PQXDH) | BSD-3-Clause | Yes | **Yes** |
| `hkdf` 0.12.3 | HKDF (RFC 5869) | Apache-2.0 OR MIT | Yes | **Yes** |
| `sha2` 0.10.8 | SHA-256 / SHA-512 | Apache-2.0 OR MIT | Yes | **Yes** |
| `sha3` 0.10.8 | SHA3-256 (Braid header hash) | Apache-2.0 OR MIT | Yes | **Yes** |
| `hmac` 0.12.1 | HMAC | Apache-2.0 OR MIT | Yes | **Yes** |
| `aes-gcm` 0.10.3 | AES-256-GCM | Apache-2.0 OR MIT | Yes | **Yes** |
| `chacha20poly1305` 0.10.1 | Alternate AEAD | Apache-2.0 OR MIT | Yes | **Yes** |
| `subtle` 2.5.0 | Constant-time equality | BSD-3-Clause | Yes | **Yes** |
| `zeroize` 1.7 | Secret zeroization | Apache-2.0 OR MIT | Yes | **Yes** |
| `rand_core` 0.6.4 / `getrandom` 0.2.12 | CSPRNG | MIT / Apache-2.0 | Yes | **Yes** |
| `thiserror` 1.0.57 | Errors | MIT OR Apache-2.0 | Yes | **Yes** |
| `hex` 0.4.3 | Hex helpers | MIT OR Apache-2.0 | Yes | **Yes** |
| `proptest` 1.4 (dev) | Property tests | MIT OR Apache-2.0 | No | **Yes** |
| `libsignal` (any form) | — | AGPL-3.0 | — | **No** |
| Any GPL / AGPL / LGPL crate | — | Reciprocal | — | **No** |

## Dependency Policy

1. No reciprocal licenses at runtime.
2. Prefer dual-licensed (MIT OR Apache-2.0) pure-Rust crates.
3. Transitive licenses must be re-scanned (`cargo deny` / `cargo-license`) before a release tag. That scan is **not** recorded in this session.
4. Do not hand-implement primitives when a reputable permissive crate exists.

## Approval Gate

**This audit is complete for the current `Cargo.toml` pins.**  
Protocol implementation may continue, subject to `docs/SOURCE_BOUNDARY.md`.
