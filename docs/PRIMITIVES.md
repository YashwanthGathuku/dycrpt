# PRIMITIVES.md

**Project:** voicechat-crypto  
**Date:** 2026-08-17  
**Status:** Primitive layer selection frozen

## Selection Principles

- No hand-implemented mathematical primitives.
- Only current, maintained, permissively licensed crates (MIT / Apache-2.0 / BSD-3-Clause).
- Prefer RustCrypto organization or dalek-cryptography where possible.
- Enable `zeroize` features wherever available.
- Document exact crate + version + purpose + license.

## Selected Libraries

| Primitive | Crate | Version (pinned) | License | Purpose / Notes |
|-----------|-------|------------------|---------|-----------------|
| CSPRNG | `rand_core` + `getrandom` | 0.6 / 0.2 | MIT/Apache | Cryptographically secure random bytes |
| X25519 | `x25519-dalek` | 2.0.1 | BSD-3-Clause | Diffie-Hellman (RFC 7748). `static_secrets` + `zeroize` |
| Curve ops / XEdDSA support | `curve25519-dalek` | 4.1 | BSD-3-Clause | Underlying field/group arithmetic; used for XEdDSA key conversion per public XEdDSA spec |
| Signatures (EdDSA / XEdDSA) | `ed25519-dalek` | 2.1 | BSD-3-Clause | Ed25519; XEdDSA constructed on top using public specification + dalek primitives |
| ML-KEM (FIPS 203) | `ml-kem` | 0.3.2 | Apache-2.0 OR MIT | Pure-Rust FIPS 203 ML-KEM-768 (linked; not a test double) |
| HKDF | `hkdf` | 0.12 | Apache-2.0 OR MIT | RFC 5869 |
| HMAC | `hmac` | 0.12 | Apache-2.0 OR MIT | RFC 2104 |
| SHA-256 / SHA-512 | `sha2` | 0.10 | Apache-2.0 OR MIT | FIPS 180-4 |
| AEAD (primary) | `aes-gcm` | 0.10 | Apache-2.0 OR MIT | AES-256-GCM |
| AEAD (alternative) | `chacha20poly1305` | 0.10 | Apache-2.0 OR MIT | ChaCha20-Poly1305 |
| Constant-time eq | `subtle` | 2.5 | BSD-3-Clause | `ConstantTimeEq` |
| Secret zeroization | `zeroize` | 1.8 | Apache-2.0 OR MIT | `Zeroize` / `ZeroizeOnDrop` |

All selected crates appear in the earlier LICENSE_AUDIT and are acceptable.

## Domain-Separated KDF Labels (Frozen)

These strings are **versioned and frozen**. They must never be changed without a protocol version bump.

```
VoiceChat/PQXDH/v1/Handshake
VoiceChat/PQXDH/v1/AD
VoiceChat/DR/v1/Root
VoiceChat/DR/v1/Chain
VoiceChat/DR/v1/Message
VoiceChat/DR/v1/Header
VoiceChat/SPQR/v1/Epoch
VoiceChat/Triple/v1/Hybrid
VoiceChat/Attachment/v1
VoiceChat/Voice/v1
VoiceChat/Fingerprint/v1
VoiceChat/Sesame/v1/Session
```

Usage pattern:

```rust
hkdf_expand(ikm, salt, b"VoiceChat/DR/v1/Root", output_len)
```

Never use generic labels such as `"key"`, `"root"`, `"chain"`, or empty info.

## Known-Answer Tests & Fuzzing

Every wrapper in `src/primitives/` has:

- Known-answer tests (KATs) against published vectors where available (RFC 7748, RFC 5869, FIPS 203 KATs, AES-GCM test vectors).
- Negative tests for:
  - Invalid / all-zero public keys
  - Malformed ML-KEM ciphertexts
  - Corrupted AEAD tags
  - Incorrect associated data
  - Incorrect keys
  - Nonce misuse (where the API can detect it)
  - Malformed lengths
  - Boundary / all-zero inputs

Fuzz targets exist for every untrusted decoding path (public keys, ciphertexts, sealed messages once wire parsing is added).

## Profile Choice

- **Classical:** X25519
- **Post-quantum KEM:** ML-KEM-768 (NIST security category 3)
- **Hash / KDF:** SHA-256 / HKDF-SHA256 (primary); SHA-512 available where specs require
- **AEAD:** AES-256-GCM (primary); ChaCha20-Poly1305 available as alternative suite

This matches the current Signal PQXDH + Triple Ratchet recommendations while remaining independent.

## Next

Primitive wrappers now include real ML-KEM-768. Protocol layers sit on top of that wrapper. Independent audit of `ml-kem` is still outstanding.