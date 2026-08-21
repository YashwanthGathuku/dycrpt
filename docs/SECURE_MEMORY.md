# SECURE_MEMORY.md — Zeroizing Secure Memory Handling

**Date:** 2026-08-17

## Goal

Minimize lifetime of secret material in process memory: message keys, chain keys, root keys, identity private keys, ML-KEM private keys, ephemeral handshake secrets, and temporary DH/HKDF buffers.

## Mechanisms

| Mechanism | Location |
|-----------|----------|
| `Zeroize` / `ZeroizeOnDrop` on secret types | `X25519Secret`, `AeadKey`, prekey structs, ratchet state, SPQR state, KEM secrets, `SecretBytes` / `SecretBytes32` |
| Explicit `mk.zeroize()` after AEAD | Classical Double Ratchet encrypt/decrypt |
| Explicit zeroize of DH intermediates and KM | PQXDH Alice/Bob paths |
| `ZeroizingScope<T>` / `with_secret_32` | Scoped temporaries that wipe on exit |
| `secure_zero` / `secure_zero_32` | One-shot wipe of buffers |
| Constant-time equality | `SecretBytes`, `SecretBytes32`, `ct_eq` via `subtle` |
| FFI | Shared-secret stack copy zeroized after install; session/identity drop zeroizes via `Drop` |

## Preferred types for secrets

- **`SecretBytes32`** — fixed 32-byte keys (preferred over raw `[u8; 32]` for new code)
- **`SecretBytes`** — variable-length secret buffers
- **`ZeroizingScope`** — RAII wipe for any `Zeroize` value

## When to zeroize

1. Immediately after a message key is used for AEAD (encrypt or decrypt)
2. After DH outputs are mixed into a KDF
3. After HKDF OKM is split into named keys
4. On consumption of one-time prekeys (storage delete + drop of secret type)
5. On session/identity handle deletion (FFI)

## Residual risks (not solved in userspace)

- Compiler may leave copies in registers or stack slots
- OS swap, crash dumps, memory compression
- Foreign heaps if JNI/Swift copy bytes (bindings must not hold secrets)
- Debugger / compromised OS

See also `docs/HARDENING.md` item 7.

## Tests

- `primitives::zeroizing` unit tests (ct_eq, secure_zero, scope)
- Ratchet tests still pass with post-use zeroize of message keys
- Adversarial tests for failed decrypt not committing state (orthogonal but related)
