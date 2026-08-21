# FFI.md — Android / iOS Bindings

**Gate:** Production mobile builds only after the full desktop Rust test suite passes.

## Architecture

```
Flutter (Dart)
    │  strongly typed method channels / Pigeon / FFIgen
    ▼
Kotlin  (Android)          Swift  (iOS)
    │                           │
    └──────────┬────────────────┘
               ▼
        C ABI  (voicechat_crypto.h)
               ▼
        Rust VoiceChatCryptoEngine
        (opaque handles; secrets never exported)
```

## Exposed high-level operations

| Operation | C symbol | Notes |
| --------- | -------- | ----- |
| createEngine | `vc_engine_create` | Identity + prekeys; 32-byte public identity only |
| generateBundle | `vc_generate_bundle` | Public prekey bundle (`VCBUNDL1`) |
| establishOutbound | `vc_establish_outbound` | PQXDH Alice path; returns session id + `VCINIT01` packet |
| processInbound | `vc_process_inbound` | PQXDH Bob path; first plaintext out |
| encrypt | `vc_encrypt` | Sealed blob (`VCSEAL01`) |
| decrypt | `vc_decrypt` | State unchanged on auth failure |
| fingerprint | `vc_fingerprint` | Binary + numeric; public keys only |
| deleteSession | `vc_delete_session` | Drops one session inside the engine |
| destroyEngine | `vc_engine_destroy` | Drops + zeroizes engine secrets |
| protocolVersion | `vc_protocol_version` | Interop check |

Size-query convention: a null output buffer (or undersized `out_len`) writes the required length and returns `VC_INVALID_ARGUMENT`.

## Never exposed

- Root keys, chain keys, message keys
- Identity **private** keys
- ML-KEM **private** keys
- PQXDH shared secret `SK`
- Signed-prekey / one-time prekey **secrets**
- Internal ratchet state blobs (except via future sealed backup APIs)

There is **no** C symbol that accepts a 32-byte shared secret or DH secret.

## Interoperability

Android and iOS builds **must** use the same `PROTOCOL_VERSION` and negotiate the same `CryptoProfile`. Cross-platform tests:

1. Create engines on A and B
2. B publishes a bundle; A calls `vc_establish_outbound`
3. B calls `vc_process_inbound` and recovers the first plaintext
4. Encrypt on Android → decrypt on iOS and the reverse
5. Compare safety fingerprints (must match symmetrically)

In-repo: `ffi::tests::alice_bob_ffi_pqxdh_no_secrets_cross` exercises this on the C ABI (not physical devices).

## Build notes

- **Android:** `cargo build --target aarch64-linux-android` (and armv7 / x86_64 as needed) → JNI glue mapping to the Kotlin `external` methods.
- **iOS:** `cargo build --target aarch64-apple-ios` (+ simulator) → static lib linked into the Xcode framework; bridging header includes `voicechat_crypto.h`.

## Secret storage

Prefer platform secure storage for any long-term private key backup:

- Android: StrongBox / Keystore-backed files
- iOS: Keychain / Secure Enclave when available

The FFI keeps secrets in Rust memory for live engines; persistence is the host app’s responsibility using the transactional storage trait.

## Files

```
src/ffi/mod.rs              # C ABI implementation
ffi/include/voicechat_crypto.h
ffi/kotlin/VoiceChatCrypto.kt
ffi/swift/VoiceChatCrypto.swift
```
