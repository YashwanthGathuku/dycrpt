# KNOWN_LIMITATIONS.md

**Status:** Living document — must not be narrowed without evidence

1. **Not production-ready** until independent expert cryptography review completes.  
2. **Toolchain:** MSRV 1.85 (required by `ml-kem` 0.3.2). This session built with rustc 1.96 + rust-lld on Windows GNU.  
3. **ML-KEM Braid / SPQR:** Triple Ratchet runs **Braid SCKA** (`BraidScka`, persist `VCBRAID3` with full in-flight agent state; `VCBRAID1`/`VCBRAID2` reload as role-only). Incremental **Encaps1/Encaps2** are implemented from FIPS 203 (`src/primitives/mlkem_inc.rs`): Encaps1 produces ct1 from the 64-byte header (ρ ‖ H(ek)) alone; Encaps2 produces ct2 from t̂. Concatenated ct matches `ml-kem` `encapsulate_deterministic` (same 34-bit compress reciprocal) and Decaps equals the FO shared secret. Handshake PQ secret still seeds the first SPQR epoch; Braid injects later epochs only after both sides have the SCKA key. Do not call the stack “quantum proof.”  
4. **XEdDSA:** XEd25519 implemented from the public spec. VXEdDSA is not implemented.  
5. **Header Encryption / Hybrid:** Optional Cargo features (`hybrid`, `header-encrypt`). Default **advertised** preference is ClassicalV1. Hybrid is experimental (unaudited Encaps1/Braid). An app may opt in via `DeviceConfig.profile`.  
6. **Sesame:** **Not a production surface.** Module is `#[cfg(any(test, feature = "sesame"))]`. Retry path still uses a hardcoded SK; do not enable the feature for VoiceChat V1.  
7. **Secure deletion:** Userspace zeroize is best-effort.  
8. **Rollback:** `storage::monotonic::MonotonicCounter` is the hook; `MemoryCounter` is not TEE-backed.  
9. **Formal models:** TLC finite instances + new `SesameMailbox` / `BraidEpoch` models. **Library is not formally verified.**  
10. **FFI:** C ABI wraps the engine. Kotlin/Swift + Android/iOS **build notes** exist. Physical device interop **not executed.**  
11. **No Signal network wire compatibility** claimed.  
12. **Independent audit** not done. Packet: `docs/AUDIT_HANDOFF.md`, `docs/SPEC_TRACE.md`.  
13. **`ml-kem` 0.3.2** upstream states it has never been independently audited.
