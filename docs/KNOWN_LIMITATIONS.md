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

## FFI persistent constructor (added 2026-08-28)

`vc_engine_open_persistent` is the production constructor. `vc_engine_create`
remains development-only in-memory storage and must not ship.

Open items an integrator and auditor must both check:

1. **`VcRollbackAnchorCallbacks` thread-safety is asserted, not proven.**
   `FfiRollbackAnchor` carries `unsafe impl Send + Sync`. The engine is
   internally concurrent, so the caller's `ctx` and both callbacks must be safe
   to invoke from multiple threads at once. Nothing in Rust checks this. It is a
   required review point for every platform adapter.
2. **No rollback anchor implementation ships with this library.** The only
   in-tree implementations are test doubles. A row in the same database as the
   state file, or a file beside it, does NOT satisfy the contract — both are
   restored together with the state they are meant to validate. Roadmap item 8
   is unstarted.
3. **No recovery path is provided, deliberately.** `RollbackDetected` and
   `StateLost` are terminal. Choosing between refuse-to-start and
   re-provision-with-forced-rekeying is a product decision with a security
   consequence; performing the latter silently is an attacker-triggerable
   downgrade that also invalidates every peer safety number without explanation.
4. **The storage key is supplied by the caller.** This library does not derive,
   wrap, or protect it. Binding it to Android Keystore / iOS Keychain is roadmap
   items 6 and 7, both unstarted, and neither can be validated without hardware.

## Platform adapters (added 2026-08-28) — UNTESTED ON HARDWARE

The Kotlin, Swift and JNI code below was written but **has never been compiled
against an Android NDK or an iOS toolchain, and has never run on a device.** It
is a starting point for hardware testing, not a validated component.

### Android had never worked

`ffi/kotlin/VoiceChatCrypto.kt` declared `external fun native*` methods since it
was written, but no JNI implementation existed in this crate and `jni` was not a
dependency. `System.loadLibrary` would have succeeded (the cdylib is real) and
every subsequent native call would have thrown `UnsatisfiedLinkError`.
`src/ffi/jni.rs` supplies the missing symbols, behind the new `android` feature.

### The rollback anchor limit, stated plainly

**Neither Android nor iOS exposes an app-accessible hardware monotonic counter.**
The bundled anchors seal a counter with Android Keystore / iOS Keychain and keep
it out of backups.

* Defends against: backup restore, device-to-device transfer, restoring an old
  app container. These surface as `VC_STATE_LOST` — terminal and correct.
* Does **not** defend against: an attacker with root or a jailbreak, who can
  capture counter and state together and replay both. The pair stays internally
  consistent and the rollback is invisible.

If the threat model includes a compromised device, the only sound anchor is a
server-held counter. `ServerRollbackAnchor` is declared as an interface
deliberately: the correctness lives in the backend's atomic conditional update
and in resolving unknown-outcome increments by re-reading, neither of which this
library can supply.

### Specific items for hardware testing

1. `VcRollbackAnchorCallbacks` thread-safety is asserted via `unsafe impl
   Send + Sync`. The engine is concurrent; the Kotlin and Swift anchors use a
   lock and a serial queue respectively. Verify under real concurrent load.
2. JNI anchor thunks acquire an `AttachGuard` per call. Not benchmarked.
3. `nativeLiveAnchorCount` exists so a create/destroy loop can be checked for
   `GlobalRef` leaks. Run it.
4. Android Keystore key invalidation (user removes lock screen) makes the
   counter permanently undecryptable and produces `VC_STATE_LOST`. Fail-closed
   and intended, but a real user-facing lockout that needs UX.
5. iOS `AfterFirstUnlockThisDeviceOnly` means the anchor is unreadable before
   first unlock after boot. Background push crypto will get
   `VC_ANCHOR_UNAVAILABLE`. That is transient and retryable and must not be
   handled as a rollback.
