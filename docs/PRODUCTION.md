# Production status

**`PRODUCTION_READY` is false.** This file lists what was closed in-repo and what still blocks a production claim.

The project rule (`AUDIT_SCOPE.md`):

```
PRODUCTION_READY :=
    external_cryptography_audit_passed
    AND all BLOCKED items cleared
    AND hybrid claims scoped to POST_QUANTUM_PROFILE non-claims
    AND mobile FFI interop evidence recorded (if shipping mobile)
```

Compilation and green tests do not flip that bit.

## Closed in-repo (engineering)

| Item | Status |
|------|--------|
| PQXDH + classical Double Ratchet | In-repo tested |
| Triple + incremental Encaps1/Encaps2 | In-repo tested; Encaps1‖Encaps2 matches `ml-kem` Encrypt |
| ClassicalV1 default advertised | `PROFILE_PREFERENCE` |
| Hybrid / HE experimental, not auto-selected | Cargo features + preference list |
| Braid MAC verify constant-time | `subtle::ConstantTimeEq` |
| Session manager panic-free lookup | `Result` instead of `unwrap` |
| Authenticator zeroized on drop | `ZeroizeOnDrop` |
| Release overflow checks + thin LTO | `Cargo.toml` `[profile.release]` |
| CI: fmt, clippy -D warnings, debug + release tests, host fuzz | `.github/workflows/ci.yml` |
| Secret-free FFI | C / Kotlin / Swift wrappers |

## Still BLOCKED (cannot be closed here)

| Item | Why |
|------|-----|
| Independent cryptography review | Required by `AUDIT_SCOPE.md`. Packet: `AUDIT_HANDOFF.md` |
| `ml-kem` 0.3.2 unaudited | Upstream statement |
| Encaps1 side-channel lab eval | Our lattice path is not a constant-time audited implementation |
| TEE-backed monotonic counter | `MemoryCounter` is in-process only |
| Physical Android/iOS interop | Build notes exist; devices not run |
| Parent VoiceChat app | Not in this workspace |
| Formal verification of the crypto | TLC checks finite models only |
| Userspace zeroize completeness | OS swap / dumps / compression |
| Signal network wire compatibility | Not claimed |

## What an integrator may do now

- Use `DeviceConfig::recommended` for new peers (**ClassicalV1** on this build).
- Hybrid only via explicit `DeviceConfig { profile: CryptoProfile::HybridPqV1, .. }` and `--features hybrid`.
- Ship **only** after an external reviewer writes ship / ship-with-fixes — not because this file exists.

## Forbidden claims

- “Production-ready”
- “Quantum-proof”
- “Formally verified”
- “Independently audited”
