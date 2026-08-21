# voicechat-crypto

Clean-room Rust crypto engine for VoiceChat. Implements **public** Signal-family specifications only (PQXDH, Double Ratchet Rev 4, XEdDSA, ML-KEM Braid as SCKA). No libsignal. No AGPL/GPL runtime deps.

**This crate is not production-ready.** Internal tests and engineering gates are not a substitute for an independent cryptography review. See [`docs/PRODUCTION.md`](docs/PRODUCTION.md) and [`docs/AUDIT_SCOPE.md`](docs/AUDIT_SCOPE.md).

**Continue work:** [`docs/HANDOFF.md`](docs/HANDOFF.md) then [`docs/NEXT_STEPS.md`](docs/NEXT_STEPS.md).

## Profiles

| Profile | Contents | How selected |
|---------|----------|--------------|
| `ClassicalV1` | PQXDH + classical Double Ratchet | **Default advertised** |
| `HybridPqV1` | PQXDH + Triple (SPQR ‖ Braid) | Experimental — explicit `DeviceConfig.profile` only |
| `ClassicalHeV1` | Classical + header encryption | Experimental opt-in |

Default advertised preference: **ClassicalV1**. Hybrid is compiled only with `--features hybrid` and is never auto-selected.

## Integrator surface

Depend on `VoiceChatCryptoEngine` / `CryptoEngineApi` only. Private keys never leave the Rust boundary.

```rust
use voicechat_crypto::{DeviceConfig, VoiceChatCryptoEngine};

let mut alice = VoiceChatCryptoEngine::initialize_device(
    DeviceConfig::recommended(b"alice-device".to_vec()),
)?;
```

## Security-property harness

[`crypto-parity/`](crypto-parity/) runs a behavioral corpus (not byte-equality, not Signal wire). libsignal is **not** linked (AGPL).

```
cargo run -p crypto-parity
```

## Build / test

```
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features -- --skip ten_thousand
```

MSRV 1.85. Windows GNU hosts need `rust-lld` (see `rust-toolchain.toml`).

## Policy

[`docs/FINAL_SECURITY_RULE.md`](docs/FINAL_SECURITY_RULE.md) — security wins over convenience. Do not invent algorithms, replace PQXDH, reuse keys, or expose secrets through FFI.
