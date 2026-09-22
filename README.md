# voicechat-crypto

Clean-room Rust engine for 1:1 encrypted sessions. It implements the **public-domain** PQXDH, Double Ratchet, and XEdDSA specifications and FIPS 203 ML-KEM, under MIT OR Apache-2.0. No AGPL/GPL runtime dependencies.

**Not affiliated with Signal. Not a port of libsignal. Not compatible with the Signal network.** Those specifications are public; libsignal (AGPL-3.0) was not used as a source.

Built so apps, devices, and **agent runtimes** can embed E2E without taking AGPL into the binary. Default profile is ClassicalV1. Hybrid PQ is experimental and opt-in.

**This crate is not production-ready.** Internal tests and engineering gates are not a substitute for an independent cryptography review. See [`docs/PRODUCTION.md`](docs/PRODUCTION.md) and [`docs/AUDIT_SCOPE.md`](docs/AUDIT_SCOPE.md).

**Continue work:** [`docs/PUBLIC_LAUNCH.md`](docs/PUBLIC_LAUNCH.md) (what to say and what to do next), [`docs/LAUNCH_RECORD.md`](docs/LAUNCH_RECORD.md) (what was measured), [`docs/KAT.md`](docs/KAT.md) (`cargo test kat`), then [`docs/HANDOFF.md`](docs/HANDOFF.md) and [`docs/NEXT_STEPS.md`](docs/NEXT_STEPS.md).

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

[`docs/V1_SCOPE.md`](docs/V1_SCOPE.md) — v1 freeze: 1:1 `ClassicalV1`, persistent storage, one FFI. Hybrid / header-encrypt / sesame stay gated.

[`docs/FINAL_SECURITY_RULE.md`](docs/FINAL_SECURITY_RULE.md) — security wins over convenience. Do not invent algorithms, replace PQXDH, reuse keys, or expose secrets through FFI.
