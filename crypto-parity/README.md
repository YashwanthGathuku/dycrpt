# crypto-parity

Behavioral / security parity harness for VoiceChatCrypto.

This is **not** a “90% same code” tool. It measures **outcomes**:

- reject vs accept
- state advancement on auth failure
- OPK single-use across crash
- identity change is not silent
- VoiceChat-specific bindings

It does **not** require:

- matching ciphertext bytes
- matching SK bytes across implementations
- decrypting libsignal wire formats

## Backends

| Backend | Status |
|---------|--------|
| VoiceChatCrypto | Linked (this workspace) |
| libsignal | **NOT_LINKED** — AGPL isolated. See `backends/libsignal/PIN.md`. |

The parent VoiceChat app is not in this repo, so the libsignal git pin is **UNVERIFIED**. Do not invent a commit hash.

## Run

```
cargo run -p crypto-parity
cargo run -p crypto-parity -- --full
```

`--full` uses a larger randomized DR budget (200×5000). 10k PQXDH handshakes remain `cargo test -p voicechat_crypto --lib ten_thousand`.

Reports land in `crypto-parity/reports/`.

## Gates (promotion)

```
[ ] 100% P0 security gates
[ ] ≥95% Signal-Core
[ ] ≥90% Operational
[ ] 100% VoiceChat invariants
[ ] 0 randomized invariant violations
[ ] 0 parser panics
[ ] no UNKNOWN classification
[ ] libsignal pin recorded (when app repo is available)
```

A 97% core score **fails** if any P0 fails.
