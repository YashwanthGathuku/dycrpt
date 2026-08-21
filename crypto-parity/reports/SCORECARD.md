# Crypto parity scorecard

**Not a code-similarity score.** Outcomes are security properties.
**Not wire-compatible with Signal.** SK/CT bytes are not compared across backends.

| Axis | Score | Passed |
|---|---:|---:|
| Signal-Core | 100.0% | 44/44 |
| Operational hardening | 100.0% | 17/17 |
| VoiceChat invariants | 100.0% | 13/13 |

P0 failures: **0**

Randomized transitions: 10128 (violations 0)

Malformed inputs: 33 (panics 0)

libsignal backend: **NOT_LINKED** (AGPL isolated; see `backends/libsignal/PIN.md`).
