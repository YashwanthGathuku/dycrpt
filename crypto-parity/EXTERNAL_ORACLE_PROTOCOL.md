# External Behavioral Differential Oracle Protocol v1

The purpose of this protocol is to compare dycrpt against an independently built
reference implementation (for example libsignal) **without linking AGPL code into
this permissively licensed repository and without comparing source code**.

Each implementation is executed as a separate process. It emits newline-delimited
JSON to stdout. The differential runner consumes only normalized behavioral
outcomes.

## Clean-room boundary

- The dycrpt oracle is `cargo run -p crypto-parity --bin external-oracle`.
- A reference oracle belongs in a separate workspace with licensing compatible
  with that reference implementation.
- Do not copy reference source, constants, comments, internal state layouts, or
  private implementation details into dycrpt.
- Reference adapters should be derived from public APIs/public protocol specs and
  return only the normalized observations below.
- Raw private keys, shared secrets, chain/root/message keys, decrypted durable
  state and production user plaintext must never appear in the oracle stream.

## Stream format

The first line is exactly one metadata record:

```json
{"type":"metadata","schema":"dycrpt-external-oracle-v1","implementation":"dycrpt","commit":"<40 hex>","protocol_family":"Signal-public-specs","private_material_logged":false}
```

The reference uses its own implementation name and exact source commit/tag, for
example `libsignal-<commit>`. The `commit` field must still be a 40-character git
SHA for reproducibility.

Then emit one scenario record per deterministic corpus ID:

```json
{"type":"scenario","id":"dr-auth-fail-no-advance","category":"ratchet","axis":"signal-core","p0":true,"status":"pass","classification":"pass","note":""}
```

Required fields:

- `id`: stable corpus scenario identifier.
- `category`: implementation-neutral category.
- `axis`: `signal-core`, `operational`, or `voicechat`.
- `p0`: whether divergence is a security-critical blocker.
- `status`: `pass`, `fail`, or `unsupported`.
- `classification`: `pass`, `fail`, `intentional-difference`, `spec-variant`,
  `unknown`, or `unsupported`.
- `note`: short non-secret reason.

The final record is:

```json
{"type":"summary","scenarios":80,"failures":0}
```

## Comparison rule

For `signal-core` and `operational` scenarios, the reference must implement every
scenario. `unsupported`, missing, duplicated, unknown or conflicting metadata is
a release failure.

For `voicechat`-specific scenarios, a general-purpose reference may mark the
scenario `unsupported`; those rows are validated independently by dycrpt's own
VoiceChat invariants and physical-device gate.

A differential pass requires:

1. identical scenario ID sets for all comparable axes;
2. zero `unknown` classifications;
3. identical pass/fail semantic outcomes for all comparable IDs;
4. zero P0 divergences;
5. exact dycrpt candidate SHA and exact reference SHA recorded;
6. `private_material_logged=false` for both implementations.

Ciphertext bytes, root keys, message keys and implementation-specific internal
state are deliberately **not** compared. Cryptographically correct independent
implementations are expected to produce different randomness and can use
completely different internal representations.

## Reference-adapter contract

The external reference adapter should execute each scenario using only public
APIs and translate the outcome into this protocol. It must not alter dycrpt source
or write files into this repository. `run_external_differential.py` treats the
reference command as untrusted input: malformed JSON, excessive output, timeout,
secret-looking field names or duplicate IDs fail closed.
