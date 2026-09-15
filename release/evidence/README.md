# Release Evidence Layout

`PRODUCTION_READY` is not a source-code opinion. A release candidate is eligible
only when `scripts/release_gate.py` validates a complete evidence directory for
the **exact git commit** being released.

Do not commit private keys, access tokens, real user plaintext, decrypted storage
or real phone numbers into evidence. Physical-device records contain hashes and
synthetic test data only.

## Directory layout

For candidate `<sha>` create a local directory (it may stay outside git):

```text
release/evidence/<sha>/
  core/summary.json
  supply-chain/summary.json
  opk/summary.json
  dynamic/miri.json
  dynamic/asan.json
  dynamic/tsan.json
  dynamic/libfuzzer.json
  timing/x86_64/summary.json
  timing/aarch64/summary.json
  formal/summary.json
  external-differential.json
  interop/android-android.json
  interop/ios-ios.json
  interop/android-ios.json
  interop/ios-android.json
  independent-audit.json
```

The CI artifacts already contain the source summary files; rename/copy them into
this layout without editing their JSON contents. The external differential,
physical-device matrix and independent audit are generated outside normal CI.

## Required strength

The final gate requires, among other checks:

- exact Rust 1.85 locked build, fmt/check/clippy/debug+release tests, 10k randomized
  PQXDH test and bounded fuzz-host pass;
- cargo-deny + RustSec + CycloneDX + auditable production artifacts + Sigstore
  keyless transparency-log-backed provenance;
- 10,000 OPK allocations with at least 100 concurrent workers and zero reuse;
- Miri strict-provenance FFI runs, ASan, TSan, and at least 30 minutes of
  libFuzzer per required target;
- five 500k-sample timing experiments on native x86_64 and native ARM64, all
  within the configured Welch-t threshold;
- all required finite-state TLA+/TLC models passing;
- zero external behavioral divergence on the comparable Signal-core/operational
  corpus;
- all four physical-device directions, all mandatory adversarial cases;
- an independent cryptography audit of the exact candidate SHA with no accepted
  Critical/High findings.

## Run

From a clean checkout of the exact candidate:

```bash
python3 scripts/release_gate.py \
  --commit "$(git rev-parse HEAD)" \
  --evidence-root "release/evidence/$(git rev-parse HEAD)"
```

On success the script writes `release-decision.json` inside the evidence root.
That file contains SHA-256 hashes of every evidence file used in the decision.
Sign that final decision together with the release binaries using the same
Sigstore workflow identity before distribution.

A missing artifact is a failure. A stale artifact from a different commit is a
failure. A short fuzz smoke run is a failure. Simulator-only interop is a failure.
An audit of an older pre-remediation SHA is a failure.
