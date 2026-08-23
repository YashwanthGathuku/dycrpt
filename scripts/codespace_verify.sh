#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

export CARGO_TERM_COLOR=always
export RUST_BACKTRACE=1
export DYCRPT_COMMIT="$(git rev-parse HEAD)"
FULL="${DYCRPT_FULL:-0}"
EVIDENCE="codespace-evidence/${DYCRPT_COMMIT}"
mkdir -p "$EVIDENCE"

run_logged() {
  local name="$1"
  shift
  printf '\n===== %s =====\n' "$name"
  "$@" 2>&1 | tee "$EVIDENCE/${name}.log"
}

printf 'dycrpt commit: %s\n' "$DYCRPT_COMMIT" | tee "$EVIDENCE/commit.txt"
rustc --version --verbose | tee "$EVIDENCE/rustc.txt"
cargo --version | tee "$EVIDENCE/cargo.txt"

# The authoritative compile/lint/test suite. This includes all features, so HE,
# Hybrid, Sesame and FFI code are compiled instead of being hidden by defaults.
run_logged core-verify bash scripts/verify.sh

# Explicit Header Encryption regression gate. Keep this separate so a future
# feature-matrix change cannot accidentally stop exercising HE.
run_logged header-encryption \
  cargo test --locked --release --features header-encrypt \
    ratchet::header_encrypt::tests:: -- --nocapture

# Explicit P02 concurrency gate.
run_logged concurrency \
  cargo test --locked --release --test p02_concurrency \
    --features 'ffi header-encrypt' -- --nocapture

# FFI undefined-behavior interpretation under multiple deterministic schedules.
MIRI_SEEDS=2
if [[ "$FULL" == "1" ]]; then MIRI_SEEDS=8; fi
for ((seed=0; seed<MIRI_SEEDS; seed++)); do
  printf '\n===== miri-ffi seed=%s =====\n' "$seed"
  MIRIFLAGS="-Zmiri-strict-provenance -Zmiri-seed=$seed" \
    cargo +nightly-2026-08-20 miri test --locked --features ffi 'ffi::tests::' \
    2>&1 | tee "$EVIDENCE/miri-ffi-${seed}.log"
done

# Native x86_64 sanitizer runs in the Codespace. ARM64 timing remains a separate
# native-architecture release artifact; emulation is not accepted for that gate.
run_logged asan \
  env RUSTFLAGS='-Zsanitizer=address -Cdebuginfo=1' \
      RUSTDOCFLAGS='-Zsanitizer=address' \
      ASAN_OPTIONS='detect_leaks=1:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1' \
      cargo +nightly-2026-08-20 test -Zbuild-std \
        --target x86_64-unknown-linux-gnu --locked --workspace --all-targets --all-features \
        -- --skip ten_thousand

run_logged tsan \
  env RUSTFLAGS='-Zsanitizer=thread -Cdebuginfo=1' \
      RUSTDOCFLAGS='-Zsanitizer=thread' \
      TSAN_OPTIONS='halt_on_error=1:second_deadlock_stack=1:history_size=7' \
      cargo +nightly-2026-08-20 test -Zbuild-std \
        --target x86_64-unknown-linux-gnu --locked --test p02_concurrency \
        --features 'ffi header-encrypt'

# Finite-state models. These prove only the configured state-machine invariants,
# not primitive cryptographic security.
printf '\n===== TLA+/TLC =====\n'
mkdir -p "$EVIDENCE/tlc"
pushd formal/tla >/dev/null
for cfg in *.cfg; do
  model="${cfg%.cfg}"
  test -f "${model}.tla"
  java -XX:+UseSerialGC -Xmx2g -cp ../tools/tla2tools.jar tlc2.TLC \
    -config "$cfg" "${model}.tla" 2>&1 \
    | tee "../../$EVIDENCE/tlc/${model}.log"
done
popd >/dev/null

# Coverage-guided parser/state fuzzing. Quick mode is intended to catch immediate
# regressions; release mode raises each target to 30 minutes.
FUZZ_SECONDS=60
if [[ "$FULL" == "1" ]]; then FUZZ_SECONDS=1800; fi
for target in envelope_parse header_decode triple_header_decode engine_wire prekey_bundle state_decoders; do
  printf '\n===== fuzz %s (%ss) =====\n' "$target" "$FUZZ_SECONDS"
  cargo +nightly-2026-08-20 fuzz run "$target" -- \
    -max_total_time="$FUZZ_SECONDS" -timeout=10 -rss_limit_mb=4096 -print_final_stats=1 \
    2>&1 | tee "$EVIDENCE/fuzz-${target}.log"
done

# Statistical timing leakage smoke on the actual Codespace CPU. This does not
# substitute for the required native ARM64 release run.
TIMING_SAMPLES=50000
if [[ "$FULL" == "1" ]]; then TIMING_SAMPLES=500000; fi
run_logged ct-timing \
  bash -lc "cargo build --locked --release --bin ct_timing && taskset -c 0 target/release/ct_timing --samples $TIMING_SAMPLES --warmup 20000 --max-t 10"

# Production-like PostgreSQL allocator concurrency. Docker-in-Docker is supplied
# by the Codespace devcontainer.
printf '\n===== OPK allocator =====\n'
docker rm -f dycrpt-postgres >/dev/null 2>&1 || true
docker run -d --name dycrpt-postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=voicechat_ci \
  -p 5432:5432 \
  postgres:16 -c max_connections=300 >/dev/null
for _ in $(seq 1 60); do
  if pg_isready -h 127.0.0.1 -U postgres -d voicechat_ci >/dev/null 2>&1; then break; fi
  sleep 1
done
export DATABASE_URL='postgresql://postgres:postgres@127.0.0.1:5432/voicechat_ci'
PGPASSWORD=postgres psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f server/postgres/001_opk_allocator.sql
PGPASSWORD=postgres psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f server/postgres/002_rollback_anchor.sql
PGPASSWORD=postgres psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f server/postgres/ci_seed.sql
OPK_REQUESTS=500
OPK_WORKERS=64
OPK_EXTRA=(--allow-smoke)
if [[ "$FULL" == "1" ]]; then
  OPK_REQUESTS=10000
  OPK_WORKERS=128
  OPK_EXTRA=()
fi
.venv/bin/python server/postgres/stress_opk_allocator.py \
  --device-hex 6465766963652d6369 \
  --requests "$OPK_REQUESTS" \
  --workers "$OPK_WORKERS" \
  --require-one-time-pq \
  --commit "$DYCRPT_COMMIT" \
  --json-out "$EVIDENCE/opk.json" \
  "${OPK_EXTRA[@]}" \
  2>&1 | tee "$EVIDENCE/opk.log"

docker rm -f dycrpt-postgres >/dev/null 2>&1 || true

python3 - <<'PY'
import json, os, pathlib, platform
root = pathlib.Path('codespace-evidence') / os.environ['DYCRPT_COMMIT']
summary = {
    'schema': 'dycrpt-codespace-verification-v1',
    'commit': os.environ['DYCRPT_COMMIT'],
    'architecture': platform.machine(),
    'full': os.environ.get('DYCRPT_FULL') == '1',
    'header_encryption_explicitly_tested': True,
    'core_verify': True,
    'miri': True,
    'asan': True,
    'tsan': True,
    'tlc': True,
    'libfuzzer': True,
    'timing_x86_smoke': True,
    'opk_allocator': True,
    'passed': True,
}
(root / 'summary.json').write_text(json.dumps(summary, sort_keys=True, indent=2) + '\n')
PY

printf '\n============================================================\n'
printf 'CODESPACE VERIFICATION PASS\n'
printf 'commit=%s full=%s\n' "$DYCRPT_COMMIT" "$FULL"
printf 'evidence=%s\n' "$EVIDENCE"
printf '============================================================\n'
