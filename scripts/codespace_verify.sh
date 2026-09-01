#!/usr/bin/env bash
set -uo pipefail

cd "$(git rev-parse --show-toplevel)"

export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
export CARGO_TERM_COLOR=always
export RUST_BACKTRACE=1
export DYCRPT_COMMIT="$(git rev-parse HEAD)"
FULL="${DYCRPT_FULL:-0}"
EVIDENCE="codespace-evidence/${DYCRPT_COMMIT}"
mkdir -p "$EVIDENCE"

FAILURES=()
SKIPPED=()

run_logged() {
  local name="$1"
  shift
  printf '\n===== %s =====\n' "$name"
  "$@" 2>&1 | tee "$EVIDENCE/${name}.log"
  local status=${PIPESTATUS[0]}
  if [[ $status -eq 0 ]]; then
    printf '===== %s: PASS =====\n' "$name"
  else
    printf '===== %s: FAIL (exit %s) =====\n' "$name" "$status"
    FAILURES+=("$name:$status")
  fi
  return 0
}

skip_stage() {
  local name="$1"
  local reason="$2"
  printf '\n===== %s =====\n' "$name"
  printf 'SKIPPED: %s\n' "$reason" | tee "$EVIDENCE/${name}.log"
  printf '===== %s: SKIPPED =====\n' "$name"
  SKIPPED+=("$name:$reason")
}

pf_has() {
  local key="$1"
  [[ "${!key:-0}" == 1 ]]
}

require_or_skip() {
  local name="$1"
  shift
  local missing=()
  local key
  for key in "$@"; do
    if ! pf_has "$key"; then
      missing+=("$key")
    fi
  done
  if ((${#missing[@]} > 0)); then
    skip_stage "$name" "missing ${missing[*]} (see env-preflight)"
    return 1
  fi
  return 0
}

printf 'dycrpt commit: %s\n' "$DYCRPT_COMMIT" | tee "$EVIDENCE/commit.txt"
rustc --version --verbose | tee "$EVIDENCE/rustc.txt"
cargo --version | tee "$EVIDENCE/cargo.txt"

run_logged env-preflight bash scripts/codespace_preflight.sh "$EVIDENCE/preflight.env"
if [[ -f "$EVIDENCE/preflight.env" ]]; then
  # shellcheck disable=SC1090
  source "$EVIDENCE/preflight.env"
fi

# Core compile/lint/test suite. verify.sh itself collects all independent core
# failures, so a rustfmt issue no longer hides test/release/fuzz-host failures.
if require_or_skip core-verify HAS_RUSTC_185; then
  run_logged core-verify bash scripts/verify.sh
fi

# Explicit Header Encryption regression gate.
if require_or_skip header-encryption HAS_RUSTC_185; then
  run_logged header-encryption \
    cargo test --locked --release --features header-encrypt \
      ratchet::header_encrypt::tests:: -- --nocapture
fi

# Explicit P02 concurrency gate.
if require_or_skip concurrency HAS_RUSTC_185; then
  run_logged concurrency \
    cargo test --locked --release --test p02_concurrency \
      --features 'ffi header-encrypt' -- --nocapture
fi

# FFI undefined-behavior interpretation under multiple deterministic schedules.
MIRI_SEEDS=2
if [[ "$FULL" == "1" ]]; then MIRI_SEEDS=8; fi
for ((seed=0; seed<MIRI_SEEDS; seed++)); do
  if require_or_skip "miri-ffi-${seed}" HAS_NIGHTLY HAS_MIRI; then
    run_logged "miri-ffi-${seed}" \
      env MIRIFLAGS="-Zmiri-strict-provenance -Zmiri-seed=$seed" \
      cargo +nightly-2026-08-20 miri test --locked --features ffi 'ffi::tests::'
  fi
done

# Native x86_64 sanitizer runs in the Codespace.
if require_or_skip asan HAS_NIGHTLY HAS_SANITIZER; then
  run_logged asan \
    env RUSTFLAGS='-Zsanitizer=address -Cdebuginfo=1' \
        RUSTDOCFLAGS='-Zsanitizer=address' \
        ASAN_OPTIONS='detect_leaks=1:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1' \
        cargo +nightly-2026-08-20 test -Zbuild-std \
          --target x86_64-unknown-linux-gnu --locked --workspace --all-targets --all-features \
          -- --skip ten_thousand
fi

if require_or_skip tsan HAS_NIGHTLY HAS_SANITIZER; then
  run_logged tsan \
    env RUSTFLAGS='-Zsanitizer=thread -Cdebuginfo=1' \
        RUSTDOCFLAGS='-Zsanitizer=thread' \
        TSAN_OPTIONS='halt_on_error=1:second_deadlock_stack=1:history_size=7' \
        cargo +nightly-2026-08-20 test -Zbuild-std \
          --target x86_64-unknown-linux-gnu --locked --test p02_concurrency \
          --features 'ffi header-encrypt'
fi

# Finite-state models. Run every configured model even if one fails.
mkdir -p "$EVIDENCE/tlc"
for cfg in formal/tla/*.cfg; do
  model="$(basename "${cfg%.cfg}")"
  if require_or_skip "tlc-${model}" HAS_JAVA HAS_TLC_JAR; then
    run_logged "tlc-${model}" bash -lc \
      "cd formal/tla && test -f '${model}.tla' && java -XX:+UseSerialGC -Xmx2g -cp ../tools/tla2tools.jar tlc2.TLC -config '${model}.cfg' '${model}.tla'"
  fi
done

# Coverage-guided parser/state fuzzing. Targets are never dropped; a missing
# cargo-fuzz binary skips them instead of reporting a false PASS.
FUZZ_SECONDS=60
if [[ "$FULL" == "1" ]]; then FUZZ_SECONDS=1800; fi
for target in envelope_parse header_decode triple_header_decode engine_wire prekey_bundle state_decoders; do
  if require_or_skip "fuzz-${target}" HAS_CARGO_FUZZ HAS_NIGHTLY; then
    run_logged "fuzz-${target}" \
      cargo +nightly-2026-08-20 fuzz run "$target" -- \
        -max_total_time="$FUZZ_SECONDS" -timeout=10 -rss_limit_mb=4096 -print_final_stats=1
  fi
done

# Statistical timing leakage smoke on the actual Codespace CPU.
TIMING_SAMPLES=50000
if [[ "$FULL" == "1" ]]; then TIMING_SAMPLES=500000; fi
if require_or_skip ct-timing HAS_RUSTC_185 HAS_TASKSET; then
  run_logged ct-timing \
    bash -lc "cargo build --locked --release --bin ct_timing && taskset -c 0 target/release/ct_timing --samples $TIMING_SAMPLES --warmup 20000 --max-t 10"
fi

# Production-like PostgreSQL allocator concurrency, isolated so cleanup occurs
# even when the allocator/migration stage fails.
OPK_REQUESTS=500
OPK_WORKERS=64
OPK_EXTRA=(--allow-smoke)
if [[ "$FULL" == "1" ]]; then
  OPK_REQUESTS=10000
  OPK_WORKERS=128
  OPK_EXTRA=()
fi

run_opk_allocator() (
  set -euo pipefail
  cleanup() { docker rm -f dycrpt-postgres >/dev/null 2>&1 || true; }
  trap cleanup EXIT

  cleanup
  docker run -d --name dycrpt-postgres \
    -e POSTGRES_USER=postgres \
    -e POSTGRES_PASSWORD=postgres \
    -e POSTGRES_DB=voicechat_ci \
    -p 5432:5432 \
    postgres:16 -c max_connections=300 >/dev/null

  ready=0
  for _ in $(seq 1 60); do
    if pg_isready -h 127.0.0.1 -U postgres -d voicechat_ci >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  [[ $ready -eq 1 ]] || { echo 'PostgreSQL did not become ready'; exit 1; }

  export DATABASE_URL='postgresql://postgres:postgres@127.0.0.1:5432/voicechat_ci'
  PGPASSWORD=postgres psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f server/postgres/001_opk_allocator.sql
  PGPASSWORD=postgres psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f server/postgres/002_rollback_anchor.sql
  PGPASSWORD=postgres psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f server/postgres/ci_seed.sql
  .venv/bin/python server/postgres/stress_opk_allocator.py \
    --device-hex 6465766963652d6369 \
    --requests "$OPK_REQUESTS" \
    --workers "$OPK_WORKERS" \
    --require-one-time-pq \
    --commit "$DYCRPT_COMMIT" \
    --json-out "$EVIDENCE/opk.json" \
    "${OPK_EXTRA[@]}"
)
if require_or_skip opk-allocator HAS_DOCKER HAS_PSQL HAS_PG_ISREADY HAS_VENV_PYTHON HAS_PSYCOPG; then
  run_logged opk-allocator run_opk_allocator
fi

FAILURES_TEXT=""
if (( ${#FAILURES[@]} > 0 )); then
  FAILURES_TEXT="$(printf '%s\n' "${FAILURES[@]}")"
fi
SKIPPED_TEXT=""
if (( ${#SKIPPED[@]} > 0 )); then
  SKIPPED_TEXT="$(printf '%s\n' "${SKIPPED[@]}")"
fi
export DYCRPT_FAILURES="$FAILURES_TEXT"
export DYCRPT_SKIPPED="$SKIPPED_TEXT"

python3 - <<'PY'
import json, os, pathlib, platform
root = pathlib.Path('codespace-evidence') / os.environ['DYCRPT_COMMIT']
failures = [x for x in os.environ.get('DYCRPT_FAILURES', '').splitlines() if x]
skipped = [x for x in os.environ.get('DYCRPT_SKIPPED', '').splitlines() if x]

def passed(prefix):
    names = [item.split(':', 1)[0] for item in failures + skipped]
    return not any(name.startswith(prefix) for name in names)

summary = {
    'schema': 'dycrpt-codespace-verification-v3',
    'commit': os.environ['DYCRPT_COMMIT'],
    'architecture': platform.machine(),
    'full': os.environ.get('DYCRPT_FULL') == '1',
    'env_preflight': passed('env-preflight'),
    'core_verify': passed('core-verify'),
    'header_encryption_explicitly_tested': passed('header-encryption'),
    'concurrency': passed('concurrency'),
    'miri': passed('miri-ffi-'),
    'asan': passed('asan'),
    'tsan': passed('tsan'),
    'tlc': passed('tlc-'),
    'libfuzzer': passed('fuzz-'),
    'timing_x86_smoke': passed('ct-timing'),
    'opk_allocator': passed('opk-allocator'),
    'failures': failures,
    'skipped': skipped,
    'passed': not failures and not skipped,
}
(root / 'summary.json').write_text(json.dumps(summary, sort_keys=True, indent=2) + '\n')
PY

printf '\n============================================================\n'
if (( ${#FAILURES[@]} > 0 || ${#SKIPPED[@]} > 0 )); then
  printf 'CODESPACE VERIFICATION FAIL (%s failed, %s skipped)\n' \
    "${#FAILURES[@]}" "${#SKIPPED[@]}"
  if (( ${#FAILURES[@]} > 0 )); then
    printf 'failed:\n'
    printf ' - %s\n' "${FAILURES[@]}"
  fi
  if (( ${#SKIPPED[@]} > 0 )); then
    printf 'skipped (prerequisites missing; not PASS):\n'
    printf ' - %s\n' "${SKIPPED[@]}"
  fi
  printf 'commit=%s full=%s\n' "$DYCRPT_COMMIT" "$FULL"
  printf 'evidence=%s\n' "$EVIDENCE"
  printf '============================================================\n'
  exit 1
fi

printf 'CODESPACE VERIFICATION PASS\n'
printf 'commit=%s full=%s\n' "$DYCRPT_COMMIT" "$FULL"
printf 'evidence=%s\n' "$EVIDENCE"
printf '============================================================\n'
