#!/usr/bin/env bash
# Collect-all environment preflight for Codespace assurance.
# Always checks every prerequisite, writes KEY=0/1 to the optional env file,
# and exits non-zero if anything required is missing.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)"
export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"

ENV_OUT="${1:-}"
MISSING=()
HAS_LINES=()

record() {
  local key="$1"
  local ok="$2"
  local detail="$3"
  HAS_LINES+=("${key}=${ok}")
  if [[ "$ok" == 1 ]]; then
    printf 'PREFLIGHT PASS  %s (%s)\n' "$key" "$detail"
  else
    printf 'PREFLIGHT FAIL  %s (%s)\n' "$key" "$detail"
    MISSING+=("$key: $detail")
  fi
}

check_cmd() {
  local key="$1"
  local cmd="$2"
  if command -v "$cmd" >/dev/null 2>&1; then
    record "$key" 1 "$(command -v "$cmd")"
  else
    record "$key" 0 "missing command: $cmd"
  fi
}

RUSTC_VER="$(rustc --version 2>&1 || true)"
CARGO_VER="$(cargo --version 2>&1 || true)"
if [[ "$RUSTC_VER" == *'1.85.0'* ]] && [[ "$CARGO_VER" == *'1.85.0'* ]]; then
  record HAS_RUSTC_185 1 "$RUSTC_VER / $CARGO_VER"
else
  record HAS_RUSTC_185 0 "need rustc and cargo 1.85.0; got rustc='$RUSTC_VER' cargo='$CARGO_VER'"
fi

NIGHTLY_VER="$(rustc +nightly-2026-08-20 --version 2>&1 || true)"
if rustc +nightly-2026-08-20 --version >/dev/null 2>&1; then
  record HAS_NIGHTLY 1 "$NIGHTLY_VER"
else
  record HAS_NIGHTLY 0 "need rustc +nightly-2026-08-20; got '$NIGHTLY_VER'"
fi

MIRI_VER="$(cargo +nightly-2026-08-20 miri --version 2>&1 || true)"
if cargo +nightly-2026-08-20 miri --version >/dev/null 2>&1; then
  record HAS_MIRI 1 "$MIRI_VER"
else
  record HAS_MIRI 0 "need cargo +nightly-2026-08-20 miri; got '$MIRI_VER'"
fi

FUZZ_VER="$(cargo fuzz --version 2>&1 || true)"
if cargo fuzz --version >/dev/null 2>&1; then
  record HAS_CARGO_FUZZ 1 "$FUZZ_VER"
else
  record HAS_CARGO_FUZZ 0 "need cargo fuzz --version; got '$FUZZ_VER'"
fi

if java -version >/dev/null 2>&1; then
  record HAS_JAVA 1 "$(java -version 2>&1 | head -n 1)"
else
  record HAS_JAVA 0 "missing java"
fi

if [[ -f formal/tools/tla2tools.jar ]]; then
  record HAS_TLC_JAR 1 "formal/tools/tla2tools.jar"
else
  record HAS_TLC_JAR 0 "missing formal/tools/tla2tools.jar"
fi

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  record HAS_DOCKER 1 "$(docker --version 2>&1)"
else
  record HAS_DOCKER 0 "docker client/daemon not usable"
fi

check_cmd HAS_PSQL psql
check_cmd HAS_PG_ISREADY pg_isready

if [[ -x .venv/bin/python ]]; then
  record HAS_VENV_PYTHON 1 "$(.venv/bin/python --version 2>&1)"
else
  record HAS_VENV_PYTHON 0 "missing executable .venv/bin/python"
fi

PSYCOPG_VER="import failed"
if [[ -x .venv/bin/python ]] && PSYCOPG_VER="$(.venv/bin/python -c "import psycopg; print(psycopg.__version__)" 2>&1)"; then
  record HAS_PSYCOPG 1 "psycopg $PSYCOPG_VER"
else
  record HAS_PSYCOPG 0 ".venv/bin/python cannot import psycopg ($PSYCOPG_VER)"
fi

check_cmd HAS_TASKSET taskset

NIGHTLY_SYSROOT="$(rustc +nightly-2026-08-20 --print sysroot 2>/dev/null || true)"
NIGHTLY_HOST="$(rustc +nightly-2026-08-20 -vV 2>/dev/null | awk '/^host:/{print $2}')"
if [[ -n "$NIGHTLY_SYSROOT" && -d "$NIGHTLY_SYSROOT/lib/rustlib/src/rust/library" ]] \
  && [[ "$NIGHTLY_HOST" == x86_64-unknown-linux-gnu ]]; then
  record HAS_SANITIZER 1 "nightly rust-src + host $NIGHTLY_HOST"
else
  record HAS_SANITIZER 0 "need nightly-2026-08-20 rust-src and host x86_64-unknown-linux-gnu (sysroot='$NIGHTLY_SYSROOT' host='$NIGHTLY_HOST')"
fi

if [[ -n "$ENV_OUT" ]]; then
  mkdir -p "$(dirname "$ENV_OUT")"
  printf '%s\n' "${HAS_LINES[@]}" >"$ENV_OUT"
fi

printf '\n'
if ((${#MISSING[@]} > 0)); then
  printf 'ENVIRONMENT PREFLIGHT FAIL (%s missing)\n' "${#MISSING[@]}"
  printf ' - %s\n' "${MISSING[@]}"
  printf 'Run: bash scripts/codespace_bootstrap.sh\n'
  exit 1
fi

printf 'ENVIRONMENT PREFLIGHT PASS\n'
exit 0
