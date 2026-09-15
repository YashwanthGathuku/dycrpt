#!/usr/bin/env bash
set -uo pipefail

cd "$(git rev-parse --show-toplevel)"

export CARGO_TERM_COLOR=always
export RUST_BACKTRACE=1

FAILURES=()

run_stage() {
  local name="$1"
  shift
  printf '\n== %s ==\n' "$name"
  "$@"
  local status=$?
  if [[ $status -eq 0 ]]; then
    printf '== %s: PASS ==\n' "$name"
  else
    printf '== %s: FAIL (exit %s) ==\n' "$name" "$status"
    FAILURES+=("$name:$status")
  fi
  return 0
}

printf '\n== toolchain ==\n'
rustc --version --verbose
cargo --version

run_stage "formatting" cargo fmt --all -- --check
run_stage "metadata/locked dependency graph" bash -lc \
  'cargo metadata --locked --no-deps --format-version 1 >/dev/null'
run_stage "debug check (all targets/features)" \
  cargo check --locked --workspace --all-targets --all-features
run_stage "clippy (deny warnings, all targets/features)" \
  cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

# Also exercise the default feature surface. This catches imports or code that are
# only used when optional profiles are enabled and would otherwise warn/fail for
# the common baseline build.
run_stage "clippy (deny warnings, default features)" \
  cargo clippy --locked --workspace --all-targets -- -D warnings

run_stage "tests (debug)" \
  cargo test --locked --workspace --all-targets --all-features -- --skip ten_thousand
run_stage "tests (release)" \
  cargo test --locked --release --workspace --all-targets --all-features -- --skip ten_thousand
run_stage "long PQXDH randomized test" \
  cargo test --locked --release ten_thousand_randomized_handshakes

if [[ -f fuzz/Cargo.toml ]]; then
  run_stage "fuzz host build" cargo build --locked --manifest-path fuzz/Cargo.toml
  run_stage "bounded fuzz host smoke" \
    cargo run --locked --manifest-path fuzz/Cargo.toml --bin host_runner -- 5000
fi

if (( ${#FAILURES[@]} > 0 )); then
  printf '\n============================================================\n'
  printf 'CORE VERIFICATION FAIL (%s stage(s))\n' "${#FAILURES[@]}"
  printf ' - %s\n' "${FAILURES[@]}"
  printf '============================================================\n'
  exit 1
fi

printf '\n============================================================\n'
printf 'CORE VERIFICATION PASS\n'
printf '============================================================\n'
