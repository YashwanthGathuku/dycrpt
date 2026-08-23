#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

export CARGO_TERM_COLOR=always
export RUST_BACKTRACE=1

printf '\n== system packages ==\n'
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  build-essential clang lld cmake pkg-config jq moreutils \
  postgresql-client python3-venv python3-pip libssl-dev ca-certificates

printf '\n== exact stable toolchain ==\n'
rustup toolchain install 1.85.0 --profile minimal \
  --component rustfmt --component clippy --component rust-src
rustup override set 1.85.0
rustc --version --verbose
cargo --version

printf '\n== assurance nightly ==\n'
rustup toolchain install nightly-2026-08-20 --profile minimal \
  --component miri --component rust-src
cargo +nightly-2026-08-20 miri setup

install_cargo_tool() {
  local binary="$1"
  local package="$2"
  local version="$3"
  if command -v "$binary" >/dev/null 2>&1; then
    printf 'already installed: %s\n' "$binary"
  else
    cargo install "$package" --version "$version" --locked
  fi
}

printf '\n== pinned assurance tools ==\n'
install_cargo_tool cargo-audit cargo-audit 0.22.2
install_cargo_tool cargo-deny cargo-deny 0.18.9
install_cargo_tool cargo-fuzz cargo-fuzz 0.13.2
install_cargo_tool cargo-cyclonedx cargo-cyclonedx 0.5.9
install_cargo_tool cargo-auditable cargo-auditable 0.7.5

printf '\n== Python database client ==\n'
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install 'psycopg[binary]>=3.2,<4'

printf '\n== locked dependency prefetch ==\n'
cargo fetch --locked
cargo fetch --locked --manifest-path fuzz/Cargo.toml

printf '\nCodespace bootstrap complete.\n'
printf 'Run: bash scripts/codespace_verify.sh\n'
printf 'Full long assurance: DYCRPT_FULL=1 bash scripts/codespace_verify.sh\n'
