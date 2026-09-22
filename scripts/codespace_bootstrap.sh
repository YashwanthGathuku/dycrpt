#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
export CARGO_TERM_COLOR=always
export RUST_BACKTRACE=1

printf '\n== system packages ==\n'
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  build-essential clang lld cmake pkg-config jq moreutils util-linux \
  postgresql-client python3-venv python3-pip libssl-dev ca-certificates \
  default-jre-headless

printf '\n== exact stable toolchain ==\n'
rustup toolchain install 1.85.0 --profile minimal \
  --component rustfmt --component clippy --component rust-src
rustup override set 1.85.0
rustc --version --verbose
cargo --version

printf '\n== assurance nightly ==\n'
rustup toolchain install nightly-2026-08-20 --profile minimal \
  --component miri --component rust-src
rustup target add x86_64-unknown-linux-gnu --toolchain nightly-2026-08-20
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

# cargo-fuzz is invoked as `cargo fuzz`, not merely as a PATH binary name.
# Its crates.io lockfile currently needs a rustc newer than the 1.85 project
# override, so the binary is built with the already-installed assurance nightly.
ensure_cargo_subcommand() {
  local subcmd="$1"
  local package="$2"
  local version="$3"
  local installer="${4:-cargo}"
  if cargo "$subcmd" --version >/dev/null 2>&1; then
    printf 'already installed: cargo %s\n' "$subcmd"
  else
    $installer install "$package" --version "$version" --locked
  fi
  if ! cargo "$subcmd" --version >/dev/null 2>&1; then
    printf 'error: cargo %s is not available after installing %s %s\n' \
      "$subcmd" "$package" "$version" >&2
    exit 1
  fi
}

printf '\n== pinned assurance tools ==\n'
install_cargo_tool cargo-audit cargo-audit 0.22.2
install_cargo_tool cargo-deny cargo-deny 0.18.9
ensure_cargo_subcommand fuzz cargo-fuzz 0.13.2 "cargo +nightly-2026-08-20"
install_cargo_tool cargo-cyclonedx cargo-cyclonedx 0.5.9
install_cargo_tool cargo-auditable cargo-auditable 0.7.5

printf '\n== Python OPK environment ==\n'
if [[ ! -x .venv/bin/python ]]; then
  printf 'creating .venv\n'
  rm -rf .venv
  python3 -m venv .venv
fi
if [[ ! -x .venv/bin/python ]]; then
  printf 'error: .venv/bin/python is missing after venv creation\n' >&2
  exit 1
fi
.venv/bin/python --version
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r server/postgres/requirements.txt
.venv/bin/python -c "import psycopg; print('psycopg', psycopg.__version__)"

printf '\n== locked dependency prefetch ==\n'
cargo fetch --locked
cargo fetch --locked --manifest-path fuzz/Cargo.toml

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  printf 'error: docker is required for the OPK allocator stage and is not usable\n' >&2
  exit 1
fi

printf '\n== environment preflight ==\n'
bash scripts/codespace_preflight.sh

printf '\nCodespace bootstrap complete.\n'
printf 'Run: bash scripts/codespace_verify.sh\n'
printf 'Full long assurance: DYCRPT_FULL=1 bash scripts/codespace_verify.sh\n'
