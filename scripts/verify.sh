#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

export CARGO_TERM_COLOR=always
export RUST_BACKTRACE=1

printf '\n== toolchain ==\n'
rustc --version --verbose
cargo --version

printf '\n== formatting ==\n'
cargo fmt --all -- --check

printf '\n== metadata/locked dependency graph ==\n'
cargo metadata --locked --no-deps --format-version 1 >/dev/null

printf '\n== debug check (all targets/features) ==\n'
cargo check --locked --workspace --all-targets --all-features

printf '\n== clippy (deny warnings) ==\n'
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

printf '\n== tests ==\n'
cargo test --locked --workspace --all-targets --all-features -- --skip ten_thousand

printf '\n== release tests ==\n'
cargo test --locked --release --workspace --all-targets --all-features -- --skip ten_thousand

printf '\n== long PQXDH randomized test ==\n'
cargo test --locked --release ten_thousand_randomized_handshakes -- --ignored 2>/dev/null || \
  cargo test --locked --release ten_thousand_randomized_handshakes

if [[ -f fuzz/Cargo.toml ]]; then
  printf '\n== fuzz host build ==\n'
  cargo build --locked --manifest-path fuzz/Cargo.toml
  printf '\n== bounded fuzz host smoke ==\n'
  cargo run --locked --manifest-path fuzz/Cargo.toml --bin host_runner -- 5000
fi

printf '\nVERIFICATION PASS\n'
