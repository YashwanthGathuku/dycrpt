#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
branch="hardening/p0-audit-fixes-2026-08-22"

if [[ "$(git branch --show-current)" != "$branch" ]]; then
  echo "Refusing: expected branch $branch" >&2
  exit 2
fi

# This layer should start from a clean tracked tree so the resulting evidence SHA
# corresponds exactly to the reviewed Clippy fixes.
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Refusing because tracked changes already exist:" >&2
  git status --short >&2
  exit 2
fi

python3 scripts/fix_clippy_layer3.py
cargo fmt --all
cargo fmt --all -- --check
git diff --check

echo "===== layer-3 Clippy fix diff (pager disabled) ====="
GIT_PAGER=cat git diff -- \
  src/fingerprint/mod.rs \
  src/primitives/mlkem_inc.rs \
  src/storage/coordinated.rs \
  src/storage/encrypted_file.rs \
  src/ffi/mod.rs

echo "===== pre-commit strict Clippy ====="
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

git add \
  src/fingerprint/mod.rs \
  src/primitives/mlkem_inc.rs \
  src/storage/coordinated.rs \
  src/storage/encrypted_file.rs \
  src/ffi/mod.rs

if git diff --cached --quiet; then
  echo "Layer-3 source fixes already committed; no new source commit needed."
else
  git -c commit.gpgsign=false commit -m "fix: clear strict clippy security-path warnings"
  git push origin HEAD
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Refusing to verify a dirty tracked tree after commit" >&2
  git status --short >&2
  exit 2
fi

bash scripts/codespace_verify_report.sh
