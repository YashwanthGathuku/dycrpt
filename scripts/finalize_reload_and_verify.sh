#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
BRANCH='hardening/p0-audit-fixes-2026-08-22'

if [[ "$(git branch --show-current)" != "$BRANCH" ]]; then
  echo "ERROR: expected branch $BRANCH" >&2
  exit 2
fi

if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
  echo 'ERROR: tracked working tree is dirty; refusing to mix unrelated edits.' >&2
  git status --short
  exit 2
fi

python3 scripts/fix_required_reload_state.py
cargo fmt --all
cargo fmt --all -- --check
git diff --check

echo '===== required-state security diff ====='
GIT_PAGER=cat git diff -- src/engine/mod.rs tests/storage_hardening.rs

echo '===== focused atomic reload gate ====='
cargo test --locked --test storage_hardening -- --nocapture

echo '===== strict all-feature Clippy gate ====='
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

git add src/engine/mod.rs tests/storage_hardening.rs
if ! git diff --cached --quiet; then
  git -c commit.gpgsign=false commit -m 'fix: fail closed on missing persisted security state'
  git push origin HEAD
else
  echo 'No source/test changes to commit.'
fi

if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
  echo 'ERROR: tracked tree dirty before assurance bootstrap.' >&2
  git status --short
  exit 2
fi

echo '===== idempotent Codespace assurance bootstrap ====='
bash scripts/codespace_bootstrap.sh

echo '===== collect-all Codespace verification ====='
bash scripts/codespace_verify_report.sh
