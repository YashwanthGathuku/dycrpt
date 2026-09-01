#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
branch="hardening/p0-audit-fixes-2026-08-22"

if [[ "$(git branch --show-current)" != "$branch" ]]; then
  echo "Refusing: expected branch $branch" >&2
  exit 2
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Refusing because tracked changes already exist:" >&2
  git status --short >&2
  exit 2
fi

python3 scripts/fix_replay_ordering_layer4.py
cargo fmt --all
cargo fmt --all -- --check
git diff --check

echo "===== replay-ordering security diff (pager disabled) ====="
GIT_PAGER=cat git diff -- src/engine/mod.rs src/engine/tests.rs

echo "===== targeted replay regressions ====="
cargo test --locked -p voicechat_crypto --lib --all-features \
  engine::tests::initiation_replay_without_one_time_prekeys_is_rejected \
  -- --exact --nocapture
cargo test --locked -p voicechat_crypto --lib --all-features \
  engine::tests::handshake_opk_and_session_atomic_across_reload \
  -- --exact --nocapture
cargo test --locked -p voicechat_crypto --lib --all-features \
  engine::tests::modified_initiation_reusing_live_session_tag_is_not_replay \
  -- --exact --nocapture

echo "===== strict Clippy preflight ====="
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

git add src/engine/mod.rs src/engine/tests.rs
if git diff --cached --quiet; then
  echo "Layer-4 source fixes already committed; no new source commit needed."
else
  git -c commit.gpgsign=false commit -m "fix: classify exact initiation replay before admission checks"
  git push origin HEAD
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Refusing to verify a dirty tracked tree after commit" >&2
  git status --short >&2
  exit 2
fi

bash scripts/codespace_verify_report.sh
