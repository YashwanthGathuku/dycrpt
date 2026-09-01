#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
branch="hardening/p0-audit-fixes-2026-08-22"

if [[ "$(git branch --show-current)" != "$branch" ]]; then
  echo "Refusing: expected branch $branch" >&2
  exit 2
fi

# Ignore generated Codespace evidence when deciding whether tracked source is clean.
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Refusing to patch because tracked changes already exist:" >&2
  git status --short >&2
  exit 2
fi

python3 scripts/fix_e0509_ownership.py
cargo fmt --all
cargo fmt --all -- --check
git diff --check

git add src/engine/mod.rs src/storage/encrypted_file.rs

echo "===== security-relevant ownership diff ====="
git diff --cached -- src/engine/mod.rs src/storage/encrypted_file.rs

git -c commit.gpgsign=false commit -m "fix: transfer zeroizing buffers without cloning"
git push origin HEAD

bash scripts/codespace_verify_report.sh
