#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
branch="hardening/p0-audit-fixes-2026-08-22"

if [[ "$(git branch --show-current)" != "$branch" ]]; then
  echo "Refusing: expected branch $branch" >&2
  exit 2
fi

# The previous helper could abort at its pager after staging exactly these two files.
# Preserve that work, but refuse any unrelated tracked edits.
unexpected="$({ git status --porcelain=v1 --untracked-files=no || true; } \
  | awk '{print $2}' \
  | grep -v -E '^(src/engine/mod.rs|src/storage/encrypted_file.rs)$' || true)"
if [[ -n "$unexpected" ]]; then
  echo "Refusing because unrelated tracked changes exist:" >&2
  git status --short >&2
  exit 2
fi

python3 scripts/fix_check_layer2.py
cargo fmt --all
cargo fmt --all -- --check
git diff --check

git add \
  src/engine/mod.rs \
  src/storage/encrypted_file.rs \
  tests/storage_hardening.rs \
  crypto-parity/src/corpus.rs

echo "===== exact staged fix diff (pager disabled) ====="
GIT_PAGER=cat git diff --cached -- \
  src/engine/mod.rs \
  src/storage/encrypted_file.rs \
  tests/storage_hardening.rs \
  crypto-parity/src/corpus.rs

# Make the evidence commit exact before verification. Do not run the verifier on
# a dirty tree: its recorded commit must contain the code under test.
git -c commit.gpgsign=false commit -m "fix: preserve zeroizing ownership through compile checks"
git push origin HEAD

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Refusing to verify a dirty tracked tree after commit" >&2
  git status --short >&2
  exit 2
fi

bash scripts/codespace_verify_report.sh
