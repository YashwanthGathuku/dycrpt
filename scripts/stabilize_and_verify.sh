#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
BRANCH="hardening/p0-audit-fixes-2026-08-22"

if [[ "$(git branch --show-current)" != "$BRANCH" ]]; then
  echo "Refusing: expected branch $BRANCH" >&2
  exit 2
fi

# Refuse unrelated tracked edits. Generated Codespace evidence is intentionally
# untracked and does not block stabilization.
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Refusing because tracked changes already exist:" >&2
  git status --short >&2
  exit 2
fi

python3 - <<'PY'
from pathlib import Path
p = Path('src/engine/mod.rs')
text = p.read_text()
old = 'use zeroize::Zeroize;\n'
new = '#[cfg(feature = "header-encrypt")]\nuse zeroize::Zeroize;\n'
if new in text:
    print('already fixed: feature-gated Zeroize import')
elif text.count(old) == 1:
    p.write_text(text.replace(old, new, 1))
    print('fixed: feature-gated Zeroize import')
else:
    raise SystemExit('expected unique Zeroize import not found; refusing broad edit')
PY

# Normalize the whole workspace before evidence is tied to a commit.
cargo fmt --all
cargo fmt --all -- --check
git diff --check

# Catch both the production all-feature surface and the baseline/default surface
# before committing, so optional-feature imports cannot hide warnings.
cargo check --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo clippy --locked --workspace --all-targets -- -D warnings

if ! git diff --quiet; then
  git add src/engine/mod.rs
  GIT_PAGER=cat git diff --cached -- src/engine/mod.rs
  git -c commit.gpgsign=false commit -m "fix: gate header-encryption zeroize import"
  git push origin HEAD
else
  echo "No source stabilization commit needed."
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Refusing to verify a dirty tracked tree" >&2
  git status --short >&2
  exit 2
fi

bash scripts/codespace_verify_report.sh
