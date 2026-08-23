#!/usr/bin/env bash
set -uo pipefail

cd "$(git rev-parse --show-toplevel)"

BRANCH="hardening/p0-audit-fixes-2026-08-22"
PR_NUMBER=1
COMMIT="$(git rev-parse HEAD)"
REPORT_DIR="codespace-evidence/${COMMIT}"
mkdir -p "$REPORT_DIR"
MASTER_LOG="$REPORT_DIR/codespace-verify-master.log"

{
  echo "dycrpt Codespace verification"
  echo "commit=$COMMIT"
  echo "branch=$(git branch --show-current)"
  echo "arch=$(uname -m)"
  echo "os=$(uname -srmo)"
  echo "rustc=$(rustc --version 2>&1 || true)"
  echo "cargo=$(cargo --version 2>&1 || true)"
} | tee "$REPORT_DIR/environment.txt"

if [[ "$(git branch --show-current)" != "$BRANCH" ]]; then
  echo "ERROR: Codespace is not on $BRANCH" | tee "$MASTER_LOG"
  exit 2
fi

set +e
bash scripts/codespace_verify.sh 2>&1 | tee "$MASTER_LOG"
STATUS=${PIPESTATUS[0]}
set -e

REPORT="$REPORT_DIR/pr-report.md"
{
  echo "## Codespace verification — $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo
  echo "- Commit: \`$COMMIT\`"
  echo "- Branch: \`$BRANCH\`"
  echo "- Architecture: \`$(uname -m)\`"
  echo "- Result: **$([[ $STATUS -eq 0 ]] && echo PASS || echo FAIL)**"
  echo
  if [[ $STATUS -ne 0 ]]; then
    if [[ -f "$REPORT_DIR/summary.json" ]]; then
      echo "### Failed stages"
      python3 - "$REPORT_DIR/summary.json" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
try:
    data = json.loads(p.read_text())
except Exception:
    data = {}
failures = data.get('failures') or []
if failures:
    for failure in failures:
        print(f"- `{failure}`")
else:
    print("- Failure occurred before a structured stage summary was produced.")
PY
      echo
    fi
    echo "### Final log tail"
    echo '```text'
    tail -n 140 "$MASTER_LOG" | sed -E \
      -e 's/(gh[pousr]_[A-Za-z0-9_=-]+)/[REDACTED_GITHUB_TOKEN]/g' \
      -e 's/(sk-[A-Za-z0-9_-]{16,})/[REDACTED_API_KEY]/g' \
      -e 's#(postgresql://[^:[:space:]]+):[^@[:space:]]+@#\1:[REDACTED]@#g'
    echo '```'
    echo
    echo "Per-stage logs and the complete transcript remain inside \`$REPORT_DIR/\`."
  else
    echo "All configured Codespace verification stages completed successfully."
    echo
    echo "Evidence directory: \`$REPORT_DIR/\`"
  fi
} > "$REPORT"

if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  gh pr comment "$PR_NUMBER" --repo YashwanthGathuku/dycrpt --body-file "$REPORT" || true
else
  echo "GitHub CLI is not authenticated; PR report was not posted." >&2
fi

cat "$REPORT"
exit "$STATUS"
