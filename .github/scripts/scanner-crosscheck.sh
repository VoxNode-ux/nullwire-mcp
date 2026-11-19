#!/usr/bin/env bash
# Independent cross-check: gitleaks and trufflehog must find nothing in
# NullWire's own scan report, even though they DO find the planted secrets in
# the raw file (the control). Usage: scanner-crosscheck.sh ./nullwire-mcp
set -euo pipefail
nw="${1:?path to nullwire-mcp}"
work="$(mktemp -d)"; cd "$work"

# Fake secrets, shaped like real ones, random every run.
python3 - <<'PY'
import random, string
a = string.ascii_letters + string.digits
r = lambda n: "".join(random.choice(a) for _ in range(n))
open("sample.env", "w").write(
    f"GITHUB_TOKEN=ghp_{r(36)}\n"
    f"STRIPE_KEY=sk_live_{r(28)}\n"
    f"DEBUG=true\n")
PY
mkdir raw report; cp sample.env raw/sample.env
"$nw" scan sample.env > report/nullwire-report.txt 2>&1 || true

count_gitleaks()   { gitleaks dir "$1" --no-banner --redact --exit-code 0 --report-format json --report-path out.json >/dev/null 2>&1 || true; python3 -c 'import json;print(len(json.load(open("out.json")) or []))'; }
count_trufflehog() { trufflehog filesystem "$1" --no-verification --no-update --json 2>/dev/null | grep -c '"SourceMetadata"' || true; }

fail=0
for tool in gitleaks trufflehog; do
  before=$("count_$tool" raw); after=$("count_$tool" report)
  echo "$tool: raw file findings=$before, NullWire report findings=$after"
  echo "| $tool | $before | $after |" >> rows.md
  if [ "$before" -lt 1 ]; then echo "::error::$tool did not detect the planted secrets (control failed, result is meaningless)"; fail=1; fi
  if [ "$after" -ne 0 ];  then echo "::error::$tool still finds secrets in NullWire's output"; fail=1; fi
done

{
  echo "## Independent scanner cross-check"
  echo "| Scanner | Findings in raw file (control, must be ≥ 1) | Findings in NullWire report (must be 0) |"
  echo "|---|---|---|"
  cat rows.md
} >> "${GITHUB_STEP_SUMMARY:-/dev/stdout}"
exit $fail
