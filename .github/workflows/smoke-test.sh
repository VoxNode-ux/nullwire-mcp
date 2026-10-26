#!/bin/sh
# Shared smoke test for NullWire-MCP. Usage: sh .github/scripts/smoke-test.sh ./binary
# POSIX sh only, so it runs on Linux, FreeBSD and Windows (git-bash).
BIN="$1"
if [ -z "$BIN" ] || [ ! -f "$BIN" ]; then
  echo "FAIL: binary not found: $BIN"
  exit 2
fi
chmod +x "$BIN" 2>/dev/null
FAIL=0

check() { # $1 = grep pattern, $2 = file, $3 = label
  if grep -q "$1" "$2"; then echo "PASS: $3"; else echo "FAIL: $3"; FAIL=1; fi
}

# 1. MCP basics ---------------------------------------------------------------
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | "$BIN" -port 0 > out.txt 2> err.txt
check inspect_traffic out.txt "tools/list answers"
echo '{"jsonrpc":"2.0","method":"notifications/initialized"}' | "$BIN" -port 0 > quiet.txt 2>/dev/null
if [ -s quiet.txt ]; then echo "FAIL: notification wrote to stdout"; FAIL=1; else echo "PASS: notification is silent"; fi

# 2. End-to-end redaction against a local upstream (no internet) -------------
PY=$(command -v python3 || command -v python || true)
if [ -z "$PY" ]; then
  echo "FAIL: python not found for the local upstream server"
  exit 1
fi
mkdir -p upstream && echo ok > upstream/index.html
"$PY" -m http.server 18081 --bind 127.0.0.1 --directory upstream > upstream.log 2>&1 &
UP=$!
i=0
while [ $i -lt 60 ]; do
  if curl -s -o /dev/null --max-time 2 http://127.0.0.1:18081/; then break; fi
  i=$((i + 1)); sleep 1
done

rm -f go.flag
( while [ ! -f go.flag ]; do sleep 1; done
  echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"inspect_traffic","arguments":{"limit":5}}}'
  sleep 3 ) | "$BIN" -port 18080 -target http://127.0.0.1:18081 > e2e-out.txt 2> e2e-err.txt &
NW=$!
i=0
while [ $i -lt 60 ]; do
  if curl -s -o /dev/null --max-time 2 http://127.0.0.1:18080/; then break; fi
  i=$((i + 1)); sleep 1
done

curl -sS -v --max-time 15 http://127.0.0.1:18080/ \
  -H "Authorization: Bearer my_secret_token_123" \
  -H "Cookie: sid=my_secret_cookie" \
  -H "X-Forwarded-For: 198.51.100.1" > e2e-curl.txt 2>&1 || echo "curl exit code $?" >> e2e-curl.txt
touch go.flag
wait $NW
kill $UP 2>/dev/null

check 'REDACTED_TOKEN#' e2e-out.txt "token tag present"
check 'REDACTED_COOKIE#' e2e-out.txt "cookie tag present"
check 'REDACTED_IP#' e2e-out.txt "ip tag present"
if grep -Eq 'my_secret_token_123|my_secret_cookie|198\.51\.100\.1' e2e-out.txt; then
  echo "FAIL: a secret leaked into the output"; FAIL=1
else
  echo "PASS: no secret leaked"
fi
echo "result: FAIL=$FAIL"
exit $FAIL
