#!/usr/bin/env python3
"""websocat end-to-end check: a secret sent through NullWire over a WebSocket
must reach the upstream untouched (frames are forwarded unmodified) but must
not appear in the captured copy. Usage: ws-redaction-check.py ./nullwire-mcp PORT UPSTREAM_URL"""
import json, random, string, subprocess, sys, time, urllib.request

BIN, PORT, TARGET = sys.argv[1:4]
secret = "ghp_" + "".join(random.choice(string.ascii_letters + string.digits) for _ in range(36))
p = subprocess.Popen([BIN, "-port", PORT, "-target", TARGET], stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
for _ in range(100):
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{PORT}/", timeout=1).read()
    except urllib.error.HTTPError:
        break
    except Exception:
        time.sleep(0.1); continue
    break

msg = f'{{"auth":"{secret}","n":1}}'
out = subprocess.run(["websocat", "-n1", f"ws://127.0.0.1:{PORT}/"], input=msg + "\n",
                     capture_output=True, text=True, timeout=20)
echoed_intact = secret in out.stdout
time.sleep(1.0)  # the flow is refreshed about every 500 ms
p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": "inspect_traffic", "arguments": {"limit": 10}}}) + "\n"); p.stdin.flush()
captured = p.stdout.readline()
p.terminate()

leaked = secret[:12] in captured or secret[-12:] in captured
ok = echoed_intact and not leaked and "REDACTED" in captured
print(f"echoed intact: {echoed_intact}; leaked into capture: {leaked}; tag present: {'REDACTED' in captured}")
sys.exit(0 if ok else 1)
