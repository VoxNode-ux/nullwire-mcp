#!/usr/bin/env python3
"""Native CI probes for NullWire: MCP handshake time, tool-call latency (empty
ring and 50 flows), memory footprint (VmRSS), and the big-body + secret stress
check. Usage: mcp-probe.py ./nullwire-mcp PROXY_PORT UPSTREAM_URL
Measures only; it exits 1 only if a secret leaks into the captured copy."""
import json, os, random, statistics, string, subprocess, sys, time, urllib.request

BIN, PORT, TARGET = sys.argv[1], sys.argv[2], sys.argv[3]
proc = None
_id = 0

def rss(pid, key="VmRSS"):
    for line in open(f"/proc/{pid}/status"):
        if line.startswith(key + ":"):
            return int(line.split()[1])  # kB
    return -1

def rpc(method, params=None):
    global _id
    _id += 1
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": _id, "method": method, "params": params or {}}) + "\n")
    proc.stdin.flush()
    while True:
        line = proc.stdout.readline()
        if not line:
            raise SystemExit("server closed stdout")
        msg = json.loads(line)
        if msg.get("id") == _id:
            return msg

def timed_calls(n, args):
    xs = []
    for _ in range(n):
        t = time.perf_counter()
        rpc("tools/call", {"name": "inspect_traffic", "arguments": args})
        xs.append((time.perf_counter() - t) * 1000)
    xs.sort()
    return {"median_ms": round(statistics.median(xs), 3), "p95_ms": round(xs[int(len(xs) * 0.95) - 1], 3)}

t0 = time.perf_counter()
proc = subprocess.Popen([BIN, "-port", PORT, "-target", TARGET], stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "probe", "version": "0"}})
res = {"handshake_ms": round((time.perf_counter() - t0) * 1000, 3)}
proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"); proc.stdin.flush()

for _ in range(100):  # wait for the proxy listener
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{PORT}/", timeout=1).read(); break
    except Exception:
        time.sleep(0.1)
res["vmrss_kb_start"] = rss(proc.pid)

res["toolcall_empty"] = timed_calls(30, {"limit": 10})
rpc("tools/call", {"name": "clear_ram_buffer", "arguments": {}})

for i in range(50):
    rq = urllib.request.Request(f"http://127.0.0.1:{PORT}/?i={i}", headers={"Authorization": "Bearer probe-token-%d" % i})
    urllib.request.urlopen(rq, timeout=5).read()
res["toolcall_50_flows"] = timed_calls(30, {"limit": 50})
res["vmrss_kb_50_flows"] = rss(proc.pid)

# Big body + secret, with the secret straddling the 32 KiB capture limit.
secret = "ghp_" + "".join(random.choice(string.ascii_letters + string.digits) for _ in range(36))
body = ("A" * (32768 - 20) + secret + "B" * (1 << 20)).encode()
rq = urllib.request.Request(f"http://127.0.0.1:{PORT}/big", data=body, method="POST")
urllib.request.urlopen(rq, timeout=30).read()
captured = json.dumps(rpc("tools/call", {"name": "inspect_traffic", "arguments": {"limit": 50}}))
leak = secret[:12] in captured or secret[-12:] in captured
res["big_body_secret_leaked"] = leak
res["vmrss_kb_after_big_body"] = rss(proc.pid)
res["vmhwm_kb_peak"] = rss(proc.pid, "VmHWM")
proc.terminate()

json.dump(res, open("mcp-probe.json", "w"), indent=2)
print(json.dumps(res, indent=2))
with open(os.environ.get("GITHUB_STEP_SUMMARY", "/dev/null"), "a") as s:
    s.write("## MCP probes (handshake, latency, memory, big body + secret)\n")
    s.write("| Probe | Result |\n|---|---|\n")
    s.write(f"| Handshake (spawn → initialize reply) | {res['handshake_ms']} ms |\n")
    s.write(f"| tools/call, empty ring | median {res['toolcall_empty']['median_ms']} ms, p95 {res['toolcall_empty']['p95_ms']} ms |\n")
    s.write(f"| tools/call, 50 flows | median {res['toolcall_50_flows']['median_ms']} ms, p95 {res['toolcall_50_flows']['p95_ms']} ms |\n")
    s.write(f"| VmRSS start / 50 flows / after 1 MiB body | {res['vmrss_kb_start']} / {res['vmrss_kb_50_flows']} / {res['vmrss_kb_after_big_body']} kB |\n")
    s.write(f"| VmHWM (peak) | {res['vmhwm_kb_peak']} kB |\n")
    s.write(f"| Secret leaked into captured copy | {'**YES**' if leak else 'no'} |\n")
sys.exit(1 if leak else 0)
