#!/usr/bin/env python3
"""Network chaos check with Toxiproxy. A Toxiproxy sits between NullWire and a
deterministic upstream and injects latency, bandwidth limits, packet slicing,
truncation, resets, timeouts and slow closes.

Rules checked:
  integrity  - the client must get exactly the upstream bytes (same SHA-256),
               whatever the network does to timing and packet sizes;
  survive    - when the connection is cut or stalled the client must get an
               error or a short body within a bound (never a hang, never a
               full-length body with different bytes);
  recovery   - after every scenario a clean request must work again.
Finally NullWire must still be running.

Usage: toxiproxy-chaos.py ./nullwire-mcp ./toxiproxy-server
Writes toxiproxy-result.json and, when set, $GITHUB_STEP_SUMMARY."""
import hashlib, http.client, json, os, select, subprocess, sys, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NW_BIN, TOXI_BIN = sys.argv[1:3]
UP, TOXI_API, TOXI_LISTEN, NW = 18090, 18474, 18091, 18092
BLOB = (hashlib.sha256(b"nullwire-toxiproxy").digest() * 32768)[: 1 << 20]  # 1 MiB
POST = BLOB[: 256 << 10]
sha = lambda b: hashlib.sha256(b).hexdigest()
BLOB_SHA, POST_SHA = sha(BLOB), sha(POST)
CLIENT_TIMEOUT = 15


class Upstream(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(200, BLOB) if self.path == "/blob" else self._send(404, b"no")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        self._send(200, body) if self.path == "/echo" else self._send(404, b"no")


def toxi(method, path, doc=None):
    req = urllib.request.Request(f"http://127.0.0.1:{TOXI_API}{path}", method=method,
                                 data=None if doc is None else json.dumps(doc).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        raw = r.read()
        return json.loads(raw) if raw else None


def add_toxic(i, kind, stream, attrs):
    toxi("POST", "/proxies/upstream/toxics",
         {"name": f"t{i}", "type": kind, "stream": stream, "toxicity": 1.0, "attributes": attrs})


def clear_toxics():
    for t in toxi("GET", "/proxies/upstream/toxics") or []:
        toxi("DELETE", f"/proxies/upstream/toxics/{t['name']}")


def fetch(method, path, body=None):
    """Returns (status, body bytes, seconds, error text)."""
    t0 = time.time()
    conn = http.client.HTTPConnection("127.0.0.1", NW, timeout=CLIENT_TIMEOUT)
    status, data, err = None, b"", ""
    try:
        conn.request(method, path, body=body, headers={"Content-Type": "application/octet-stream"})
        resp = conn.getresponse()
        status = resp.status
        data = resp.read()
    except http.client.IncompleteRead as e:
        data, err = e.partial, "IncompleteRead"
    except Exception as e:  # reset, timeout, closed early: all are valid outcomes under chaos
        err = type(e).__name__
    finally:
        conn.close()
    return status, data, time.time() - t0, err


# (name, toxics [(type, stream, attrs)], kind, method, path, body, expected sha, minimum ms)
S = [
    ("baseline", [], "integrity", "GET", "/blob", None, BLOB_SHA, 0),
    ("latency 150ms +-50 (downstream)", [("latency", "downstream", {"latency": 150, "jitter": 50})],
     "integrity", "GET", "/blob", None, BLOB_SHA, 100),
    ("latency 150ms (upstream) + 256 KiB POST", [("latency", "upstream", {"latency": 150, "jitter": 0})],
     "integrity", "POST", "/echo", POST, POST_SHA, 100),
    ("bandwidth 4096 KB/s (downstream)", [("bandwidth", "downstream", {"rate": 4096})],
     "integrity", "GET", "/blob", None, BLOB_SHA, 150),
    ("slicer 48 +-24 bytes (downstream)", [("slicer", "downstream", {"average_size": 48, "size_variation": 24, "delay": 100})],
     "integrity", "GET", "/blob", None, BLOB_SHA, 0),
    ("slicer 64 +-32 bytes (upstream) + POST", [("slicer", "upstream", {"average_size": 64, "size_variation": 32, "delay": 100})],
     "integrity", "POST", "/echo", POST, POST_SHA, 0),
    ("latency + bandwidth + slicer", [("latency", "downstream", {"latency": 80, "jitter": 40}),
                                       ("bandwidth", "downstream", {"rate": 8192}),
                                       ("slicer", "downstream", {"average_size": 512, "size_variation": 128, "delay": 50})],
     "integrity", "GET", "/blob", None, BLOB_SHA, 100),
    ("limit_data 300000 bytes (cut mid-body)", [("limit_data", "downstream", {"bytes": 300000})],
     "survive", "GET", "/blob", None, BLOB_SHA, 0),
    ("reset_peer after 50 ms", [("reset_peer", "downstream", {"timeout": 50})],
     "survive", "GET", "/blob", None, BLOB_SHA, 0),
    ("timeout toxic 1500 ms (stall then close)", [("timeout", "downstream", {"timeout": 1500})],
     "survive", "GET", "/blob", None, BLOB_SHA, 0),
    ("slow_close 1000 ms", [("slow_close", "downstream", {"delay": 1000})],
     "survive", "GET", "/blob", None, BLOB_SHA, 0),
]


def rss_mb(pid):
    try:
        for line in open(f"/proc/{pid}/status"):
            if line.startswith("VmRSS:"):
                return round(int(line.split()[1]) / 1024, 1)
    except OSError:
        pass
    return None


def main():
    srv = ThreadingHTTPServer(("127.0.0.1", UP), Upstream)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    tp = subprocess.Popen([TOXI_BIN, "-host", "127.0.0.1", "-port", str(TOXI_API)],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    nw = None
    rows, failed = [], []
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{TOXI_API}/version", timeout=1).read()
                break
            except Exception:
                time.sleep(0.1)
        toxi("POST", "/proxies", {"name": "upstream", "listen": f"127.0.0.1:{TOXI_LISTEN}",
                                  "upstream": f"127.0.0.1:{UP}", "enabled": True})
        nw = subprocess.Popen([NW_BIN, "-port", str(NW), "-target", f"http://127.0.0.1:{TOXI_LISTEN}"],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              text=True, bufsize=1)
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{NW}/", timeout=1).read()
            except urllib.error.HTTPError:
                break
            except Exception:
                time.sleep(0.1)
                continue
            break
        rss0 = rss_mb(nw.pid)
        for name, toxics, kind, method, path, body, want, min_ms in S:
            clear_toxics()
            for i, (k, st, at) in enumerate(toxics):
                add_toxic(i, k, st, at)
            status, data, secs, err = fetch(method, path, body)
            clear_toxics()
            ms = int(secs * 1000)
            full = len(data) == (len(BLOB) if method == "GET" else len(POST))
            same = sha(data) == want
            if kind == "integrity":
                ok = status == 200 and same and not err and ms >= min_ms
                note = "" if ok else ("toxic had no effect" if same and ms < min_ms else "bytes differ or request failed")
            else:
                hung = err in ("timeout", "TimeoutError") or secs >= CLIENT_TIMEOUT - 0.5
                corrupt = full and not same
                ok = not hung and not corrupt
                note = "hang" if hung else ("full-length body with wrong bytes" if corrupt else "")
            s2, d2, _, e2 = fetch("GET", "/blob")  # recovery
            recovered = s2 == 200 and sha(d2) == BLOB_SHA and not e2
            if not recovered:
                ok, note = False, (note + "; " if note else "") + "no recovery after removing toxics"
            rows.append({"scenario": name, "kind": kind, "status": status, "bytes": len(data),
                         "sha_match": same, "client_error": err, "ms": ms, "recovered": recovered,
                         "verdict": "PASS" if ok else "FAIL", "note": note})
            if not ok:
                failed.append(name)
        alive = nw.poll() is None
        rss1 = rss_mb(nw.pid) if alive else None
        captured = ""
        if alive:
            nw.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": "inspect_traffic", "arguments": {"limit": 1}}}) + "\n")
            nw.stdin.flush()
            if select.select([nw.stdout], [], [], 10)[0]:
                captured = nw.stdout.readline()
        if not alive:
            failed.append("NullWire exited during the run")
        elif not captured:
            failed.append("NullWire did not answer inspect_traffic afterwards")
    finally:
        if nw is not None and nw.poll() is None:
            nw.terminate()
        tp.terminate()
        srv.shutdown()

    result = {"scenarios": rows, "failed": failed, "nullwire_rss_mb_before": rss0 if rows else None,
              "nullwire_rss_mb_after": rss1 if rows else None}
    json.dump(result, open("toxiproxy-result.json", "w"), indent=2)
    lines = ["## Network chaos (Toxiproxy)", "",
             "| Scenario | Rule | Verdict | HTTP | Bytes | SHA-256 | ms | Recovered | Note |",
             "|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['scenario']} | {r['kind']} | {r['verdict']} | {r['status'] or r['client_error']} | {r['bytes']} | "
                     f"{'match' if r['sha_match'] else 'differs'} | {r['ms']} | {'yes' if r['recovered'] else 'no'} | {r['note']} |")
    lines += ["", f"NullWire RSS before/after: {result['nullwire_rss_mb_before']} / {result['nullwire_rss_mb_after']} MB",
              f"Result: {'all scenarios passed' if not failed else 'FAILED: ' + ', '.join(failed)}"]
    text = "\n".join(lines)
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write(text + "\n")
    return 1 if failed else 0


sys.exit(main())
