<div align="center">

# ⚡ NullWire-MCP

### Let your AI agent debug live HTTP traffic — without it ever seeing a single secret.

[![CI](https://github.com/VoxNode-ux/nullwire-mcp/actions/workflows/release.yml/badge.svg)](https://github.com/VoxNode-ux/nullwire-mcp/actions/workflows/release.yml)
![Dependencies: 0](https://img.shields.io/badge/dependencies-0%20(pure%20Go%20stdlib)-brightgreen)
![Disk writes: 0 bytes](https://img.shields.io/badge/disk%20writes-0%20bytes%20(RAM--only)-brightgreen)
![MCP](https://img.shields.io/badge/MCP-2026--07--28%20%7C%202025--11--25%20%7C%202024--11--05-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

**One static binary. Zero dependencies. Zero disk writes. Salted correlation tags instead of secrets.**

</div>

---

## 🔥 Why this exists

You point an AI agent at your network traffic so it can help you debug. The proxy hands it **everything**: live bearer tokens, session cookies, internal IPs. That all lands in a cloud LLM context window, and often in a capture file left on disk.

Blind `[REDACTED]` fixes the leak but breaks the debugging. The agent can no longer tell whether request #1 and request #2 used the *same* token or a *different* one, and that is exactly the question behind most auth bugs.

NullWire-MCP redacts every secret **in RAM** and replaces it with a **deterministic, per-process salted tag**. Equal secrets get equal tags, so the agent can still reason about identity, rotation and reuse. It sees **zero bytes** of the real value.

```diff
- WITHOUT NullWire  (what a typical capture-and-dump MCP wrapper hands the model; illustrative)
- GET /v1/orders HTTP/1.1
- Authorization: Bearer sk-live-51Hk3...redacted-by-me-for-this-readme
- Cookie: session=9f8e7d6c5b4a39281706f5e4d3c2b1a0
- X-Forwarded-For: 10.0.4.17
-   ...and a ./capture.flows file now sits on disk with all of it.

+ WITH NullWire-MCP  (what the AI agent actually receives)
+ GET /v1/orders HTTP/1.1
+ Authorization: Bearer [REDACTED_TOKEN#a1b2c3]
+ Cookie: [REDACTED_COOKIE#d4e5f6]
+ X-Forwarded-For: [REDACTED_IP#98f1a2]
+   ...and nothing was written to disk. Ever.
```

**The trick that makes the AI useful again:**

```text
Request #1   Authorization: Bearer [REDACTED_TOKEN#a1b2c3]
Request #2   Authorization: Bearer [REDACTED_TOKEN#a1b2c3]   ◄── same token, reused ✔
Request #3   Authorization: Bearer [REDACTED_TOKEN#7f09de]   ◄── different token, it rotated ✔
```

> The tag is `SHA-256(nonce ‖ secret)[:6]`. The `nonce` is 32 random bytes drawn from `crypto/rand` at startup, kept **only in RAM**, and gone when the process exits. See [Security deep-dive](#-security--protocol-engineering-deep-dive) for why that matters.

---

## 🧭 Architecture & wire data flow

```text
╔══ [1] LOCAL APP / CLI ══════════════════════════════════════╗
║ curl · SDK · browser · your service                         ║▒
║ speaks plain HTTP to 127.0.0.1:8080                         ║▒
╚═════════════════════════════════════════════════════════════╝▒
 ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
                               │
                               ▼  plain HTTP, loopback only
╔══ [2] NULLWIRE PROXY  127.0.0.1:8080 ═══════════════════════╗
║ bound with net.Listen(tcp4) + IsLoopback() check            ║▒
║ forward mode : absolute URL  (curl -x)                      ║▒
║ reverse mode : -target flag / X-Target-URL header           ║▒
║ guards : DNS-rebind 403 · self-loop 508 · CONNECT 501       ║▒
╚═════════════════════════════════════════════════════════════╝▒
 ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
                               │
                               ▼  io.TeeReader split
               ┌───────────────┴────────────────┐
               ▼                                ▼
╔══ [3a] ROUNDTRIP ══════════╗   ╔══ [3b] DLP SCRUBBER ═══════╗
║ http.Transport (isolated)  ║▒  ║ async copy, capped at 64KB ║▒
║ Accept-Encoding stripped   ║▒  ║ regex scrub, THEN truncate ║▒
║ Host = upstream host       ║▒  ║ SHA-256(nonce|secret)[:6]  ║▒
║ bytes forwarded untouched  ║▒  ║ 32-byte crypto/rand nonce  ║▒
╚════════════════════════════╝▒  ╚════════════════════════════╝▒
 ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
               │                                │
               ▼                                ▼
┌── UPSTREAM API ────────────┐   ╔══ [4] RAM RING ════════════╗
│ http:// or https://        │▒  ║ 50 slots · sync.RWMutex    ║▒
│ TLS handled by Go, no MITM │▒  ║ req 8KB / resp 16KB max    ║▒
└────────────────────────────┘▒  ║ newest-first reads         ║▒
 ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒  ║ disk writes: none          ║▒
               │                 ╚════════════════════════════╝▒
◄──┘ original response            ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
    returns to the app                          │
                                                ▼
╔══ [5] JSON-RPC 2.0 MCP (2026-07-28 + legacy) ═══════════════╗
║ initialize · discover · ping · tools/list · call            ║▒
║ inspect_traffic · export_sanitized_curl · clear_ram_buffer  ║▒
║ notifications → zero bytes written                          ║▒
╚═════════════════════════════════════════════════════════════╝▒
 ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
               │                                │
               ▼                                ▼
╔══ STDOUT ▓▓▓ ══════════════╗   ┌── STDERR ░░░ ──────────────┐
║ one compact JSON line      ║▒  │ ANSI status bar,           │▒
║ per frame, ends in \n      ║▒  │ banners, errors            │▒
║ NOTHING else, ever         ║▒  │ (human telemetry)          │▒
╚════════════════════════════╝▒  └────────────────────────────┘▒
 ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
               │                                │
               ▼                                ▼
╔══ AI AGENT (MCP) ══════════╗   ┌── HUMAN ───────────────────┐
║ Claude Code · Desktop      ║▒  │ you, in a terminal         │▒
║ Cursor · Windsurf          ║▒  └────────────────────────────┘▒
╚════════════════════════════╝▒   ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
 ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
```

**Your app always gets the real, untouched response.** Only the AI agent's view is scrubbed.

The live telemetry bar on `stderr` (redrawn in place with `\r\033[K`):

```text
⚡ [NullWire-MCP] Proxy 127.0.0.1:8080 | RAM Ring: 14/50 | Scrubbed: 9 Tokens, 4 Cookies, 6 IPs | Disk: 0B
```

---

## 📊 NullWire-MCP vs. traditional MITM MCP wrappers

| | **⚡ NullWire-MCP** | Typical MITM-based MCP wrapper |
|---|---|---|
| **Third-party dependencies** | **0** (Go standard library only; `go.mod` has no `require`) | Dozens of transitive Python / Node / JVM packages |
| **Disk footprint** | **0 B**, RAM-only 50-slot ring; the code contains no file I/O | Flow files / SQLite databases on disk |
| **Secret redaction** | **Salted SHA-256 correlation tags**, so reuse is provable and the secret is unseen | None, or blind `[REDACTED]` that destroys correlation |
| **Startup** | Native static binary: no interpreter, no VM, no package resolution | Interpreter / VM cold start |
| **MCP protocol** | **2026-07-28 stateless + 2025-11-25 / 2024-11-05 legacy** | Usually legacy only |
| **HTTPS upstreams** | Reverse gateway: no root CA, no keychain changes | Install a root CA and intercept TLS |
| **Supply chain to audit** | One `main.go` | The whole dependency tree |

<sub>The right-hand column describes the general class of tools that capture traffic with a MITM proxy and hand it to an LLM. It is not a claim about any specific product. We have not published startup benchmarks; the startup row is architectural.</sub>

---

## 🚀 30-second install

**Option A: `go install`** (Go 1.23+)

```bash
go install github.com/VoxNode-ux/nullwire-mcp@latest
```

**Option B: prebuilt static binary**, verified against `SHA256SUMS.txt` from [GitHub Releases](https://github.com/VoxNode-ux/nullwire-mcp/releases):

| Platform | File |
|---|---|
| Linux x86-64 / ARM64 | `nullwire-linux-amd64` / `nullwire-linux-arm64` |
| macOS Intel / Apple Silicon | `nullwire-darwin-amd64` / `nullwire-darwin-arm64` |
| Windows x86-64 | `nullwire-windows-amd64.exe` |

```bash
# Linux example (swap the file name for your platform)
BASE=https://github.com/VoxNode-ux/nullwire-mcp/releases/latest/download
curl -LO "$BASE/nullwire-linux-amd64"
curl -LO "$BASE/SHA256SUMS.txt"
grep ' nullwire-linux-amd64$' SHA256SUMS.txt | sha256sum -c -     # macOS: shasum -a 256 -c -
chmod +x nullwire-linux-amd64
sudo mv nullwire-linux-amd64 /usr/local/bin/nullwire-mcp
```

```powershell
# Windows (PowerShell)
Get-FileHash .\nullwire-windows-amd64.exe -Algorithm SHA256   # compare with SHA256SUMS.txt
```

**Option C: build from source**

```bash
git clone https://github.com/VoxNode-ux/nullwire-mcp && cd nullwire-mcp
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o nullwire-mcp .
```

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `-port` | `8080` | Loopback port. The host is hard-coded to `127.0.0.1`; there is no way to bind elsewhere. `0` picks a free port. |
| `-target` | *(none)* | Default upstream base URL for reverse-gateway mode, e.g. `https://api.example.com` |

### Plug it into your AI client

The client launches `nullwire-mcp` as a subprocess and talks JSON-RPC over stdio. Your app then sends its traffic to `127.0.0.1:8080`. (Config file locations change between client releases, so check your client's docs if a path below is out of date.)

**Claude Code CLI**

```bash
claude mcp add nullwire -- nullwire-mcp -port 8080 -target https://api.example.com
```

**Claude Desktop** (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "nullwire": {
      "command": "nullwire-mcp",
      "args": ["-port", "8080", "-target", "https://api.example.com"]
    }
  }
}
```

**Cursor** (`~/.cursor/mcp.json`, or `.cursor/mcp.json` in a project)

```json
{
  "mcpServers": {
    "nullwire": {
      "command": "nullwire-mcp",
      "args": ["-port", "8080", "-target", "https://api.example.com"]
    }
  }
}
```

**Windsurf** (`~/.codeium/windsurf/mcp_config.json`)

```json
{
  "mcpServers": {
    "nullwire": {
      "command": "nullwire-mcp",
      "args": ["-port", "8080", "-target", "https://api.example.com"]
    }
  }
}
```

Omit `-target` if you only use forward-proxy mode or the per-request `X-Target-URL` header.

---

## 🔀 Two capture modes

### Mode 1: Forward proxy (plain HTTP)

Send a full URL through the proxy. The request is forwarded as-is and a scrubbed copy lands in the ring.

```bash
curl -x http://127.0.0.1:8080 http://httpbin.org/headers

# or for any app that honours the standard variable
HTTP_PROXY=http://127.0.0.1:8080 ./my-service
```

> `HTTPS_PROXY` makes clients send `CONNECT`, which is answered `501` by design. See [Honest scope](#-honest-scope--known-limitations). Use Mode 2 for HTTPS.

### Mode 2: Reverse gateway (HTTPS upstreams, no MITM certificates)

Talk plain HTTP to NullWire; NullWire speaks TLS to the real server using Go's normal certificate verification. Nothing to install in your trust store.

```bash
# Fixed upstream for the whole session
nullwire-mcp -target https://api.github.com
curl http://127.0.0.1:8080/users/octocat

# Or choose the upstream per request (the header is removed before forwarding)
curl -H 'X-Target-URL: https://httpbin.org' http://127.0.0.1:8080/anything?api_key=hunter2hunter2
```

Point an SDK at it by changing only its base URL:

```bash
export OPENAI_BASE_URL=http://127.0.0.1:8080/v1   # with: nullwire-mcp -target https://api.openai.com
```

The upstream `Host` header is set to the target's host, so virtual hosting and TLS SNI behave normally.

---

## 🧰 MCP tool reference

All three tools return `{"resultType":"complete","content":[{"type":"text","text":"…"}],"isError":false}`. Tool-level problems (for example an unknown flow id) set `isError` to `true` instead of failing the RPC.

### `inspect_traffic`

Recent scrubbed flows, newest first.

```json
{
  "name": "inspect_traffic",
  "inputSchema": {
    "type": "object",
    "properties": {
      "limit":      { "type": "integer", "default": 10, "minimum": 1, "maximum": 50 },
      "method":     { "type": "string",  "description": "HTTP method filter, case-insensitive" },
      "url_filter": { "type": "string",  "description": "Substring of the scrubbed URL, case-insensitive" }
    },
    "additionalProperties": false
  }
}
```

Example result text:

```json
{
  "ring_size": 3,
  "ring_capacity": 50,
  "returned": 1,
  "scrubbed_totals": { "tokens": 5, "cookies": 1, "ips": 1 },
  "flows": [
    {
      "id": 3,
      "timestamp": "2026-10-25T14:03:11Z",
      "method": "POST",
      "url": "http://[REDACTED_IP#98f1a2]:9000/v1/orders?api_key=[REDACTED_TOKEN#3c9a1e]",
      "request_headers": {
        "Authorization": "Bearer [REDACTED_TOKEN#a1b2c3]",
        "Content-Type": "application/json",
        "Cookie": "[REDACTED_COOKIE#d4e5f6]"
      },
      "request_body": "{\"item\":\"widget\",\"client_secret\":\"[REDACTED_TOKEN#5b7e20]\"}",
      "status_code": 401,
      "response_headers": { "Content-Type": "application/json" },
      "response_body": "{\"error\":\"token expired\"}",
      "latency_ms": 42,
      "redaction_count": 5
    }
  ]
}
```

### `export_sanitized_curl`

Rebuilds a runnable POSIX `curl` command for one flow. Every redaction tag becomes an environment-variable placeholder, and a comment legend maps each placeholder back to the tag it replaced, so you can tell which real value belongs where.

```json
{
  "name": "export_sanitized_curl",
  "inputSchema": {
    "type": "object",
    "properties": {
      "flow_id": { "type": "integer", "minimum": 1, "description": "An id returned by inspect_traffic" }
    },
    "required": ["flow_id"],
    "additionalProperties": false
  }
}
```

Example result text for flow `3` above:

```bash
# Replay of flow 3 (2026-10-25T14:03:11Z)
# Set these environment variables first (distinct tags share one placeholder):
# export NULLWIRE_IP=...   # was [REDACTED_IP#98f1a2]
# export NULLWIRE_AUTH_TOKEN=...   # was [REDACTED_TOKEN#3c9a1e]
# export NULLWIRE_AUTH_TOKEN=...   # was [REDACTED_TOKEN#5b7e20]
# export NULLWIRE_AUTH_TOKEN=...   # was [REDACTED_TOKEN#a1b2c3]
# export NULLWIRE_COOKIE=...   # was [REDACTED_COOKIE#d4e5f6]
curl -X 'POST' 'http://'"$NULLWIRE_IP"':9000/v1/orders?api_key='"$NULLWIRE_AUTH_TOKEN" \
  -H 'Authorization: Bearer '"$NULLWIRE_AUTH_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Cookie: '"$NULLWIRE_COOKIE" \
  --data-raw '{"item":"widget","client_secret":"'"$NULLWIRE_AUTH_TOKEN"'"}'
```

Hop-by-hop headers, `Host`, `Content-Length` and `Accept-Encoding` are left out so `curl` can set them itself. Truncated or encoded request bodies get a `# WARNING:` line instead of silently replaying something incomplete.

### `clear_ram_buffer`

Zeroes all 50 slots and resets the scrub counters. Flow ids keep counting upward, so an old id can never point at a new flow. Takes no arguments (`{"type":"object","properties":{},"additionalProperties":false}`).

---

## 🛡️ Security & protocol engineering deep-dive

Every item below is implemented in `main.go` and exercised by `main_test.go`.

| Measure | What it does | Why |
|---|---|---|
| **Strict loopback bind** | The listener address is hard-coded `127.0.0.1`, opened with `net.Listen("tcp4", …)`, then re-checked with `TCPAddr.IP.IsLoopback()`. The process exits if the check fails. There is no `-host` flag. | Nothing on your LAN can reach a proxy that sees your tokens. |
| **DNS-rebinding guard** | In reverse mode, any request whose `Host` header is not `127.0.0.1`, `localhost` or `::1` gets `403 Forbidden`. | A malicious web page that rebinds its domain to `127.0.0.1` can't use your gateway as an authenticated relay. |
| **Self-loop protection** | A target that resolves to the proxy's own `host:port` gets `508 Loop Detected`. | Prevents a request storm from a misconfigured `-target`. |
| **Scrub-before-truncate** | Up to **64 KB** of each body is captured, fully regex-scrubbed, and only *then* cut to **8 KB** (request) / **16 KB** (response). | A secret straddling the 8 KB boundary is already a tag by the time we cut. Truncating first would keep half a token. |
| **Per-process ephemeral nonce** | 32 bytes from `crypto/rand`, held only in RAM. Tag = first 6 hex chars of `SHA-256(nonce ‖ secret)`. | Without a salt, a hash of a low-entropy secret (a short PIN, a guessable password) can be brute-forced or rainbow-tabled from a leaked transcript. With a secret nonce nobody can precompute anything, and tags can't be linked across restarts. |
| **Strict `stdout` discipline** | `stdout` carries only single-line JSON-RPC frames ending in `\n`, written under a mutex. Banners, errors and the status bar go to `stderr`. | One stray byte on `stdout` corrupts the MCP stream. |
| **Silent notifications** | A message with no `id` (or `id: null` with a `notifications/*` method), such as `notifications/initialized`, writes **0 bytes**. | JSON-RPC forbids replying to notifications, and strict clients disconnect if you do. |
| **Original traffic untouched** | The app receives the real response through a streaming, flushing copy. Scrubbing happens on a separate copy in a background goroutine. | The proxy must never break the thing you're debugging. |
| **Isolated transport** | A dedicated `http.Transport` with no proxy, no compression and no redirect-following. | No accidental proxy chains; redirects reach your app unchanged. |
| **Hop-by-hop stripping** | `Connection`, `Proxy-*`, `TE`, `Upgrade`, … are removed in both directions. | Correct proxy behaviour per RFC 9110. |
| **Panic containment** | Capture and RPC dispatch recover from panics instead of killing the process. | A weird payload can't take your session down. |

**What gets scrubbed**

| Pattern | Tag |
|---|---|
| `Authorization`, `Proxy-Authorization`, `X-API-Key`, `API-Key`, `X-Auth-Token` header values; `Bearer` / `Basic` / `Token` credentials anywhere | `TOKEN` |
| `Cookie`, `Set-Cookie` header values (whole header hashed as one unit) | `COOKIE` |
| JWTs (`eyJ….….…`) | `TOKEN` |
| API keys: `sk-…`, `ghp_…`, `github_pat_…`, `AIza…`, `xox[baprs]-…`, `AKIA…` | `TOKEN` |
| JSON fields: `access_token`, `refresh_token`, `id_token`, `api_key`, `apikey`, `secret`, `client_secret`, `password`, `passwd`, `session_id`, `auth_token` | `TOKEN` |
| Query / form params: `api_key`, `apikey`, `token`, `access_token`, `refresh_token`, `id_token`, `secret`, `client_secret`, `password`, `passwd`, `key` | `TOKEN` |
| `user:password@host` in URLs | `TOKEN` |
| IPv4 addresses (`127.0.0.1` and `0.0.0.0` are left alone) | `IP` |

---

## ⚖️ Honest scope & known limitations

We would rather you hear these from us than discover them in production.

- **`HTTP CONNECT` returns `501 Not Implemented`, by design.** Inspecting HTTPS through `CONNECT` means man-in-the-middling TLS, which means generating a root CA and getting it into your OS or browser trust store. That is key material and keychain pollution, the opposite of a zero-footprint tool. The **reverse gateway** gets the same visibility without any of that: point your app at `http://127.0.0.1:8080` and let NullWire do the TLS to the upstream.
- **No WebSocket / `Upgrade` pass-through.** `Upgrade` and `Connection` are treated as hop-by-hop headers and stripped, so upgraded protocols won't work through the proxy. Plain request/response and streaming responses (e.g. SSE) are supported.
- **Redaction is pattern-based, not magic.** It catches the shapes in the table above. A secret in a format we don't recognise, in a field we don't know, or split across a body boundary can pass through. Treat the scrubber as a strong seatbelt, not a guarantee, and test it with your own traffic. IPv6 addresses are not redacted yet. IPv4-shaped strings that aren't addresses (some version numbers) can be redacted as false positives.
- **Tags are 24 bits.** Six hex characters are plenty to tell apart the handful of secrets in a 50-slot buffer, but collisions are possible in principle. They are for correlation, not identification.
- **Bodies are bounded.** Only the first 64 KB of each body is captured, and stored bodies are cut to 8 KB / 16 KB. Responses that arrive with a `Content-Encoding` (e.g. gzip) are stored as a short placeholder rather than decoded. NullWire strips `Accept-Encoding` from forwarded requests so most servers reply uncompressed, but it can't force them to.
- **"RAM-only" means the program never writes files.** `Disk: 0B` in the status bar is a design invariant (the source has no file I/O), not a measured counter. The OS can still swap memory pages or write crash dumps; NullWire doesn't control that.
- **The ring is ephemeral.** The 50 most recent flows vanish when the process exits. That is the point.
- **Your app sees raw traffic.** NullWire protects what the *AI agent* sees, not what your local app sees. It isn't a security boundary for the app itself.
- **Protocol coverage is what's documented.** Initialization, discovery, ping, `tools/list` and `tools/call` for the 2026-07-28 / 2025-11-25 / 2024-11-05 specs. Resources, prompts and sampling aren't implemented and return `-32601`.
- **Release binaries are unsigned.** Verify them with `SHA256SUMS.txt`. On macOS you may need `xattr -d com.apple.quarantine ./nullwire-darwin-arm64`.

---

## ✅ Verification & testing

```bash
go vet ./...
go test -v ./...
go test -v -race ./...      # the race detector needs cgo (gcc/clang) on most platforms
```

The suite uses only the standard library (`net/http/httptest`) and covers:

- Deterministic tagging: equal secrets share a tag, different secrets don't, nothing leaks, `127.0.0.1` survives.
- Ring-buffer wrap-around eviction and `Clear()` with monotonic ids.
- A full reverse-gateway round trip: `Accept-Encoding` stripped, tokens scrubbed in the ring, a valid sanitized `curl` exported.
- MCP dispatch: `server/discover`, `initialize`, `ping`, `tools/list`, `tools/call`, error codes, and **zero stdout bytes for notifications**.

CI (`.github/workflows/release.yml`) runs `go vet` and `go test`, cross-compiles static `CGO_ENABLED=0` binaries for linux, darwin and windows, and publishes them with `SHA256SUMS.txt` on `v*` tags.

---

## 📄 License

[MIT](LICENSE) © 2026 VoxNode-ux

<div align="center">

**If NullWire saved you from pasting a live token into a chat window, a ⭐ helps other engineers find it.**

</div>
