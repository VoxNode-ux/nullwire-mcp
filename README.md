<div align="center">

# ⚡ NullWire-MCP

### See the traffic. Never the secrets.

**A zero-dependency, RAM-only network inspector that lets your AI assistant debug HTTP, HTTPS and WebSocket traffic, with every secret scrubbed before the model ever sees it.**

[![CI and Release](https://github.com/VoxNode-ux/nullwire-mcp/actions/workflows/release.yml/badge.svg)](https://github.com/VoxNode-ux/nullwire-mcp/actions/workflows/release.yml)
[![Security checks](https://github.com/VoxNode-ux/nullwire-mcp/actions/workflows/security.yml/badge.svg)](https://github.com/VoxNode-ux/nullwire-mcp/actions/workflows/security.yml)
![Go 1.26](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-2ea44f)
![Disk writes: 0](https://img.shields.io/badge/disk%20writes-0-2ea44f)
![MCP](https://img.shields.io/badge/MCP-stdio-7c3aed)

[Quick start](#-quick-start) · [How it works](#-how-it-works) · [What gets redacted](#-what-gets-redacted) · [MCP tools](#-mcp-tools) · [Configuration](#-configuration) · [CLI reference](#-cli-reference) · [Security model](#-security-model-and-honest-limits)

</div>

---

## 🧠 Why NullWire exists

Your AI assistant is great at debugging an API call, until the request it needs to read carries an `Authorization` header, a session cookie, a database URL or a customer's email. Pasting raw traffic into a chat means pasting your secrets with it.

NullWire sits between your app and the network. It records what passes through, **scrubs every secret out of the recorded copy**, and hands that clean copy to your assistant through the [Model Context Protocol](https://modelcontextprotocol.io). Your app keeps working exactly as before, because the live traffic is never touched.

```text
  your app ──► NullWire (127.0.0.1) ──► the real server
                    │
                    ├─ forwards every byte, unmodified
                    └─ keeps a scrubbed copy in RAM ──► your AI assistant (MCP)
```

## ✨ At a glance

| | |
|---|---|
| 🪶 **Zero dependencies** | Go standard library only. One static binary, nothing to install. |
| 🧠 **RAM only** | The last 50 flows live in memory. The program never writes a file, and a stop signal wipes the buffer. |
| 🔒 **Loopback only** | The proxy binds to `127.0.0.1`. A DNS-rebinding guard answers only loopback `Host` headers. |
| 🧽 **Layered redaction** | Private keys, JSON/XML/query secrets, JWTs, 50+ vendor key formats, IPs, secrets hiding in base64, and a randomness detector for keys nobody has seen before. |
| 🛡️ **Fail-closed shields** | Bodies that can't be inspected are refused or flagged, never silently passed to the model. |
| 🔌 **HTTP, HTTPS and WebSocket** | Plain proxying, blind `CONNECT` tunnels, a reverse gateway for full HTTPS visibility, and WebSocket text capture in both directions. |
| 🔁 **Safe replay** | Export any captured request as a `curl` command with secrets swapped for environment variables. |
| 🔎 **Secret scanner** | `scan` and `protect` look for secrets in your MCP configs, `.env`, TOML, YAML and ZIP files before they leak. |
| 📱 **Runs anywhere** | Linux, macOS, Windows, Docker and Termux on Android. |

---

## 🚀 Quick start

### 1. Get the binary

<details open>
<summary><b>Download a release</b></summary>

| Platform | File |
|---|---|
| Linux x86-64 | `nullwire-linux-amd64` |
| Linux ARM64 (Raspberry Pi, Termux) | `nullwire-linux-arm64` |
| macOS Intel | `nullwire-darwin-amd64` |
| macOS Apple Silicon | `nullwire-darwin-arm64` |
| Windows x86-64 | `nullwire-windows-amd64.exe` |

```bash
chmod +x nullwire-linux-amd64
sha256sum -c SHA256SUMS.txt --ignore-missing   # verify the download
```
</details>

<details>
<summary><b>Build from source</b></summary>

```bash
go install github.com/VoxNode-ux/nullwire-mcp@latest
# or
git clone https://github.com/VoxNode-ux/nullwire-mcp && cd nullwire-mcp
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o nullwire-mcp .
```
Go 1.26 or newer. There is nothing to `go get`: the module has no dependencies.
</details>

<details>
<summary><b>Docker</b></summary>

```bash
docker run -i --rm ghcr.io/voxnode-ux/nullwire-mcp
```
The server speaks MCP over stdio, so run it with `-i`. The proxy listens on the container's own loopback by design, so a published port (`-p`) cannot reach it. On Linux, add `--network host` to use it from the host's `127.0.0.1`.
</details>

### 2. Add it to your MCP client

```bash
# Claude Code
claude mcp add nullwire -- /path/to/nullwire-mcp
```

```jsonc
// Claude Desktop, Cursor, Windsurf, Cline and other JSON-configured clients
{
  "mcpServers": {
    "nullwire": {
      "command": "/path/to/nullwire-mcp",
      "args": ["-port", "8080"]
    }
  }
}
```

The client starts NullWire, and NullWire starts the proxy in the same process. A live status bar on stderr shows what is happening:

```text
⚡ [NullWire-MCP] Proxy 127.0.0.1:8080 | RAM Ring: 3/50 | Scrubbed: 7 Tokens, 2 Cookies, 1 IPs | Disk: 0B
```

### 3. Send some traffic through it

```bash
# Plain HTTP through the proxy
curl -x http://127.0.0.1:8080 http://httpbin.org/headers

# HTTPS through the proxy (a blind tunnel, see "How it works")
curl -x http://127.0.0.1:8080 https://example.com

# HTTPS with full request visibility: the reverse gateway
nullwire-mcp -target https://api.example.com
curl http://127.0.0.1:8080/v1/things -H "Authorization: Bearer sk-live-..."
```

### 4. Ask your assistant

> *"Use `inspect_traffic` to show my last 5 requests and tell me why the third one returned 401."*

---

## 🔭 How it works

```mermaid
flowchart LR
    A[Your app or curl] -->|HTTP_PROXY / base URL| P[NullWire proxy<br/>127.0.0.1:8080]
    P -->|unmodified bytes| S[(Real server)]
    S -->|unmodified bytes| P
    P --> C[Capture copy]
    C --> R[Redaction layers]
    R --> B[(RAM ring<br/>50 flows)]
    B -->|MCP over stdio| M[AI assistant]
```

The key idea: **the model reads a scrubbed copy, your app talks to the real server.** Nothing the proxy forwards is rewritten, so debugging never changes the behaviour you are debugging.

### Four ways to capture traffic

| Mode | How you use it | What the assistant sees |
|---|---|---|
| **Forward proxy** | `HTTP_PROXY=http://127.0.0.1:8080` and `http://` URLs | Full request and response, scrubbed |
| **HTTPS tunnel** | `HTTPS_PROXY=http://127.0.0.1:8080` (`CONNECT`) | Only the target `host:port`, timing and byte counts. The encrypted payload is never opened. |
| **Reverse gateway** | Point your app's base URL at `http://127.0.0.1:8080` and start with `-target https://…` (or send an `X-Target-URL` header) | Full HTTPS request and response, scrubbed. NullWire makes the TLS connection to the real server. |
| **WebSocket** | Any `Upgrade: websocket` request through either proxy mode | Text messages in both directions, scrubbed, as one flow recorded when the connection closes. Frames are forwarded unmodified. |

> **Why no HTTPS interception?** Reading HTTPS from a forward proxy would require a custom root certificate installed on your machine. That is key material and a trust-store change, the opposite of a zero-footprint tool. The reverse gateway gets you the same visibility with no certificate games.

### Several APIs at once

Give each upstream a name. The first path segment picks the upstream and is removed before forwarding:

```bash
nullwire-mcp -target openai=https://api.openai.com,anthropic=https://api.anthropic.com

export OPENAI_BASE_URL=http://127.0.0.1:8080/openai/v1       # → https://api.openai.com/v1
export ANTHROPIC_BASE_URL=http://127.0.0.1:8080/anthropic    # → https://api.anthropic.com
```

Names are letters, digits, `.`, `_` and `-` (up to 32 characters, case-insensitive). One unnamed URL may be added as the default for paths that match no name. An `X-Target-URL` header overrides everything for a single request.

---

## 🧰 MCP tools

NullWire exposes three tools over stdio. It speaks MCP protocol versions `2026-07-28`, `2025-11-25` and `2024-11-05`, and accepts JSON-RPC batches.

| Tool | What it does | Arguments |
|---|---|---|
| `inspect_traffic` | Returns recent scrubbed flows. | `limit` (1 to 50, default 10), `method`, `url_filter` |
| `export_sanitized_curl` | Rebuilds a captured request as a `curl` command. Redacted values become environment variables you fill in yourself. | `flow_id` (required) |
| `clear_ram_buffer` | Wipes all 50 slots and resets the counters. | none |

A flow looks like this (illustrative):

```json
{
  "id": 7,
  "timestamp": "2026-10-31T09:14:02Z",
  "method": "POST",
  "url": "https://api.example.com/v1/charge",
  "request_headers": { "Authorization": "[REDACTED_TOKEN#a1b2c3]", "Content-Type": "application/json" },
  "request_body": "{\"card_token\":\"[REDACTED_TOKEN#9f3e21]\",\"amount\":4200}",
  "status_code": 401,
  "response_body": "{\"error\":\"invalid_api_key\"}",
  "latency_ms": 143,
  "redaction_count": 2
}
```

**Tags are stable and correlatable.** `[REDACTED_TOKEN#a1b2c3]` is a short salted hash, so the same secret gets the same tag everywhere in one run. Your assistant can see that two requests used the *same* token without learning it. The salt is random per run, so tags can't be compared across restarts or reversed.

Tag kinds: `TOKEN`, `COOKIE`, `IP` and `KEY` (private keys).

`export_sanitized_curl` produces something like:

```bash
# Replay of flow 7
# Set environment variables first:
# export NULLWIRE_AUTH_TOKEN=...   # was [REDACTED_TOKEN#a1b2c3]
curl -X POST 'https://api.example.com/v1/charge' \
  -H "Authorization: $NULLWIRE_AUTH_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-raw '…'
```

Placeholders are `NULLWIRE_AUTH_TOKEN`, `NULLWIRE_COOKIE`, `NULLWIRE_IP` and `NULLWIRE_PRIVATE_KEY`. `CONNECT` tunnels have no replayable request, and NullWire says so.

---

## 🧽 What gets redacted

Every URL, header, request body and response body passes through these layers, in this order:

| # | Layer | Catches | Example |
|---|---|---|---|
| 1 | **Private keys** | PEM blocks: RSA, EC, OpenSSH, encrypted, PGP; JSON-escaped ones; blocks cut off by a size limit | `-----BEGIN PRIVATE KEY-----…` |
| 2 | **Secret fields** | JSON string values and **arrays**, and query parameters, for names like `password`, `api_key`, `access_token`, `secret`, `session_id` | `"password": ["a","b"]`, `?api_key=…` |
| 3 | **XML elements** | Element text for secret-looking names, with namespaces and CDATA; the tags themselves stay intact | `<wsse:Password>…</wsse:Password>` |
| 4 | **URL credentials** | `user:password@host` in any URL or connection string | `postgres://app:pw@db/prod` |
| 5 | **Auth schemes** | `Bearer`, `Basic` and `Token` credentials | `Authorization: Bearer …` |
| 6 | **JWTs** | Three-part `eyJ…` tokens | |
| 7 | **Vendor keys** | 50+ formats in three tiers (below) | `AKIA…`, `ghp_…`, `sk-ant-…`, `SG.…` |
| 8 | **Secret-named fields** | `key: value` or `key=value` pairs where the *name* says secret and the value is 12 to 256 characters | `x-custom-auth: …`, `session=…` |
| 9 | **Your patterns** | Regexes from the [config file](#-configuration) | |
| 10 | **IP addresses** | IPv4 (strictly validated) and IPv6, except loopback and unspecified | `203.0.113.9` |
| 11 | **Base64** | Base64 or URL-safe base64 whose *decoded* text contains a secret. Images and other binary data are left alone. | `eyJhcGlfa2V5…` |
| 12 | **Randomness detector** | 16 to 128 character tokens that look machine-generated: mixed case or digits, high Shannon entropy, few vowels. UUIDs are exempt. | an unknown vendor's key |

**Headers.** `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `Api-Key`, `X-Auth-Token` and `Proxy-Authorization` are always redacted, plus any you add.

**Vendor tiers.** Matching all prefixes the same way would redact ordinary words, so they are tiered:

| Tier | Needs after the prefix | Examples |
|---|---|---|
| **Strong** | 16+ token characters | `sk-ant-`, `sk-proj-`, `AKIA`, `ASIA`, `ghp_`, `github_pat_`, `glpat-`, `xoxb-`, `sk_live_`, `sk_test_`, `rk_live_`, `npm_`, `SG.`, `AIza`, `ya29.`, `pplx-` |
| **Weak** (also occur in normal words) | 20+ characters, plus a digit, a capital or 24+ characters | `hf_`, `r8_`, `secret_`, `api_key_`, `access_token_`, `bearer `, `token ` |
| **Connection strings** | 8+ characters | `postgres://`, `mysql://`, `mongodb+srv://`, `redis://`, `amqp://` |

Prefixes are matched case-sensitively, so `asiapacific_region` is left alone.

**Bodies are decoded before scrubbing.** `gzip` and `deflate` (up to 1 MiB expanded, a decompression-bomb guard). `multipart/form-data` forms are split into fields; file parts keep only the field name, file name and size.

---

## 🛡️ Safety shields

| Shield | Behaviour |
|---|---|
| **Request shield** | A request body with a `Content-Encoding` NullWire can't read (`br`, `zstd`, stacked encodings) is **refused with `415`**, because a body that can't be scrubbed must not reach the model. `-allow-uninspectable` forwards such requests anyway. |
| **Response shield** | The client's `Accept-Encoding` is cut down to `gzip` and `deflate` before it reaches the server, so servers never answer in Brotli or Zstd. A client that offers nothing usable gets `identity`. |
| **Unreadable bodies** | Any other encoded body is stored as a short placeholder with a visible warning in the flow's `note`. |
| **Protobuf and gRPC** | Binary bodies are not stored. Only their size is recorded. |
| **Size limits** | See the table below. A secret that straddles a limit is still scrubbed first, thanks to an 8 KiB scrub window. |
| **Loopback only** | The proxy binds to `127.0.0.1`. The reverse gateway answers only loopback `Host` headers (`403` otherwise) and refuses to proxy to itself (`508`). |
| **Tunnel limits** | At most 256 concurrent tunnels and upgraded connections, each closed after 10 minutes idle. |
| **Wipe on exit** | `SIGINT` and `SIGTERM` clear the ring buffer before the process exits. |

### Limits

| What | Limit |
|---|---|
| Flows kept in RAM | 50 |
| Stored request body | 32 KiB |
| Stored response body | 256 KiB |
| In-flight capture buffer | 64 KiB request, 512 KiB response |
| Scrub window past the stored size | 8 KiB |
| Decoded gzip/deflate | 1 MiB |
| Randomness detector | 16 to 128 characters |

---

## ⚙️ Configuration

Pass `-secrets-config path/to/file.json` to tune redaction without recompiling. Every field is optional.

```json
{
  "sensitive_headers":     ["X-Company-Auth", "X-Api-Signature"],
  "ignore_url_substrings": ["/healthz", "/metrics"],
  "ignore_headers":        ["User-Agent"],
  "custom_vendors": [
    { "name": "Internal DB", "prefix": "db_prod_", "pattern": "" },
    { "name": "Acme Auth",   "prefix": "acme_",    "pattern": "acme_[a-zA-Z0-9]{32}" }
  ],
  "extra_regex_patterns": [
    { "name": "app_key", "pattern": "app_k_[a-zA-Z0-9]{24}" }
  ]
}
```

| Field | Effect |
|---|---|
| `sensitive_headers` | Header values that are always redacted, like `Authorization`. `-scrub-headers a,b` adds more from the command line. |
| `ignore_url_substrings` | Flows whose URL contains one of these are **never recorded** (health checks, metrics). |
| `ignore_headers` | Header values that are left as they are. |
| `custom_vendors` | `prefix` redacts anything with 8+ token characters after it. `pattern` is an optional full regex. |
| `extra_regex_patterns` | Extra regexes; every match is redacted. |

Patterns use Go's RE2 syntax, which runs in linear time, so a bad pattern cannot freeze the proxy.

---

## 🔎 Scan your machine: `scan` and `protect`

Secrets leak long before traffic does: a token in an MCP config, a password in `.env`. NullWire can find them. Scanning **never writes to disk and never prints a secret**: findings are shown already scrubbed, and shell history text is never shown at all.

```bash
nullwire-mcp scan --discover                 # known MCP client configs, ~/.env, ~/.codex/config.toml, …
nullwire-mcp scan .mcp.json .env             # specific files
nullwire-mcp scan --deep ./my-project --toml --yaml --zip
nullwire-mcp scan --history                  # opt-in: count secrets in shell history
```

| Option | Meaning |
|---|---|
| `--discover` | Check the usual config locations under your home and config directories. |
| `--deep DIR` | Walk a directory for MCP config JSON and `.env` files. Skips `node_modules`, `.git`, `dist`, `build`, `vendor` and similar by exact folder name. |
| `--toml`, `--yaml`, `--zip` | Also scan `*.toml`, `*.yaml`/`*.yml` and ZIP archives. Off by default so a deep scan doesn't open every CI file. |
| `--history` | Count lines with secrets in bash, zsh, fish and PowerShell history. Text is never printed. |
| exit codes | `0` done, `1` every file failed to scan, `2` bad usage |

File types are recognised by name, so `nullwire-mcp scan some.env config.toml settings.yaml bundle.zip` routes each to the right scanner. Files over 4 MiB are skipped. ZIP archives are read in memory under a **zip-bomb shield**: entries over 1 MiB, archives over 20 MiB of content or 1000 entries are skipped and reported.

**`protect`** runs a quick scan of the usual places, then starts the normal server:

```bash
nullwire-mcp protect --target https://api.example.com --deep .
```

It accepts the server options (`--port`, `--target`, `--cacert`, `--dns`, `--secrets-config`, `--scrub-headers`, `--allow-uninspectable`) plus `--deep DIR`, `--history` and `--no-scan`. The scan report goes to stderr, so the MCP channel on stdout stays clean, and stop signals are passed on to the server.

---

## 📟 CLI reference

```text
nullwire-mcp [flags]                 run the MCP server and the proxy
nullwire-mcp scan [options] [PATH…]  look for secrets in files
nullwire-mcp protect [options]       scan, then run the server
```

| Flag | Default | Meaning |
|---|---|---|
| `-port` | `8080` | Proxy port. Always bound to `127.0.0.1`. |
| `-target` | none | Reverse-gateway upstream: a URL and/or `name=URL` entries, comma-separated. |
| `-cacert` | none | Extra CA certificates (a PEM file or a directory) for upstream HTTPS. |
| `-dns` | `auto` | Upstream DNS: `auto`, `system`, or a comma list of IPs such as `1.1.1.1,9.9.9.9:53`. |
| `-secrets-config` | none | Path to the [JSON config](#-configuration). |
| `-scrub-headers` | none | Extra header names to always redact. |
| `-allow-uninspectable` | off | Forward request bodies that can't be inspected instead of refusing them with `415`. |

---

## 📱 Platform notes

**Termux and Android.** Static Go binaries have no system DNS settings or CA certificates on Android. NullWire detects Termux and uses `1.1.1.1` and `9.9.9.9` for lookups, printing a notice (those resolvers will see the hostnames you contact). Choose your own with `-dns <resolver>`, or `-dns system` to turn this off. Upstream HTTPS uses the CA certificates found in Termux's standard locations; add more with `-cacert`.

```bash
chmod +x nullwire-linux-arm64
sleep infinity | ./nullwire-linux-arm64   # keep stdin open; use a second session for curl
```

**Corporate networks.** If your company re-signs HTTPS traffic, add its root with `-cacert /path/to/company-root.pem`.

**Windows.** Use the `.exe` and the same flags. `scan --history` also checks PowerShell's PSReadLine history.

---

## 🔐 Security model and honest limits

NullWire is a *diagnostic* tool. Be clear-eyed about what it does and does not promise.

**What it guarantees**
- Nothing is written to disk by the server, and a stop signal wipes memory.
- The proxy is reachable only from your own machine.
- The model never sees the live traffic, only the scrubbed copy.
- Live traffic is never rewritten, so what you debug is what runs.

**What it does not do**
- **It is not a TLS interceptor.** `CONNECT` tunnels show only the destination and byte counts. Use the reverse gateway when you need HTTPS content.
- **Redaction is pattern and heuristic based.** A secret in a shape nobody anticipated, and low in randomness, can slip through. The randomness detector can also redact a harmless long identifier. Add your own patterns in the config for secrets you know about.
- **Brotli and Zstd bodies are never decoded** (the standard library can't, and pulling in a package would break the zero-dependency rule). They are refused (requests) or flagged (responses).
- **WebSocket flows appear when the connection closes.** Messages compressed with `permessage-deflate` can't be read, so NullWire drops the client's extension offer to keep frames readable.
- **An XML secret element that contains nested markup** is not covered by the XML layer.
- **Upstream connections use HTTP/1.1.** HTTP/2 and gRPC bodies are not captured.

If you find a secret NullWire missed, please open an issue with a *fake* sample that has the same shape. Never post a real one.

---

## 🧪 Development

```bash
go vet ./...
go test -race ./...
```

- **Zero dependencies:** `go.mod` has no `require` lines, and CI keeps it that way.
- **Fuzzing:** the scrubber, the IPv6 and vendor-key matchers and the WebSocket frame reader have fuzz targets. They check that no secret survives scrubbing, that results don't depend on how input is chunked, and that nothing panics.
- **CI:** builds for Linux, macOS and Windows, runs the race detector, and publishes a multi-arch Docker image. Security checks run `govulncheck` and the fuzz targets. GitHub Actions are pinned to full commit hashes.

<details>
<summary><b>Project layout</b></summary>

| File | Purpose |
|---|---|
| `main.go` | Proxy, scrubber, ring buffer, MCP server and CLI |
| `ws.go` | WebSocket frame reader and capture (read-only taps) |
| `inspect.go` | Request shield, multipart scrubbing, `Accept-Encoding` and protobuf rules |
| `scrub_extra.go` | JSON array, XML and base64 redaction |
| `vendors.go` | Vendor prefix tiers |
| `scan.go`, `env_scan.go`, `toml_scan.go`, `yaml_scan.go`, `zip_scan.go`, `history_scan.go` | The `scan` command |
| `protect.go`, `protect_helpers.go` | The `protect` command |
| `feature_test.go` | Tests for the features above |

</details>

---

## ❓ Troubleshooting

| Symptom | Cause and fix |
|---|---|
| **HTTPS shows only a `CONNECT` entry** | That is the blind tunnel. Use the reverse gateway (`-target`) to see HTTPS requests. |
| **`415 Unsupported Media Type` from NullWire** | Your client sent a request body compressed with `br` or `zstd`. Send it uncompressed or gzipped, or start with `-allow-uninspectable`. |
| **`403 reverse gateway only answers loopback Host headers`** | Reach the gateway as `127.0.0.1`, `localhost` or `[::1]` on the proxy port. |
| **`certificate signed by unknown authority` (Termux or a corporate network)** | Add the CA with `-cacert`. |
| **A harmless value shows as `[REDACTED_TOKEN#…]`** | The randomness detector matched a long random-looking identifier. Add its URL to `ignore_url_substrings` or tell us the shape. |
| **`address already in use`** | Another NullWire (or program) uses the port. Pick another with `-port`. |
| **The assistant sees no flows** | Check the status bar's `RAM Ring: n/50`. If it stays at 0, your traffic isn't going through the proxy. |

---

<div align="center">

Built by [VoxNode-ux](https://github.com/VoxNode-ux) · Version 1.2.0 · License: see the repository's `LICENSE` file

**If NullWire saved you from pasting a secret into a chat, a ⭐ helps others find it.**

</div>
