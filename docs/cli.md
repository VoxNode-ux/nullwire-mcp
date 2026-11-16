# CLI, MCP tools and configuration

[Back to the README](../README.md)

<a id="cli-reference"></a>

## CLI reference

```text
nullwire-mcp [flags]                 run the MCP server and the proxy
nullwire-mcp scan [options] [PATH…]  look for secrets in files
nullwire-mcp protect [options]       scan, then run the server
nullwire-mcp install [options]       register NullWire with your MCP clients
```

| Flag | Default | Meaning |
|---|---|---|
| `-port` | `8080` | Proxy port. Always bound to `127.0.0.1`. |
| `-target` | none | Reverse-gateway upstream: a URL and/or `name=URL` entries, comma-separated. |
| `-cacert` | none | Extra CA certificates (a PEM file or a directory) for upstream HTTPS. |
| `-dns` | `auto` | Upstream DNS: `auto`, `system`, or a comma list of IPs such as `1.1.1.1,9.9.9.9:53`. |
| `-secrets-config` | none | Path to the [JSON config](#configuration). |
| `-scrub-headers` | none | Extra header names to always redact. |
| `-allow-uninspectable` | off | Forward request bodies that can't be inspected instead of refusing them with `415`. |
| `-max-body` | none (32 KiB request, 256 KiB response) | Raise the stored body size for both requests and responses, for debugging large errors. Accepts a byte count or a `k`/`m` suffix: `-max-body 1m`. Between 32 KiB and 2 MiB; it never lowers a default. Secrets are scrubbed before the text is cut, so one that straddles the limit is still redacted. Memory: the ring keeps up to 50 flows, so `2m` can hold about 200 MiB of body text. |
| `-ws-deflate` | off | Keep the WebSocket `permessage-deflate` offer and decode compressed text messages for capture. By default the offer is dropped so frames stay readable, which is safer. Decoding is capped per message and per connection (16 MiB) against compression bombs. |

## Capture modes

| Mode | How you use it | What the assistant sees |
|---|---|---|
| **Forward proxy** | `HTTP_PROXY=http://127.0.0.1:8080` and `http://` URLs | Full request and response, scrubbed |
| **HTTPS tunnel** | `HTTPS_PROXY=http://127.0.0.1:8080` (`CONNECT`) | Only the target `host:port`, timing and byte counts. The encrypted payload is never opened. |
| **Reverse gateway** | Point your app's base URL at `http://127.0.0.1:8080` and start with `-target https://…` (or send an `X-Target-URL` header) | Full HTTPS request and response, scrubbed. NullWire makes the TLS connection to the real server. |
| **WebSocket** | Any `Upgrade: websocket` request through either proxy mode | Text messages in both directions, scrubbed, as one flow. The flow appears when the socket opens (status 101), is refreshed about every 500 ms while messages arrive (slower for very busy streams), and is finalized when the connection closes. Frames are forwarded unmodified. |

> **Why no HTTPS interception?** Reading HTTPS from a forward proxy would require a custom root certificate installed on your machine. That is key material and a trust-store change, the opposite of a zero-footprint tool. The reverse gateway gets you the same visibility with no certificate games.

### Several APIs at once

Give each upstream a name. The first path segment picks the upstream and is removed before forwarding:

```bash
nullwire-mcp -target openai=https://api.openai.com,anthropic=https://api.anthropic.com

export OPENAI_BASE_URL=http://127.0.0.1:8080/openai/v1       # → https://api.openai.com/v1
export ANTHROPIC_BASE_URL=http://127.0.0.1:8080/anthropic    # → https://api.anthropic.com
```

Names are letters, digits, `.`, `_` and `-` (up to 32 characters, case-insensitive). One unnamed URL may be added as the default for paths that match no name. An `X-Target-URL` header overrides everything for a single request.

<a id="mcp-tools"></a>

## MCP tools

NullWire exposes three tools over stdio. It speaks MCP protocol versions `2026-07-28`, `2025-11-25` and `2024-11-05`, and accepts JSON-RPC batches.

| Tool | What it does | Arguments |
|---|---|---|
| `inspect_traffic` | Returns recent scrubbed flows. | `limit` (1 to 50, default 10), `method`, `url_filter` |
| `export_sanitized_curl` | Rebuilds a captured request as a `curl` command. Redacted values become environment variables you fill in yourself. | `flow_id` (required) |
| `clear_ram_buffer` | Clears all 50 slots and resets the counters. | none |

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

**Tags are stable and correlatable.** `[REDACTED_TOKEN#a1b2c3]` is the first 6 hex characters of an HMAC-SHA256 of the secret, keyed with an ephemeral 256-bit random key held in RAM only. The same secret gets the same tag everywhere in one run, so your assistant can see that two requests used the *same* token without learning it. The key is new on every start, so tags can't be compared across restarts or reversed.

Tag kinds: `TOKEN`, `COOKIE`, `IP`, `KEY` (private keys and prefix-less cloud keys) and `PAN` (payment card numbers).

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

Placeholders are `NULLWIRE_AUTH_TOKEN`, `NULLWIRE_COOKIE`, `NULLWIRE_IP`, `NULLWIRE_PRIVATE_KEY` and `NULLWIRE_CARD_NUMBER`. `CONNECT` tunnels have no replayable request, and NullWire says so.

<a id="configuration"></a>

## Configuration

Pass `-secrets-config path/to/file.json` to tune redaction without recompiling. Every field is optional.

```json
{
  "sensitive_headers":     ["X-Company-Auth", "X-Api-Signature"],
  "ignore_url_substrings": ["/healthz", "/metrics"],
  "ignore_headers":        ["User-Agent"],
  "ignore_fields":         ["session_ttl", "key"],
  "ignore_patterns":       ["pk_test_[A-Za-z0-9]{24}"],
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
| `ignore_fields` | **Body** fields whose value is left as it is, matched by name without regard to case: a JSON member (`"key": "…"`), `key=value` in a query string, form or env file, or an XML element. A recognised secret format inside the value (a vendor key, a JWT, a private key, a password in a URL) is still redacted. Headers and URLs are not affected. |
| `ignore_patterns` | **Body** text that matches one of these regexes is left completely alone, for known harmless values such as a public test key. A pattern that matches the empty string or any character is refused at startup, because it would exempt everything. |
| `custom_vendors` | `prefix` redacts anything with 8+ token characters after it. `pattern` is an optional full regex. |
| `extra_regex_patterns` | Extra regexes; every match is redacted. |

Patterns use Go's RE2 syntax, which runs in linear time, so a bad pattern cannot freeze the proxy.

**Fixing a false positive yourself.** If a harmless value in a body is redacted, add its field name to `ignore_fields`, or a pattern that matches just that value to `ignore_patterns`. This changes nothing for anyone else: with neither list set, the defaults are exactly as shipped. The two lists apply to bodies only. For headers use `ignore_headers`, and for a whole URL use `ignore_url_substrings`.

## Scan your machine: `scan` and `protect`

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
| `--fail` | Exit with code `3` when any secret is found (for git hooks and CI). Without it, findings never change the exit code. |
| exit codes | `0` done, `1` every file failed to scan, `2` bad usage, `3` secrets found (only with `--fail`) |

File types are recognised by name, so `nullwire-mcp scan some.env config.toml settings.yaml bundle.zip` routes each to the right scanner. Files over 4 MiB are skipped. ZIP archives are read in memory under a **zip-bomb shield**: entries over 1 MiB, archives over 20 MiB of content or 1000 entries are skipped and reported.

**Git hook.** Block commits that contain secrets with [pre-commit](https://pre-commit.com):

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/VoxNode-ux/nullwire-mcp
    rev: v1.2.0
    hooks:
      - id: nullwire-scan            # builds nullwire-mcp from source (needs Go)
      # - id: nullwire-scan-system   # or use the nullwire-mcp already on your PATH
```
The hook runs `nullwire-mcp scan --fail --yaml` on staged `.env`, MCP config, TOML and YAML files. The report shows scrubbed values only.

**Shortcut.** Add `alias nw="nullwire-mcp"` to your `~/.bashrc` or `~/.zshrc` (PowerShell: `Set-Alias nw nullwire-mcp`), then `nw scan --discover`.

**`protect`** runs a quick scan of the usual places, then starts the normal server:

```bash
nullwire-mcp protect --target https://api.example.com --deep .
```

It accepts the server options (`--port`, `--target`, `--cacert`, `--dns`, `--secrets-config`, `--scrub-headers`, `--allow-uninspectable`, `--max-body`, `--ws-deflate`) plus `--deep DIR`, `--history` and `--no-scan`. The scan report goes to stderr, so the MCP channel on stdout stays clean, and stop signals are passed on to the server.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| **HTTPS shows only a `CONNECT` entry** | That is the blind tunnel. Use the reverse gateway (`-target`) to see HTTPS requests. |
| **`415 Unsupported Media Type` from NullWire** | Your client sent a request body compressed with `br` or `zstd`. Send it uncompressed or gzipped, or start with `-allow-uninspectable`. |
| **`403 reverse gateway only answers loopback Host headers`** | Reach the gateway as `127.0.0.1`, `localhost` or `[::1]` on the proxy port. |
| **`certificate signed by unknown authority` (Termux or a corporate network)** | Add the CA with `-cacert`. |
| **A harmless value shows as `[REDACTED_TOKEN#…]`** | The randomness detector matched a long random-looking identifier. If it is in a body, add the field name to `ignore_fields` or a matching pattern to `ignore_patterns`; if it is in a header, use `ignore_headers`; to skip a whole URL, use `ignore_url_substrings`. Or tell us the shape. |
| **`install` says a config is "not plain JSON"** | The file has comments or a syntax error, so it was left untouched. Fix it, or use `install --print` and paste the entry yourself. |
| **A long number (timestamp, id) is not redacted** | Runs of only decimal digits are exempt from the randomness detector on purpose. If one is really a secret, put it under a secret-looking field name, or add a pattern under `extra_regex_patterns`. |
| **`address already in use`** | Another NullWire (or program) uses the port. Pick another with `-port`. |
| **The assistant sees no flows** | Check the status bar's `RAM Ring: n/50`. If it stays at 0, your traffic isn't going through the proxy. |