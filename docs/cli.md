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
| `-target-map` | none | Fixed routes for clients that cannot send `X-Target-URL`: `name=URL` entries, comma-separated, reached as `/_gw/<name>/…`. See [fixed routes](#fixed-routes). |
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

<a id="fixed-routes"></a>

### Fixed routes with `-target-map`

Some SDKs let you set a base URL but not a header, and a bare `/name/` prefix can collide with a real path of the default upstream. `-target-map` adds routes under a reserved `/_gw/` prefix instead:

```bash
nullwire-mcp -target https://api.example.com \
  -target-map auth=https://auth.example.com,local=http://127.0.0.1:9000/v2

export AUTH_BASE_URL=http://127.0.0.1:8080/_gw/auth        # → https://auth.example.com
export LOCAL_BASE_URL=http://127.0.0.1:8080/_gw/local/items  # → http://127.0.0.1:9000/v2/items
export API_BASE_URL=http://127.0.0.1:8080                  # → https://api.example.com (the default)
```

- **It is an allowlist, not open routing.** Only the names you list work. `/_gw/anything-else/…` gets a `404` that names the valid routes, and is never forwarded to the default upstream.
- **Local backends are allowed.** A route may point at `127.0.0.1` or `localhost`, which is normal for development. The existing guards still apply: only loopback `Host` headers are answered, and a route that points back at NullWire itself is refused (`508`).
- **Every entry needs a name** (`name=URL`), and a name cannot be used both here and in `-target`. Names listed in `-target` also work under `/_gw/`.
- **The prefix is reserved only while `-target-map` is set.** Without it, `/_gw/…` is just a path.
- Like named upstreams, the prefix must not be percent-encoded, and an `X-Target-URL` header still overrides everything for one request.

<a id="mcp-tools"></a>

## MCP tools

NullWire exposes four tools over stdio. It speaks MCP protocol versions `2026-07-28`, `2025-11-25` and `2024-11-05`, and accepts JSON-RPC batches.

| Tool | What it does | Arguments |
|---|---|---|
| `inspect_traffic` | Returns recent scrubbed flows. | `limit` (1 to 50, default 10), `method`, `url_filter` |
| `export_har` | Returns recent scrubbed flows as a HAR 1.2 document, built in memory. Nothing is written to disk. | `limit` (1 to 50, default 10), `method`, `url_contains`, `include_bodies` (default `false`) |
| `export_sanitized_curl` | Rebuilds a captured request as a `curl` command. Redacted values become environment variables you fill in yourself. | `flow_id` (required) |
| `clear_ram_buffer` | Clears all 50 slots and resets the counters. | none |
| `export_attestation` | Returns a signed local attestation (ECDSA P-256): counts, policy SHA-256, active presets and a control summary. It holds no URLs, bodies, headers or redaction tags. | none |

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

**GraphQL calls are labelled.** A flow's `note` says which operation it was, for example `GraphQL mutation Login.`, so a list of `POST /graphql` calls can be told apart. NullWire reads `operationName`, the operation named in the query, JSON batches (`GraphQL batch of 3: query A, mutation B, ...`), `application/graphql` bodies, GET query strings and persisted queries (`extensions.persistedQuery`). Query text, variables and persisted-query hashes are never copied into the note. A name is shown only if it is a plain GraphQL name (letters, digits and `_`, up to 64 characters) that also passes through the scrubber unchanged; otherwise the note says `<invalid name>` or `<redacted>`.

**HAR export is bounded.** `export_har` is meant for opening a capture in a HAR viewer without a huge reply. Bodies are left out unless you set `include_bodies`. `limit`, `method` and `url_contains` choose the flows. Whatever you ask for, the whole document is capped at 1 MiB: an entry that does not fit with its bodies is included without them (marked in its `_nullwire` block), and entries that still do not fit are counted in `omitted_for_size`. Entries are listed oldest first. Sizes are those of the stored, scrubbed text, and the HTTP version is reported as `unknown` because it is not recorded.

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

It accepts the server options (`--port`, `--target`, `--target-map`, `--cacert`, `--dns`, `--secrets-config`, `--scrub-headers`, `--allow-uninspectable`, `--max-body`, `--ws-deflate`) plus `--deep DIR`, `--history` and `--no-scan`. The scan report goes to stderr, so the MCP channel on stdout stays clean, and stop signals are passed on to the server.

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

## Host egress controls

`-secrets-config` accepts `allowed_upstream_hosts` and `blocked_upstream_hosts`. Each entry is an exact host (`api.example.com`), a wildcard (`*.example.com`, subdomains only), an IP or a CIDR (`10.0.0.0/8`, `2001:db8::/32`). Bad syntax fails startup.

- `blocked` always beats `allowed`; when `allowed` is non-empty, unlisted hosts are denied.
- Checked for HTTP proxying (403 before the request is sent) and `CONNECT` tunnels (403).
- IP/CIDR rules are also enforced on the address the dialer actually connects to, so a name that resolves or rebinds into a blocked range is refused (403).
- Allowed CIDRs admit by address. If `allowed_upstream_hosts` has only IPs/CIDRs, host names pass the name check and their resolved address must be inside an allowed CIDR. If it has any name rule, host names must match one.

## `-disable-tools`

`-disable-tools export_sanitized_curl,export_har` hides the listed MCP tools from `tools/list` and refuses `tools/call` for them. Unknown names fail startup. Tools: `inspect_traffic`, `export_har`, `export_sanitized_curl`, `clear_ram_buffer`, `export_attestation`.

## `-policy-pubkey` and signed policy packs

By default `-secrets-config` works as before and needs no signature. With `-policy-pubkey <PEM file | hex file | hex>` the server refuses to start unless `<secrets-config>.sig` (ECDSA P-256 over SHA-256, ASN.1, hex) verifies against the exact bytes it then reads. The option also refuses `-allow-uninspectable`, so the command line cannot weaken a signed policy. Presets can only be added on the command line, never removed.

No OpenSSL is needed:

```
nullwire-mcp policy keygen -out corp            # corp.key (0600, keep offline) + corp.pub
nullwire-mcp policy sign -key corp.key secrets.json   # writes secrets.json.sig
nullwire-mcp policy verify -pubkey corp.pub secrets.json
nullwire-mcp -secrets-config secrets.json -policy-pubkey corp.pub
```

## Attestation: `export_attestation`, `-attest-out`, `-attest-key`

`export_attestation` returns one line of JSON: `{"report": {...}, "signature": {...}}`. The report has the tool version, UTC start and generation times, flow and redaction counts, the SHA-256 of the policy file, whether it was signed, the active presets, egress rule counts, and the main controls (listener kind, token required, `-allow-uninspectable`, `-ws-deflate`, disabled tools). It never holds URLs, bodies, headers or redaction tags.

- Without `-attest-key` a fresh ECDSA P-256 key signs each run and its public half is in the envelope: a tamper-evident session receipt. It proves the report was not changed after signing, not who signed it.
- With `-attest-key <PEM>` your org or host key signs. Check it with `nullwire-mcp policy attest -pubkey corp.pub report.json`.
- `-attest-out <path>` also writes the report (mode 0600) when the server exits.

## `-proxy-token` and `-listen`

The proxy stays on `127.0.0.1` and adds no CA. To keep other local users and processes out:

- `-proxy-token <token>` (16+ characters of `A-Za-z0-9-._~`) or `-proxy-token auto` (makes one and prints the proxy URL). It can also come from `NULLWIRE_PROXY_TOKEN`, which is cleared from the environment at start. Every request must carry it, as the password of `Proxy-Authorization` (`HTTP_PROXY=http://nw:<token>@127.0.0.1:8080` works in curl, Python and Node) or as `X-Nullwire-Token` in gateway mode. The credentials are removed before anything is forwarded or captured. `nullwire-mcp protect -proxy-token ...` passes the token to the server through its environment, not the command line.
- `-listen unix:///absolute/path.sock` (Linux and macOS, opt-in, never the default) listens on a socket with mode 0600 instead of TCP. The file is removed at exit.
