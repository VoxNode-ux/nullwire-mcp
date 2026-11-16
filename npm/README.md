# NullWire-MCP

**See the traffic. Never the secrets.**

NullWire is a local inspector for HTTP, HTTPS and WebSocket traffic, built so an AI assistant can help debug it. It records traffic as it passes through, removes secrets from the recorded copy, and serves that copy over the [Model Context Protocol](https://modelcontextprotocol.io). It is one static Go binary with no dependencies, and it keeps the last 50 flows in RAM only.

This package is the `npx` launcher. It has no dependencies and no install script: it downloads the matching release binary, checks it, and runs it.

## Quick start

```bash
# Registers NullWire with your MCP clients
npx -y nullwire-mcp install --client all
```

Restart your MCP client, then send some traffic through the proxy:

```bash
# Plain HTTP through the proxy
curl -x http://127.0.0.1:8080 http://httpbin.org/headers

# HTTPS with full request visibility: the reverse gateway
npx -y nullwire-mcp -target https://api.example.com
curl http://127.0.0.1:8080/v1/things -H "Authorization: Bearer sk-live-..."
```

Then ask your assistant: *"Use `inspect_traffic` to show my last 5 requests and tell me why the third one returned 401."*

## What the model sees

Every secret is replaced by a salted tag such as `[REDACTED_TOKEN#a1b2c3]`: the first 6 hex characters of an HMAC-SHA256 of the secret, keyed with an ephemeral 256-bit key that lives in RAM only. The same secret gets the same tag for the whole run, so the assistant can see that two requests used the same token without learning it. The key changes on every start.

Redaction runs in three stages (unwrap, deterministic rules, match and score) across twelve layers, including Aho-Corasick rule gating, Luhn-checked card numbers, entropy and bigram log-odds scoring for unknown keys, and a SipHash taint ring that redacts a secret seen once wherever it reappears.

## Honest limits

- It is not a TLS interceptor. `CONNECT` tunnels show only the destination and byte counts; use the reverse gateway for HTTPS content.
- Redaction is pattern and heuristic based. A secret in an unanticipated shape that is also low in randomness can slip through, and the detector can redact a harmless long identifier.
- A secret made only of decimal digits is not caught by the randomness detector. It is still redacted under a secret-looking field name or in a secret header.
- Brotli and Zstd bodies are never decoded: requests are refused with `415` (unless you pass `-allow-uninspectable`) and responses are flagged.
- Binary protobuf and gRPC bodies are not captured. WebSocket flows appear when the connection closes.
- Release binaries carry signed build provenance, not OS-vendor code-signing certificates. Verify them with `SHA256SUMS.txt` and `gh attestation verify`.

## Documentation

Full documentation lives on GitHub:

- [Install methods and MCP client setup](https://github.com/VoxNode-ux/nullwire-mcp/blob/main/docs/install.md)
- [CLI flags, MCP tools and configuration](https://github.com/VoxNode-ux/nullwire-mcp/blob/main/docs/cli.md)
- [The three stages and twelve layers](https://github.com/VoxNode-ux/nullwire-mcp/blob/main/docs/redaction.md)
- [Security model and safety shields](https://github.com/VoxNode-ux/nullwire-mcp/blob/main/docs/security.md)
- [Architecture](https://github.com/VoxNode-ux/nullwire-mcp/blob/main/docs/architecture.md)
- [How it compares to other tools](https://github.com/VoxNode-ux/nullwire-mcp/blob/main/docs/comparison.md)
- [Live redactor demo](https://voxnode-ux.github.io/nullwire-mcp/) (runs in your browser; nothing is uploaded)

Source, issues and security reports: https://github.com/VoxNode-ux/nullwire-mcp

Built by [VoxNode-ux](https://github.com/VoxNode-ux). License: see the repository's `LICENSE` file.