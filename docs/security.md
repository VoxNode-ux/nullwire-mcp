# Security model

[Back to the README](../README.md)

<a id="security-model-and-honest-limits"></a>

## Security model and honest limits

NullWire is a *diagnostic* tool. Be clear-eyed about what it does and does not promise.

**What it guarantees**
- Nothing is written to disk by the server, and a stop signal clears the buffer (references are dropped; memory is not zeroed). The `install` command edits MCP client configs only when you run it, and backs each file up first.
- The proxy is reachable only from your own machine.
- The model never sees the live traffic, only the scrubbed copy.
- Request and response bodies are never rewritten. Headers are adjusted only where inspection needs it: `Accept-Encoding` is reduced to `gzip`/`deflate`, and the WebSocket `permessage-deflate` offer is dropped.

**What it does not do**
- **Release binaries carry signed build provenance, not OS-vendor code-signing certificates.** Verify authenticity with `SHA256SUMS.txt` and `gh attestation verify`. Because they are not signed with an Apple Developer ID or Microsoft Authenticode certificate, on macOS you may need `xattr -d com.apple.quarantine ./nullwire-darwin-arm64`.
- **It is not a TLS interceptor.** `CONNECT` tunnels show only the destination and byte counts. Use the reverse gateway when you need HTTPS content.
- **Redaction is pattern and heuristic based.** A secret in a shape nobody anticipated, and low in randomness, can slip through. The randomness detector can also redact a harmless long identifier. Add your own patterns in the config for secrets you know about.
- **Brotli and Zstd bodies are never decoded** (the standard library can't, and pulling in a package would break the zero-dependency rule). They are refused (requests) or flagged (responses).
- **WebSocket flows appear when the connection closes.** Messages compressed with `permessage-deflate` can't be read, so NullWire drops the client's extension offer to keep frames readable.
- **An XML secret element that contains nested markup** is not covered by the XML layer.
- **A secret made only of decimal digits is not caught by the randomness detector**, because that is the shape of timestamps and ids. It is still redacted when it sits under a secret-looking name (`token`, `password`, …) or in a secret header.
- **A password with a decoded `?` or `#`** in a URL is only partly matched by the URL-credentials rule, because those characters end the password field.
- **HTTP/2 text bodies are captured; binary bodies are not.** HTTP/2 and h2c text and JSON bodies are scrubbed like HTTP/1.1. Binary protobuf and gRPC message bodies are skipped, and `Grpc-Status` and `Grpc-Message` trailers are scrubbed.

If you find a secret NullWire missed, please open an issue with a *fake* sample that has the same shape. Never post a real one.

<a id="safety-shields"></a>

## Safety shields

| Shield | Behaviour |
|---|---|
| **Request shield** | A request body with a `Content-Encoding` NullWire can't read (`br`, `zstd`, stacked encodings) is **refused with `415`**, because a body that can't be scrubbed must not reach the model. `-allow-uninspectable` forwards such requests anyway. |
| **Response shield** | The client's `Accept-Encoding` is cut down to `gzip` and `deflate` before it reaches the server, so servers never answer in Brotli or Zstd. A client that offers nothing usable gets `identity`. |
| **Unreadable bodies** | Any other encoded body is stored as a short placeholder with a visible warning in the flow's `note`. |
| **Protobuf and gRPC** | Binary bodies are not stored. Only their size is recorded. |
| **Size limits** | See the table below. A secret that straddles a limit is still scrubbed first, thanks to an 8 KiB scrub window. |
| **Loopback only** | The proxy binds to `127.0.0.1`. The reverse gateway answers only loopback `Host` headers (`403` otherwise) and refuses to proxy to itself (`508`). |
| **Tunnel limits** | At most 256 concurrent tunnels and upgraded connections, each closed after 10 minutes idle. |
| **Clear on exit** | `SIGINT` and `SIGTERM` clear the ring buffer before the process exits. |

### Limits

| What | Limit |
|---|---|
| Flows kept in RAM | 50 |
| Stored request body | 32 KiB |
| Stored response body | 256 KiB |
| In-flight capture buffer | 64 KiB request, 512 KiB response |
| Scrub window past the stored size | 8 KiB |
| Decoded gzip/deflate | 1 MiB |
| Randomness detector | 16 to 128 characters in bodies, 16 to 2,048 in headers and URLs |

## Tested on

| Platform | Status | What was run |
|---|---|---|
| Linux x86-64 (Ubuntu 24.04) | verified | `go vet`, unit tests with `-race`, smoke test, end-to-end redaction |
| macOS 15 (Apple Silicon) | verified | smoke test, silent notifications, end-to-end redaction |
| macOS 15 (Intel) | verified | smoke test, silent notifications, end-to-end redaction |
| Windows x86-64 | verified | smoke test, silent notifications, end-to-end redaction |
| Windows ARM64 | verified | smoke test, silent notifications, end-to-end redaction |
| FreeBSD amd64 (VM) | verified | smoke test, silent notifications, end-to-end redaction |
| Linux ARMv7 (QEMU) | emulated | smoke test, silent notifications, end-to-end redaction |
| Linux RISC-V 64 (QEMU) | emulated | smoke test, silent notifications, end-to-end redaction |
| Linux x86 32-bit, FreeBSD ARM64, OpenBSD (amd64, ARM64), NetBSD (amd64, ARM64) | built in CI, smoke test pending first run | cross-compiled on every push |
| Linux ARM64 (Android / Termux) | verified on device (v1.2.0 CA-bundle change awaiting a device re-check) | live upstream proxy, redaction tags, `export_sanitized_curl`, reverse gateway, guards (needs `termux-chroot`) |

*emulated* means run under QEMU, not on real hardware. Details are in [test-results.md](test-results.md).