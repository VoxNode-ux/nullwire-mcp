# Security model

[Back to the README](../README.md)

<a id="security-model-and-honest-limits"></a>

## Security model and honest limits

NullWire is a *diagnostic* tool. Be clear-eyed about what it does and does not promise.

**What it guarantees**
- Nothing is written to disk by the server, and a stop signal clears the buffer (references are dropped; memory is not zeroed). The `install` command edits MCP client configs only when you run it, and backs each file up first.
- The proxy is reachable only from your own machine.
- The model never sees the live traffic, only the scrubbed copy.
- Request and response bodies are never rewritten. Headers are adjusted only where inspection needs it: `Accept-Encoding` is reduced to `gzip`/`deflate`, and the WebSocket `permessage-deflate` offer is dropped (unless you start with `-ws-deflate`).

**What it does not do**
- **Release binaries carry signed build provenance, not OS-vendor code-signing certificates.** Verify authenticity with `SHA256SUMS.txt` and `gh attestation verify`. Because they are not signed with an Apple Developer ID or Microsoft Authenticode certificate, on macOS you may need `xattr -d com.apple.quarantine ./nullwire-darwin-arm64`.
- **It is not a TLS interceptor.** `CONNECT` tunnels show only the destination and byte counts. Use the reverse gateway when you need HTTPS content.
- **Redaction is pattern and heuristic based.** A secret in a shape nobody anticipated, and low in randomness, can slip through. The randomness detector can also redact a harmless long identifier. Add your own patterns in the config for secrets you know about.
- **Brotli and Zstd bodies are never decoded** (the standard library can't, and pulling in a package would break the zero-dependency rule). They are refused (requests) or flagged (responses).
- **A WebSocket flow is refreshed live, not instantly.** It appears when the socket opens and is updated about every 500 ms (slower on very busy streams, to bound CPU). Messages compressed with `permessage-deflate` can't be read by default, so NullWire drops the client's extension offer to keep frames readable. With `-ws-deflate` they are decoded, within per-message and per-connection size caps, but binary compressed messages are not decoded and, when the connection uses context takeover, end decoding for the messages after them.
- **XML attributes are not read by the XML layer.** Secrets in element text (including nested and CDATA text) are covered; `<add key="Password" value="…"/>` relies on the other layers.
- **A secret made only of decimal digits is not caught by the randomness detector**, because that is the shape of timestamps and ids. It is still redacted when it sits under a secret-looking name (`token`, `password`, …) or in a secret header.
- **A password with a decoded `?` or `#`** in a URL is only partly matched by the URL-credentials rule, because those characters end the password field.
- **HTTP/2 text bodies are captured; binary bodies are not.** HTTP/2 and h2c text and JSON bodies are scrubbed like HTTP/1.1. Protobuf and gRPC message bodies are decoded without a schema (see the table below), and `Grpc-Status` and `Grpc-Message` trailers are scrubbed. MessagePack and CBOR are the exception: they are read, as described below.

If you find a secret NullWire missed, please open an issue with a *fake* sample that has the same shape. Never post a real one.

<a id="safety-shields"></a>

## Safety shields

| Shield | Behaviour |
|---|---|
| **Request shield** | A request body with a `Content-Encoding` NullWire can't read (`br`, `zstd`, stacked encodings) is **refused with `415`**, because a body that can't be scrubbed must not reach the model. `-allow-uninspectable` forwards such requests anyway. |
| **Response shield** | The client's `Accept-Encoding` is cut down to `gzip` and `deflate` before it reaches the server, so servers never answer in Brotli or Zstd. A client that offers nothing usable gets `identity`. |
| **Unreadable bodies** | Any other encoded body is stored as a short placeholder with a visible warning in the flow's `note`. |
| **Protobuf and gRPC** | Read without a `.proto` schema: the 5-byte gRPC frame header is removed (gzip and deflate messages are decompressed), and each message is shown as numbered fields such as `2: "text"` or `3: { ... }`. Text values and nested messages are found by checking the bytes; anything else is shown as a byte count, never as raw bytes. The text is scrubbed like any other body. Field names do not exist, so rules that depend on a key name (`password`, `token`) cannot fire: only value-based rules apply. A body that is not readable protobuf records only its size. The decoded view is for reading and is not replayable by `export_sanitized_curl`. |
| **MessagePack and CBOR** | Bodies of type `application/msgpack` and `application/cbor` (also `+msgpack`, `+cbor`, `application/cbor-seq` and the usual `x-` variants) are walked read-only into JSON, which is then scrubbed like any other body. Map keys and UTF-8 strings are kept; binary strings and extension values are never stored, only a byte-count placeholder such as `"[binary 32 bytes]"`. A body cut off by a size limit is read as far as it goes. A body that can't be read at all is stored as a short placeholder with its size. |
| **Size limits** | See the table below. A secret that straddles a limit is still scrubbed first, thanks to an 8 KiB scrub window. |
| **Loopback only** | The proxy binds to `127.0.0.1`. The reverse gateway answers only loopback `Host` headers (`403` otherwise) and refuses to proxy to itself (`508`). |
| **Tunnel limits** | At most 256 concurrent tunnels and upgraded connections, each closed after 10 minutes idle. |
| **Clear on exit** | `SIGINT` and `SIGTERM` clear the ring buffer before the process exits. |

### Limits

| What | Limit |
|---|---|
| Flows kept in RAM | 50 |
| Stored request body | 32 KiB (`-max-body` raises it, up to 2 MiB) |
| Stored response body | 256 KiB (`-max-body` raises it, up to 2 MiB) |
| In-flight capture buffer | 64 KiB request, 512 KiB response (twice `-max-body` when that is larger) |
| Scrub window past the stored size | 8 KiB |
| Decoded gzip/deflate | 1 MiB (twice `-max-body` when that is larger) |
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
| Linux x86 32-bit | verified | smoke test, silent notifications, end-to-end redaction |
| OpenBSD amd64 (VM) | verified | smoke test, silent notifications, end-to-end redaction |
| NetBSD amd64 (VM) | verified | smoke test, silent notifications, end-to-end redaction |
| FreeBSD ARM64 (QEMU) | emulated | smoke test, silent notifications, end-to-end redaction |
| OpenBSD ARM64 (QEMU) | emulated | smoke test, silent notifications, end-to-end redaction |
| NetBSD ARM64 (QEMU) | emulated | smoke test, silent notifications, end-to-end redaction |
| Linux ARM64 (Android / Termux) | verified on device (including the v1.2.0 CA-bundle change) | live upstream proxy, redaction tags, `export_sanitized_curl`, reverse gateway, guards (needs `termux-chroot`) |

*emulated* means run under QEMU, not on real hardware. Details are in [test-results.md](test-results.md).