# Architecture

[Back to the README](../README.md)

This page lists the algorithms NullWire uses and where they live in `internal/app/`, then the project layout and the development workflow.

## Algorithms

### Pattern matching

- **Aho-Corasick deterministic finite automaton, alphabet-compressed.** A 256-entry class table folds the alphabet, ASCII case is folded as the text is read, and each state carries a bitmask of the rule groups whose literals end there. One pass over the text says which rules are worth running and allocates nothing. `gatemask.go`, `internal/vendors/vendors.go`.
- **Context-aware regular expressions with boundary checks.** RE2 expressions (linear time) with word-boundary, placeholder and false-positive guards, applied by context (header, query, body). `app.go`, `scrub_context.go`, `cloud_secrets.go`, `guards.go`.

### Information theory and statistical modeling

- **Shannon entropy in bits per byte.** `app.go`, `cloud_secrets.go`, `scrub_context.go`, `taint.go`.
- **Sliding-window localized maximum entropy.** A 24-byte window with incrementally updated counts, so a long run is scored by its most random stretch in O(n). `tokenscore.go`.
- **First-order Markov log-likelihood.** A 128 by 128 int8 bigram matrix gives the mean per-pair evidence that a run is natural text. `tokenscore.go`.
- **Additive-smoothed log-likelihood ratio trainer.** `go generate` counts byte pairs in benign and secret corpora and writes the pairs with enough evidence as log2(P(pair | benign) / P(pair | secret)). `tools/bigramgen/main.go`.
- **Additive log-odds score.** Combines the maximum window entropy, the bigram mean, the vowel ratio and the length into one score; above zero means secret. `tokenscore.go`.
- **Control-byte ratio.** Decoded base64 is only scanned if it is valid UTF-8 with fewer than 5% control bytes. `scrub_extra.go`.

### Cryptography, hashing and checksums

- **HMAC-SHA256 keyed tags.** The first 6 hex characters of HMAC-SHA256 over the secret, keyed with a 32-byte `crypto/rand` nonce held in RAM only. `app.go`.
- **SipHash-2-4.** A keyed 64-bit pseudorandom function with no heap allocation. `siphash.go`.
- **Cross-flow taint ring.** A 500-slot circular ring of SipHash values, with each secret also stored as 24-byte sub-window shingles, so a secret seen once is redacted by identity wherever it reappears, even cut or embedded. Only hashes are kept, never the secret. `taint.go`.
- **Luhn mod-10 checksum.** Payment card numbers need a known network prefix, a valid length and a valid checksum. `luhn.go`.

### Bounded-memory structures and protocol handling

- **Circular ring buffer.** 50 flows in RAM, overwritten oldest first. `app.go`.
- **Overlap capture window.** 8 KiB beyond the size limit is captured before truncation and scrubbed with the body. `app.go`.
- **Zip-bomb shield.** Size and entry limits on archives, and a decoded-size cap on gzip and base64 content. `scrub_extra.go`.
- **permessage-deflate (opt-in).** One flate reader per direction, the last 32 KiB of output kept as the next message's dictionary under context takeover, with per-message and per-connection output caps. `ws.go`.
- **WebSocket unmasking.** Client-to-server frames are XORed with the 4-byte masking key at index `(position + i) & 3`, on a read-only copy of the payload. `ws.go`.

<a id="development"></a>

## Development

```bash
go vet ./...
go test -race ./...
```

- **Zero dependencies:** `go.mod` has no `require` lines, and CI keeps it that way.
- **Retraining the token scorer:** the randomness detector's character-pair table starts from built-in priors. `go generate ./internal/app` runs `tools/bigramgen`, which counts character pairs in identifiers from your source and docs and in a secrets corpus (seeded synthetic hex, base62 and base64url strings, plus an optional file of real secrets with one per line), and writes `internal/app/bigram_trained.go`. Pairs with too little evidence keep the built-in value. Synthetic secrets only teach "not natural text"; for the best result pass real leaked secrets:
  ```bash
  go run ./tools/bigramgen -benign . -secrets leaked-secrets.txt -synthetic 20000 -out internal/app/bigram_trained.go
  ```
  Test files and the generated file itself are excluded from the benign corpus. Until you generate it, `bigram_trained.go` is an empty stub and the built-in table is used. After retraining, run the benchmarks and fuzz tests and re-tune the weights at the top of `tokenscore.go` if the false-positive or false-negative balance moves. Keep `leaked-secrets.txt` out of version control.
- **Release transparency:** every release is built with Go 1.27 and includes `SHA256SUMS.txt`, a CycloneDX SBOM (`nullwire-sbom.cdx.json`) and a signed build provenance attestation, which you can verify with `gh attestation verify`. The same proof is attached to each release as `nullwire-provenance.intoto.jsonl`. The `go vet` and `go test -race` logs of every CI run are saved as a `test-logs` artifact for 30 days. Pushes to `main` update a rolling `latest` pre-release; numbered tags produce stable releases. Pull requests never publish anything.
- **Quality checks:** `quality.yml` runs golangci-lint (errcheck, staticcheck, revive, ineffassign), reports test coverage (Codecov) and compares benchmarks against the base branch with `benchstat`. Run the benchmarks yourself with `go test -run='^$' -bench=. -benchmem ./...`. `chaos_test.go` injects network faults (slowloris, dropped connections, malformed and truncated streams) and checks that nothing crashes or leaks.
- **Supply chain:** releases are signed with keyless cosign, the Docker image is signed and scanned with Trivy every week, `reproducible.yml` rebuilds all 15 binaries on four different runners and requires identical checksums, and `security.yml` (weekly) runs `govulncheck`, `gosec` and the fuzz targets. Verify a download with `cosign verify-blob --bundle nullwire-linux-amd64.sigstore.json --certificate-identity-regexp 'https://github.com/VoxNode-ux/nullwire-mcp/\.github/workflows/release\.yml@.*' --certificate-oidc-issuer https://token.actions.githubusercontent.com nullwire-linux-amd64` (cosign v3, or v2.5+ with `--new-bundle-format`).
- **Releases:** a stable tag publishes the release, the `.deb`/`.rpm`/`.apk` packages, the npm package (with provenance), the Homebrew and Scoop taps, the AUR, winget, Chocolatey, PyPI and the official MCP Registry. Release notes are grouped by pull request label (`.github/release.yml`).
- **Fuzzing:** the scrubber, the IPv6 and vendor-key matchers and the WebSocket frame reader have fuzz targets. They check that no secret survives scrubbing, that results don't depend on how input is chunked, and that nothing panics.
- **CI:** checks the shell and Node installers for syntax errors, runs `go vet` and the race detector, cross-compiles static binaries for all 15 platforms (Linux x86-64, 32-bit x86, ARM64, ARMv7 and RISC-V 64; macOS Intel and Apple Silicon; Windows x86-64 and ARM64; FreeBSD, OpenBSD and NetBSD on x86-64 and ARM64), and publishes a multi-arch Docker image (amd64 and arm64). `smoke.yml` and `smoke-extra.yml` run on demand (Actions → Run workflow): end-to-end redaction tests on Ubuntu, macOS (Apple Silicon and Intel), Windows (x86-64 and ARM64), VMs for FreeBSD, OpenBSD and NetBSD (x86-64, and ARM64 under QEMU), Linux 32-bit x86 run natively, and QEMU-emulated Linux ARMv7 and RISC-V 64. Security checks run `govulncheck` and the fuzz targets. GitHub Actions are pinned to full commit hashes.

<details>
<summary><b>Project layout</b></summary>

| File | Purpose |
|---|---|
| `main.go` | Tiny entry point (keeps `go install github.com/VoxNode-ux/nullwire-mcp@latest` working) |
| `internal/app/app.go` | Proxy, scrubber, ring buffer, MCP server and CLI |
| `internal/app/ws.go` | WebSocket frame reader and capture (read-only taps) |
| `internal/app/gateway.go` | `-target-map`: the `/_gw/<name>/` route allowlist for the reverse gateway |
| `internal/app/graphql.go` | GraphQL operation labels for the flow note: JSON, batches, GET, persisted queries |
| `internal/app/har.go` | The `export_har` tool: scrubbed flows as a size-capped HAR 1.2 document, in memory |
| `internal/app/protowire.go` | Schema-less protobuf and gRPC decoder: frame header, varints, text or nested message or bytes |
| `internal/app/inspect.go` | Request shield, multipart scrubbing, `Accept-Encoding` and protobuf rules |
| `internal/app/scrub_extra.go` | JSON array, XML, base64, hex, Base32 and Base58 redaction |
| `internal/app/scrub_xml.go` | Nested XML, CDATA and escaped-XML redaction (`encoding/xml`) |
| `internal/app/binary_json.go` | Shared core of the MessagePack and CBOR walkers: the JSON writer, depth and size limits, and the Content-Type entry point |
| `internal/app/msgpack.go` | Read-only MessagePack walker: map keys and UTF-8 strings into JSON, `bin` and `ext` payloads left out |
| `internal/app/cbor.go` | Read-only CBOR walker (RFC 8949): the same for CBOR, including indefinite lengths and tag 24 |
| `internal/app/ws_live.go` | Live refresh of an open WebSocket's flow |
| `internal/app/limits.go` | `-max-body` and the limits derived from it |
| `internal/app/scrub_context.go` | Header, query and body contexts; the decode pass for URL-encoded and escaped secrets (`%XX`, `\"`, `\/`, `\uXXXX`) |
| `internal/app/guards.go` | False-positive guards: bare `key` fields, prose after `Token`/`Basic`, resource ids, IPv4 handling |
| `internal/app/siphash.go` | SipHash-2-4, the keyed hash behind the taint ring |
| `internal/app/taint.go` | Cross-flow taint ring: redacts a secret by identity wherever it reappears |
| `internal/app/gatemask.go` | Aho-Corasick bitmask gate that decides which rules are worth running |
| `internal/app/allowlist.go` | Optional `ignore_fields` / `ignore_patterns` from the secrets config, to silence false positives in bodies |
| `internal/app/h2.go` | HTTP/1.1 and plain-text HTTP/2 (h2c) serving, and the transport per upstream |
| `internal/app/wiring.go` | Hands the app's scrubber to the `scan` package |
| `internal/app/luhn.go` | Payment card number detection (network prefix, length, Luhn check) |
| `internal/app/tokenscore.go` | Log-odds score behind the randomness detector |
| `internal/app/bigram_trained.go` | Trained character-pair table (an empty stub until `go generate` runs) |
| `tools/bigramgen/` | Generator that trains the character-pair table |
| `tools/trigramgen/` | Generator for the optional trigram table used only on borderline scores (`internal/app/trigram_trained.go`, empty = off) |
| `tools/internal/corpus/` | Shared reproducible benign/secret corpora and holdout split |
| `internal/vendors/` | Vendor prefix tiers |
| `internal/app/cloud_secrets.go` | Prefix-less cloud credentials (AWS, Azure, Cloudflare) and their headers |
| `internal/scan/` | The `scan` command (`scan.go`, `env_scan.go`, `toml_scan.go`, `yaml_scan.go`, `zip_scan.go`, `history_scan.go`, plus the small `Scrubber` interface in `scrubber.go`) |
| `internal/protect/` | The `protect` command |
| `internal/install/` | The `install` command (client config editing) |
| `internal/wasm/` | Compiles the scrubber to WebAssembly for the live demo (`scripts/build-wasm.sh`) |
| `scripts/` | Installers for macOS, Linux, FreeBSD, OpenBSD, NetBSD, Termux and Windows (`install.sh`, `install.ps1`, `termux-install.sh`) |
| `npm/` | The `npx` launcher (no dependencies, no install script) |
| `packaging/` | Homebrew, Scoop, AUR, winget and Chocolatey templates, `render.sh`, Nix package, `gh` extension and asdf/mise plugin sources |
| `flake.nix`, `nfpm.yaml` | Nix flake; `.deb`/`.rpm`/`.apk` package definition |
| `python/` | The `pip` / `pipx` launcher |
| `docs/` | GitHub Pages site (live redactor demo) and the short install URL |
| `internal/app/bench_test.go`, `internal/app/chaos_test.go` | Benchmarks and network fault-injection tests |
| `internal/app/feature_test.go` | Tests for the features above |
| `internal/app/guards_test.go`, `internal/app/guardrail_test.go` | False-positive and leak regression tests, including a concurrency stress test (run with `-race`) |
| `internal/app/unwrap_unicode_test.go` | Tests for `\uXXXX` and `\/` decoding |

</details>
