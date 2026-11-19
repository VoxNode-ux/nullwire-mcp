# Smoke test results

These smoke tests are run by hand (Actions → Run workflow) on the release builds. Unit tests, `go vet` and the cross-builds run automatically on every push.

| Platform | Build + MCP | Notifications silent | End-to-end redaction | Status |
|---|---|---|---|---|
| Linux x86-64 (Ubuntu 24.04) | pass | pass | pass | verified |
| macOS 15 (Apple Silicon) | pass | pass | pass | verified |
| macOS 15 (Intel) | pass | pass | pass | verified |
| Windows x86-64 | pass | pass | pass | verified |
| Windows ARM64 | pass | pass | pass | verified |
| FreeBSD amd64 (VM) | pass | pass | pass | verified |
| Linux ARMv7 (QEMU) | pass | pass | pass | emulated |
| Linux RISC-V 64 (QEMU) | pass | pass | pass | emulated |
| Linux x86 32-bit (native on an x86-64 runner) | pass | pass | pass | verified |
| FreeBSD ARM64 (QEMU VM) | pass | pass | pass | emulated |
| OpenBSD amd64 (VM) | pass | pass | pass | verified |
| OpenBSD ARM64 (QEMU VM) | pass | pass | pass | emulated |
| NetBSD amd64 (VM) | pass | pass | pass | verified |
| NetBSD ARM64 (QEMU VM) | pass | pass | pass | emulated |
| Linux ARM64 (Android / Termux) | pass | pass | pass | verified on device, needs `termux-chroot` |

Emulated = run under QEMU, not on real hardware.

## v1.2.0 changes

The vendor-key, IPv6, named-upstream and TLS-root tests run with `go test` on every push. The new fuzz targets (`FuzzVendorKeysNoLeak`, `FuzzIPv6NoLeak`, `FuzzIPv6Stable`) run from the manual security workflow. The Termux CA-bundle fix has been re-checked on a real device and is marked verified in the table above.

## Verification tools and probes

These run in CI and never change the repository. Versions and checksums are pinned in the workflow files.

| Tool | Version | Where it runs | What it checks |
|---|---|---|---|
| gitleaks | v8.30.1 | `deep-verify.yml` | Repo and history scan; must find nothing in NullWire's own scan report |
| trufflehog | v3.99.9 | `deep-verify.yml`, `benchmarks.yml` | Same cross-check, unverified mode (no network); `test_keys` before/after |
| websocat | v1.14.2 (source zip, SHA-256 checked) | `deep-verify.yml` | A secret sent over a WebSocket reaches the upstream intact and stays out of the captured copy |
| rakyll/hey | v0.1.5 | `benchmarks.yml` | HTTP/1.1 load, 1 MiB body + secret stress, bash + hey soak |
| h2load | nghttp2-client (Ubuntu 24.04) | `benchmarks.yml` | HTTP/2 cleartext, gRPC and gRPC-Web POST throughput |
| SonarQube scan action | v8.5.0 | `sonarqube.yml` | `go test -json` and `cover.out` reports, quality gate |
| SonarScanner CLI | 8.4.0.16527 | `sonarqube.yml` (manual option) | Same analysis through the Docker image |

Unit tests repeated 20 times under `-race` in `deep-verify.yml` (`internal/app/scrub_context_test.go`): `TestUnwrapPercentEncodedSecret`, `TestUnwrapEncodedDigits`, `TestUnwrapEscapedJSONKeepsEscaping`, `TestNeedsUnwrap`, `TestContextEntropyLimit`, `TestContextHexWebhookSecrets`, `TestEntropyExemptHeaders`, `TestCheapChecksMatchTheirRules`.

Native probes in `benchmarks.yml`: MCP handshake time, binary size, scrubber CPU speed, MCP tool-call latency (empty ring and 50 flows), memory footprint (VmRSS and heap in use), big body + secret stress, gRPC / gRPC-Web throughput, and the memory-leak soak.

Not wired in: The Stack v2 (gated, no pinned tarball), CodeSearchNet (a code-search corpus, not a secrets corpus), RedVault and GitGuardian (no public versioned dataset), and the websocat v4 alpha.
