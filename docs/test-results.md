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