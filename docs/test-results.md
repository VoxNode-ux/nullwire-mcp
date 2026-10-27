# Smoke test results

Automated checks run on each commit. Raw logs for each run are in the `test-results` branch.

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
| Linux ARM64 (Android / Termux) | pass | pass | pass | verified on device, needs `termux-chroot` |

Emulated = run under QEMU, not on real hardware.
