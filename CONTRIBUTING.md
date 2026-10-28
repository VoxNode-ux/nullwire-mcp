# Contributing to NullWire-MCP

Thanks for helping! The program is one `main.go`, with tests in `main_test.go` and `fuzz_test.go`, so it is easy to read end to end before you change anything.

## Quick start

```bash
git clone https://github.com/VoxNode-ux/nullwire-mcp && cd nullwire-mcp
go vet ./...
go test -v ./...
go test -v -race ./...    # needs cgo (gcc/clang) on most platforms
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o nullwire-mcp .
```

Go 1.26+ is required.

## Ground rules

These are the project's core promises. PRs that break them will not be merged.

1. **Standard library only.** No third-party dependencies, so `go.mod` never gets a `require`.
2. **No file I/O.** Nothing is ever written to disk.
3. **`stdout` is sacred.** It carries only single-line JSON-RPC frames ending in `\n`. Logs, banners and the status bar go to `stderr`.
4. **Loopback only.** No flag or option may bind the proxy to a non-loopback address.
5. **Scrub before truncate.** Secrets must be redacted before any body is cut to its size limit.
6. **Notifications stay silent.** Messages without an `id` must write zero bytes.
7. **Be honest in docs.** If a change adds a limitation, update the README's "Honest scope" section.

## Good first contributions

- **New secret formats:** add a pattern and a test (use fake values only)
- **IPv6 scrubbing:** currently only IPv4 is redacted
- **Client recipes:** config snippets for other MCP clients
- **Platform reports:** Windows ARM64 is cross-compiled in CI but not run, so a test report helps a lot
- **Docs:** typos, clearer examples, troubleshooting tips

## Adding or changing a scrubbing pattern

1. Add the regex in `NewScrubber` in `main.go`.
2. Handle it in `ScrubText` (or `ScrubHeaders` for headers).
3. Add a test in `main_test.go` that checks:
   - the secret does **not** appear in the output
   - equal secrets get equal tags, different secrets get different tags
   - harmless text is **not** over-redacted
4. Add a row to the README's "What gets scrubbed" table.

**Never put real secrets in tests, issues, or PRs.** Use obviously fake values like `sk-test-000000000000000000000`.

## Pull request checklist

- [ ] `go vet ./...` is clean
- [ ] `go test -race ./...` passes
- [ ] New behaviour has a test
- [ ] No new dependencies and no file I/O
- [ ] README updated if behaviour, flags or limitations changed
- [ ] Commit messages explain the *why*

Keep PRs small and focused; one change per PR is easiest to review.

## Updating GitHub Actions

Dependabot is set up only as an "updates available" notifier. Please don't merge its pull requests directly. Copy the new version into your own commit, run the workflows, and check they still pass before merging.

## Reporting bugs

Open an issue with your OS/arch, NullWire version, the command you ran, and what you expected vs. what happened. Redact anything sensitive first.

**Security problems:** please do not open a public issue. Follow [SECURITY.md](SECURITY.md).

## Code of conduct

Be kind, assume good intent, and keep feedback about the code. Harassment or personal attacks are not welcome.
