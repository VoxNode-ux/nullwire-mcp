# Install and connect

[Back to the README](../README.md)

## Install the binary

Pick whichever fits your machine. Every method checks the download against the release's `SHA256SUMS.txt` and installs nothing if it doesn't match. Release binaries also carry signed GitHub build provenance and keyless [cosign](https://docs.sigstore.dev/) signatures (`*.sigstore.json`, made with cosign v3: verify with cosign v3, or with v2.5+ and `--new-bundle-format`), and each release includes a CycloneDX SBOM (`nullwire-sbom.cdx.json`).

<details open>
<summary><b>With Node.js (no install step): <code>npx</code></b></summary>

```bash
npx -y nullwire-mcp install --client all
```
Nothing to download by hand: the launcher fetches and verifies the binary on first run and keeps it in a cache folder. Your MCP clients are then set to run `npx -y nullwire-mcp`.
</details>

<details>
<summary><b>macOS, Linux and Termux: install script</b></summary>

```bash
curl -fsSL https://raw.githubusercontent.com/VoxNode-ux/nullwire-mcp/main/scripts/install.sh | sh -s -- --setup
```
Installs to `~/.local/bin` (or `$PREFIX/bin` on Termux). `--setup` also registers NullWire with your MCP clients. Drop it to install only. `--uninstall` removes everything again.
</details>

<details>
<summary><b>Windows: install script</b></summary>

```powershell
irm https://raw.githubusercontent.com/VoxNode-ux/nullwire-mcp/main/scripts/install.ps1 | iex
nullwire-mcp install --client all
```
Installs to `%LOCALAPPDATA%\Programs\nullwire-mcp` and adds it to your user PATH. To pass options, run it as `& ([scriptblock]::Create((irm https://raw.githubusercontent.com/VoxNode-ux/nullwire-mcp/main/scripts/install.ps1))) -Setup`.
</details>

<details>
<summary><b>Short install URL (GitHub Pages)</b></summary>

```bash
curl -fsSL https://voxnode-ux.github.io/nullwire-mcp/install.sh | sh -s -- --setup
```
```powershell
irm https://voxnode-ux.github.io/nullwire-mcp/install.ps1 | iex
```
Same scripts as above, just a shorter address.
</details>

<details>
<summary><b>Linux packages and distributions</b></summary>

```bash
# Debian, Ubuntu: download the .deb from the release page, then
sudo apt install ./nullwire-mcp_1.2.0_amd64.deb
# Fedora, RHEL
sudo dnf install ./nullwire-mcp-1.2.0-1.x86_64.rpm
# Alpine (packages are not signed with an Alpine key)
sudo apk add --allow-untrusted ./nullwire-mcp_1.2.0_x86_64.apk
# Arch Linux (AUR)
yay -S nullwire-mcp-bin
# Nix
nix run github:VoxNode-ux/nullwire-mcp
```
Packages are built for amd64, arm64 and ARMv7.
</details>

<details>
<summary><b>Windows: winget and Chocolatey</b></summary>

```powershell
winget install VoxNode.NullWire
choco install nullwire-mcp
```
</details>

<details>
<summary><b>Python, GitHub CLI, mise and asdf</b></summary>

```bash
pipx run nullwire-mcp install --client all        # or: pip install nullwire-mcp
gh extension install VoxNode-ux/gh-nullwire && gh nullwire scan --discover
mise use -g github:VoxNode-ux/nullwire-mcp        # mise, no plugin needed
mise plugin install nullwire-mcp https://github.com/VoxNode-ux/asdf-nullwire-mcp   # or the asdf plugin
```
</details>

<details>
<summary><b>Homebrew and Scoop</b></summary>

```bash
brew install VoxNode-ux/nullwire/nullwire-mcp                                   # macOS, Linux
scoop bucket add nullwire https://github.com/VoxNode-ux/scoop-nullwire           # Windows
scoop install nullwire-mcp
```
All package files (Homebrew, Scoop, AUR, winget, Chocolatey) are generated from the templates in [`packaging/`](../packaging/README.md).
</details>

<details>
<summary><b>Download a release by hand</b></summary>

| Platform | File |
|---|---|
| Linux x86-64 / ARM64 (Raspberry Pi 4+, Termux) | `nullwire-linux-amd64` / `nullwire-linux-arm64` |
| Linux ARMv7 (older Raspberry Pi) / RISC-V 64 | `nullwire-linux-armv7` / `nullwire-linux-riscv64` |
| Linux x86 32-bit | `nullwire-linux-386` |
| macOS Intel / Apple Silicon | `nullwire-darwin-amd64` / `nullwire-darwin-arm64` |
| Windows x86-64 / ARM64 | `nullwire-windows-amd64.exe` / `nullwire-windows-arm64.exe` |
| FreeBSD x86-64 / ARM64 | `nullwire-freebsd-amd64` / `nullwire-freebsd-arm64` |
| OpenBSD x86-64 / ARM64 | `nullwire-openbsd-amd64` / `nullwire-openbsd-arm64` |
| NetBSD x86-64 / ARM64 | `nullwire-netbsd-amd64` / `nullwire-netbsd-arm64` |

```bash
chmod +x nullwire-linux-amd64
sha256sum -c SHA256SUMS.txt --ignore-missing   # verify the download (macOS: shasum -a 256 -c)
gh attestation verify nullwire-linux-amd64 --repo VoxNode-ux/nullwire-mcp   # optional: verify signed build provenance
```
</details>

<details>
<summary><b>Build from source</b></summary>

```bash
go install github.com/VoxNode-ux/nullwire-mcp@latest
# or
git clone https://github.com/VoxNode-ux/nullwire-mcp && cd nullwire-mcp
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o nullwire-mcp .
```
Go 1.27 or newer. There is nothing to `go get`: the module has no dependencies.
</details>

<details>
<summary><b>Docker</b></summary>

```bash
docker run -i --rm ghcr.io/voxnode-ux/nullwire-mcp
```
The server speaks MCP over stdio, so run it with `-i`. The proxy listens on the container's own loopback by design, so a published port (`-p`) cannot reach it. On Linux, add `--network host` to use it from the host's `127.0.0.1`.
</details>

## Add it to your MCP clients

One command registers NullWire with every supported client it finds on your machine:

```bash
nullwire-mcp install --client all --dry-run   # look first: nothing is written
nullwire-mcp install --client all             # then do it, and restart the client
```

It covers Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, Cline, Roo Code, Gemini CLI and Codex CLI. See [Connect your MCP clients](#connect-your-mcp-clients) for details, or add it by hand:

```bash
# Claude Code
claude mcp add nullwire -- /path/to/nullwire-mcp
```

```jsonc
// Claude Desktop, Cursor, Windsurf, Cline and other JSON-configured clients
{
  "mcpServers": {
    "nullwire": {
      "command": "/path/to/nullwire-mcp",
      "args": ["-port", "8080"]
    }
  }
}
```

The client starts NullWire, and NullWire starts the proxy in the same process. A live status bar on stderr shows what is happening:

```text
⚡ [NullWire-MCP] Proxy 127.0.0.1:8080 | RAM Ring: 3/50 | Scrubbed: 7 Tokens, 2 Cookies, 1 IPs | Disk: 0B
```

<a id="connect-your-mcp-clients"></a>

## Connect your MCP clients: `install`

`install` writes NullWire into your MCP clients' config files, and removes it again, so you never have to hunt for the right file or JSON key.

```bash
nullwire-mcp install --list                          # supported clients and whether they are here
nullwire-mcp install --client all --dry-run          # preview every change
nullwire-mcp install --client cursor,vscode          # just these two
nullwire-mcp install --client cursor -- -port 8081   # save server flags with the entry (after --)
nullwire-mcp install --uninstall --client all        # take it back out
nullwire-mcp install --print                         # a snippet to paste into clients that aren't supported
```

| Client | `--client` | What it edits |
|---|---|---|
| Claude Desktop | `claude-desktop` | `claude_desktop_config.json` in your user config folder |
| Claude Code | `claude-code` | runs `claude mcp add --scope user` (needs the `claude` command) |
| Cursor | `cursor` | `~/.cursor/mcp.json` |
| Windsurf | `windsurf` | `~/.codeium/windsurf/mcp_config.json` |
| VS Code (Copilot) | `vscode` | your user `mcp.json` |
| Cline | `cline` | `cline_mcp_settings.json` |
| Roo Code | `roo` | `mcp_settings.json` |
| Gemini CLI | `gemini` | `~/.gemini/settings.json` |
| Codex CLI | `codex` | `~/.codex/config.toml` (`[mcp_servers.nullwire]`) |

Other clients (Zed, Continue, JetBrains and more) are not edited. Use `--print` and paste the snippet where that client keeps its MCP servers.

**How it stays safe**

- With `--client all` it only touches clients it finds on your machine. Name a client explicitly to create its config.
- The first time it changes a file it keeps a copy next to it as `<file>.nullwire-bak`. That copy is never overwritten, so it always holds the original.
- Files are written through a temporary file and renamed, and symlinked dotfiles stay symlinks.
- Your other servers, settings, numbers and extra fields on the NullWire entry (such as `env`) are kept. JSON keys may be re-ordered.
- A config it can't parse as plain JSON (for example one with comments) is left alone, with a clear message.
- Running it twice changes nothing the second time.

| Option | Meaning |
|---|---|
| `--client` | Comma-separated client ids, or `all` (default). |
| `--name` | Name to register the server under (default `nullwire`). |
| `--binary PATH` | Register this binary instead of the one that is running. |
| `--npx` | Register `npx -y nullwire-mcp` (used automatically when you started it through npx). |
| `--dry-run`, `--uninstall`, `--list`, `--print` | As described above. |
| `-- …` | Everything after `--` is saved as the server's own flags. |

## Platform notes

**Termux and Android.** Static Go binaries have no system DNS settings or CA certificates on Android. NullWire detects Termux and uses `1.1.1.1` and `9.9.9.9` for lookups, printing a notice (those resolvers will see the hostnames you contact). Choose your own with `-dns <resolver>`, or `-dns system` to turn this off. Upstream HTTPS uses the CA certificates found in Termux's standard locations; add more with `-cacert`.

```bash
chmod +x nullwire-linux-arm64
sleep infinity | ./nullwire-linux-arm64   # keep stdin open; use a second session for curl
```

**Corporate networks.** If your company re-signs HTTPS traffic, add its root with `-cacert /path/to/company-root.pem`.

**Windows.** Use the `.exe` and the same flags. `scan --history` also checks PowerShell's PSReadLine history.