# Packaging: Homebrew, Scoop, AUR, winget, Chocolatey and friends

The package files are generated, not written by hand. `render.sh` fills the two
templates in this folder with a release's version and the checksums from its
`SHA256SUMS.txt`.

| Template | Generates | Goes in |
|---|---|---|
| `nullwire-mcp.rb.tmpl` | `nullwire-mcp.rb` (Homebrew formula) | `Formula/` of the tap repo `VoxNode-ux/homebrew-nullwire` |
| `nullwire-mcp.json.tmpl` | `nullwire-mcp.json` (Scoop manifest) | `bucket/` of the bucket repo `VoxNode-ux/scoop-nullwire` |

## Publish a new version

Do this after the release exists on GitHub (the checksums come from it).

```bash
sh packaging/render.sh -v v1.2.0 -o out      # downloads SHA256SUMS.txt for that tag
cp out/nullwire-mcp.rb   ../homebrew-nullwire/Formula/
cp out/nullwire-mcp.json ../scoop-nullwire/bucket/
```

Commit and push each repo. Then check them:

```bash
brew install VoxNode-ux/nullwire/nullwire-mcp && brew test nullwire-mcp   # macOS or Linux
scoop bucket add nullwire https://github.com/VoxNode-ux/scoop-nullwire    # Windows
scoop install nullwire-mcp
```

`render.sh` has no network need if you pass the sums file yourself:
`sh packaging/render.sh -v v1.2.0 -s dist/SHA256SUMS.txt`. It stops if a
checksum is missing or malformed, or if a `@@PLACEHOLDER@@` is left over.

## Placeholders

`@@VERSION@@` (1.2.0), `@@TAG@@` (v1.2.0), and `@@SHA_DARWIN_ARM64@@`,
`@@SHA_DARWIN_AMD64@@`, `@@SHA_LINUX_ARM64@@`, `@@SHA_LINUX_AMD64@@`,
`@@SHA_WINDOWS_AMD64@@`, `@@SHA_WINDOWS_ARM64@@`.

## Notes

- Homebrew covers macOS (Intel, Apple Silicon) and Linux (x86-64, ARM64). ARMv7,
  RISC-V and FreeBSD binaries are only on the release page.
- The Scoop manifest also has `checkver` and `autoupdate`, so Scoop's own
  tooling can bump versions in the bucket and read hashes from `SHA256SUMS.txt`.
- Uninstalling a package does not remove NullWire's entries from MCP client
  configs. Run `nullwire-mcp install --uninstall --client all` first.

## More package managers

`render.sh` also writes the files for the Arch User Repository, winget and
Chocolatey (into `aur/`, `winget/` and `choco/` under the output folder). After a
stable release, `.github/workflows/distribute.yml` renders and pushes all of
them automatically when the matching secret is set. The first submission to
winget, the AUR and Chocolatey is done by hand once. Other sources in this
folder:

| Folder | What it is | Lives in |
|---|---|---|
| `nix/package.nix` | Nix package used by `flake.nix` (and for nixpkgs) | this repo |
| `gh-nullwire/` | GitHub CLI extension | its own repo `VoxNode-ux/gh-nullwire` |
| `asdf-nullwire-mcp/` | asdf and mise plugin | its own repo `VoxNode-ux/asdf-nullwire-mcp` |