# asdf-nullwire-mcp

[asdf](https://asdf-vm.com) and [mise](https://mise.jdx.dev) plugin for
[NullWire-MCP](https://github.com/VoxNode-ux/nullwire-mcp). This folder is the
content of the separate repository `VoxNode-ux/asdf-nullwire-mcp`.

```bash
# mise
mise plugin install nullwire-mcp https://github.com/VoxNode-ux/asdf-nullwire-mcp
mise use -g nullwire-mcp@latest

# asdf
asdf plugin add nullwire-mcp https://github.com/VoxNode-ux/asdf-nullwire-mcp
asdf install nullwire-mcp latest
asdf global nullwire-mcp latest
```

mise can also install the release binary directly, with no plugin at all:
`mise use -g github:VoxNode-ux/nullwire-mcp`.

Downloads are checked against the release's `SHA256SUMS.txt`. Linux and macOS,
x86-64 and ARM64.
