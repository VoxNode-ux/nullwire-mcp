# nullwire-mcp (Python launcher)

A tiny launcher for [NullWire-MCP](https://github.com/VoxNode-ux/nullwire-mcp).
It has no dependencies. On first run it downloads the binary for your platform
from the project's GitHub release, checks it against the release's
`SHA256SUMS.txt` (and refuses to run it if the check fails), keeps it in a cache
folder, and starts it with the same arguments and stdin/stdout, so it works as an
MCP stdio server.

```bash
pipx run nullwire-mcp install --client all     # no install
pip install nullwire-mcp && nullwire-mcp --help
```

Environment: `NULLWIRE_VERSION` (release tag), `NULLWIRE_BASE_URL` (mirror),
`NULLWIRE_CACHE_DIR` (where the binary is kept).
