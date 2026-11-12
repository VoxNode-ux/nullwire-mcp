// nullwire-mcp: a zero-dependency, RAM-only DLP diagnostic HTTP proxy and
// MCP server. The implementation lives in internal/app; this file only
// starts it, so that "go install github.com/VoxNode-ux/nullwire-mcp@latest"
// keeps working.
package main

import "github.com/VoxNode-ux/nullwire-mcp/internal/app"

func main() { app.Main() }