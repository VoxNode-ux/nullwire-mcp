# Security Policy

NullWire-MCP exists to keep secrets away from AI agents, so security reports are taken seriously.

## Supported versions

Only the **latest release** receives security fixes. Please update before reporting.

## Reporting a vulnerability

**Please do not open a public issue for anything that could expose real secrets or weaken the proxy.**

Use GitHub's private reporting instead. Open this link directly:

**[Report a vulnerability privately](https://github.com/VoxNode-ux/nullwire-mcp/security/advisories/new)**

Or go to the repository's [Security tab](https://github.com/VoxNode-ux/nullwire-mcp/security) and click **Report a vulnerability**. Then describe the problem and how to reproduce it.

Please include:

- The NullWire-MCP version (or commit) and your OS / architecture
- Exact steps or a minimal request that reproduces it
- What you expected vs. what happened
- **Fake example values only.** Never paste a real token, cookie, or key.

**Timeline:** you will get an acknowledgement within 7 days and a status update within 14 days. This is a small, volunteer-run project, so fixes may take longer for complex issues, and you will be kept informed.

## What counts as a security issue

**Report privately:**

- A way for a real secret to reach the agent's view in a shape the [documented scrubber](https://github.com/VoxNode-ux/nullwire-mcp#-security--protocol-engineering-deep-dive) is supposed to catch
- Any way to make the proxy listen on a non-loopback address
- Bypassing the DNS-rebinding guard (`403`) or the self-loop guard (`508`)
- Anything that writes bytes other than JSON-RPC frames to `stdout`, or writes data to disk
- Crashes or hangs triggered by crafted traffic or MCP messages
- Tag collisions or salt/nonce handling that let a secret value be recovered

**Public issue is fine:**

- A secret *format* the scrubber does not yet recognise (for example a new vendor key prefix). Open a normal issue with a **fake** example of the shape. See [Honest scope](https://github.com/VoxNode-ux/nullwire-mcp#-honest-scope--known-limitations): redaction is pattern-based by design.
- Feature requests, such as IPv6 scrubbing or extra client configs

## Out of scope

These are documented limitations, not vulnerabilities:

- `HTTP CONNECT` returns `501` by design (no TLS interception)
- Your own app sees raw traffic; NullWire only protects the AI agent's view
- OS-level swap or crash dumps can write RAM contents to disk
- Unsigned release binaries (verify them with `SHA256SUMS.txt`)
- 24-bit tags can collide in principle; they are for correlation, not identification

## Disclosure

Please give a reasonable window, normally **90 days** from your report, to fix an issue before public disclosure. Reporters who want credit will be thanked in the release notes and in the [published advisory](https://github.com/VoxNode-ux/nullwire-mcp/security/advisories).

For contributing fixes, see [CONTRIBUTING.md](https://github.com/VoxNode-ux/nullwire-mcp/blob/main/CONTRIBUTING.md).
