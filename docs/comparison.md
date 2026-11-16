# How it compares

[Back to the README](../README.md)

NullWire is deliberately narrow: it lets an AI assistant look at your network traffic while the secrets in it are replaced before the model sees them. Other tools do other jobs, and some of them do those jobs better. Here is the honest picture.

| | NullWire-MCP | mitmproxy | Langfuse | Presidio |
|---|---|---|---|---|
| **Built for** | Letting an AI assistant debug traffic with secrets scrubbed | Interactive proxy to inspect and modify HTTP(S) and WebSocket traffic | LLM tracing, evals and prompt management | Detecting and anonymizing personal data (PII) in text |
| **Sees inside HTTPS** | Only through the reverse gateway; the plain proxy tunnels HTTPS blind | Yes, once you install its CA certificate | Not a proxy; traces come from your app's SDK | Not a proxy; you give it text |
| **Secret redaction** | Built in, applied before anything reaches the model | No built-in redaction; scriptable with Python add-ons | You write your own masking function (SDK `mask` callback) | Built in (patterns and NER), aimed mainly at personal data |
| **Where data lives** | RAM only (last 50 flows), never written to disk | In memory; saved to a file only if you choose to | Stored in its database (Cloud or self-hosted) | Stays in your own process |
| **Runtime** | One static Go binary, no dependencies | Python-based tool | Cloud, or self-hosted (web, worker, Postgres, ClickHouse, Redis) | Python package, or Docker with a REST API |
| **Best when** | You want an AI assistant to debug traffic without leaking keys | You need full traffic inspection and modification | You monitor LLM apps in production | You clean PII out of text pipelines |

NullWire does not replace mitmproxy for full HTTPS interception, Langfuse for production tracing, or Presidio for PII pipelines. If one of those fits your job, use it. If you want your assistant to see traffic and never the secrets in it, that is what NullWire is for.

*These comparisons come from each project's own documentation. If something is out of date, please open an issue.*
