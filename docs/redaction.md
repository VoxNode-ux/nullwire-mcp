# What gets redacted

[Back to the README](../README.md)

Every URL, header, request body and response body passes through **three stages**. The twelve numbered layers are the rules inside stages 2 and 3, listed in the order they run.

```mermaid
flowchart LR
    I[Text] --> U["Stage 1<br/>Unwrap<br/>decode a copy"]
    U --> D["Stage 2<br/>Deterministic rules<br/>layers 1 to 11"]
    D --> H["Stage 3<br/>Match and guess<br/>layer 12"]
    H --> O[Scrubbed copy]
```

### Stage 1: Unwrap

Secrets hidden by URL-encoding or escaped JSON are found on a decoded copy and replaced in place in the original. It runs first, and only on text that holds a `%XX`, `\"`, `\\`, `\/` or ASCII `\uXXXX` escape. It applies the same rules and false-positive guards as stage 2, so the encoded and plain form of a secret are treated alike. Details are under [Secrets hidden by encoding](#secrets-hidden-by-encoding) below.

### Stage 2: Deterministic rules (layers 1 to 11)

Known shapes and names. These rules are exact, so they run before any guesswork.

| # | Layer | Catches | Example |
|---|---|---|---|
| 1 | **Private keys** | PEM blocks: RSA, EC, OpenSSH, encrypted, PGP; JSON-escaped ones; blocks cut off by a size limit | `-----BEGIN PRIVATE KEY-----…` |
| 2 | **Secret fields** | JSON string values and **arrays**, and query parameters, for names like `password`, `api_key`, `access_token`, `secret`, `session_id` | `"password": ["a","b"]`, `?api_key=…` |
| 3 | **XML elements** | Element text for secret-looking names, with namespaces and CDATA; the tags themselves stay intact | `<wsse:Password>…</wsse:Password>` |
| 4 | **URL credentials** | `user:password@host` in any URL or connection string, including a password that is URL-encoded (`p%40ss`) | `postgres://app:pw@db/prod` |
| 5 | **Auth schemes** | `Bearer`, `Basic` and `Token` credentials. In a body, a short all-lowercase word after `Basic` or `Token` is read as ordinary English (`invalid token provided`); in a header or a query string the value is always a credential, so `Authorization: Token mysecretkey` is redacted. | `Authorization: Bearer …` |
| 6 | **JWTs** | Three-part `eyJ…` tokens | |
| 7 | **Vendor keys** | 200+ prefixes in three tiers (below), plus webhook URLs and connection strings | `AKIA…`, `ghp_…`, `sk-ant-…`, `cfut_…`, `SG.…` |
| 8 | **Secret-named fields** | `key: value` or `key=value` pairs where the *name* says secret and the value is 12 to 256 characters. A `;` ends the value (connection strings), and the rule also reads inside escaped JSON. Placeholders such as `${VAR}`, `{{var}}`, `%VAR%` and `******` are kept; a value that merely starts with `%` (`password=%mysecret1234`) is still redacted. | `x-custom-auth: …`, `session=…`, `{\"custom_key\":\"…\"}` |
| 9 | **Your patterns** | Regexes from the [config file](cli.md#configuration) | |
| 10 | **IP addresses** | IPv4 (strictly validated) and IPv6, except loopback and unspecified. A version number after a product name (`Chrome/120.0.6099.109`) is kept; an address in a URL path is redacted. | `203.0.113.9`, `/nodes/10.1.2.3/status` |
| 11 | **Base64** | Base64 or URL-safe base64 whose *decoded* text contains a secret. Images and other binary data are left alone. | `eyJhcGlfa2V5…` |

### Stage 3: Match and guess (layer 12)

First, any value redacted earlier in the run is matched by identity, so one secret keeps one tag wherever it appears. Then the randomness heuristics run last, because they are guesses. Both are skipped for exempt headers and allowlisted fields.

| # | Layer | Catches | Example |
|---|---|---|---|
| 12 | **Randomness detector** | 16 to 128 character tokens in bodies, and up to 2,048 characters in headers and URLs, that look machine-generated. A smooth log-odds score combines sliding-window Shannon entropy, character-pair statistics, vowel ratio and length. UUIDs, provider resource ids and runs of **only decimal digits** (timestamps, order numbers) are exempt. | an unknown vendor's key |

**Headers.** `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `Api-Key`, `X-Auth-Token` and `Proxy-Authorization` are always redacted, plus common cloud and developer-tool headers (`X-Auth-Key`, `Ocp-Apim-Subscription-Key`, `X-Amz-Security-Token`, `X-Goog-Api-Key`, `Private-Token`, `X-Vault-Token`, `Apikey`, and others), plus any you add. Use `ignore_headers` to opt a header out.

**Headers and URLs are scrubbed more strictly than bodies.** A header value or a URL is one short value at a time, so a long random-looking run there is almost always a secret. Header and query text get the longer randomness limit above, a longer limit for secret-named fields (2,048 instead of 256 characters), and a rule for standalone 32, 40 and 64 digit hex values (the size of MD5, SHA-1 and SHA-256 webhook secrets and signatures). Bodies keep the looser rules to avoid false positives. `ETag`, `If-None-Match`, `If-Match`, `X-Request-Id`, `X-Correlation-Id` and `Traceparent` are exempt from the randomness checks because they carry identifiers and content hashes, not secrets.

<a id="secrets-hidden-by-encoding"></a>

**Secrets hidden by encoding.** A key written with URL-encoding (`%73k_live_…`, or digits as `%39%38…`), inside double-escaped JSON (`{\"api_key\":\"…\"}`), or with JSON serializer escapes (`\u003d` for `=`, `\u0026` for `&`, `\/` for `/`) is found on a decoded copy and redacted in place. That pass covers vendor keys, JWTs, secret fields, query parameters, `Bearer` credentials, private keys, URL passwords, prefix-less AWS secret keys and payment card numbers (`%2F` in a key, `%40` in a password, `%20` between card digits). Only ASCII `\uXXXX` escapes are decoded; escapes for other characters are left as they are. Escaping outside the secret is left exactly as it was, so escaped JSON stays valid. The encoded and the plain form of one secret get the same `[REDACTED_TOKEN#…]` tag. Text with none of these escapes never takes this path.

**Look-alikes are not redacted, in either form.** The decoded pass applies the same false-positive guards as the normal rules: existing `[REDACTED_…]` tags, `ignore_fields` markers, placeholders (`${VAR}`, `{{var}}`, `%DB_PASSWORD%`, `******`), `key` fields holding short words or paths, and plain-English `Token`/`Basic` phrases in bodies. A placeholder is checked as written as well as decoded, so `%DB_PASSWORD%` is not mistaken for the escape `%DB`.

**Cloud credentials without a prefix.** AWS secret access keys, Azure storage and Service Bus keys, Azure AD client secrets (`…8Q~…`) and SQL connection-string passwords have no vendor prefix. They are caught by the name they are stored under (`SecretAccessKey`, `AccountKey`, `SharedAccessKey`, `client_secret`, `Password=` in a connection string), by their shape (a standalone 40-character random base64 string, an Azure AD secret), or by the header they travel in. Cloudflare API tokens are caught by `Authorization: Bearer`, `X-Auth-Key`, the new `cfut_`/`cfat_` prefixes, or the randomness detector.

**Vendor tiers.** Matching all prefixes the same way would redact ordinary words, so they are tiered:

| Tier | Needs after the prefix | Examples |
|---|---|---|
| **Strong** | 16+ token characters | `sk-ant-`, `sk-proj-`, `AKIA`, `ASIA`, `ghp_`, `github_pat_`, `glpat-`, `xoxb-`, `sk_live_`, `sk_test_`, `rk_live_`, `npm_`, `SG.`, `AIza`, `ya29.`, `pplx-` |
| **Weak** (also occur in normal words) | 20+ characters, plus a digit, a capital or 24+ characters | `hf_`, `r8_`, `secret_`, `api_key_`, `access_token_`, `bearer `, `token ` |
| **Connection strings** | 8+ characters | `postgres://`, `mysql://`, `mongodb+srv://`, `redis://`, `amqp://` |

Prefixes are matched case-sensitively, so `asiapacific_region` is left alone.

**Bodies are decoded before scrubbing.** `gzip` and `deflate` (up to 1 MiB expanded, a decompression-bomb guard). `multipart/form-data` forms are split into fields; file parts keep only the field name, file name and size.

## Recent changes

These are the redaction changes since 1.2.0. They are not yet in a tagged release.

**Fewer leaks**
- An IPv4 address in a URL path (`/nodes/10.1.2.3/status`) is now redacted. Only a version number after a product name (`Chrome/120.0.6099.109`) is kept.
- `Authorization: Token mysecretkey` (short, lowercase) in a header or query string is now redacted. The plain-English exemption applies to bodies only.
- A value that starts with `%` but is not a `%NAME%` placeholder (`password=%mysecret1234`) is now redacted.
- The decode pass now also catches private keys, URL passwords (`%40`), prefix-less AWS secret keys (`%2F`) and card numbers (`%20`), and decodes `\uXXXX` and `\/` escapes.
- `{\"custom_key\":\"…\"}` (escaped JSON) is now covered by the secret-named-field rule.

**Fewer false positives**
- `{"key": ["pk", "sk"]}` and other short bare `key` values are left alone, in arrays too.
- The decode pass no longer redacts values the normal rules would keep: bare `key` words, `Invalid token provided`, `${VAR}` placeholders, `%DB_PASSWORD%` and existing redaction tags.
- `Password=******;Uid=app` is kept: a `;` now ends a field value.
- Runs of only decimal digits (nanosecond timestamps, order numbers) are no longer flagged as random.
- A URL with a query containing an `@` (`https://user:p%40ss@db.internal?email=a@b.com`) keeps its host and query; only the password is redacted.

**Tooling**
- New `go generate` step to train the randomness detector's character-pair table (see [Development](architecture.md#development)).
- New regression tests: `guardrail_test.go` (false positives, leaks, concurrency) and `unwrap_unicode_test.go`.
