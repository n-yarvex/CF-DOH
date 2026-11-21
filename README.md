2# doh-ech-worker

A hardened, dependency-free **DNS-over-HTTPS (RFC 8484) proxy for Cloudflare Workers** that can transparently **inject Encrypted Client Hello (ECH) configuration** into `HTTPS` (type 65) DNS answers for domains served from Cloudflare's network.

Single file. No build step. No npm dependencies. Configured entirely through environment variables.

---

## Table of Contents

- [Why this exists](#why-this-exists)
- [Features](#features)
- [Architecture](#architecture)
- [Request routing](#request-routing)
- [ECH injection in depth](#ech-injection-in-depth)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [Usage](#usage)
- [Error model](#error-model)
- [Operational limits](#operational-limits)
- [Caching](#caching)
- [Observability](#observability)
- [Security considerations](#security-considerations)
- [Limitations and design trade-offs](#limitations-and-design-trade-offs)
- [Troubleshooting](#troubleshooting)

---

## Why this exists

Encrypted Client Hello hides the real server name (SNI) inside the TLS handshake. A client can only use ECH if it first learns the server's **ECH configuration**, which is published in the `ech=` parameter of the domain's `HTTPS`/`SVCB` DNS record.

Many resolvers and many zones do not return that parameter, even when the origin sits behind Cloudflare, which accepts ECH using a shared public name, `cloudflare-ech.com`. This Worker sits between the client and a normal upstream DoH resolver and, **only when it is safe to do so**, answers `HTTPS` queries with a synthesized record carrying Cloudflare's current ECH configuration. Everything else is passed through untouched.

In short: a normal DoH proxy that makes ECH work for Cloudflare-hosted sites, with fail-open behaviour.

## Features

- **RFC 8484 compliant** proxy: `POST` and `GET ?dns=` with `application/dns-message`.
- **JSON API passthrough** (`GET ?name=&type=`, `application/dns-json`) with an automatic **fallback endpoint** for providers whose JSON API lives on a different path.
- **ECH injection** for `HTTPS` queries, gated by a check that the queried name actually resolves to a Cloudflare IP range.
- **Fail-open design**: any failure in the ECH path silently falls back to ordinary proxying.
- **Strict config validation** with a startup-style SSRF guard on the upstream URL (no private hosts, IP literals, credentials, query strings or fragments).
- **Bounded everything**: 5 s upstream timeout, 64 KiB request cap, 1 MiB response cap, manual redirect handling.
- **Hop-by-hop header scrubbing** and `Set-Cookie`/`Location` stripping.
- **Structured JSON logs** with a per-request `X-Request-Id`; upstream query strings are never logged.
- **Open CORS**, so browser-based clients and extensions can call it directly.

## Architecture

```
                       ┌──────────────────────────────────────────────┐
                       │                Cloudflare Worker              │
 Client ──DoH──►       │                                              │
 (browser / OS /       │  route ► validate ► dispatch                 │
  stub resolver)       │                                              │
                       │   wire query (GET dns= / POST)               │
                       │        │                                     │
                       │        ▼                                     │
                       │   parse question ── QTYPE=65, QCLASS=IN? ──no──┐
                       │        │ yes                                 │ │
                       │        ▼                                     │ │
                       │   name → A records (upstream JSON)           │ │
                       │        │                                     │ │
                       │        ▼                                     │ │
                       │   any A in Cloudflare CIDRs? ───────no───────┤ │
                       │        │ yes                                 │ │
                       │        ▼                                     │ │
                       │   fetch ECH params for cloudflare-ech.com    │ │
                       │        │ (cached 15 min)                     │ │
                       │        ▼                                     │ │
                       │   synthesize DNS response (HTTPS RR) ──► reply │
                       │                                              │ │
                       │   (any failure) ─────────────────────────────┘ │
                       │        ▼                                       │
                       │   forward verbatim to upstream DoH ◄───────────┘
                       └──────────────────────────────────────────────┘
                                         │
                                         ▼
                              Upstream DoH (default: cloudflare-dns.com)
```

## Request routing

All requests are evaluated in this order:

1. `OPTIONS` is answered immediately with `204` and CORS headers (this precedes the path check, so preflights always succeed).
2. Configuration is parsed and validated (cached per environment object). Invalid config yields `500 Service misconfigured`.
3. The request path (trailing slashes ignored) must equal `/<PATH>`; otherwise `404`.
4. Only `GET` and `POST` are allowed; anything else yields `405` with an `Allow` header.
5. Dispatch:

| Method | Query / body                    | Behaviour                                                        |
|--------|---------------------------------|------------------------------------------------------------------|
| `POST` | body `application/dns-message`  | Size-checked, ECH injection attempted, otherwise forwarded       |
| `GET`  | `?dns=<base64url>`              | Wire-format GET, ECH injection attempted, otherwise forwarded    |
| `GET`  | `?name=<fqdn>[&type=...]`       | JSON API request (`type` defaults to `A`) with fallback chain    |
| `GET`  | both `dns` and `name`           | `400` (ambiguous)                                                |
| `GET`  | neither                         | `400`                                                            |

### JSON mode and fallback

The Worker first queries the primary upstream (`DOH`) with `Accept: application/dns-json`. If a second endpoint is configured through `JSON_PATH` (same origin as `DOH`, different path), it is tried when the first attempt:

- failed at the network level or timed out,
- returned a `5xx`,
- returned `406` or `415` (the endpoint does not speak JSON), or
- returned `2xx` with a non-JSON `Content-Type`.

A `json_fallback` warning is logged for each hop. If the final response is `2xx` but still not JSON, the client receives `502 Upstream did not return JSON`.

## ECH injection in depth

ECH injection applies **only to wire-format requests** (`POST`, or `GET ?dns=`). JSON-mode queries are never modified.

### Eligibility gate

A query is rewritten only if **all** of the following hold:

1. The DNS message parses: at least 12 header bytes and `QDCOUNT >= 1`.
2. The first question has **`QTYPE = 65` (HTTPS)** and **`QCLASS = 1` (IN)**.
3. The queried name resolves, via an upstream JSON `A` lookup, to at least one IPv4 address that falls inside a **Cloudflare IP range** (the list published at `https://api.cloudflare.com/client/v4/ips`).
4. A valid ECH configuration for `cloudflare-ech.com` can be obtained.

If any step fails, returns nothing, or throws, the original query is forwarded untouched. A broken or slow ECH path therefore degrades to a plain DoH proxy rather than breaking name resolution.

### Obtaining the ECH configuration

The Worker queries the upstream's JSON API for `cloudflare-ech.com` `type=65`, parses the presentation-format RDATA (`<priority> <target> key=value ...`), and keeps only two SvcParams:

| SvcParam | Key number | Encoding on the wire                                      |
|----------|-----------:|-----------------------------------------------------------|
| `alpn`   |          1 | Comma-separated list → length-prefixed protocol IDs       |
| `ech`    |          5 | Base64 → raw bytes                                        |

The record is accepted only if an `ech` parameter is present. Generic-format answers (`\#`) are rejected. Parameters are re-emitted **sorted by ascending key**, as required by the SVCB specification.

### Synthesized response

The reply is a hand-built DNS message:

| Field            | Value                                                          |
|------------------|----------------------------------------------------------------|
| ID               | Copied from the client query                                   |
| Flags            | `0x8180` (QR, RD, RA; `RCODE=0`)                               |
| Counts           | `QDCOUNT=1`, `ANCOUNT=1`, others `0`                           |
| Question         | Re-encoded from the parsed name, type 65, class IN             |
| Answer name      | Compression pointer `0xC00C` (back to the question)            |
| Answer           | Type 65, class IN, **TTL 300 s**                               |
| RDATA            | `SvcPriority`, `TargetName`, then sorted `alpn` / `ech` params |
| `Content-Type`   | `application/dns-message`                                      |

The message carries no `OPT` pseudo-record and no DNSSEC material.

### What this does to the zone's real `HTTPS` record

For an eligible name, the client receives the **synthesized** record **instead of** the one the zone actually publishes. Any other SvcParams (`ipv4hint`, `ipv6hint`, `port`, and so on) are not carried over. This is deliberate, since the point is to supply a known-good Cloudflare ECH config, but you should be aware of it.

### Latency cost

Each eligible `HTTPS` query costs one extra upstream JSON lookup (the `A` check). The Cloudflare CIDR list and the ECH config are cached; the per-name `A` lookup is not.

## Configuration

All settings are Worker environment variables (plain-text vars are fine; none are secrets, though see [Security considerations](#security-considerations) for using `PATH` as a soft secret).

| Variable    | Default          | Description |
|-------------|------------------|-------------|
| `PATH`      | `dns-query`      | The single path segment the Worker serves. Leading/trailing slashes are trimmed. |
| `DOH`       | `cloudflare-dns.com` | Upstream DoH resolver. Bare host or full `https://` URL. If no path is given, `/dns-query` is used. |
| `JSON_PATH` | *(unset)*        | Optional single path segment on the **same origin as `DOH`** used as a JSON fallback endpoint. Ignored if it resolves to the same URL as the primary. |

### Validation rules

Invalid values cause every request (except `OPTIONS`) to fail with `500 Service misconfigured`, and the reason is logged as `config_error`.

- `PATH` and `JSON_PATH` must be strings, contain a **single** segment, must not be `.` or `..`, and may only contain `A-Z a-z 0-9 . _ ~ -`.
- `DOH` must be a valid **`https://`** URL with **no credentials, query string or fragment**.
- `DOH`'s host must not be empty, `localhost`, `*.localhost`, `*.local`, `*.internal`, `*.home.arpa`, or an **IP literal** (IPv4, IPv6 or bracketed).

Examples:

```text
DOH=cloudflare-dns.com                 → https://cloudflare-dns.com/dns-query
DOH=https://dns.example.net/resolver   → https://dns.example.net/resolver
DOH=https://dns.google                 → https://dns.google/dns-query
JSON_PATH=resolve                      → https://dns.google/resolve   (fallback JSON endpoint)
```

> **Note on non-Cloudflare upstreams:** ECH injection fetches `cloudflare-ech.com` through the upstream's JSON API and expects Cloudflare-style presentation data for type 65. Cloudflare's resolver is the best-tested choice. With other upstreams the injection may simply never trigger, in which case the Worker behaves as a plain proxy.

## Deployment

### With Wrangler

Save the script as `workers.js` and create `wrangler.jsonc`:

```jsonc
{
  "name": "doh-ech-worker",
  "main": "workers.js",
  "compatibility_date": "2025-01-01",
  "vars": {
    "PATH": "dns-query",
    "DOH": "cloudflare-dns.com"
    // "JSON_PATH": "resolve"
  }
}
```

```bash
npx wrangler deploy
```

### With the dashboard

1. **Workers & Pages → Create → Worker**, then paste `workers.js` into the editor.
2. Under **Settings → Variables**, add `PATH`, `DOH` and optionally `JSON_PATH`.
3. Deploy.

### Use a custom domain for full caching

The Worker uses the Workers **Cache API** (`caches.default`) to share the Cloudflare CIDR list and ECH config across requests. The Cache API is **not functional on `*.workers.dev`**; attach the Worker to a **custom domain or route** to benefit from it. Without it the Worker still works, using in-memory per-isolate caches, but refetches more often.

## Usage

Assume the Worker is reachable at `https://doh.example.com/dns-query`.

**Wire-format (RFC 8484) with curl:**

```bash
curl --doh-url https://doh.example.com/dns-query https://example.com -I
```

**Inspect an `HTTPS` record:**

```bash
doggo example.com HTTPS @https://doh.example.com/dns-query
kdig +https=/dns-query @doh.example.com example.com HTTPS
```

For a Cloudflare-hosted domain, the answer should include `alpn` and `ech` parameters with a 300-second TTL.

**JSON API:**

```bash
curl 'https://doh.example.com/dns-query?name=example.com&type=AAAA'
```

`type` defaults to `A` when omitted. All other query parameters are forwarded upstream.

**Clients:**

- **Firefox:** set the DNS-over-HTTPS provider to *Custom* with the Worker URL (and enable ECH under `network.dns.echconfig.enabled` where applicable).
- **Chrome / Edge:** *Settings → Privacy and security → Security → Use secure DNS → custom*.
- **Systemd-resolved, dnscrypt-proxy, Android Private DNS alternatives, etc.:** any RFC 8484 client works with the URL above.

Every response includes `X-Request-Id`, which matches the `requestId` in logs.

## Error model

Errors are JSON, sent with `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, CORS headers and `X-Request-Id`:

```json
{ "error": "Upstream timeout" }
```

| Status | Message / cause |
|-------:|-----------------|
| 400 | `Provide either 'dns' or 'name', not both` · `Missing 'dns' or 'name' query parameter` · `Request payload must not be empty` |
| 404 | `Not Found` (path does not match `/<PATH>`) |
| 405 | `Method not allowed: <method>` (with `Allow: GET, POST, OPTIONS`) |
| 413 | `Request payload too large` (> 65 535 bytes, by header or by streamed length) |
| 415 | `Content-Type must be application/dns-message` |
| 500 | `Service misconfigured` · `Internal error` |
| 502 | `Upstream returned <5xx>` · `Upstream redirect not allowed` · `Upstream response too large` · `Upstream request failed` · `Upstream did not return JSON` |
| 504 | `Upstream timeout` |

Upstream `4xx` responses are relayed as received, with the upstream's `Content-Type` and `no-store` caching.

## Operational limits

| Limit | Value |
|-------|-------|
| Upstream request timeout | 5 s |
| Max request body (POST) | 65 535 bytes |
| Max upstream response body | 1 MiB (1 048 576 bytes) |
| Upstream redirects | Never followed (`redirect: "manual"`); 3xx other than 304 → `502` |
| ECH config cache (memory and Cache API) | 15 min |
| Cloudflare CIDR cache | 1 h in memory, 24 h in Cache API |
| Synthesized record TTL | 300 s |
| CORS preflight cache | 86 400 s |

## Caching

| Data | Memory (per isolate) | Cache API (per data centre) | Key |
|------|----------------------|-----------------------------|-----|
| Cloudflare CIDR ranges | 1 h | `max-age=86400` | `https://cf-cidr.internal/v1` |
| ECH config (parsed) | 15 min | `max-age=900` | `https://ech-config.internal/rdata-v1` |

Cache writes are pushed through `ctx.waitUntil` so they never delay the response. If a CIDR refresh fails, the previously cached ranges are reused when available.

Successful proxied DNS responses keep the upstream's `Cache-Control`, so downstream HTTP caches and clients still see the resolver's intended freshness. Error responses are always `no-store`.

## Observability

Logs are single-line JSON with `ts`, `level` and `evt`. The upstream URL is logged as **origin + path only**, which keeps query contents, and therefore queried names, out of the upstream-error logs.

| Event | Level | Meaning |
|-------|-------|---------|
| `config_error` | error | Invalid environment configuration |
| `upstream_network_error` | error | Fetch failed or timed out (`timeout: true/false`) |
| `upstream_body_too_large` | error | Upstream exceeded the 1 MiB cap |
| `upstream_redirect` | error | Upstream returned 3xx |
| `upstream_5xx` | error | Upstream returned a server error (with a 512-byte body snippet) |
| `upstream_not_json` | error | JSON mode got a non-JSON 2xx |
| `unhandled_exception` | error | Unexpected error (stack truncated to 2 KiB) |
| `json_fallback` | warn | Switched from the primary to the fallback JSON endpoint |
| `cf_cidr_fetch_failed` | warn | Could not refresh Cloudflare IP ranges |
| `ech_config_fetch_failed` | warn | Could not fetch the ECH config |
| `ech_injected` | info | A synthesized `HTTPS` answer was returned (includes the queried `name`) |

Use `npx wrangler tail` to stream logs live.

> `ech_injected` records the queried hostname. Disable or filter that event if your privacy policy forbids it.

## Security considerations

- **This is an open proxy by default.** There is no authentication, and CORS allows any origin. Treat the `PATH` value as a lightweight shared secret (for example `PATH=k7f3-9a2c-dns`), and/or protect the route with Cloudflare Access, WAF rules or rate limiting. The `Authorization` header is permitted by CORS but is **not validated** by this code.
- **SSRF guard.** The upstream is operator-configured, not user-controlled, and is restricted to public `https://` hostnames with no credentials. Redirects are never followed, so an upstream cannot bounce the Worker to an internal address.
- **Header hygiene.** Hop-by-hop headers, `Content-Length`, `Content-Encoding`, `Location` and `Set-Cookie` are never relayed from upstream; `nosniff` is always set.
- **Bounded resource use.** Streaming reads enforce size limits even when `Content-Length` is absent or lies.
- **No DNSSEC validation** is performed. Injected records are unsigned and the `AD` bit is not set.
- **Trust model.** Clients using this Worker must trust it to return honest answers, since it can rewrite `HTTPS` records. Self-host it rather than using an untrusted instance.

## Limitations and design trade-offs

- **IPv4-only eligibility check.** The Cloudflare membership test uses `A` records. Names that are IPv6-only will not be eligible.
- **First question only**, and the parser does not follow compression pointers inside the question name (standard clients do not compress it).
- **One-way substitution.** For eligible names the real `HTTPS` record, including any `ipv4hint`/`ipv6hint`/`port`, is replaced by the synthesized one.
- **Extra upstream round-trip** for each eligible `HTTPS` query (not cached per name).
- **ECH is only useful if the origin accepts it.** If a zone's Cloudflare ECH support is disabled, an ECH-capable client may need to retry without ECH, which depends on client behaviour.
- **Upstream compatibility.** ECH injection assumes a Cloudflare-style JSON API for type 65 answers.
- **Cache API caveat** on `workers.dev` (see [Deployment](#use-a-custom-domain-for-full-caching)).
- **No built-in rate limiting or authentication.**

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `500 Service misconfigured` | Check `wrangler tail` for the `config_error` message (bad `DOH`, `PATH` or `JSON_PATH`). |
| `404 Not Found` | The request path does not equal `/<PATH>`. |
| `415` on POST | Missing `Content-Type: application/dns-message`. |
| No `ech` in `HTTPS` answers | The domain does not resolve to Cloudflare IPv4 ranges, the upstream is not Cloudflare-compatible, or the ECH fetch failed (see `ech_config_fetch_failed`). |
| Frequent CIDR/ECH refetches | Running on `*.workers.dev`, where the Cache API does not persist. Use a custom domain. |
| `502 Upstream did not return JSON` | Configure `JSON_PATH` for providers whose JSON API is on a different path (e.g. `resolve`). |
| `504 Upstream timeout` | The upstream did not answer within 5 s. |

