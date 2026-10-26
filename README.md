# crawlgate

[![Release](https://img.shields.io/github/v/release/North-web-dev/crawlgate?sort=semver)](https://github.com/North-web-dev/crawlgate/releases) [![Go Reference](https://pkg.go.dev/badge/github.com/North-web-dev/crawlgate.svg)](https://pkg.go.dev/github.com/North-web-dev/crawlgate) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) ![Go](https://img.shields.io/github/go-mod/go-version/North-web-dev/crawlgate)

Defensive bot management in one Go binary. crawlgate sits in front of a web
service (as a reverse proxy, or as `net/http` middleware inside your own
server) and does three things:

1. **Verifies legitimate search crawlers** with forward-confirmed reverse DNS,
   so real Googlebot/Bingbot/etc. are recognised and always let through.
2. **Rate-limits everyone else** with a per-IP token bucket.
3. **Tarpits unverified abusive crawlers** that ignore `robots.txt` — serving
   them a cheap, non-destructive labyrinth of synthetic pages instead of your
   real content.

It is the defensive counterpart to our client-side tooling: where
[`impersonate-http`](https://github.com/North-web-dev/impersonate-http) and
[`ja4-guard`](https://github.com/North-web-dev/ja4-guard) deal in TLS
fingerprints, crawlgate is about *who gets to crawl you, and what the bad ones
get instead of your data.*

## Ethical stance (read this first)

This is **defense, not attack.** The design is deliberately conservative:

- **Verified good bots always pass.** A crawler that is forward-confirmed as
  real Googlebot/Bingbot/Applebot/YandexBot is sent straight to your upstream
  and is **never** rate-limited or tarpitted. We never trap real search
  engines — that is the whole point of verifying first.
- **`robots.txt` advertises the trap.** crawlgate serves (or merges) a
  `robots.txt` that `Disallow`s the trap path. Any crawler that obeys
  `robots.txt` never enters the labyrinth. Only bots that **ignore** the rules
  they were told about fall in. That is what makes this ethical rather than a
  blanket trap.
- **Fail-open for humans.** Ordinary, unknown traffic is passed through
  untouched by default. A real person is never tarpitted for browsing normally;
  the tarpit is reached only by spoofed crawlers, robots-ignoring bots, and
  automated clients that blow past the rate limit.
- **The tarpit is non-destructive.** It serves small, generated, fully-escaped
  HTML pages containing only synthetic nonsense text. It never fetches a URL,
  never executes anything, never impersonates a real site or person, and never
  emits attacker-controlled content. It wastes a scraper's budget; it does not
  attack it.

If you want to *block* rather than slow abusive bots, point the trap path at a
`404` upstream instead — crawlgate does not require the tarpit.

## How crawler verification works

A `User-Agent` string is trivially forged, so crawlgate never trusts it alone.
When a request *claims* to be a known crawler, crawlgate runs
**forward-confirmed reverse DNS**:

1. **PTR lookup** of the client IP → one or more hostnames.
2. **Suffix check**: the hostname must end in a suffix known to belong to that
   crawler, matched on a dot boundary (so `.googlebot.com` matches
   `crawl-1.googlebot.com` but not `evilgooglebot.com`).
3. **Forward confirm**: that hostname is resolved back to A/AAAA records, and
   the original client IP must appear among them.

Only if all three pass is the client marked **verified**. A raw PTR record is
attacker-influenceable (anyone can set reverse DNS for IPs they control), which
is exactly why step 3 is mandatory and why **rDNS is the authoritative check**
in crawlgate.

Published IP ranges (e.g. Google's `googlebot.json`) are supported via
`--ipranges` as a **fast-path / offline supplement**: an IP inside a trusted
range short-circuits to verified without a DNS round-trip. Ranges are optional
and never required; rDNS remains authoritative.

Default rules cover **Googlebot, Bingbot, Applebot, and YandexBot** — the major
crawlers that operate forward-confirmable reverse DNS. Crawlers that only
publish IP ranges (for example DuckDuckBot) should be supplied via
`--ipranges`.

## Classification

For a request that is **not** a verified crawler:

| Condition | Outcome |
|---|---|
| Claims a known crawler but fails rDNS (a spoofer) | **tarpit** |
| Hits a `--verified-only-paths` prefix | **403** |
| Hits the `--trap-path` prefix (robots-disallowed) | **tarpit** |
| Over the rate limit **and** looks automated (bot UA / non-browser JA4) | **tarpit** |
| Over the rate limit but looks human | **429** + `Retry-After` |
| Otherwise | **passed through** (fail-open) |

"Looks automated" is a User-Agent heuristic (`bot`, `crawl`, `spider`,
`python-requests`, `curl/`, `GPTBot`, …) plus, optionally, a non-browser JA4
signal. See [Honest limits](#honest-limits) — these heuristics are evadable and
only decide *429 vs. tarpit* for already-over-limit clients.

## Install

```
go install github.com/North-web-dev/crawlgate/cmd/crawlgate@latest
```

or grab a binary from [Releases](https://github.com/North-web-dev/crawlgate/releases),
or use the container (distroless, static, non-root):

```
docker build -t crawlgate .
docker run --rm -p 8080:8080 crawlgate --upstream http://your-upstream:9000
```

## Usage as a reverse proxy

```
crawlgate \
  --addr 127.0.0.1:8080 \
  --upstream http://127.0.0.1:9000 \
  --trap-path /trap/ \
  --rate 5 --burst 20 \
  --ipranges googlebot.json \
  --verified-only-paths /internal,/premium
```

crawlgate binds **loopback by default**. Binding a non-loopback address
requires the explicit `--allow-public` flag (and prints a warning), so you
never expose it by accident.

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--upstream` | (required) | Upstream base URL to proxy to. |
| `--addr` | `127.0.0.1:8080` | Listen address; non-loopback needs `--allow-public`. |
| `--trap-path` | `/trap/` | Robots-disallowed honeypot prefix. |
| `--rate` / `--burst` | `5` / `20` | Per-IP token bucket (req/s, capacity) for non-verified clients. |
| `--verified-only-paths` | — | Comma-separated prefixes only verified crawlers may hit (else `403`). |
| `--ipranges` | — | JSON file of trusted crawler IP ranges (see below). |
| `--ja4` | `false` | Use JA4 TLS fingerprinting as an extra bot signal (needs TLS). |
| `--max-trap-pages` | `50` | Max trap pages per IP per 10m window before the maze ends. |
| `--trap-byte-rate` | `0` | Throttle trap output to N bytes/second (0 = unthrottled). |
| `--seed` | `1` | Seed for deterministic trap content. |
| `--trust-forwarded` | `false` | Read client IP from `X-Forwarded-For` (trusted proxy only). |
| `--robots-file` | — | A `robots.txt` to merge; the trap `Disallow` is always ensured. |
| `--tls-cert` / `--tls-key` | — | Serve HTTPS (required for `--ja4`). |
| `--allow-public` | `false` | Permit binding a non-loopback address. |

### `--ipranges` file format

```json
{
  "Googlebot": ["66.249.64.0/19", "34.100.182.96/28"],
  "Bingbot":   ["157.55.39.0/24"]
}
```

Keys are crawler names (matching the default rules); values are CIDRs. Google
and Bing publish authoritative range files you can convert to this shape.

## Usage as middleware

```go
vf := verify.New(verify.Options{}) // forward-confirmed rDNS, default rules

gate, _ := crawlgate.New(crawlgate.Config{
    TrapPath: "/trap/",
    Rate:     5,
    Burst:    20,
    Verifier: vf,
})

mux := http.NewServeMux()
mux.Handle("/", myApp)
http.ListenAndServe(":8080", gate.Wrap(mux))
```

The sub-packages are usable on their own: `verify` (forward-confirmed rDNS),
`ratelimit` (bounded per-IP token bucket), and `tarpit` (deterministic
synthetic maze).

## Optional JA4 signal

With `--ja4` (and TLS enabled), crawlgate uses
[`ja4-guard`](https://github.com/North-web-dev/ja4-guard) to fingerprint the
inbound TLS ClientHello. It calls `guard.FromRequest(r)` to read the client's
JA4 and `guard.KnownBrowserPolicy()` to test it against ja4-guard's embedded
known-browser set; a fingerprint that is **not** a recognised browser is
treated as a bot signal feeding the classifier. It is **off by default** and is
only ever an additional signal — it never overrides crawler verification and
never hard-blocks on its own.

**Caveat (same as ja4-guard / impersonate-http):** JA4 is read by peeking the
ClientHello, which means crawlgate must **terminate TLS**. There is no L4
SNI-passthrough mode; if you need to forward encrypted bytes untouched, JA4 is
not available at this layer. HTTP/2 requests also carry no JA4H.

## Security notes

- The tarpit emits only locally-generated, HTML-escaped synthetic content. It
  is not an open proxy and performs no outbound fetches, so it cannot be abused
  for SSRF.
- Per-IP state (rate-limit buckets, rDNS cache, trap budgets) is bounded by TTL
  and an LRU cap, so a flood of distinct source IPs cannot exhaust memory.
- rDNS results are cached with a TTL (positive and negative) to bound lookup
  cost and resist repeated-lookup amplification.
- The client IP comes from `RemoteAddr` by default. `X-Forwarded-For` is read
  **only** with `--trust-forwarded`; enable it solely behind a proxy you
  control, since the header is otherwise spoofable.
- Logged paths have their query string stripped so credentials in query
  parameters are not written to logs.
- `ReadHeaderTimeout` is set on the server to mitigate slow-header attacks.

## Honest limits

crawlgate **raises the cost** of abusive crawling; it is not a wall.

- **UA and JA4 heuristics are evadable.** A scraper can send a browser-like
  User-Agent and (with enough effort) a browser-like TLS fingerprint. These
  signals only choose *429 vs. tarpit* for clients already over the rate limit;
  they are not used to block.
- **A determined scraper that rotates IPs still gets through.** Per-IP rate
  limiting and per-IP trap budgets are defeated by a large, rotating address
  pool. crawlgate makes that expensive; it does not make it impossible.
- **Verification depends on correct reverse DNS.** A legitimate crawler that
  does not operate forward-confirmable rDNS (and is not covered by an
  `--ipranges` entry) will not be marked verified. Supply its published ranges.
- **The tarpit's per-connection cap is approximated per-IP.** HTTP keep-alive
  makes a strict per-TCP-connection cap unreliable, so the page budget is
  enforced per-IP within a TTL window instead.
- **`--trust-forwarded` trusts the header.** Behind an untrusted network it can
  be spoofed to evade or misattribute rate limiting. Leave it off unless a
  trusted proxy sets it.

## Development

```
go build ./... && go vet ./... && gofmt -l . && go test ./... -race
```

## Support

If crawlgate is useful to you, a ⭐ on the repo is appreciated. Donations are
welcome but never expected:

| Coin | Address |
|---|---|
| **BTC** | `bc1q0sfghv7yfl594gjurhyhlhdgm0dtwh4dkjha36` |
| **ETH / USDT-ERC20 / BNB-BEP20** | `0xB827b5a8B6c5111946c5D872933b2C23484E87dE` |
| **SOL** | `3ch5aHrPp3CierhiNXmqmtFH2dMHh6Gfv7a97KtLMMCh` |
| **USDT-TRC20 / TRX** | `TUAyz7TjgJdFVD2oFHWUUTNrzzAnBRgySG` |
| **TON** | `UQAJmYVuR3hh02etjaPKJF-h6jcpdSnq9ZIFvI64NEskS6tx` |

## License

MIT — see [LICENSE](LICENSE).
