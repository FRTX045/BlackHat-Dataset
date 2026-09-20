# apache-shopfront — medium — 2026-09-18

236,505 lines of Apache Combined access log, with a ground-truth
record for every one of them.

| | |
|---|---|
| Lines | 236,505 |
| Seed | `19` |
| Commit | `c46476d82521e2e53b1d00b1a3735bda2039f10b` |
| Built | 2026-09-18T08:11:07.878328+00:00 |
| Wall clock | 851.609s |

## How this dataset was produced

### Server stack

Apache 2.4.68 (Debian) with PHP 8.3.33 under `mpm_prefork`, in Docker, built
from `php:8.3-apache`. Image actually used:
`logforge/apache-shopfront-web@sha256:886cf18a681a85c9610e45b6709eea98683650a88326f5e22abf2a529365188a`.

Modules: `mod_remoteip`, `mod_php`, `mod_rewrite`, `mod_headers`,
`mod_deflate`, `mod_setenvif`. Two server-level `CustomLog` directives,
`combined` and `tagged`, both redefined to use `%b` rather than Debian's `%O`.
No host port published. `/.lab-health` excluded from both logs.

### The application

A PHP 8.3 + SQLite shopfront, 130 products across 10 categories, seeded from
`19`. Deliberately vulnerable in 8 documented places and
hardened in 5 others — see `projects/apache-shopfront/app/VULNERABILITIES.md`. Never
reachable beyond its three Docker networks.

### How the traffic was generated

Sessions from a non-homogeneous Poisson process with diurnal and weekly curves;
heavy-tailed session lengths; seven personas with coherent address-and-agent
identity. Asset cascades discovered by parsing each page, with a per-visit
browser cache that revalidates rather than refetches.

Measured for this run:

- **2,785 distinct clients**, top-10 share
  0.223, busiest made
  15,428 requests
- **68 distinct user agents**, top-1 share
  0.232
- Referer present on 49.37%
  of non-asset requests
- Inter-arrival coefficient of variation
  6.1334

**569 of these requests came from a real Chromium**, driven
by Playwright across 5 personas
(`desktop-laptop`, `desktop-returning`, `desktop-wide`, `mobile-android`, `tablet`). That traffic is not
built by the driver at all: the browser was handed a URL and the log records
what Chromium chose to ask for.

It is a small share of the log and worth more than its size. A browser asks
for a page's subresources in an order no hand-rolled driver reproduces — the
preload scanner runs first, fonts wait for the CSS that references them to
parse, XHR interleaves with lazily-loaded images across six connections. It
also *declines* to make requests, because a second page view asks for nothing
already in its cache, and absence is as much a part of a real log as presence.
The conditional requests in this traffic come from Chromium's own cache
deciding to revalidate rather than from a coin flip.

No request interception was used. Playwright can rewrite headers per request,
which would have let the browser mint its own request ids, but it disables the
HTTP cache — and the cache is most of why running a browser is worth anything.
The tag proxy mints the ids instead, exactly as it does for the security
tools, so this traffic is labelled per request. One consequence: a browser
`instance_id` is a run of one activity rather than a whole session, which is
what `instance_id` already means for every proxy-labelled source here.

#### When it says it happened

**The timestamps in `access.log` were rewritten, and `access.raw.log` is
the log Apache actually wrote.** The driver issues its whole plan as fast as
the sockets allow, so the capture covers
792 seconds — the request *sequence* is
meaningful and the timing is not.

The rewrite moves each session's start onto the same diurnal and weekly curves
the driver plans against, and reconstructs the spacing inside a session from
what each request was: a subresource follows its page in milliseconds, a
person reads for a few seconds before clicking, an operator waits longer
because they are reading what came back. Every other byte of every line, and
the order of requests within a session, is as captured.

That last part is inference, not measurement. The capture's sub-second
structure is gone, so the labels are the only signal left to rebuild pacing
from. If you need the unrewritten article, it is `access.raw.log` with
`truth.raw.jsonl` beside it.

| | |
|---|---|
| Window | 2026-03-09T00:02:20.580286+00:00 → 2026-03-16T00:07:00.828969+00:00 |
| Span | 7.00 days |
| Days covered | 8 |
| Achieved rate | 0.3909 requests/second |
| Busiest second | 971 requests |
| Sessions | 8,230 (52 pushed later to keep one session per address at a time) |

### Which tools produced the attack traffic

| Tool | Version | Source IP | Requests | Exit | What it was pointed at |
|---|---|---|---|---|---|
| whatweb | `0.5.5-1` | 192.0.2.32 | 6 | 0 | the site root, fingerprinting |
| dirb | `2.22+dfsg-5` | 198.51.100.31 | 4,619 | 0 | / with dirb's common wordlist |
| gobuster | `3.5.0-1+b1` | 198.51.100.33 | 4,615 | 0 | / with dirb's common wordlist, at four threads |
| nmap | `7.93+dfsg1-1` | 198.51.100.32 | 10 | 0 | the proxy's HTTP port with http-* NSE scripts |
| sqlmap | `1.7.2-1` | 192.0.2.31 | 45 | 0 | the planted SQL injection on /search |

The **Requests** column is the count the tag proxy actually recorded from each tool's address, not a count of tools that were started. A tool that ran, exited cleanly and reached nothing would otherwise be indistinguishable here from one that worked; the build refuses to finish if any of them is zero.

Hand-written campaigns, each from its own address, each a phased story with
ordinary browsing interleaved:

| Campaign | Outcome |
|---|---|
| `blind_injector` | came away with nothing |
| `cms_bot` | came away with nothing |
| `credential_hunter` | came away with nothing |
| `fruitless_prober` | came away with nothing |
| `metadata_hunter` | came away with nothing |
| `webshell_operator` | came away with nothing |

0 of 6 campaigns found something;
6 did not. Attack traffic is
**7.25%** of all lines.

An attack alone in a quiet window is separable on timestamp without reading a
single request, so the campaigns and tool runs are issued *concurrently* with
the ordinary traffic. Two figures, because one is not enough:

| | |
|---|---|
| Attack lines sharing their exact second with ordinary traffic | 13.43% |
| Attack lines with ordinary traffic within ±30s | **79.93%** |

The first falls with the request rate for reasons that have nothing to do with
how well the attack is hidden — a log at one request a second has almost no
second holding two of anything. The second is the one that answers whether a
timestamp filter would separate the attack out, and it does not move with the
rate.

### How the labels were produced

Every request carries a unique `X-Request-Id`; the derived log is the tagged
log with that prefix removed, so line N of the log and line N of its truth
file are the same request by construction.

- Derived vs the log Apache wrote independently, on
  `access.raw.log`: **236486/236505 lines agreed; Apache's own log has 236505 lines; first divergence at line 2156**
- Unmatched request ids: **511**
- Of those, labelled by reserved source address:
  **294**
- Lines that did not parse as Combined: **0**

### How to rebuild it

```bash
git checkout c46476d82521e2e53b1d00b1a3735bda2039f10b
python3 tools/build.py apache-shopfront medium
```

The tree was clean when this was built, so the commit above is the whole story.

The same seed reproduces the same request sequence. Timestamps and interleaving
differ between runs under real concurrency; this is not byte-identical output
and does not claim to be.

## Category shares

| Category | Share |
|---|---|
| `static_asset` | 68.62% |
| `crawling` | 10.53% |
| `browsing` | 8.22% |
| `enumeration` | 6.06% |
| `api_call` | 4.54% |
| `reconnaissance` | 1.13% |
| `authentication` | 0.75% |
| `unknown` | 0.09% |
| `injection` | 0.02% |
| `credential_attack` | 0.02% |
| `access_control` | 0.01% |
| `exploitation` | 0.00% |
| `path_traversal` | 0.00% |
| `ssrf` | 0.00% |

## Status distribution

| Status | Share |
|---|---|
| `200` | 73.36% |
| `301` | 0.01% |
| `302` | 0.55% |
| `304` | 18.79% |
| `400` | 0.13% |
| `401` | 0.08% |
| `403` | 0.13% |
| `404` | 6.90% |
| `415` | 0.00% |
| `429` | 0.05% |
| `500` | 0.00% |
| `504` | 0.00% |

## Does it look generated?

`tools/audit.py` runs 9 tells for whether a log looks generated. On this dataset **1 of them fires**.

- **`perfectly_ordered_timestamps`** — measured `0` against a threshold of `1`. Count of lines whose timestamp precedes the line above them. A concurrent server always produces a few; none at all means a single writer, or that the file was sorted.

The detector lives in this repository and is pointed at our own datasets
first. Findings above are the ones it makes about *this* file — published
here rather than left for a reader to discover, which is the only reason
owning the detector is worth anything.

```bash
python3 tools/audit.py <this directory> -v
python3 tools/audit.py <this directory> --compare access.raw.log
```

## Known limitations

Written as they are, not as one would like them.

- **Attack share is 7.25%.** The target is 2–8%.
- **Static assets are 68.62%
  of all lines.** High, though an image-heavy shop genuinely looks like this.
- **XSS is barely visible in an access log.** The reflected payload appears in
  `%r`; retrieval of a stored payload is indistinguishable from ordinary
  browsing. Labelled by what the request was, never by what the response
  contained.
- **A successful IDOR looks exactly like a legitimate order view** — same
  status, same size, same URL shape. Only the sequence reveals it.
- **Client addresses are documentation and CGNAT ranges.** Geographic and ASN
  analysis is meaningless on this data.
- **The clock is reconstructed, not captured.** Session starts follow the arrival model rather than anything that was observed, and within-session spacing is inferred from each request's label. Use `access.raw.log` if you need what the server recorded.
- **Single-request clients are
  4.34% of clients**, far below what the
  address pool draws. In a log carrying asset cascades a one-page visitor still
  makes twenty requests; the pool's draw distribution and the log's per-client
  distribution are different things.
- **No TLS**, so no `:443` and no protocol-downgrade behaviour.
- **Combined format carries no response time**, so latency analysis is
  impossible.
- **Webfonts are not real fonts** — a valid `wOF2` signature and deterministic
  padding. The requests and byte counts are genuine; the glyphs are not.
- **The stylesheets and scripts are generated, not authored.** They are real
  CSS and JavaScript — the output parses, the selectors are real, the browser
  personas apply and execute it — and they are sized against what a production
  origin serves, but a person did not write them. The byte counts Apache
  recorded are genuine either way.
- **The product catalogue is one shop.** 130 products across 10 departments,
  so the URL space is smaller than a real retailer's. Tracking parameters and
  on-site search give it a long tail, but the set of *pages* is finite in a way
  a real catalogue is not.
- **Apache's internal dummy connections are kept**, labelled `unknown`, from
  `127.0.0.1`. Every real Apache log has them.
