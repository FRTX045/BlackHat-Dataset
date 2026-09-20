# apache-shopfront — large — 2026-09-20

950,859 lines of Apache Combined access log, with a ground-truth
record for every one of them.

| | |
|---|---|
| Lines | 950,859 |
| Seed | `31` |
| Commit | `6c593016d5c54d9a5ba91b9f4d99d3218c03058e` |
| Built | 2026-09-20T14:10:53.348420+00:00 |
| Wall clock | 3575.024s |

## How this dataset was produced

### Server stack

Apache 2.4.68 (Debian) with PHP 8.3.33 under `mpm_prefork`, in Docker, built
from `php:8.3-apache`. Image actually used:
`logforge/apache-shopfront-web@sha256:0ecf4ac0a46c3b167ba276bf617e08eea0d54405e1afc6fe13c582a482761c12`.

Modules: `mod_remoteip`, `mod_php`, `mod_rewrite`, `mod_headers`,
`mod_deflate`, `mod_setenvif`. Two server-level `CustomLog` directives,
`combined` and `tagged`, both redefined to use `%b` rather than Debian's `%O`.
No host port published. `/.lab-health` excluded from both logs.

### The application

A PHP 8.3 + SQLite shopfront, 130 products across 10 categories, seeded from
`31`. Deliberately vulnerable in 8 documented places and
hardened in 5 others — see `projects/apache-shopfront/app/VULNERABILITIES.md`. Never
reachable beyond its three Docker networks.

### How the traffic was generated

Sessions from a non-homogeneous Poisson process with diurnal and weekly curves;
heavy-tailed session lengths; seven personas with coherent address-and-agent
identity. Asset cascades discovered by parsing each page, with a per-visit
browser cache that revalidates rather than refetches.

Measured for this run:

- **7,434 distinct clients**, top-10 share
  0.2022, busiest made
  67,171 requests
- **68 distinct user agents**, top-1 share
  0.2538
- Referer present on 54.65%
  of non-asset requests
- Inter-arrival coefficient of variation
  6.5583

**639 of these requests came from a real Chromium**, driven
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
3,460 seconds — the request *sequence* is
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
| Window | 2026-03-09T00:02:25.063937+00:00 → 2026-04-08T00:01:57.807904+00:00 |
| Span | 30.00 days |
| Days covered | 31 |
| Achieved rate | 0.3668 requests/second |
| Busiest second | 776 requests |
| Sessions | 32,031 (213 pushed later to keep one session per address at a time) |

### Which tools produced the attack traffic

| Tool | Version | Source IP | Requests | Exit | What it was pointed at |
|---|---|---|---|---|---|
| whatweb | `0.5.5-1` | 192.0.2.32 | 6 | 0 | the site root, fingerprinting |
| dirb | `2.22+dfsg-5` | 198.51.100.31 | 4,619 | 0 | / with dirb's common wordlist |
| gobuster | `3.5.0-1+b1` | 198.51.100.33 | 4,615 | 0 | / with dirb's common wordlist, at four threads |
| nmap | `7.93+dfsg1-1` | 198.51.100.32 | 10 | 0 | the proxy's HTTP port with http-* NSE scripts |
| sqlmap | `1.7.2-1` | 192.0.2.31 | 47 | 0 | the planted SQL injection on /search |

The **Requests** column is the count the tag proxy actually recorded from each tool's address, not a count of tools that were started. A tool that ran, exited cleanly and reached nothing would otherwise be indistinguishable here from one that worked; the build refuses to finish if any of them is zero.

Hand-written campaigns, each from its own address, each a phased story with
ordinary browsing interleaved:

| Campaign | Outcome |
|---|---|
| `api_abuser` | came away with nothing |
| `blind_injector` | came away with nothing |
| `credential_hunter` | came away with nothing |
| `cve_sweeper` | came away with nothing |
| `metadata_hunter` | came away with nothing |

0 of 5 campaigns found something;
5 did not. Attack traffic is
**4.29%** of all lines.

An attack alone in a quiet window is separable on timestamp without reading a
single request, so the campaigns and tool runs are issued *concurrently* with
the ordinary traffic. Two figures, because one is not enough:

| | |
|---|---|
| Attack lines sharing their exact second with ordinary traffic | 8.54% |
| Attack lines with ordinary traffic within ±30s | **61.70%** |

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
  `access.raw.log`: **950766/950859 lines agreed; Apache's own log has 950859 lines; first divergence at line 565**
- Unmatched request ids: **1838**
- Of those, labelled by reserved source address:
  **910**
- Lines that did not parse as Combined: **0**

### How to rebuild it

```bash
git checkout 6c593016d5c54d9a5ba91b9f4d99d3218c03058e
python3 tools/build.py apache-shopfront large
```

The tree was clean when this was built, so the commit above is the whole story.

The same seed reproduces the same request sequence. Timestamps and interleaving
differ between runs under real concurrency; this is not byte-identical output
and does not claim to be.

## Category shares

| Category | Share |
|---|---|
| `static_asset` | 71.09% |
| `crawling` | 10.51% |
| `browsing` | 8.49% |
| `api_call` | 4.76% |
| `enumeration` | 3.19% |
| `reconnaissance` | 1.09% |
| `authentication` | 0.76% |
| `unknown` | 0.10% |
| `injection` | 0.01% |
| `credential_attack` | 0.00% |
| `access_control` | 0.00% |
| `path_traversal` | 0.00% |
| `ssrf` | 0.00% |
| `exploitation` | 0.00% |

## Status distribution

| Status | Share |
|---|---|
| `200` | 75.52% |
| `301` | 0.00% |
| `302` | 0.42% |
| `304` | 19.71% |
| `400` | 0.10% |
| `401` | 0.07% |
| `403` | 0.14% |
| `404` | 4.04% |
| `429` | 0.00% |
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

- **Attack share is 4.29%.** The target is 2–8%.
- **Static assets are 71.09%
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
  3.47% of clients**, far below what the
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
