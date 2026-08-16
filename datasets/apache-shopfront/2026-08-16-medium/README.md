# apache-shopfront — medium — 2026-08-16

249,590 lines of Apache Combined access log, with a ground-truth
record for every one of them.

| | |
|---|---|
| Lines | 249,590 |
| Seed | `19` |
| Commit | `f2025bc974ad267672552a79c6bf09995ec8abb9` |
| Built | 2026-08-16T18:41:24.852932+00:00 |
| Wall clock | 724.87s |

## How this dataset was produced

### Server stack

Apache 2.4.68 (Debian) with PHP 8.3.33 under `mpm_prefork`, in Docker, built
from `php:8.3-apache`. Image actually used:
`logforge/apache-shopfront-web@sha256:c484783cc09a14cf9ded4eb703d0e7f0743468948da9b873e18a9e4e0ec5ee8a`.

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

- **2,393 distinct clients**, top-10 share
  0.2306, busiest made
  17,009 requests
- **54 distinct user agents**, top-1 share
  0.2025
- Referer present on 62.85%
  of non-asset requests
- Inter-arrival coefficient of variation
  10.5907

No headless-browser traffic: Playwright was not built. The cascades are real
requests for real subresources, ordered by the driver rather than by Chromium.

#### When it says it happened

**The timestamps in `access.log` were rewritten, and `access.raw.log` is
the log Apache actually wrote.** The driver issues its whole plan as fast as
the sockets allow, so the capture covers
692 seconds — the request *sequence* is
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
| Window | 2026-03-09T00:02:20.580286+00:00 → 2026-03-15T23:57:16.259660+00:00 |
| Span | 7.00 days |
| Days covered | 7 |
| Achieved rate | 0.4129 requests/second |
| Busiest second | 20 requests |
| Sessions | 7,219 (54 pushed later to keep one session per address at a time) |

### Which tools produced the attack traffic

| Tool | Version | Source IP | Requests | Exit | What it was pointed at |
|---|---|---|---|---|---|
| whatweb | `0.5.5-1` | 192.0.2.32 | 6 | 0 | the site root, fingerprinting |
| dirb | `2.22+dfsg-5` | 198.51.100.31 | 4,619 | 0 | / with dirb's common wordlist |
| gobuster | `3.5.0-1+b1` | 198.51.100.33 | 4,615 | 0 | / with dirb's common wordlist, at four threads |
| nmap | `7.93+dfsg1-1` | 198.51.100.32 | 8 | 0 | the proxy's HTTP port with http-* NSE scripts |
| sqlmap | `1.7.2-1` | 192.0.2.31 | 51 | 0 | the planted SQL injection on /search |

The **Requests** column is the count the tag proxy actually recorded from each tool's address, not a count of tools that were started. A tool that ran, exited cleanly and reached nothing would otherwise be indistinguishable here from one that worked; the build refuses to finish if any of them is zero.

Hand-written campaigns, each from its own address, each a phased story with
ordinary browsing interleaved:

| Campaign | Outcome |
|---|---|
| `patient_operator` | found something |
| `webshell_operator` | found something |
| `blind_injector` | found something |
| `metadata_hunter` | found something |
| `credential_hunter` | came away with nothing |
| `fruitless_prober` | came away with nothing |

4 of 6 campaigns found something;
2 did not. Attack traffic is
**3.12%** of all lines.

An attack alone in a quiet window is separable on timestamp without reading a
single request, so the campaigns and tool runs are issued *concurrently* with
the ordinary traffic. Two figures, because one is not enough:

| | |
|---|---|
| Attack lines sharing their exact second with ordinary traffic | 14.67% |
| Attack lines with ordinary traffic within ±30s | **75.11%** |

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
  `access.raw.log`: **249566/249590 lines agreed; Apache's own log has 249590 lines; first divergence at line 3556**
- Unmatched request ids: **484**
- Of those, labelled by reserved source address:
  **294**
- Lines that did not parse as Combined: **0**

### How to rebuild it

```bash
git checkout f2025bc974ad267672552a79c6bf09995ec8abb9
python3 tools/build.py apache-shopfront medium
```

The same seed reproduces the same request sequence. Timestamps and interleaving
differ between runs under real concurrency; this is not byte-identical output
and does not claim to be.

## Category shares

| Category | Share |
|---|---|
| `static_asset` | 76.10% |
| `browsing` | 12.32% |
| `api_call` | 4.67% |
| `crawling` | 3.37% |
| `enumeration` | 2.03% |
| `reconnaissance` | 1.01% |
| `authentication` | 0.35% |
| `unknown` | 0.08% |
| `access_control` | 0.05% |
| `injection` | 0.01% |
| `credential_attack` | 0.01% |
| `exploitation` | 0.00% |
| `path_traversal` | 0.00% |
| `ssrf` | 0.00% |

## Status distribution

| Status | Share |
|---|---|
| `200` | 73.16% |
| `301` | 0.01% |
| `302` | 0.32% |
| `304` | 19.75% |
| `400` | 0.13% |
| `401` | 0.00% |
| `403` | 0.13% |
| `404` | 6.46% |
| `429` | 0.04% |
| `500` | 0.01% |
| `504` | 0.00% |

## Does it look generated?

`tools/audit.py` runs 8 tells for whether a log looks generated. On this dataset **1 of them fires**.

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

- **Attack share is 3.12%.** The target is 2–8%.
- **Static assets are 76.10%
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
  1.76% of clients**, far below what the
  address pool draws. In a log carrying asset cascades a one-page visitor still
  makes twenty requests; the pool's draw distribution and the log's per-client
  distribution are different things.
- **No TLS**, so no `:443` and no protocol-downgrade behaviour.
- **Combined format carries no response time**, so latency analysis is
  impossible.
- **Webfonts are not real fonts** — a valid `wOF2` signature and deterministic
  padding. The requests and byte counts are genuine; the glyphs are not.
- **Apache's internal dummy connections are kept**, labelled `unknown`, from
  `127.0.0.1`. Every real Apache log has them.
