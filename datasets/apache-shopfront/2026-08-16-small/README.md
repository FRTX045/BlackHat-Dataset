# apache-shopfront — small — 2026-08-16

75,474 lines of Apache Combined access log, with a ground-truth
record for every one of them.

| | |
|---|---|
| Lines | 75,474 |
| Seed | `7` |
| Commit | `cf823b3b6431a0a25aeb633c015f1df06cfa97c3` |
| Built | 2026-08-16T19:19:32.750992+00:00 |
| Wall clock | 214.928s |

## How this dataset was produced

### Server stack

Apache 2.4.68 (Debian) with PHP 8.3.33 under `mpm_prefork`, in Docker, built
from `php:8.3-apache`. Image actually used:
`logforge/apache-shopfront-web@sha256:4bf3789dd55f2160ce8e5565f4ea45e8a125fbaf9b19c79dffc60257bd413689`.

Modules: `mod_remoteip`, `mod_php`, `mod_rewrite`, `mod_headers`,
`mod_deflate`, `mod_setenvif`. Two server-level `CustomLog` directives,
`combined` and `tagged`, both redefined to use `%b` rather than Debian's `%O`.
No host port published. `/.lab-health` excluded from both logs.

### The application

A PHP 8.3 + SQLite shopfront, 130 products across 10 categories, seeded from
`7`. Deliberately vulnerable in 8 documented places and
hardened in 5 others — see `projects/apache-shopfront/app/VULNERABILITIES.md`. Never
reachable beyond its three Docker networks.

### How the traffic was generated

Sessions from a non-homogeneous Poisson process with diurnal and weekly curves;
heavy-tailed session lengths; seven personas with coherent address-and-agent
identity. Asset cascades discovered by parsing each page, with a per-visit
browser cache that revalidates rather than refetches.

Measured for this run:

- **911 distinct clients**, top-10 share
  0.2543, busiest made
  5,984 requests
- **53 distinct user agents**, top-1 share
  0.2338
- Referer present on 64.66%
  of non-asset requests
- Inter-arrival coefficient of variation
  9.6312

No headless-browser traffic: Playwright was not built. The cascades are real
requests for real subresources, ordered by the driver rather than by Chromium.

#### When it says it happened

**The timestamps in `access.log` were rewritten, and `access.raw.log` is
the log Apache actually wrote.** The driver issues its whole plan as fast as
the sockets allow, so the capture covers
202 seconds — the request *sequence* is
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
| Window | 2026-03-09T00:00:48.713548+00:00 → 2026-03-09T23:55:56.602090+00:00 |
| Span | 1.00 days |
| Days covered | 1 |
| Achieved rate | 0.8765 requests/second |
| Busiest second | 24 requests |
| Sessions | 2,301 (33 pushed later to keep one session per address at a time) |

### Which tools produced the attack traffic

| Tool | Version | Source IP | Requests | Exit | What it was pointed at |
|---|---|---|---|---|---|
| whatweb | `0.5.5-1` | 192.0.2.32 | 6 | 0 | the site root, fingerprinting |
| dirb | `2.22+dfsg-5` | 198.51.100.35 | 961 | 0 | / with dirb's small wordlist |
| gobuster | `3.5.0-1+b1` | 198.51.100.34 | 961 | 0 | / with dirb's small wordlist, at four threads |
| nmap | `7.93+dfsg1-1` | 198.51.100.32 | 10 | 0 | the proxy's HTTP port with http-* NSE scripts |
| sqlmap | `1.7.2-1` | 192.0.2.31 | 47 | 0 | the planted SQL injection on /search |

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
**5.68%** of all lines.

An attack alone in a quiet window is separable on timestamp without reading a
single request, so the campaigns and tool runs are issued *concurrently* with
the ordinary traffic. Two figures, because one is not enough:

| | |
|---|---|
| Attack lines sharing their exact second with ordinary traffic | 27.71% |
| Attack lines with ordinary traffic within ±30s | **94.40%** |

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
  `access.raw.log`: **75474/75474 lines agreed, in order**
- Unmatched request ids: **144**
- Of those, labelled by reserved source address:
  **94**
- Lines that did not parse as Combined: **0**

### How to rebuild it

```bash
git checkout cf823b3b6431a0a25aeb633c015f1df06cfa97c3
python3 tools/build.py apache-shopfront small
```

The same seed reproduces the same request sequence. Timestamps and interleaving
differ between runs under real concurrency; this is not byte-identical output
and does not claim to be.

## Category shares

| Category | Share |
|---|---|
| `static_asset` | 76.79% |
| `browsing` | 8.72% |
| `api_call` | 4.64% |
| `enumeration` | 4.48% |
| `crawling` | 3.73% |
| `reconnaissance` | 1.03% |
| `authentication` | 0.37% |
| `injection` | 0.09% |
| `unknown` | 0.07% |
| `access_control` | 0.04% |
| `credential_attack` | 0.03% |
| `exploitation` | 0.01% |
| `path_traversal` | 0.01% |
| `ssrf` | 0.01% |

## Status distribution

| Status | Share |
|---|---|
| `200` | 74.69% |
| `301` | 0.02% |
| `302` | 0.39% |
| `304` | 19.40% |
| `400` | 0.12% |
| `401` | 0.01% |
| `403` | 0.12% |
| `404` | 5.19% |
| `429` | 0.05% |
| `500` | 0.00% |
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

- **Attack share is 5.68%.** The target is 2–8%.
- **Static assets are 76.79%
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
  2.52% of clients**, far below what the
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
