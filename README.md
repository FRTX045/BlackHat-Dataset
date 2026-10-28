# LogarX Dataset

A labelled web-server access log for forensic log-analysis research: one shop,
attacked and browsed, with a ground-truth label on every line.

- **One real application on a real server.** A deliberately vulnerable PHP 8.3
  shop, served by Apache 2.4 in Docker on an isolated network.
- **Scripted, people-shaped traffic.** Shoppers, admins, crawlers and a real
  Chromium driven at it, hand-written attack campaigns that read each response
  before deciding what to send next, and five real security tools: whatweb,
  dirb, gobuster, nmap and sqlmap.
- **The server's own log, and a label for every line of it.** Each line of
  `access.log` was written by Apache in answer to a request that was really
  made; `truth.jsonl` says, line for line, what each one was.
- **Three sizes:** a day, a week and a month of traffic.
- **The same traffic in 21 log formats.** Apache's own, and 20 more rendered
  from it — nginx, ingress-nginx, Traefik, Caddy, Cloudflare, Google Cloud,
  Elastic (ECS), IIS, CloudFront, HAProxy, Envoy, Istio and AWS ALB among them —
  each with its own truth file, and with every line that server would have
  written differently flagged.

It was built to measure [LogarX](https://github.com/FRTX045/LogarX), and reads
directly into it, but nothing here depends on LogarX.

## What is synthetic and what is not

The terms the rest of this page uses:

- the **traffic is scripted** — who visits, and what they are after, comes from
  a seeded plan;
- the **log lines are real server output** — no line is templated or written
  by a log generator;
- the **timestamps in `access.log` are rewritten** onto the arrival curves the
  plan was drawn from, because the harness issues the plan far faster than real
  visitors arrive. Every other byte of every line, and the order of requests
  within each session, is as Apache wrote it, and `access.raw.log` ships
  alongside with the timestamps Apache actually wrote.
- the **other 20 formats are rendered**, never captured: no nginx, IIS or CDN
  served this traffic. See [The same traffic in 21 formats](#the-same-traffic-in-21-formats).

## Layout

| Path | Holds |
|---|---|
| [`projects/apache-shopfront/`](projects/apache-shopfront/) | The shop, the server configuration, the traffic, the attacks and the scenarios |
| `datasets/apache-shopfront/<date>-<tier>/` | One folder per build |
| [`docs/methodology.md`](docs/methodology.md) | How the labels are made, what is manipulated, how to audit a build |
| [`docs/rendered-formats.md`](docs/rendered-formats.md) | The rules for every rendered format, with sources |
| `tools/` | `build.py`, `verify.py`, `audit.py`, `render.py`, `package.py` |

## Build it

One command brings the server up, drives the traffic, runs the attacks,
collects the logs, writes the truth file, verifies the result, writes the
manifest, and tears the server down.

```bash
python3 tools/build.py apache-shopfront small
python3 tools/verify.py datasets/apache-shopfront/<date>-small
```

Requirements: Docker, and Python 3.11+ for the entry points. The entry points
and everything under `shared/` are **standard-library only** — no virtualenv, no
pip install. Every third-party dependency lives inside a container image.

## Scale tiers

| Tier | Lines | `access.log` | Span of the log | Build time | Peak memory: remap / `verify.py` | Purpose |
|---|---|---|---|---|---|---|
| `small` | 63,310 | 14 MB | 1 day | 2.5 min | 134 MiB / 316 MiB | Fast iteration |
| `medium` | 235,732 | 53 MB | 7 days | 9.4 min | 464 MiB / 1,072 MiB | The main dataset |
| `large` | 941,031 | 214 MB | 30 days | 39.8 min | 1,816 MiB / 4,236 MiB | A month of history |

Every figure is measured on the 2026-10-06 builds: lines and build time are
`lines` and `wall_clock_seconds` from each build's `MANIFEST.json`, and the
size is that build's `access.log`. A rebuild lands near them, not on them.
Peak memory is not recorded by the build; it was measured afterwards on the
same builds for the two steps that hold a whole log at once — the timestamp
remap, about 2 KB per line, and `tools/verify.py`, about 4.6 KB per line — so
verifying the large tier wants a machine with 5 GB or more free. There is no
streaming version of the remap's global sort, and claiming one would be worse
than the cost.

Larger tiers are not the small one repeated. A month contains things a day
cannot show: a crawler that appears partway through and stays, an attacker who
returns eleven days after their first visit, four weekends rather than none,
and enough volume that a per-client baseline built in week one can be tested
against week four.

The **span of the log is not the duration of the build**. The driver issues its
whole plan as fast as the sockets allow, so a run that takes eight minutes
produces requests in the right *order* and at an impossible *rate*. Timestamps
are therefore rewritten onto the same arrival curves the traffic was planned
against — and the log the server actually wrote ships alongside as
`access.raw.log`, so nothing is taken on trust.
[docs/methodology.md](docs/methodology.md) says exactly what is done and what
it costs.

## What ships

Committed to the repository:

- all source, scenario configs and seeds
- for each build, under `datasets/apache-shopfront/<date>-<tier>/`:
  - `MANIFEST.json` — seed, commit, tool versions, every attack command line
    with its source IP and time window, wall-clock duration, final line count
  - `README.md` — what that build is, and its known limitations
  - `sample.log` — 5,000 lines, for eyeballing
  - `sample.truth.jsonl` — its matching truth records

Written by every build into that same folder, and too large to commit. For
the 2026-10-06 builds they are **published as GitHub releases**, one per build —
[small](https://github.com/FRTX045/LogarX-Dataset/releases/tag/2026-10-06-small),
[medium](https://github.com/FRTX045/LogarX-Dataset/releases/tag/2026-10-06-medium),
[large](https://github.com/FRTX045/LogarX-Dataset/releases/tag/2026-10-06-large)
— `xz`-compressed by `tools/package.py`, with a `SHA256SUMS`. For any other
build, regenerate them:

- the full `access.log` and `truth.jsonl`
- `access.raw.log` and `truth.raw.jsonl` — the log the server actually wrote,
  before timestamps were rewritten, and its truth file
- `access.apache.log` — Apache's own independently written Combined log, so
  the derived-vs-Apache comparison can be repeated
- `access.tagged.log` and `error.log`

`SHA256SUMS` covers **the uncompressed contents as well as the archives**, and
the committed files too. A checksum over an archive proves the download
arrived; a checksum over the contents proves the dataset is the one the
manifest describes, and it survives recompression.

```bash
python3 tools/package.py datasets/apache-shopfront/<date>-<tier>   # to make the assets
for f in *.xz; do xz -dk "$f"; done                                # after a download
sha256sum -c SHA256SUMS --ignore-missing
```

xz rather than zstd: `lzma` is in the standard library, so packaging needs
nothing installed, which is the same rule every host entry point here follows.

### What regenerating gives you

For a build with no release, regenerating is the only way to get the full
logs, so it matters what it reproduces.

- **Check out the commit the manifest names.** The 2026-10-06 builds name
  `d2ef291`. Later commits change the traffic: `24c1f1e` changed which page an
  attacker's `Referer` names, so a build from `main` no longer makes the request
  shipped as line 162,137 of `2026-10-06-medium` — a page view whose `Referer`
  is `http://shop.test/api/cart?id=1`.
- **At that commit, the same seed gives the same plan, not the same bytes.**
  The requests are issued concurrently against a live server, so which lines
  land next to which, the captured timestamps, and what the reactive attack
  campaigns and tools go on to send all depend on how that run went. Within a
  single run Apache's two logs already disagree on order — 6 of 63,310 lines in
  `2026-10-06-small`. `truth.jsonl` is written line for line from the log, so
  it differs in the same places. A rebuild is the same experiment run again,
  not a copy; [docs/methodology.md](docs/methodology.md#on-reproducibility)
  says why byte-identical output is not claimed.
- **The images are named by tag, not by digest** — `php:8.3-apache`,
  `python:3.12-slim`, `debian:bookworm-slim` — so a later rebuild can pull a
  newer Apache or PHP than the shipped build ran, and the server's banner and
  responses can change with it. `base_image_digest` in `MANIFEST.json`
  identifies the web image a build used; it is built locally and cannot be
  pulled.
- **The shipped bytes themselves** are the releases. To check a figure measured
  on a 2026-10-06 build, download that build's release rather than rebuilding:
  a rebuild lands near those bytes, the release is them.

## The same traffic in 21 formats

A detector that reads many log formats can misread one in a way no single test
line shows. So a build's capture can be written into 20 other formats, the
same requests in the same order in each:

```bash
python3 tools/render.py datasets/apache-shopfront/2026-10-06-medium
```

That writes `rendered/` inside the build: a `<format>.log` and its
`<format>.truth.jsonl` for each format, a `MANIFEST.json` and a `SHA256SUMS`.
Like the full logs, they are regenerated rather than committed.

| Family | Formats |
|---|---|
| Apache | `apache-common`, `apache-vhost-common`, `apache-vhost-combined`, `apache-combined-io` |
| nginx | `nginx-main`, `nginx-combined-forwarded`, `ingress-nginx`, `nginx-json` |
| Traefik, Caddy | `traefik-common`, `traefik-json`, `caddy-json` |
| Cloud and CDN | `cloudflare-json`, `gcp-http-json`, `ecs-http`, `cloudfront` |
| Windows | `iis-w3c` |
| Proxies | `haproxy`, `envoy`, `istio`, `aws-alb` |

**Every one of these files is rendered from the Apache capture, never
captured.** Apache and PHP answered every request; each file writes what they
logged in another server's columns, so that one detector can be run on the
same traffic in every format and the results compared. Rendered this way:

- **Each field is written the way that server writes it** — its layout, its
  escaping, its time format — checked against the vendor's documentation or
  source, cited per format in [docs/rendered-formats.md](docs/rendered-formats.md).
- **What the capture never measured is a declared constant**: durations,
  client ports, the Host header, a proxy's own fields. Byte counts that include
  headers carry the body size, and the manifest names each as a lower bound.
- **Records are one to one** with `access.log`. Formats that start with header
  lines (IIS +4, CloudFront +2) have their truth's `line_no` moved past them.
- **Lines a real server would have written differently are flagged** by line
  number in `rendered/MANIFEST.json`: the noise client's malformed request
  lines, which each server refuses its own way, and Apache's own dummy
  connections, which only Apache writes.
- **The renderer refuses** unless re-running the timestamp remap reproduces the
  shipped `access.log` exactly, so a sub-second time or a request id can never
  land on the wrong line.

LogarX's own results on these files, for the 2026-10-06 small and medium
builds, are in its
[evaluation](https://github.com/FRTX045/LogarX/blob/main/docs/evaluation.md),
"The same traffic in every log format — 2026-10-27".

## The ground truth file

JSON Lines. One header line, then exactly one record per log line, in order.

```json
{"kind":"logarc-truth","version":1,"scenario":"apache-shopfront-small","seed":7,"source_file_id":"access.log","granularity":"category","generated_at":"2026-08-16T09:00:00+00:00"}
{"line_no":1,"client_ip":"203.0.113.5","category":"browsing","instance_id":"203.0.113.5#17"}
{"line_no":2,"client_ip":"198.51.100.9","category":"enumeration","instance_id":"198.51.100.9#2"}
```

`"kind":"logarc-truth"` is the format
[LogarX](https://github.com/FRTX045/LogarX)'s `evaluate` command reads; the
name is from before LogarX was renamed, and LogarX 1.0 reads it as well as
`logarx-truth`. It is kept so that every build here, old and new, has the same
header. LogarX's published scores — its README's
[How well does it work](https://github.com/FRTX045/LogarX#how-well-does-it-work)
— were measured on `2026-10-06-medium`.

- `line_no` — 1-based, contiguous, matching `access.log` exactly
- `client_ip` — equals the address on that log line
- `category` — one of the fourteen strings below, and nothing else
- `instance_id` — **consecutive lines sharing one id are one episode.** This is
  what lets a consumer ask not just "was each request classified correctly" but
  "were the boundaries between activities found in the right places"

The header carries no total: a count derived on read cannot contradict the
records it describes.

### Controlled vocabulary

| Category | Means |
|---|---|
| `browsing` | Ordinary navigation of HTML pages by a person |
| `static_asset` | CSS, JS, images, fonts, favicon |
| `api_call` | XHR/JSON endpoints called by the front-end |
| `authentication` | Legitimate login, logout, registration, password reset |
| `crawling` | Well-behaved bots — search engines, feed readers, uptime monitors |
| `reconnaissance` | Probing for what exists: `robots.txt`, `.git/config`, `.env`, version fingerprinting |
| `enumeration` | Systematic directory or file brute-forcing |
| `injection` | SQLi, command injection, SSTI, XSS payloads |
| `path_traversal` | `../` sequences, LFI, absolute path access |
| `access_control` | IDOR, forced browsing to admin areas, verb tampering |
| `credential_attack` | Brute force, credential stuffing, password spraying |
| `ssrf` | Making the server fetch an attacker-chosen URL |
| `exploitation` | Known-CVE attempts, webshell upload and use, RCE, post-compromise activity |
| `unknown` | Genuinely unclassifiable. Used sparingly, and explained in the dataset README |

## How the labels are guaranteed correct

The hard problem in this work is knowing which log line came from which client
intent. Matching on IP, timestamp and path breaks the moment two sessions
overlap, and a truth file that is subtly wrong is worse than none at all.

It is solved at the source. Every request carries a unique `X-Request-Id`, and
Apache writes a second log that includes it. The shipped `access.log` is that
tagged log with the id prefix removed — so line N of the log and line N of the
truth file are the same request **by construction**, at any amount of
concurrency. Attack tools, which will not send a header for us, are proxied
through a component that stamps one, so their lines get the same exactness
rather than being labelled by a time window.

The verifier reports the agreement between that derived log and the ordinary
Combined log Apache wrote independently, as a number, on every build.

Full detail: [docs/methodology.md](docs/methodology.md).

## Verification

`tools/verify.py` fails loudly. No build is reported as finished until it
passes and its output has been read.

It checks that truth records equal log lines exactly, that every `client_ip`
matches its line, that every category is in the vocabulary, that `instance_id`
groups are contiguous per client, and that every line parses as Apache
Combined. That is the shape of the line, not of the request inside it: Apache
logs whatever request line arrived, and the noise client sends deliberately
malformed ones — `"GARBAGE"`, `"GET /.env x"`, a bare `"GET /backup.zip"`;
94, 294 and 910 lines in the three 2026-10-06 tiers, answered `400` or `404`.
Those lines parse, with method, path or protocol left empty where the request
line has none. It then prints the realism statistics — status distribution,
inter-arrival shape, requests per session, user-agent cardinality, `Referer`
share, the share of `304`/`206`/`HEAD`/`OPTIONS`, attack share per category,
and client IP concentration — as numbers to actually look at.

Every build's README ends with a **Known limitations** section naming what is
still unrealistic about it. Scripted traffic always leaves some.

### The fake-log audit

`tools/audit.py` asks the only question that decides whether research done on
a generated log transfers to a real one: could an analyst tell?

```bash
python3 tools/audit.py datasets/apache-shopfront/2026-10-06-small -v
python3 tools/audit.py datasets/apache-shopfront/2026-10-06-small --compare access.raw.log
python3 tools/audit.py /var/log/apache2/access.log      # or anybody else's
```

The first two need that build's full logs, which are in its release, not in
the repository.

Nine tells — toy-sized responses, round-number response sizes, an implausible
request rate, user-agent monoculture, uniform client volumes, missing status
classes, an absence of malformed requests, perfectly ordered timestamps, and
client addresses counted out of a subnet. Each publishes the threshold it used,
and too little data is reported as *inconclusive* rather than as a pass.

It is pointed at this dataset first and hardest, **and it does find things.**
Whatever fires on a build is written into that build's README and its
manifest. The point of owning the detector is that the findings are ours to
publish rather than somebody else's to discover.

## Safety

The shop is **deliberately vulnerable**, and every planted weakness is
documented in
[`projects/apache-shopfront/app/VULNERABILITIES.md`](projects/apache-shopfront/app/VULNERABILITIES.md).
It exists to be attacked by the build process and by nothing else.

- It binds to an isolated Docker network and publishes no host port.
- Every attack targets the lab's own application on that network. No external
  host is ever a target.
- No real credentials, no real personal data, no third-party services.
- Client addresses are drawn only from the documentation and shared-address
  ranges `203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24` and
  `100.64.0.0/10`. No address here belongs to an identifiable person or company.

Do not deploy this application anywhere reachable.
