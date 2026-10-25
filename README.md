# BlackHat-Dataset

Labelled web-server log datasets for forensic log-analysis research.

Every line in every log here was written by a real server, in response to a
request that was genuinely made. No line is templated or emitted by a log
generator. A real web application is stood up, a real Apache serves it,
scripted people-shaped traffic and real security tools are driven at it, and the
log the server wrote is the log that ships — alongside a ground truth file that
says what every single line actually was.

That last part is the point. A dataset nobody can score against is a dataset
nobody can measure with.

What is synthetic and what is not, in the terms the rest of this page uses:
the **traffic is scripted** — who visits, and what they are after, comes from a
seeded plan; the **log lines are real server output**; and the **timestamps in
`access.log` are rewritten** onto the arrival curves the plan was drawn from,
because the harness issues the plan far faster than real visitors arrive.
Every other byte of every line, and the order of requests within each session,
is as Apache wrote it, and `access.raw.log` ships alongside with the timestamps
Apache actually wrote.

## Projects

| Project | Server | Format | Status |
|---|---|---|---|
| [`apache-shopfront`](projects/apache-shopfront/) | Apache 2.4 | Combined | `small`, `medium`, `large` |

The repository is built to hold many. nginx, IIS W3C, HAProxy, Tomcat,
ModSecurity audit logs, CDN JSON logs and `sshd` auth logs are all plausible
additions; see [docs/adding-a-project.md](docs/adding-a-project.md).

## Build a dataset

One command does everything — brings the server up, drives the traffic, runs the
attacks, collects the logs, writes the truth file, verifies the result, writes
the manifest, and tears the server down.

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
`access.raw.log`, so nothing is taken on trust. This is the one thing in the
project that is computed rather than collected;
[docs/methodology.md](docs/methodology.md) says exactly what is done and what
it costs.


## What ships

Committed to the repository:

- all source, scenario configs and seeds
- for each build, under `datasets/<project>/<date>-<tier>/`:
  - `MANIFEST.json` — seed, commit, tool versions, every attack command line
    with its source IP and time window, wall-clock duration, final line count
  - `README.md` — what that build is, and its known limitations
  - `sample.log` — 5,000 lines, for eyeballing
  - `sample.truth.jsonl` — its matching truth records

Written by every build into that same folder, and **not published anywhere
yet**. Release assets are planned — `tools/package.py` already builds them,
`xz`-compressed with a `SHA256SUMS` — but no release exists today, so the way
to get these files is to regenerate them:

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
python3 tools/package.py datasets/apache-shopfront/<date>-<tier>
sha256sum -c SHA256SUMS --ignore-missing
```

xz rather than zstd: `lzma` is in the standard library, so packaging needs
nothing installed, which is the same rule every host entry point here follows.

### What regenerating gives you

Regenerating is today the only way to get the full logs, so it matters what it
reproduces.

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
- **The shipped bytes themselves** exist only on the machine that built them
  until a release is published, and until then nobody else can check a digest
  against them.

## The ground truth file

JSON Lines. One header line, then exactly one record per log line, in order.

```json
{"kind":"logarc-truth","version":1,"scenario":"apache-shopfront-small","seed":7,"source_file_id":"access.log","granularity":"category","generated_at":"2026-08-16T09:00:00+00:00"}
{"line_no":1,"client_ip":"203.0.113.5","category":"browsing","instance_id":"203.0.113.5#17"}
{"line_no":2,"client_ip":"198.51.100.9","category":"enumeration","instance_id":"198.51.100.9#2"}
```

`"kind":"logarc-truth"` names the format that
[logarc](https://github.com/FRTX045/logarc)'s `logarc evaluate` command reads,
so a build here can be scored by it as it stands. logarc's published scores —
its README's
[How well does it work](https://github.com/FRTX045/logarc#how-well-does-it-work)
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

`tools/verify.py` fails loudly. No dataset is reported as finished until it
passes and its output has been read.

It checks that truth records equal log lines exactly, that every `client_ip`
matches its line, that every category is in the vocabulary, that `instance_id`
groups are contiguous per client, and that every line parses as Apache
Combined. That is the shape of the line, not of the request inside it: Apache
logs whatever request line arrived, and the noise client sends deliberately
malformed ones — `"GARBAGE"`, `"GET /.env x"`, a bare `"GET /backup.zip"`;
65, 190 and 602 lines in the three 2026-10-06 tiers, answered `400` or `404`.
Those lines parse, with method, path or protocol left empty where the request
line has none. It then prints the realism statistics — status distribution,
inter-arrival shape, requests per session, user-agent cardinality, `Referer`
share, the share of `304`/`206`/`HEAD`/`OPTIONS`, attack share per category,
and client IP concentration — as numbers to actually look at.

Every dataset README ends with a **Known limitations** section naming what is
still unrealistic about it. Scripted traffic always leaves some.

### The fake-log audit

`tools/audit.py` asks the only question that decides whether research done on
a generated log transfers to a real one: could an analyst tell?

```bash
python3 tools/audit.py datasets/apache-shopfront/2026-10-06-small -v
python3 tools/audit.py datasets/apache-shopfront/2026-10-06-small --compare access.raw.log
python3 tools/audit.py /var/log/apache2/access.log      # or anybody else's
```

The first two need that build's full logs, which are not in the repository; on
a fresh clone, point them at a build of your own.

Nine tells — toy-sized responses, round-number response sizes, an implausible
request rate, user-agent monoculture, uniform client volumes, missing status
classes, an absence of malformed requests, perfectly ordered timestamps, and
client addresses counted out of a subnet. Each publishes the threshold it used,
and too little data is reported as *inconclusive* rather than as a pass.

It is pointed at our own datasets first and hardest, **and it does find
things.** Whatever fires on a dataset is written into that dataset's README
and its manifest. The point of owning the detector is that the findings are
ours to publish rather than somebody else's to discover.

## Safety

The applications in this repository are **deliberately vulnerable** and are
documented as such in each project's `VULNERABILITIES.md`. They exist to be
attacked by the build process and by nothing else.

- They bind to an isolated Docker network and publish no host port.
- Every attack targets the lab's own application on that network. No external
  host is ever a target.
- No real credentials, no real personal data, no third-party services.
- Client addresses are drawn only from the documentation and shared-address
  ranges `203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24` and
  `100.64.0.0/10`. No address here belongs to an identifiable person or company.

Do not deploy these applications anywhere reachable.
