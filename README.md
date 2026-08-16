# BlackHat-Dataset

Labelled web-server log datasets for forensic log-analysis research.

Every line in every log here was written by a real server, in response to a
request that was genuinely made. Nothing is templated, sampled from a
distribution, or emitted by a log generator. A real web application is stood up,
a real Apache serves it, real people-shaped traffic and real security tools are
driven at it, and the log the server wrote is the log that ships — alongside a
ground truth file that says what every single line actually was.

That last part is the point. A dataset nobody can score against is a dataset
nobody can measure with.

## Projects

| Project | Server | Format | Status |
|---|---|---|---|
| [`apache-shopfront`](projects/apache-shopfront/) | Apache 2.4 | Combined | `small`, `medium` |

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

| Tier | Lines | Approx. size | Virtual span | Purpose |
|---|---|---|---|---|
| `small` | ~50,000 | ~12 MB | a few hours | Fast iteration |
| `medium` | ~1,000,000 | ~230 MB | 7–14 days | The main dataset |

Larger tiers are not the small one repeated. A multi-week log contains things a
four-hour log cannot: weekend dips, a traffic spike, a deployment that changes
which paths exist, a bot that appears halfway through, an attacker who returns a
week after their first visit.

## What ships

Committed to the repository:

- all source, scenario configs and seeds
- `MANIFEST.json` — seed, commit, tool versions, every attack command line with
  its source IP and time window, wall-clock duration, final line count
- `sample.log` — 5,000 lines, for eyeballing
- `sample.truth.jsonl` — its matching truth records

Published as release assets, `zstd`-compressed with a `SHA256SUMS`:

- the full `access.log`, `error.log` and `truth.jsonl`

**Regeneration is the primary distribution channel.** Anyone with this
repository runs one command and gets the dataset. Releases are a convenience.

## The ground truth file

JSON Lines. One header line, then exactly one record per log line, in order.

```json
{"kind":"weblog-truth","version":1,"scenario":"apache-shopfront-small","seed":7,"source_file_id":"access.log","granularity":"category","generated_at":"2026-08-16T09:00:00+00:00"}
{"line_no":1,"client_ip":"203.0.113.5","category":"browsing","instance_id":"203.0.113.5#17"}
{"line_no":2,"client_ip":"198.51.100.9","category":"enumeration","instance_id":"198.51.100.9#2"}
```

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
groups are contiguous per client, and that every line parses as valid Apache
Combined. It then prints the realism statistics — status distribution,
inter-arrival shape, requests per session, user-agent cardinality, `Referer`
share, the share of `304`/`206`/`HEAD`/`OPTIONS`, attack share per category,
and client IP concentration — as numbers to actually look at.

Every dataset README ends with a **Known limitations** section naming what is
still unrealistic about it. Every synthetic dataset has some.

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
