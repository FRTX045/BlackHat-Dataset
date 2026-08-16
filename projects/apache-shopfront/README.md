# apache-shopfront

Apache 2.4 access logs in Combined format, from a real PHP shopfront served by
a real Apache, attacked by real security tools and hand-written playbooks.

```bash
python3 tools/build.py apache-shopfront small
python3 tools/verify.py datasets/apache-shopfront/<date>-small
```

The application is **deliberately vulnerable** and is documented as such in
[app/VULNERABILITIES.md](app/VULNERABILITIES.md). It publishes no host port and
is reachable only from its three isolated Docker networks. Do not deploy it
anywhere reachable.

## How this dataset was produced

### Server stack

Apache **2.4.68 (Debian)** with **PHP 8.3.33**, in Docker, built from
`php:8.3-apache`
(`sha256:bcf7ac6941725b08123df2732065b8ede097ed0977ba2891b411654efb35cc23`).
Process model is `mpm_prefork`, because `mod_php` is not thread-safe.

Modules: `mod_remoteip`, `mod_php`, `mod_rewrite`, `mod_headers`,
`mod_deflate`, `mod_setenvif`.

Two `CustomLog` directives at server level — `combined` and `tagged`, the
latter prefixed with `%{X-Request-Id}i`. Both formats are **redefined** rather
than inherited: Debian's stock `combined` uses `%O`, which never emits `-`,
and these datasets use the canonical `%b` so a `304` and a `HEAD` record `-`.

`RemoteIPTrustedProxy` names exactly two addresses, the driver and the tag
proxy. Attacker containers are untrusted on purpose, so their real container
address is what lands in `%h`.

No host port is published. One path, `/.lab-health`, is excluded from both
access logs; it is the build's readiness probe and nothing else uses it.

### The application

A PHP 8.3 + SQLite shopfront — **130 products across 10 categories**, seeded
deterministically from the run seed, with real internal linking so a product
page is only reachable from a listing.

Deliberately vulnerable in **8 documented places** — SQL injection, IDOR, path
traversal, SSRF, an upload bypass ending in a webshell, command injection,
SSTI, and XSS — and hardened in **5 others**, so attack traffic has somewhere
to fail as well as somewhere to succeed. Every one is recorded in
[app/VULNERABILITIES.md](app/VULNERABILITIES.md) with the request that exploits
it and the measured `%b` a successful exploit produces.

### How the traffic was generated

Sessions arrive from a **non-homogeneous Poisson process** with a diurnal and a
weekly curve, produced by thinning. Session lengths are heavy-tailed: the
median visit is a couple of pages, the 99th percentile is in the dozens.

Seven personas — casual browser, shopper, returning customer, mobile user,
search-engine crawler, uptime monitor, and opportunistic scanner. Client
identity is coherent across three modules: a mobile visitor arrives from mobile
CGNAT space carrying a mobile agent, a crawler from cloud space carrying a bot
string.

Traffic is issued by an async `httpx` driver. Asset cascades are **discovered,
not scripted** — the driver fetches a page and requests the subresources that
page actually references, holding a per-visit cache so a revisit either serves
from it or revalidates with a conditional GET. That is where the `304`s come
from.

Background noise arrives over raw sockets from an address reserved for nothing
else: `CONNECT` requests, requests with no `Host` header, and request lines
malformed enough that Apache rejects them before reading a header.

> **Not included:** real headless-browser traffic. The plan called for 10–20%
> of sessions through Playwright; that is not built. The cascades in this data
> are real requests for real subresources, but their ordering is the driver's
> rather than Chromium's.

### Which tools produced the attack traffic

> **As of this commit, no tool-driven traffic is in the shipped datasets.** The
> attacker image and the five tool runs below are written and their
> declarations are tested, but `tools/build.py` does not yet execute them. The
> attack traffic in every dataset here is entirely hand-written. Each
> dataset's own README states what actually ran in that build; this table
> describes what the project is set up to run.

Declared in [attacks/toolruns.py](attacks/toolruns.py), image in
[attacks/Dockerfile](attacks/Dockerfile):

| Tool | Version | Source IP | Invocations | What it was pointed at |
|---|---|---|---|---|
| sqlmap | pinned by Debian bookworm | 192.0.2.31 | 1 | the planted SQL injection on `/search` |
| nikto | pinned by Debian bookworm | 192.0.2.32 | 1 | the site root |
| dirb | pinned by Debian bookworm | 198.51.100.31 | 1 | `/` with dirb's common wordlist |
| hydra | pinned by Debian bookworm | 192.0.2.33 | 1 | `POST /login` |
| nmap | pinned by Debian bookworm | 198.51.100.32 | 1 | the proxy's HTTP port, `http-*` NSE scripts |

When they do run, every invocation is recorded in `MANIFEST.json` with its
exact command line, source address, resolved version and time window, and the
verifier fails if a tool in the manifest is missing from this table. Tools are
pointed at the **tag proxy**, never at Apache directly, so each of their
requests acquires a request id and one `nikto` run splits into
`reconnaissance` and `injection` rather than taking a single blanket label.

**Not included:** `gobuster`, `ffuf` and `nuclei` are Go release binaries,
`wpscan` is a Ruby gem, and ZAP needs a JRE. Adding four download paths and a
JVM would triple the image and make the version pin depend on upstream release
pages rather than Debian's archive. The hand-written playbooks cover the same
ground with better labels.

Hand-written attacks are in [attacks/playbooks.py](attacks/playbooks.py) and are
paced like a person, with pauses, wrong guesses and dead ends — the first UNION
gets the column count wrong, the first traversal does not count enough levels.
They run as six **campaigns**, each from its own address, each telling a phased
story with ordinary browsing interleaved. **Two of the six find nothing**,
which is what most real attack traffic looks like and what published datasets
almost never contain.

### How the labels were produced

Every request carries a unique `X-Request-Id`. The driver and the hand-written
attacks set their own; tools are proxied through a component that stamps one.
Apache writes a `tagged` log carrying that id, and the shipped `access.log` is
that file with the id prefix removed — so line N of the log and line N of
`truth.jsonl` are the same request **by construction**, at any concurrency.

Apache's independently written `combined` log ships beside it as
`access.apache.log`, and the verifier compares the two on every build and
reports the agreement as a number.

> That comparison is not a formality. On a 75,676-line run the two logs
> disagreed on **exactly two lines — swapped with each other**, same second,
> different Apache processes. Under a positional join those two would have been
> given each other's truth records, both labels would have looked plausible,
> and nothing would have noticed. See
> [docs/methodology.md](../../docs/methodology.md).

Lines Apache rejects before `mod_remoteip` runs carry neither a declared
address nor an id. Those shapes are issued from an address reserved for nothing
else, and the join labels them by that address — reported separately from
unmatched lines so nobody has to guess which mechanism produced a label.

### How to rebuild it

```bash
python3 tools/build.py apache-shopfront small
```

The seed lives in [scenarios/small.toml](scenarios/small.toml); the commit and
the resolved seed are recorded in each dataset's `MANIFEST.json`. The same seed
reproduces the same **request sequence**. Timestamps and interleaving differ
between runs under real concurrency — this is not, and does not claim to be,
byte-identical output.
