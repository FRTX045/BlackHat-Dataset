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

**A share of the traffic comes from a real Chromium**, driven by Playwright
across five personas ([traffic/browser.py](traffic/browser.py)). That source
does not decide what to request: it is handed a URL and the log records what
the browser chose to ask for.

It is a few hundred lines of a seventy-thousand-line file, and it is worth
more than its size, because it is the only traffic here that is not a
program's idea of what a browser does:

- **Subresource order as Chromium orders it.** The preload scanner runs
  before layout, fonts wait for the CSS that references them to parse, and XHR
  interleaves with lazily-loaded images across six connections. The driver's
  cascades are real requests for real subresources; their *sequence* is a
  program's.
- **The requests it does not make.** A second page view asks for nothing
  already in its cache. Absence is as much a part of a real log as presence,
  and it is very hard to fake convincingly.
- **Conditional requests from a real cache** deciding to revalidate, rather
  than from a coin flip.
- **The favicon**, asked for once per origin, prompted by no markup at all.

One container serves all five personas: each connects to its own tag-proxy
port, and those ports run in **fixed** mode, so the address the proxy declares
is the persona's rather than the container's. Their addresses sit in the
residential range below the block `ippools` draws recurring clients from, so
the session driver can never draw one — two sources writing episodes for one
client would break the contiguity the truth file promises.

No request interception is used. Playwright can rewrite headers per request,
which would let the browser mint its own request ids and declare its own
labels, but it disables the HTTP cache — and the cache is most of the reason
to run a browser at all. The tag proxy mints the ids instead, so this traffic
is labelled per request, and a browser `instance_id` is a run of one activity
rather than a whole session.

### Which tools produced the attack traffic

Both hand-written campaigns and real tools. The campaigns are in
[attacks/playbooks.py](attacks/playbooks.py); the tool runs are declared in
[attacks/toolruns.py](attacks/toolruns.py) and their image is
[attacks/Dockerfile](attacks/Dockerfile).

| Tool | Version | Source IP | Invocations | What it was pointed at |
|---|---|---|---|---|
| sqlmap | pinned by Debian bookworm | 192.0.2.31 | 1 | the planted SQL injection on `/search` |
| whatweb | pinned by Debian bookworm | 192.0.2.32 | 1 | the site root, fingerprinting |
| dirb | pinned by Debian bookworm | 198.51.100.31 | 1 | `/` with dirb's common wordlist |
| gobuster | pinned by Debian bookworm | 198.51.100.33 | 1 | the same wordlist, at four threads |
| nmap | pinned by Debian bookworm | 198.51.100.32 | 1 | the proxy's HTTP port, `http-*` NSE scripts |

`dirb` and `gobuster` cover identical ground on purpose. Two tools over the
same wordlist leave visibly different traces — different agent, different
concurrency, different ordering — and a log holding both is a better test of
whether a detector learned the tool or the behaviour.

**`hydra` is declared and does not run**, and this is worth stating rather than
quietly omitting. Its `http-post-form` module sends one request and then
blocks against this application, whatever failure condition it is given — `F=`
with a body substring, or `S=302`, all behave alike. Three separate 40-second
runs produced three requests between them. The cause looks to be that `/login`
answers **401 with no `WWW-Authenticate` header**, which is a protocol
violation on the application's side, and hydra waits for a challenge that never
arrives. Fixing the header would change what the hardened login demonstrates,
so the declaration stays in
[attacks/toolruns.py](attacks/toolruns.py) with the reason beside it and no
scenario lists it. Credential attacks against that endpoint come from the
hand-written `brute_force` and `credential_stuffing` playbooks and the
`credential_hunter` campaign, which produce better labels anyway.

Every invocation is recorded in `MANIFEST.json` with its exact command line,
source address, resolved version, time window, exit code and **the number of
requests the proxy actually saw from it**. That last field is why the table is
a record rather than a claim: a tool that started, exited cleanly and reached
nothing would otherwise be indistinguishable here from one that worked, and
the build refuses to finish if any tool produced no traffic at all. Which
tools a given tier runs is a scenario decision, listed under `[attacks] tools`.

Tools are pointed at the **tag proxy**, never at Apache directly, so each of
their requests acquires a request id and joins as exactly as a driver request.
Each also gets **its own proxy port**, and that is what makes the label right:
the proxy records the actor configured for the port, and `labels.py` decides a
tool run's category from that actor rather than from individual requests,
because no single request in a wordlist walk reveals that the activity is a
wordlist walk.

That was got wrong once and shipped. Every tool arrived on one shared port
under the generic actor `tool`, the labeller never matched its `tool:dirb`
rule, and **98% of 9,293 tool requests were labelled `browsing`** in two
datasets — directory brute-forcing recorded as ordinary browsing. Both were
rebuilt. Per-request labelling is simply unreliable for tools: sqlmap's boolean
payloads carry no `UNION` and no `or 1=1`, so the payload regex catches about
one request in forty-five.

Every run is wrapped in `timeout`, and being cut off is recorded rather than
smoothed over — it changes how that tool's line count should be read.

The two tiers scan at different sizes. The one-day `small` tier uses dirb's
959-word `small.txt`; the week-long `medium` tier uses the 4,614-word
`common.txt`. Two full walks inside a single day put enumeration at 11% of the
log and the attack share at 14% against a 2–8% target, and are more scanning
than one small shop sees in a day.

**`nikto` is not here, and not by choice.** It was dropped from Debian and
bookworm has no package for it, so there is no way to pin its version from the
archive the way every other tool here is pinned. `whatweb` covers the
fingerprinting half of what it was doing; the hand-written `recon` playbook
covers the known-file probing half with better labels.

**Also not included:** `ffuf`, which is packaged but would only duplicate
gobuster and dirb over the same wordlist; `nuclei`; `wpscan`, a Ruby gem; and
ZAP, which needs a JRE. A JVM would triple the image and make the version pin
depend on an upstream release page rather than on Debian's archive.

An earlier version of this section claimed `gobuster` and `ffuf` were Go
release binaries with no Debian package. That was wrong — both are packaged in
bookworm, which is why gobuster is now in the table above.

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
