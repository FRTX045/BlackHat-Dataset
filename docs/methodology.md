# Methodology

How the datasets in this repository are produced, and how to audit one.

This document is repo-wide. Each project restates it concretely for its own
stack under **"How this dataset was produced"** in the project README, and each
built dataset restates it again with that run's specifics.

---

## The principle

**No log line is generated. Every line is collected.**

A log generator produces lines that look like log lines. It cannot produce the
things that make a real log real: the asset cascade that follows one page view
in the same second, the `304` a browser earns by having a cached copy, the byte
count that varies because the response genuinely varied, the small local
disorder in timestamps that concurrency creates, the `400` from a request that
was actually malformed.

So the approach here is to make those things happen rather than imitate them:

1. Build a real, working web application with enough surface area for realistic
   behaviour to exist.
2. Serve it with a real Apache, configured the way a real Apache is configured.
3. Drive genuine HTTP traffic at it — a fraction of it through a real headless
   browser, the bulk through an async client replaying the same session shapes.
4. Attack it with the real security tools, and let them be as loud as they
   naturally are.
5. Ship the log the server wrote.

Everything else in this document exists to make step 5 trustworthy.

### The limit of the principle

Collecting rather than generating guarantees the log is **honest**. It does not
guarantee the log is **representative**, and the difference caught this project
out.

For a long time the application served a 1.4 KB home page, a 600-byte
stylesheet and a 574-byte "bundle". Apache recorded those faithfully, so every
byte count in the dataset was true. It was also useless: `%b` is where real
analysis starts for exfiltration volume, response-size anomalies and cache
work, and against a real origin those figures are wrong by one to three orders
of magnitude. Every aggregate check passed. It was found by reading
twenty-five lines of a shipped log by eye.

So the rule has a second half. Collect everything — and make sure the thing
being collected from is the size and shape of the real thing. The application
is not a placeholder for a shop; where its output reaches the log, it has to
*be* a shop. That is why the stylesheets, scripts, markup and API payloads are
sized against published figures for real origins, and why `tools/audit.py`
now measures response size per content kind on every build.

---

## The labelling problem, and how it is solved

The hard problem is knowing **which log line came from which client intent**.

The obvious approach — match on client IP, timestamp and path — breaks the
moment two sessions overlap, which is to say immediately. Two visitors fetching
`/assets/css/site.css` in the same second from the same NAT range are
indistinguishable by those three fields, and they may belong to entirely
different activities. A truth file that is subtly wrong is worse than no truth
file at all, because the first one gets trusted.

It is solved at the source, not by inference.

### Request ids

Apache is configured with two log formats:

```apache
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%{X-Request-Id}i %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" tagged
```

Every request that reaches the server carries a unique `X-Request-Id`, and the
component that issued it recorded what that request was meant to be. Joining the
tagged log to that record gives a provably correct label for every line, under
any amount of concurrency.

### Why `access.log` is derived, not captured in parallel

The natural implementation is two `CustomLog` directives writing two files, then
joining them line by line. **That is not safe.** Apache serves this application
under `mpm_prefork`, because `mod_php` is not thread-safe, so concurrent
requests are handled by separate processes; each writes to both files
independently. Nothing orders one process's write to `access.log` against
another's write to `access.tagged.log`. Line N of one is not guaranteed to be
line N of the other, and the divergence would occur precisely on the
overlapping requests the dataset exists to represent.

So the shipped `access.log` is **derived from the tagged log by removing the id
prefix**. Line N of the log and line N of `truth.jsonl` are then the same
request by construction, with no ordering assumption anywhere.

Every character of the shipped log was still written by Apache. The only
transformation is the removal of a leading field that we added.

Apache's ordinary `combined` `CustomLog` is still configured and still written.
The verifier compares it against the derived file on every build and **reports
the agreement as a number** — `N/N lines agreed, in order`. The assumption is
measured rather than trusted, and a divergence is published rather than hidden.

### This is not hypothetical — it has been observed

On a 75,676-line run at 32-way concurrency, the two logs **disagreed on two
lines**:

```
line 14559  access.log         100.78.35.241 ... "GET /c/fasteners HTTP/1.1" 200 1440
            access.apache.log  100.71.46.109 ... "GET /assets/img/p/110.jpg HTTP/1.1" 200 199843
line 14560  access.log         100.71.46.109 ... "GET /assets/img/p/110.jpg HTTP/1.1" 200 199843
            access.apache.log  100.78.35.241 ... "GET /c/fasteners HTTP/1.1" 200 1440
```

The two lines are **swapped**. Every other line agreed, and the two files
contain exactly the same set of lines — the divergence is purely ordering. Two
requests arriving in the same second, from different clients, handled by
different Apache processes, were written to the two `CustomLog` files in
opposite orders.

Under the brief's positional join those two lines would have been labelled with
**each other's** truth records: a category listing labelled `static_asset` and
an image labelled `browsing`. Both labels would have looked entirely plausible,
the line counts would still have matched, and no check anywhere would have
noticed.

The derived log cannot do this. Line N of the shipped log and line N of
`truth.jsonl` come from the same physical line of the same file, so there is no
ordering to get wrong. Two lines in 75,676 is a rate of 0.003% — small enough to
be missed by inspection and large enough to matter in a dataset whose whole
purpose is being scored against.

### Attack tools

Security tools will not send our header. The usual fallback is to give each tool
run a dedicated source IP and a recorded start and end time, then label by IP
plus window — exact only to the resolution of the clock, and only able to assign
one blanket category to a whole run.

Instead, every tool run is pointed at a small proxy that sits in front of Apache.
It preserves the tool's real network address as `X-Forwarded-For` and stamps a
unique `X-Request-Id` on each request, recording the request line against it.
Tool traffic therefore gets the same per-line exactness as everything else.

**Each tool arrives on its own proxy port**, and the port carries that tool's
actor. That is what makes the label right: a tool run's category is decided
from the actor rather than from the individual requests, because no single
request in a wordlist walk reveals that the activity *is* a wordlist walk.

An earlier version of this document claimed the opposite — that one tool run
would split per request into `reconnaissance` for its fingerprint probes and
`injection` for its payloads. It would not have, and the attempt to do it that
way is what produced the worst labelling bug this project has had: every tool
shared one port under the generic actor `tool`, the per-tool rules never
matched, and 98% of 9,293 tool requests were labelled `browsing` in two
shipped datasets. Per-request labelling is simply unreliable for tools —
sqlmap's boolean payloads carry no `UNION` and no `or 1=1`, so a payload regex
catches about one request in forty-five.

### Client addresses

All traffic originates inside an isolated Docker network, but a log full of
`172.17.0.x` would be useless. Apache runs `mod_remoteip` with
`RemoteIPHeader X-Forwarded-For`, so `%h` records the address the client
declared.

`RemoteIPTrustedProxy` lists **only** the traffic driver and the tag proxy.
Attacker containers are deliberately untrusted, so their own real network
address is what lands in the log — they cannot declare an address even if a tool
sends the header.

That boundary is not assumed. `tests/server/test_apache_logging.py` drives real
requests at a real container and asserts it in both directions: a source outside
the trust list sending `X-Forwarded-For` gets its own address logged, and one
inside the list gets the declared address logged. It covers `100.64.0.0/10`
specifically, because `mod_remoteip` treats non-public addresses differently
under `RemoteIPTrustedProxy` than under `RemoteIPInternalProxy` and the mobile
personas have no valid addresses if that case fails. The tests run against the
server on every change to its configuration.

Addresses are drawn only from `203.0.113.0/24`, `198.51.100.0/24`,
`192.0.2.0/24` and `100.64.0.0/10`, weighted by role — residential, mobile
CGNAT, cloud for the well-behaved bots, datacenter for the scanners. The
distribution matters more than the numbers: a few heavy clients and a long tail
of one-request visitors. No address here belongs to an identifiable party.

### The log format, and the one request that is not logged

The `combined` nickname is **redefined** rather than inherited. Debian's stock
definition uses `%O` — bytes put on the wire, response headers included — which
never emits `-`. These datasets use `%b`, the canonical Combined Log Format
field, so a `304` and a `HEAD` record `-` rather than a header count. That is
what every log-analysis tool reading this data will expect, and a plausible
number in a field that should be empty is the kind of error nothing downstream
would flag.

One class of request is deliberately absent from the shipped log: the build
polls `/.lab-health` to decide the server has started, and that path is excluded
from both `CustomLog` directives. It carries no request id, and it is an
artefact of the harness rather than traffic anyone sent. Nothing else Apache
handles is excluded — including the malformed requests, the `CONNECT` attempts
and the requests with no `Host` header, which are all a deliberate part of the
data.

### Apache's own internal dummy connections

Every real Apache log contains a handful of lines like this:

```
127.0.0.1 - - [...] "OPTIONS * HTTP/1.0" 200 - "-" "Apache/2.4.68 (Debian) ... (internal dummy connection)"
```

The parent process makes them to wake idle children. They are not client
traffic, they carry no request id, and they come from `127.0.0.1` rather than
any client range.

**They are kept.** The log Apache wrote is the log that ships, and filtering
these would make the file less like the real thing rather than more. They are
labelled `unknown` — which is what that category is for — and they are the main
reason a run reports a non-zero unmatched count. A small-tier run produces
about one per few thousand lines.

Anyone computing per-client statistics should expect them and exclude
`127.0.0.1` explicitly; the truth file makes that trivial, because they are the
only `unknown` records with that address.

---

## What is manipulated, and what is not

A traffic run that takes three minutes produces a log spanning three minutes.
A real investigation spans days. The timestamps are the one thing in this
project that is rewritten rather than collected, and this section says exactly
what is done to them and what it costs.

**What was wrong.** The driver plans its sessions across hours of virtual time
and then issues the whole plan as fast as the sockets allow. A small run put
seventy thousand requests inside a hundred and eighty seconds of wall clock,
at four hundred requests a second, with the busiest second holding seven
hundred and thirty-three. The *sequence* was right — every session, every
cascade, every campaign phase in the order it was meant to happen — and the
timing was unusable. Nothing rate-based, burst-based or session-duration-based
could be studied on that file.

**What is done now.** Both tiers are remapped, by
[`shared/timeline/remap.py`](../shared/timeline/remap.py). Every line keeps
every byte except the bracketed timestamp field.

| | |
|---|---|
| Session start, human traffic | Redrawn from the same diurnal and weekly curves the driver plans against, one draw per session, handed out in a **shuffled** order |
| Session start, automated traffic | Redrawn **uniformly** across the window |
| Order within a session | As captured |
| Spacing within a session | Reconstructed from what each request was |
| One address's sessions | Kept in capture order, and never overlapping |
| Everything else on the line | Byte for byte as Apache wrote it |

**Why automated traffic gets its own treatment.** An uptime monitor polls on a
timer and contributes as many lines at 04:00 as at 20:00. Search, SEO and AI
crawlers work to their own schedules. Opportunistic scanning is, if anything,
night-heavy. Drawing all of them from the shoppers' curve gave a finished log a
peak-to-trough ratio of 26.8, where real e-commerce logs sit nearer 5–10 — and
the reason they do is precisely that the small hours are not empty but
bot-dominated.

Measured before the rule existed: the 01:00–05:00 window was 6.4% automated
and the 18:00–21:00 peak 20.7%, which is exactly backwards. After: **49.9% at
night against 12.0% at peak**, and a peak-to-trough ratio of 6.9.

This is not cosmetic. A detector trained on a log whose nights are genuinely
empty learns that any traffic at 4am is suspicious, which is the opposite of
what real night traffic looks like.

The rule is keyed on the **truth label**, not on the persona, and it lives in
`remap.py` rather than in the session planner. That distinction was learned the
hard way: the planner was taught the same rule first and it changed nothing at
all, because the driver never reads a planned session's start time and the
remap discards them.

**Why the draws are shuffled.** Handing them out in capture order stamps the
harness's own schedule onto the clock. The campaigns start with the driver and
finish early; the noise generator runs last. Assigned in order, every campaign
landed in the same hour of the rewritten day — and because attack sessions are
short, that hour got a hole in its ordinary traffic as well. Measured on the
first build: 44% of all attack lines inside two hours, sitting in the deepest
trough of the day. Shuffling is what breaks that.

**Why the draws are per session and not per address.** Drawing once per
address and keeping each address's internal spacing from the capture looks
more faithful and is not: `ippools` reuses addresses hard, so an address is
not one actor but a succession of unrelated visitors spanning the whole run.
Anchoring on the first of them made nearly every address as long as the
window, which then had to be pulled back to fit — and 651 requests landed on
the first second of the log.

**The honest limit.** Spacing *within* a session is inferred from the truth
labels: a subresource follows its page in milliseconds, a person reads for a
few seconds before clicking, an operator waits longer because they are reading
what came back. The capture's sub-second structure is gone, so the labels are
the only signal left to rebuild pacing from. This is the one place in the
project where a number in the shipped file was computed rather than observed,
and it is stated in the manifest and in every dataset README that ships a
remapped log.

Two consequences worth naming, both of which the fake-log audit finds in our
own data and both of which are published in the dataset README:

- **The rewritten log is perfectly ordered.** A real prefork server interleaves
  its writes and produces occasional out-of-order lines; ours has none,
  because it was sorted. `access.raw.log` has them.
- **The gap between an operator's campaign phases is redrawn, not preserved.**
  Their order is preserved. A campaign is still one address working through
  its phases in sequence; the hours between them come from the arrival model.

When any remapping is applied:

- the unmodified Apache output is kept as `access.raw.log`, with its own
  `truth.raw.jsonl`
- `MANIFEST.json` carries a `timestamps` block naming which file is the
  capture, both spans, and how many sessions had to be pushed
- the derived-vs-Apache agreement check runs against `access.raw.log`, because
  that check is about the labelling mechanism and would be meaningless against
  a file whose timestamps and order deliberately changed
- the dataset README says so plainly

A rewritten log is never presented as a raw capture.

---

## Attack traffic

Attack lines are **2–8% of the total**, verified and reported. More than that
and the dataset stops resembling a server that real people also used.

Both kinds are present, because they look completely different in a log and that
difference is most of the value:

- **Hand-written attacks**, paced like a person — slower, with pauses to think,
  with mistakes, dead ends and retries.
- **Real tools**, run as they actually behave, at their natural volume.

Attacks are organised into **campaigns**: one attacker address moving through
phases over hours or days — reconnaissance, directory enumeration, injection
probing, successful exploitation, data access, and return visits using what was
found — with the attacker's own ordinary browsing interleaved between phases,
because real attackers look at a site like anyone else.

At least one campaign **fails**: probes for an hour, finds nothing, leaves. That
is a common real case and it is almost absent from synthetic datasets.

Attacks always overlap in time with normal traffic. An attack that runs while
the site is otherwise idle is separable by timestamp alone and teaches nothing,
so the campaigns and tool runs are issued *concurrently* with the driver rather
than before or after it.

The verifier **reports** this rather than failing on it, in two forms, because
one figure is not enough. The strict measure — attack lines sharing their exact
second with an ordinary request — falls with the request rate for reasons that
have nothing to do with how well the attack is hidden: a log at one request a
second has almost no second holding two of anything. The second measure asks
whether ordinary traffic was going on *within a minute either side*, which is
what actually makes a timestamp filter useless, and it does not move with the
rate. Both are printed with the window attached.

---

## Auditing a shipped dataset

Everything needed to check the work is in the dataset folder.

1. **Rebuild it.** `python3 tools/build.py <project> <tier>` with the seed from
   `MANIFEST.json` reproduces the same request sequence.
2. **Check the truth file against the log yourself.**
   `python3 tools/verify.py <dataset-dir>` re-runs every integrity check.
3. **Read the manifest.** Every attack tool invocation is there verbatim — the
   exact command line, its source address, and its time window.
4. **Read `VULNERABILITIES.md`.** Every planted weakness is documented with what
   a successful exploit looks like in the log, so a detector's findings can be
   checked against ground truth rather than against an assumption.
5. **Compare `access.raw.log`** against `access.log` if timestamps were
   remapped. `python3 tools/audit.py <dataset-dir> --compare access.raw.log`
   runs the fake-log audit over both and prints them side by side, so the
   difference between the two columns is exactly what the rewrite cost and
   what it bought.
6. **Run the fake-log audit.** `python3 tools/audit.py <dataset-dir> -v` runs
   eight tells for whether a log looks generated — round-number response
   sizes, an implausible request rate, user-agent monoculture, uniform client
   volumes, missing status classes, an absence of malformed requests,
   perfectly ordered timestamps, and client addresses counted out of a subnet.
   It is pointed at our own datasets first and it does find things; what it
   finds is in each dataset's README. It works on any Combined log, so it can
   be pointed at a third-party dataset for comparison.
7. **Read the log.** Two hundred lines by eye catches things no check does.

### On reproducibility

The same seed produces the same **request sequence**. Timestamps and
interleaving differ between runs, because the requests are genuinely issued
concurrently against a real server and the ordering depends on how that run
actually went.

Byte-identical output is not claimed, because it cannot be delivered. A dataset
that claims a property it does not have is worse than one that is honest about
its limits — the first one gets trusted.
