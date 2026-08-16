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

### Attack tools

Security tools will not send our header. The usual fallback is to give each tool
run a dedicated source IP and a recorded start and end time, then label by IP
plus window — exact only to the resolution of the clock, and only able to assign
one blanket category to a whole run.

Instead, every tool run is pointed at a small proxy that sits in front of Apache.
It preserves the tool's real network address as `X-Forwarded-For` and stamps a
unique `X-Request-Id` on each request, recording the request line against it.
Tool traffic therefore gets the same per-line exactness as everything else — and
a single `nikto` run splits correctly into `reconnaissance` for its fingerprint
probes and `injection` for its payload attempts, rather than both being flattened
into one label.

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

A traffic run that takes twenty minutes produces a log spanning twenty minutes.
A real investigation spans days. Both a multi-day span and real sub-second burst
structure cannot come out of one wall-clock run, so the choice is made
deliberately and per tier, and it is written down.

| Tier | Timestamps |
|---|---|
| `small` | **Untouched.** Real wall clock. The span is however long the run took. |
| `medium` | **Idle gaps between sessions are stretched.** Timing *inside* a session is untouched. |

The driver already schedules every session at a chosen virtual timestamp, so
that schedule is the authority. Each line's new timestamp is
`session_virtual_start + (line_real_time − session_real_start)`, which shifts
whole sessions apart while leaving every interval within a session exactly as
Apache recorded it. The asset cascades, the burst structure and the concurrency
interleaving all survive intact.

Lines are then stable-sorted by the new timestamp. Because Apache's `%t` has
one-second resolution, ties are common, and a stable sort preserves the original
interleaving — so the small local disorder that real concurrency produces is not
ironed out into a perfectly sorted log.

When any remapping is applied:

- the unmodified Apache output is kept in the dataset folder as `access.raw.log`
- the mapping is described in `MANIFEST.json` in enough detail to reverse it
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
the site is otherwise idle is separable by timestamp alone and teaches nothing.
The verifier checks this and fails if it is not true.

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
5. **Compare `access.raw.log`** against `access.log` if timestamps were remapped.
6. **Read the log.** Two hundred lines by eye catches things no check does.

### On reproducibility

The same seed produces the same **request sequence**. Timestamps and
interleaving differ between runs, because the requests are genuinely issued
concurrently against a real server and the ordering depends on how that run
actually went.

Byte-identical output is not claimed, because it cannot be delivered. A dataset
that claims a property it does not have is worse than one that is honest about
its limits — the first one gets trusted.
