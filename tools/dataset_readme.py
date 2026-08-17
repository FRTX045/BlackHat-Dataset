"""Render a dataset's own README, filled in with what the run measured.

Every dataset carries the same six-subsection provenance section its project
does, but instanced: the numbers here are this run's, not the project's general
description. `tools/verify.py` fails the build if any subsection is missing or
empty, so this is what stops a dataset shipping undocumented.

Numbers are written exactly as they came out. A realism figure that
disappointed is still the figure.

Stdlib only.
"""

import json


def _percent(share):
    return f"{share * 100:.2f}%"


def _table(mapping, key_header, value_header, limit=None):
    rows = list(mapping.items())[:limit]
    lines = [f"| {key_header} | {value_header} |", "|---|---|"]
    lines += [f"| `{k}` | {v} |" for k, v in rows]
    return "\n".join(lines)


def render(*, project, tier, manifest, stats, tool_runs, campaigns):
    agreement = manifest["derived_vs_apache_combined"]
    clients = stats["client_concentration"]
    agents = stats["user_agents"]
    overlap = stats["attack_overlap"]
    clock = manifest.get("timestamps", {"remapped": False})
    span = stats["timespan"]

    if clock.get("remapped"):
        clock_text = f"""**The timestamps in `access.log` were rewritten, and `access.raw.log` is
the log Apache actually wrote.** The driver issues its whole plan as fast as
the sockets allow, so the capture covers
{clock['captured_span_seconds']:,.0f} seconds — the request *sequence* is
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
| Window | {clock['start']} → {clock['end']} |
| Span | {clock['span_seconds'] / 86400:.2f} days |
| Days covered | {span['distinct_days']} |
| Achieved rate | {span['requests_per_second']} requests/second |
| Busiest second | {span['busiest_second_requests']} requests |
| Sessions | {clock['sessions']:,} ({clock['sessions_pushed']:,} pushed later to keep one session per address at a time) |"""
    else:
        clock_text = f"""Timestamps are exactly as Apache wrote them, and that is a limitation rather
than a feature: the driver issues its whole plan as fast as the sockets allow,
so this log covers {span['span_seconds']:,.0f} seconds at
{span['requests_per_second']} requests a second. The request *sequence* is
meaningful; the timing is not. Nothing rate-based, burst-based or
session-duration-based can be studied on this file."""

    if tool_runs:
        tool_table = "\n".join(
            ["| Tool | Version | Source IP | Requests | Exit | What it was pointed at |",
             "|---|---|---|---|---|---|"]
            + [f"| {r['tool']} | `{r.get('version') or 'unrecorded'}` | "
               f"{r['source_ip']} | {r['requests']:,} | "
               f"{r['exit_code']}{' (cut off)' if r.get('timed_out') else ''} | "
               f"{r['target']} |" for r in tool_runs])
        tool_table += (
            "\n\nThe **Requests** column is the count the tag proxy actually "
            "recorded from each tool's address, not a count of tools that "
            "were started. A tool that ran, exited cleanly and reached "
            "nothing would otherwise be indistinguishable here from one that "
            "worked; the build refuses to finish if any of them is zero.")
    else:
        tool_table = ("None — no tool-driven attacks ran in this build. The "
                      "attack traffic here is entirely hand-written, from "
                      "`attacks/playbooks.py`.")

    browser = manifest.get("browser") or {}
    if browser.get("requests"):
        browser_text = f"""**{browser['requests']:,} of these requests came from a real Chromium**, driven
by Playwright across {len(browser['personas'])} personas
({', '.join(f'`{p}`' for p in browser['personas'])}). That traffic is not
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
what `instance_id` already means for every proxy-labelled source here."""
    else:
        browser_text = ("No headless-browser traffic in this build. The "
                        "cascades are real requests for real subresources, "
                        "ordered by the driver rather than by Chromium.")

    findings = manifest.get("audit", {}).get("findings", [])
    fired = [f for f in findings if f["suspicious"]]
    if findings:
        audit_text = "\n".join(
            [f"`tools/audit.py` runs {len(findings)} tells for whether a log "
             f"looks generated. On this dataset "
             f"**{len(fired)} of them "
             f"{'fires' if len(fired) == 1 else 'fire'}**.", ""]
            + ([f"- **`{f['name']}`** — measured `{f['measured']}` against a "
                f"threshold of `{f['threshold']}`. {f['explanation']}"
                for f in fired]
               if fired else
               ["None fired, which is a statement about these eight checks "
                "and not a claim that the log is indistinguishable from a "
                "real one."]))
    else:
        audit_text = "The audit was not run for this dataset."

    succeeded = [c for c in campaigns if c.get("succeeds")]
    failed = [c for c in campaigns if not c.get("succeeds")]

    return f"""# {project} — {tier} — {manifest['started_at'][:10]}

{stats['lines']:,} lines of Apache Combined access log, with a ground-truth
record for every one of them.

| | |
|---|---|
| Lines | {stats['lines']:,} |
| Seed | `{manifest['seed']}` |
| Commit | `{manifest['commit']}` |
| Built | {manifest['started_at']} |
| Wall clock | {manifest['wall_clock_seconds']}s |

## How this dataset was produced

### Server stack

Apache 2.4.68 (Debian) with PHP 8.3.33 under `mpm_prefork`, in Docker, built
from `php:8.3-apache`. Image actually used:
`{manifest.get('base_image_digest')}`.

Modules: `mod_remoteip`, `mod_php`, `mod_rewrite`, `mod_headers`,
`mod_deflate`, `mod_setenvif`. Two server-level `CustomLog` directives,
`combined` and `tagged`, both redefined to use `%b` rather than Debian's `%O`.
No host port published. `/.lab-health` excluded from both logs.

### The application

A PHP 8.3 + SQLite shopfront, 130 products across 10 categories, seeded from
`{manifest['seed']}`. Deliberately vulnerable in 8 documented places and
hardened in 5 others — see `projects/{project}/app/VULNERABILITIES.md`. Never
reachable beyond its three Docker networks.

### How the traffic was generated

Sessions from a non-homogeneous Poisson process with diurnal and weekly curves;
heavy-tailed session lengths; seven personas with coherent address-and-agent
identity. Asset cascades discovered by parsing each page, with a per-visit
browser cache that revalidates rather than refetches.

Measured for this run:

- **{clients['distinct_clients']:,} distinct clients**, top-10 share
  {clients['top_10_share']}, busiest made
  {clients['busiest_client_requests']:,} requests
- **{agents['distinct_agents']} distinct user agents**, top-1 share
  {agents['top_1_share']}
- Referer present on {_percent(stats['referer_share']['non_asset_requests'])}
  of non-asset requests
- Inter-arrival coefficient of variation
  {stats['inter_arrival'].get('coefficient_of_variation')}

{browser_text}

#### When it says it happened

{clock_text}

### Which tools produced the attack traffic

{tool_table}

Hand-written campaigns, each from its own address, each a phased story with
ordinary browsing interleaved:

{_table({c['name']: ('found something' if c.get('succeeds') else 'came away with nothing')
         for c in campaigns}, 'Campaign', 'Outcome') if campaigns else 'None.'}

{len(succeeded)} of {len(campaigns)} campaigns found something;
{len(failed)} did not. Attack traffic is
**{_percent(stats['attack_share'])}** of all lines.

An attack alone in a quiet window is separable on timestamp without reading a
single request, so the campaigns and tool runs are issued *concurrently* with
the ordinary traffic. Two figures, because one is not enough:

| | |
|---|---|
| Attack lines sharing their exact second with ordinary traffic | {_percent(overlap['overlapping_share'])} |
| Attack lines with ordinary traffic within ±30s | **{_percent(overlap.get('overlapping_share_within_60s', 0))}** |

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
  `{agreement.get('compared_file', 'access.log')}`: **{agreement['summary']}**
- Unmatched request ids: **{manifest['unmatched_request_ids']}**
- Of those, labelled by reserved source address:
  **{manifest['address_fallback_lines']}**
- Lines that did not parse as Combined: **{manifest['unparsed_log_lines']}**

### How to rebuild it

```bash
git checkout {manifest['commit']}
python3 tools/build.py {project} {tier}
```

The same seed reproduces the same request sequence. Timestamps and interleaving
differ between runs under real concurrency; this is not byte-identical output
and does not claim to be.

## Category shares

{_table({k: _percent(v) for k, v in stats['category_shares'].items()},
        'Category', 'Share')}

## Status distribution

{_table({k: _percent(v) for k, v in stats['status_distribution'].items()},
        'Status', 'Share')}

## Does it look generated?

{audit_text}

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

- **Attack share is {_percent(stats['attack_share'])}.** The target is 2–8%.
- **Static assets are {_percent(stats['category_shares'].get('static_asset', 0))}
  of all lines.** High, though an image-heavy shop genuinely looks like this.
- **XSS is barely visible in an access log.** The reflected payload appears in
  `%r`; retrieval of a stored payload is indistinguishable from ordinary
  browsing. Labelled by what the request was, never by what the response
  contained.
- **A successful IDOR looks exactly like a legitimate order view** — same
  status, same size, same URL shape. Only the sequence reveals it.
- **Client addresses are documentation and CGNAT ranges.** Geographic and ASN
  analysis is meaningless on this data.
- {"**The clock is reconstructed, not captured.** Session starts follow the "
   "arrival model rather than anything that was observed, and within-session "
   "spacing is inferred from each request's label. Use `access.raw.log` if "
   "you need what the server recorded."
   if clock.get("remapped") else
   "**Timestamps are the wall clock of a run that took "
   f"{span['span_seconds']:,.0f} seconds.** Nothing time-based is usable."}
- **Single-request clients are
  {_percent(clients['single_request_share'])} of clients**, far below what the
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
"""


def write(path, **kwargs):
    path.write_text(render(**kwargs), encoding="utf-8")
    return path
