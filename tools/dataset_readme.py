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

    if tool_runs:
        tool_table = "\n".join(
            ["| Tool | Version | Source IP | Invocations | What it was pointed at |",
             "|---|---|---|---|---|"]
            + [f"| {r['tool']} | {r.get('version') or 'unrecorded'} | "
               f"{r['source_ip']} | 1 | {r['target']} |" for r in tool_runs])
    else:
        tool_table = ("None — no tool-driven attacks ran in this build. The "
                      "attack traffic here is entirely hand-written, from "
                      "`attacks/playbooks.py`.")

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

No headless-browser traffic: Playwright was not built. The cascades are real
requests for real subresources, ordered by the driver rather than by Chromium.

### Which tools produced the attack traffic

{tool_table}

Hand-written campaigns, each from its own address, each a phased story with
ordinary browsing interleaved:

{_table({c['name']: ('found something' if c.get('succeeds') else 'came away with nothing')
         for c in campaigns}, 'Campaign', 'Outcome') if campaigns else 'None.'}

{len(succeeded)} of {len(campaigns)} campaigns found something;
{len(failed)} did not. Attack traffic is
**{_percent(stats['attack_share'])}** of all lines, and
{_percent(overlap['overlapping_share'])} of it shares its second with ordinary
traffic — an attack alone in a quiet window would be separable on timestamp
without reading a single request.

### How the labels were produced

Every request carries a unique `X-Request-Id`; the shipped `access.log` is the
tagged log with that prefix removed, so line N of the log and line N of
`truth.jsonl` are the same request by construction.

- Derived vs the log Apache wrote independently: **{agreement['summary']}**
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
