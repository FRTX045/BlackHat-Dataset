"""Rewrite a captured log's timestamps onto a realistic clock.

The driver plans its sessions across hours of virtual time and then issues the
whole plan as fast as the sockets allow. The *sequence* that comes out is
right -- every session, every cascade, every campaign phase in the order it
was meant to happen -- and the *timing* is not. A small run puts sixty
thousand requests inside about two hundred seconds of wall clock, with 99.7%
of consecutive lines sharing a second. Nothing time-based can be studied on
that: no rate limiting, no burst detection, no session reconstruction, no
diurnal baseline.

This module fixes the clock and touches nothing else.

**It is a rewrite, and it is never presented as a capture.** A dataset that
remaps ships `access.raw.log` beside `access.log` -- the bytes Apache actually
wrote, timestamps and all -- and its manifest and README say plainly which is
which. The raw log is what the derived-vs-Apache agreement check runs against,
because that check is about the labelling mechanism and would be meaningless
against a file whose timestamps and order have deliberately changed.

What survives, exactly:

- every line, byte for byte apart from the bracketed timestamp field
- every truth record, re-numbered but otherwise untouched
- the pairing between line N and record N
- the order of requests *within* a session
- one session per client at a time, so episode groups stay contiguous

What changes:

- when each session starts -- drawn from the same diurnal and weekly curves
  the driver plans against, so the finished log has a night and a rush hour
- the spacing between requests inside a session, reconstructed from what each
  request *was*: an image follows its page in milliseconds, a person reads for
  a few seconds before clicking again, an operator waits longer than that
  because they are reading what came back

That last one is inference, not measurement, and it is the honest limit of
this module: the captured log's sub-second structure is almost entirely gone,
so the labels are the only signal left to rebuild pacing from. Said out loud
here, in the manifest, and in every dataset README that ships a remapped log.

Stdlib only, by project rule.
"""

import random
from datetime import datetime, timedelta
from typing import NamedTuple

from shared.verify.combined import LINE_RE

#: The format Apache writes and this module reads back. Fixed here rather than
#: taken from the locale for the same reason `_MONTHS` is written out below.
_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"

#: Written out rather than taken from strftime: %b is locale-dependent, and a
#: build on a machine set to another language would emit month names no
#: Combined parser in the world accepts.
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

#: Subresources of the page before them. A browser opens several connections
#: at once, so these overlap rather than queue.
_CASCADE = {
    "static_asset": (0.008, 0.30),
    "api_call": (0.05, 1.10),
}

#: Somebody reading a page and then clicking. Lognormal because think time
#: has a long right tail -- most clicks come quickly, a few come after the
#: reader has gone to make tea -- and a uniform draw would give the log a
#: flat gap distribution no human produces.
_HUMAN = {"browsing", "authentication", "crawling"}
_HUMAN_SHAPE = (1.65, 0.90, 240.0)      # mu, sigma, ceiling in seconds

#: An operator reading a response and deciding what to send next. Slower than
#: a shopper and much slower than a tool.
_OPERATOR_SHAPE = (2.20, 0.80, 400.0)

#: Everything left over, including Apache's own dummy connections.
_OTHER = (0.4, 4.0)

#: Two sessions from one address must not overlap, or the episode groups stop
#: being contiguous and the truth file stops being checkable. This is the
#: smallest gap left between one session ending and the next beginning.
_SESSION_GAP = 30.0

#: Categories whose episodes are placed uniformly across the window rather
#: than on the diurnal curve.
#:
#: An uptime monitor polls on a timer and contributes as many lines at 04:00 as
#: at 20:00; search, SEO and AI crawlers work to their own schedules; and
#: opportunistic scanning is if anything night-heavy. Placing them on the
#: shoppers' curve makes the small hours genuinely empty, when in a real log
#: they are bot-dominated -- and makes every attack in the dataset happen
#: during business hours.
#:
#: Measured before this existed: the finished log's small hours were 6.4%
#: automated against 20.7% in the evening peak, which is exactly backwards. A
#: detector trained on that learns that any traffic at 4am is suspicious.
#:
#: **This module is the only thing that decides when anything in the shipped
#: log happened.** The session planner was taught the same lesson first and it
#: changed nothing, because the remap discards the planner's times entirely.
ROUND_THE_CLOCK = frozenset({
    "crawling",
    "reconnaissance", "enumeration", "injection", "path_traversal",
    "access_control", "credential_attack", "ssrf", "exploitation",
})


class RemapReport(NamedTuple):
    lines: int
    episodes: int
    original_span_seconds: float
    new_span_seconds: float
    #: Sessions whose drawn start collided with the same client's previous
    #: session and had to be pushed later. A large number here means the
    #: window is too short for the traffic in it.
    episodes_pushed: int
    unparsed_lines: int
    start: str
    end: str
    description: str


def _stamp(when):
    return (f"{when.day:02d}/{_MONTHS[when.month - 1]}/{when.year}:"
            f"{when.hour:02d}:{when.minute:02d}:{when.second:02d} "
            f"{when.strftime('%z')}")


def _rewrite(line, match, when):
    """Replace only the bracketed timestamp, by span, leaving the rest alone.

    Splicing by the match's own span rather than searching for a bracket means
    a request line containing "[" cannot move the edit somewhere else.
    """
    lo, hi = match.span("ts")
    return line[:lo] + _stamp(when) + line[hi:]


def _gap(rng, category):
    if category in _CASCADE:
        return rng.uniform(*_CASCADE[category])
    if category in _HUMAN:
        mu, sigma, ceiling = _HUMAN_SHAPE
    elif category in ("unknown",):
        return rng.uniform(*_OTHER)
    else:
        mu, sigma, ceiling = _OPERATOR_SHAPE
    return min(rng.lognormvariate(mu, sigma), ceiling)


def _episodes(records):
    """Group line indices into sessions: a contiguous run of one instance_id
    for one client. Grouping by the id alone would silently merge two sessions
    that reused it, which `validate_records` forbids but this module should
    not depend on having been checked first."""
    groups, current, active = [], {}, {}
    for index, record in enumerate(records):
        ip = record.get("client_ip")
        instance = record.get("instance_id")
        if active.get(ip) != instance:
            active[ip] = instance
            current[ip] = len(groups)
            groups.append((ip, []))
        groups[current[ip]][1].append(index)
    return groups




def remap_records(lines, records, *, start, duration_seconds, seed):
    """Return ``(new_lines, new_records, RemapReport)``.

    Args:
        lines: the log, in order, as strings without line endings.
        records: one truth record per line, in the same order.
        start: timezone-aware datetime the rewritten log begins at. Its offset
            is the one written into every line.
        duration_seconds: how long the rewritten log should span.
        seed: fixes both the session starts and the within-session pacing.

    Raises:
        ValueError: if the counts disagree, or if any record names a different
            address from its line. Either means the pairing this whole project
            rests on is already broken, and carrying it forward quietly would
            put a wrong label on every line after it.
    """
    from shared.timeline.arrivals import arrival_times_for_count

    if len(lines) != len(records):
        raise ValueError(
            f"the log has {len(lines)} lines but the truth file has "
            f"{len(records)} records; they must correspond one to one")

    matches = [LINE_RE.match(line.rstrip("\r\n")) for line in lines]
    unparsed = sum(1 for m in matches if m is None)

    for index, (match, record) in enumerate(zip(matches, records), 1):
        if match and match.group("client_ip") != record.get("client_ip"):
            raise ValueError(
                f"line {index}: the log says {match.group('client_ip')!r} but "
                f"the truth record says {record.get('client_ip')!r}")

    original = [m.group("ts") for m in matches if m]
    groups = _episodes(records)

    # One draw per session from the arrival curve, handed out in a **shuffled**
    # order, then sorted back into place within each address.
    #
    # Each of those three steps is answering a specific way of getting this
    # wrong, all three found by measuring a build rather than by reasoning:
    #
    # Assigning the draws in capture order stamps the harness's own schedule
    # onto the clock. The campaigns start with the driver and finish early and
    # the noise generator runs last, so every campaign landed in the same hour
    # of the rewritten day -- and because attack sessions are short, that hour
    # got a hole in its ordinary traffic too. Measured: 44% of all attack
    # lines inside two hours, sitting in the deepest trough of the day.
    # Shuffling is what breaks that correlation.
    #
    # Drawing once per *address* instead, and keeping each address's internal
    # spacing from the capture, looks like the more faithful thing and is not:
    # `ippools` reuses addresses hard, so an address is not one actor but a
    # succession of unrelated visitors spanning the whole run. Anchoring on
    # the first of them made almost every address as long as the window, which
    # then had to be pulled back to fit -- and 651 requests landed on the
    # first second of the log.
    #
    # Sorting each address's own draws back into capture order costs nothing
    # and buys the one ordering guarantee that matters: an operator's phases
    # come out in the order they were worked, and one address never has two
    # sessions open at once.
    # Automated episodes are placed uniformly, human ones on the curve. An
    # episode counts as automated when most of its lines are, which is what
    # makes a crawler's occasional non-crawling request harmless.
    automated = [
        sum(1 for i in indices
            if records[i].get("category") in ROUND_THE_CLOCK) * 2 > len(indices)
        for _, indices in groups]

    rng = random.Random(seed ^ 0x5F3759DF)
    human_anchors = arrival_times_for_count(
        start, duration_seconds, sum(1 for a in automated if not a), seed)
    rng.shuffle(human_anchors)
    auto_anchors = [start + timedelta(seconds=rng.uniform(0, duration_seconds))
                    for a in automated if a]

    anchors, human_i, auto_i = [], iter(human_anchors), iter(auto_anchors)
    for is_auto in automated:
        anchors.append(next(auto_i) if is_auto else next(human_i))

    per_client = {}
    for position, (ip, _) in enumerate(groups):
        per_client.setdefault(ip, []).append(position)
    assigned = [None] * len(groups)
    for positions in per_client.values():
        for position, drawn in zip(positions,
                                   sorted(anchors[p] for p in positions)):
            assigned[position] = drawn

    pushed = 0
    when_at = [None] * len(lines)
    ends = {}

    for (ip, indices), drawn in zip(groups, assigned):
        earliest = ends.get(ip)
        if earliest is not None and drawn < earliest:
            drawn = earliest
            pushed += 1
        clock = drawn
        for position, index in enumerate(indices):
            if position:
                clock = clock + timedelta(
                    seconds=_gap(rng, records[index].get("category")))
            when_at[index] = clock
        ends[ip] = clock + timedelta(seconds=_SESSION_GAP)

    # Stable by construction: ties keep the original index, so requests that
    # land in the same second come out in the order they were made.
    order = sorted(range(len(lines)), key=lambda i: (when_at[i], i))

    new_lines, new_records = [], []
    for position, index in enumerate(order, 1):
        match = matches[index]
        new_lines.append(_rewrite(lines[index], match, when_at[index])
                         if match else lines[index])
        new_records.append(dict(records[index], line_no=position))

    stamps = [when_at[i] for i in order]
    span = (stamps[-1] - stamps[0]).total_seconds() if stamps else 0.0
    return new_lines, new_records, RemapReport(
        lines=len(lines),
        episodes=len(groups),
        original_span_seconds=_span_of(original),
        new_span_seconds=span,
        episodes_pushed=pushed,
        unparsed_lines=unparsed,
        start=stamps[0].isoformat() if stamps else start.isoformat(),
        end=stamps[-1].isoformat() if stamps else start.isoformat(),
        description=(
            "Timestamps were rewritten: session starts redrawn from the "
            "diurnal and weekly curves, spacing within a session "
            "reconstructed from what each request was. Every other byte of "
            "every line, and the order of requests within a session, is as "
            "captured. access.raw.log is the log Apache wrote."),
    )


def _span_of(stamps):
    if len(stamps) < 2:
        return 0.0
    try:
        first = datetime.strptime(stamps[0], _TS_FMT)
        last = datetime.strptime(stamps[-1], _TS_FMT)
    except ValueError:
        return 0.0
    return (last - first).total_seconds()


def remap_files(log_path, truth_path, out_log, out_truth, *,
                start, duration_seconds, seed):
    """Remap a log and its truth file on disk, header preserved.

    The whole log is held in memory: the sort is global, so there is no
    streaming version of this. At the medium tier that is roughly 200 MB of
    line strings plus the per-line bookkeeping. Stated rather than hidden --
    a claim of streaming this module does not do would be worse than the cost.
    """
    import json

    from shared.truth.reader import read_truth

    lines = log_path.read_text(encoding="utf-8",
                               errors="replace").splitlines()
    header, records = read_truth(truth_path)
    new_lines, new_records, report = remap_records(
        lines, list(records), start=start,
        duration_seconds=duration_seconds, seed=seed)

    out_log.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    with open(out_truth, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(header, separators=(",", ":")) + "\n")
        for record in new_records:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")
    return report
