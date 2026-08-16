"""The fake-log audit: how obviously generated does this log look?

Everything else in `shared/verify` describes a dataset. This asks the only
question that decides whether research done on one transfers to a real log --
whether an analyst holding it could tell.

It is pointed at our own datasets first and hardest, and it does find things:
a remapped log is perfectly ordered by construction, and `perfectly_ordered_
timestamps` fires on every one we ship. That is the point of owning the
detector rather than waiting for somebody else to run theirs.

Three rules the tells follow.

**A threshold is published with every measurement.** A verdict nobody can
check is not a finding, and a threshold that could be quietly retuned later
would make every published audit unreadable in hindsight.

**Not enough data is `inconclusive`, never `clean`.** Fifty lines from a quiet
server are perfectly ordered for innocent reasons. An audit whose empty-input
answer is "no tells found" is worse than no audit at all, because it will be
run on a file that failed to parse and believed.

**Every tell reports what it measured whether it fired or not.** Otherwise the
report says only what is wrong and never what was looked at, and a reader
cannot tell the difference between a check that passed and one that was never
written.

Works on any Combined log, ours or a third party's. Stdlib only.
"""

import collections
import ipaddress
import statistics
from typing import NamedTuple


class Tell(NamedTuple):
    name: str
    #: What was measured. None only when the log carried nothing to measure.
    measured: object
    #: The line the measurement is judged against, published so the judgement
    #: can be checked and so a later change to it is visible.
    threshold: object
    suspicious: bool
    #: True when the log was too small or too uniform to say anything. Never
    #: reported as clean.
    inconclusive: bool
    explanation: str


#: Below this many lines, most of these measurements are noise.
_MIN_LINES = 150

#: A log ordered by wall clock is unremarkable until it is long enough that a
#: concurrent server would have interleaved something.
_MIN_LINES_FOR_ORDER = 400


def _tell(name, measured, threshold, suspicious, explanation,
          inconclusive=False):
    return Tell(name=name, measured=measured, threshold=threshold,
                suspicious=bool(suspicious) and not inconclusive,
                inconclusive=bool(inconclusive), explanation=explanation)


def _too_small(name, threshold, explanation, n, floor=_MIN_LINES):
    if n >= floor:
        return None
    return _tell(name, None, threshold, False,
                 f"{explanation} Not assessed: {n} lines is below the {floor} "
                 f"this measurement needs to mean anything.",
                 inconclusive=True)


def round_response_sizes(records):
    """Byte counts of real responses are near enough uniform modulo ten.

    A generator that drew sizes from a list of round numbers leaves the most
    easily checked fingerprint in the file, and it is the first thing anybody
    looks at.
    """
    name, threshold = "round_response_sizes", 0.25
    explanation = ("Share of response sizes that are exact multiples of 100. "
                   "Real byte counts are near-uniform modulo ten, so about 1% "
                   "is expected.")
    small = _too_small(name, threshold, explanation, len(records))
    if small:
        return small

    sizes = [r["bytes"] for r in records if r.get("bytes")]
    if not sizes:
        return _tell(name, 0.0, threshold, False,
                     explanation + " No response in this log carried a body.",
                     inconclusive=True)
    share = sum(1 for s in sizes if s % 100 == 0) / len(sizes)
    return _tell(name, round(share, 4), threshold, share > threshold,
                 explanation)


def implausible_rate(records):
    """A rate no single server of this kind would sustain.

    This is the defect this project found in its own first datasets: sixty
    thousand requests inside two hundred seconds of wall clock, because the
    driver issued its whole plan as fast as the sockets allowed.
    """
    name, threshold = "implausible_rate", 50.0
    explanation = ("Mean requests per second across the log's whole span. "
                   "A small application server sustaining more than this for "
                   "the entire log is a harness, not a shop.")
    small = _too_small(name, threshold, explanation, len(records))
    if small:
        return small

    stamps = [r["ts"] for r in records]
    span = (max(stamps) - min(stamps)).total_seconds()
    if span <= 0:
        return _tell(name, None, threshold, True,
                     explanation + " Every line carries the same timestamp.")
    rate = len(records) / span
    return _tell(name, round(rate, 3), threshold, rate > threshold,
                 explanation)


def agent_monoculture(records):
    name, threshold = "agent_monoculture", 0.55
    explanation = ("Share of requests made by the single most common "
                   "User-Agent. One browser build dominating a whole log is "
                   "a population that was drawn, not observed.")
    small = _too_small(name, threshold, explanation, len(records))
    if small:
        return small

    counts = collections.Counter(r.get("user_agent") for r in records)
    top = counts.most_common(1)[0][1] / len(records)
    return _tell(name, round(top, 4), threshold, top > threshold, explanation)


def uniform_client_volumes(records):
    """Real per-client request counts are heavy-tailed.

    A handful of crawlers make thousands of requests and a very long tail of
    people look at one page and leave. A generator that gives every client a
    similar number produces a distribution with almost no spread, which is
    visible without plotting anything.
    """
    name, threshold = "uniform_client_volumes", 1.0
    explanation = ("Coefficient of variation of per-client request counts. "
                   "Real client populations are heavy-tailed and score well "
                   "above 1; an evenly-drawn one scores near 0.")
    small = _too_small(name, threshold, explanation, len(records))
    if small:
        return small

    counts = list(collections.Counter(
        r["client_ip"] for r in records).values())
    if len(counts) < 8:
        return _tell(name, None, threshold, False,
                     explanation + f" Only {len(counts)} distinct clients.",
                     inconclusive=True)
    mean = statistics.mean(counts)
    spread = statistics.stdev(counts) / mean if mean else 0.0
    return _tell(name, round(spread, 4), threshold, spread < threshold,
                 explanation)


def missing_response_classes(records):
    """A log of nothing but 200s is not a log of a web server."""
    name = "missing_response_classes"
    threshold = "304 and 404 both present"
    explanation = ("Whether the status classes every public server produces "
                   "are present. A log with no 304 has no caching, and one "
                   "with no 404 has never been crawled or mistyped at.")
    small = _too_small(name, threshold, explanation, len(records))
    if small:
        return small

    seen = {r["status"] for r in records}
    absent = [str(s) for s in (304, 404) if s not in seen]
    return _tell(name, sorted(seen)[:12], threshold, bool(absent),
                 explanation + (f" Absent here: {', '.join(absent)}."
                                if absent else " All present."))


def no_malformed_requests(records):
    """Every log that has been on a network for an hour contains junk.

    A truncated request line, a CONNECT probe, a stray non-ASCII byte. A log
    with none of it has not been on a network -- and this is one of the few
    tells that cannot be fixed by tuning a distribution, only by actually
    putting a server somewhere requests come from.
    """
    name, threshold = "no_malformed_requests", 1
    explanation = ("Count of request lines Apache could not parse into "
                   "method, path and protocol. Real logs always have some.")
    small = _too_small(name, threshold, explanation, len(records))
    if small:
        return small

    junk = sum(1 for r in records
               if r.get("method") is None or r.get("path") is None
               or "\\x" in (r.get("request") or ""))
    return _tell(name, junk, threshold, junk < threshold, explanation)


def perfectly_ordered_timestamps(records):
    """A concurrent server interleaves its writes.

    Under prefork or a thread pool, a large real log always contains a few
    lines whose timestamp precedes the line above: two processes finished in
    one order and wrote in the other. Perfect order across tens of thousands
    of lines means one writer, or a sort.

    **This fires on our own remapped logs**, which are sorted by construction.
    Published rather than excused.
    """
    name, threshold = "perfectly_ordered_timestamps", 1
    explanation = ("Count of lines whose timestamp precedes the line above "
                   "them. A concurrent server always produces a few; none at "
                   "all means a single writer, or that the file was sorted.")
    small = _too_small(name, threshold, explanation, len(records),
                       floor=_MIN_LINES_FOR_ORDER)
    if small:
        return small

    stamps = [r["ts"] for r in records]
    backwards = sum(1 for a, b in zip(stamps, stamps[1:]) if b < a)
    return _tell(name, backwards, threshold, backwards < threshold,
                 explanation)


def sequential_client_addresses(records):
    """Clients drawn by counting rather than by anything real.

    Genuine client populations are scattered across the address space; a
    generator that walked a subnet leaves a dense run of consecutive
    addresses. Measured as the share of addresses whose immediate neighbour is
    also present, which catches the walk without being confused by the two or
    three adjacent addresses a real log has.
    """
    name, threshold = "sequential_client_addresses", 0.75
    explanation = ("Share of client addresses whose numeric neighbour is also "
                   "in the log. A handful is ordinary; most of them means the "
                   "population was counted out rather than observed.")
    small = _too_small(name, threshold, explanation, len(records))
    if small:
        return small

    numeric = set()
    for record in records:
        try:
            numeric.add(int(ipaddress.ip_address(record["client_ip"])))
        except ValueError:
            continue
    if len(numeric) < 8:
        return _tell(name, None, threshold, False,
                     explanation + f" Only {len(numeric)} distinct addresses.",
                     inconclusive=True)
    adjacent = sum(1 for n in numeric if n + 1 in numeric or n - 1 in numeric)
    share = adjacent / len(numeric)
    return _tell(name, round(share, 4), threshold, share > threshold,
                 explanation)


TELLS = (
    round_response_sizes,
    implausible_rate,
    agent_monoculture,
    uniform_client_volumes,
    missing_response_classes,
    no_malformed_requests,
    perfectly_ordered_timestamps,
    sequential_client_addresses,
)


def audit(records):
    """Run every tell over a parsed log and return the findings, in order."""
    return [tell(list(records) if not isinstance(records, list) else records)
            for tell in TELLS]


def by_name(findings, name):
    for finding in findings:
        if finding.name == name:
            return finding
    raise KeyError(f"no tell called {name!r}")


def summary(findings):
    """Counts for a report header, without collapsing them into a verdict."""
    return {
        "tells_checked": len(findings),
        "tells_fired": sum(1 for f in findings if f.suspicious),
        "inconclusive": sum(1 for f in findings if f.inconclusive),
        "fired": [f.name for f in findings if f.suspicious],
    }
