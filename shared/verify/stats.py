"""Format-independent realism statistics.

These are the numbers a consumer should look at before trusting this data, and
the verifier prints every one of them whether they flatter the dataset or not.
Nothing here has a pass mark: a statistic that silently succeeded would be a
statistic nobody read.

Kept in `shared/` because none of it knows anything about Apache. It takes
parsed log records and truth records and counts.

Stdlib only.
"""

import collections
import math
import statistics

#: The eight categories that represent hostile activity. `browsing`,
#: `static_asset`, `api_call`, `authentication`, `crawling` and `unknown` are
#: not attacks.
ATTACK_CATEGORIES = frozenset({
    "reconnaissance", "enumeration", "injection", "path_traversal",
    "access_control", "credential_attack", "ssrf", "exploitation",
})


def _share(count, total):
    return round(count / total, 4) if total else 0.0


def status_distribution(records):
    counts = collections.Counter(r["status"] for r in records)
    total = len(records)
    return {str(code): _share(n, total) for code, n in sorted(counts.items())}


def method_distribution(records):
    counts = collections.Counter(r["method"] or "(malformed)" for r in records)
    total = len(records)
    return {m: _share(n, total) for m, n in counts.most_common()}


def client_concentration(records):
    """How unevenly requests are spread across clients.

    A flat distribution is the tell of a generated log. Note that
    `single_request_share` is measured over *log lines*, which is not the same
    thing as the address pool's draw distribution: in a log carrying asset
    cascades, a visitor who looks at one page still makes twenty requests.
    """
    counts = collections.Counter(r["client_ip"] for r in records)
    total = len(records)
    ordered = sorted(counts.values(), reverse=True)
    return {
        "distinct_clients": len(counts),
        "top_1_share": _share(ordered[0] if ordered else 0, total),
        "top_10_share": _share(sum(ordered[:10]), total),
        "single_request_share": round(
            sum(1 for n in ordered if n == 1) / len(ordered), 4)
        if ordered else 0.0,
        "busiest_client_requests": ordered[0] if ordered else 0,
    }


def user_agent_spread(records):
    counts = collections.Counter(
        r["user_agent"] for r in records if r["user_agent"])
    total = len(records)
    ordered = counts.most_common()
    return {
        "distinct_agents": len(counts),
        "top_1_share": _share(ordered[0][1] if ordered else 0, total),
        "top_10_share": _share(sum(n for _, n in ordered[:10]), total),
        "absent_share": _share(
            sum(1 for r in records if not r["user_agent"]), total),
    }


def referer_share(records):
    total = len(records)
    present = sum(1 for r in records if r["referer"])
    pages = [r for r in records
             if r["path"] and not r["path"].startswith("/assets")]
    return {
        "all_requests": _share(present, total),
        "non_asset_requests": _share(
            sum(1 for r in pages if r["referer"]), len(pages)),
    }


def response_shapes(records):
    """The classes a log is expected to contain and a generated one often lacks."""
    total = len(records)
    return {
        "not_modified_304": _share(
            sum(1 for r in records if r["status"] == 304), total),
        "partial_206": _share(
            sum(1 for r in records if r["status"] == 206), total),
        "head_requests": _share(
            sum(1 for r in records if r["method"] == "HEAD"), total),
        "options_requests": _share(
            sum(1 for r in records if r["method"] == "OPTIONS"), total),
        "malformed_requests": _share(
            sum(1 for r in records if r["method"] is None), total),
        "no_body_bytes": _share(
            sum(1 for r in records if r["bytes"] is None), total),
    }


def inter_arrival(records):
    """Shape of the gaps between requests.

    The coefficient of variation is the headline: an exponential process
    scores 1.0 and a metronome scores 0. `%t` has one-second resolution, so
    this is coarse by construction and is reported as such.
    """
    stamps = [r["ts"] for r in records]
    gaps = [(b - a).total_seconds() for a, b in zip(stamps, stamps[1:])]
    if len(gaps) < 2:
        return {"samples": len(gaps)}
    mean = statistics.mean(gaps)
    return {
        "samples": len(gaps),
        "mean_seconds": round(mean, 4),
        "coefficient_of_variation": round(
            statistics.stdev(gaps) / mean, 4) if mean else 0.0,
        "zero_gap_share": _share(sum(1 for g in gaps if g == 0), len(gaps)),
    }


def timespan(records):
    """How long the log covers, and how fast it actually ran.

    The statistic that catches a log issued as fast as the sockets allow.
    Zero-gap share cannot do it: a page load is a dozen requests inside one
    second, so that share is high on any busy real log and a threshold on it
    would be tuning against a number that means nothing on its own. A rate of
    three hundred requests a second against a small shop has no such innocent
    reading.

    `distinct_days` is here for the same reason: a log that never crosses
    midnight cannot show a diurnal cycle no matter how well the arrivals were
    modelled, and a consumer studying baselines needs to know that before they
    start rather than after.
    """
    if not records:
        return {"span_seconds": 0.0, "requests_per_second": None,
                "busiest_second_requests": 0, "distinct_days": 0}

    stamps = [r["ts"] for r in records]
    span = (max(stamps) - min(stamps)).total_seconds()
    per_second = collections.Counter(s.replace(microsecond=0) for s in stamps)
    return {
        "span_seconds": round(span, 3),
        # None rather than a division by zero, and never a fabricated number:
        # a log with no span has no rate to report.
        "requests_per_second": round(len(records) / span, 4) if span else None,
        "busiest_second_requests": max(per_second.values()),
        "distinct_days": len({s.date() for s in stamps}),
    }


def category_shares(truth_records):
    counts = collections.Counter(r["category"] for r in truth_records)
    total = len(truth_records)
    return {c: _share(n, total) for c, n in counts.most_common()}


def attack_share(truth_records):
    total = len(truth_records)
    hostile = sum(1 for r in truth_records
                  if r["category"] in ATTACK_CATEGORIES)
    return _share(hostile, total)


def episode_shape(truth_records):
    counts = collections.Counter(r["instance_id"] for r in truth_records)
    lengths = sorted(counts.values())
    if not lengths:
        return {"episodes": 0}
    return {
        "episodes": len(lengths),
        "median_length": lengths[len(lengths) // 2],
        "p99_length": lengths[min(len(lengths) - 1,
                                  int(len(lengths) * 0.99))],
        "longest": lengths[-1],
    }


#: Half-width of the window used by the second overlap measure, in seconds.
#: Reported alongside the number, because a share with no window attached is
#: not interpretable and changing it later would silently change what the
#: published figure meant.
OVERLAP_WINDOW = 30


def attack_overlap(records, truth_records):
    """Whether the attack traffic could be separated out on timing alone.

    An attack that occupies a quiet window of its own is separable by
    timestamp without reading a single request, which teaches a detector
    nothing. Two measures, because one is not enough:

    `overlapping_share` is the strict one -- attack lines sharing their exact
    second with an ordinary request. It is badly rate-dependent: a log at one
    request a second has almost no second containing two of anything, so this
    figure collapses as the log gets sparser whether or not the attack is
    well hidden. Kept because it is the tightest statement that can be made.

    `overlapping_share_within_60s` is the one that answers the question an
    analyst asks -- was ordinary traffic going on *around* this request. That
    is what makes a timestamp filter useless, and it does not move with the
    rate.
    """
    hostile_seconds = collections.Counter()
    benign_seconds = collections.Counter()
    for record, truth in zip(records, truth_records):
        bucket = record["ts"].replace(microsecond=0)
        if truth["category"] in ATTACK_CATEGORIES:
            hostile_seconds[bucket] += 1
        else:
            benign_seconds[bucket] += 1

    total_hostile = sum(hostile_seconds.values())
    if not total_hostile:
        return {"attack_lines": 0, "overlapping_share": 0.0,
                "overlapping_share_within_60s": 0.0,
                "window_seconds": OVERLAP_WINDOW * 2}

    overlapping = sum(n for second, n in hostile_seconds.items()
                      if benign_seconds.get(second))

    # One merge pass over both sorted second-lists rather than a search per
    # attack line: at a million lines the per-line binary search is the
    # difference between a second and a minute.
    benign = sorted(benign_seconds)
    near, cursor = 0, 0
    for second in sorted(hostile_seconds):
        while (cursor < len(benign)
               and (second - benign[cursor]).total_seconds() > OVERLAP_WINDOW):
            cursor += 1
        if (cursor < len(benign)
                and abs((benign[cursor] - second).total_seconds())
                <= OVERLAP_WINDOW):
            near += hostile_seconds[second]

    return {
        "attack_lines": total_hostile,
        "seconds_with_attacks": len(hostile_seconds),
        "overlapping_share": _share(overlapping, total_hostile),
        "overlapping_share_within_60s": _share(near, total_hostile),
        "window_seconds": OVERLAP_WINDOW * 2,
    }


def summarise(records, truth_records):
    """Every statistic, as one dict, for printing and for the manifest."""
    return {
        "lines": len(records),
        "status_distribution": status_distribution(records),
        "method_distribution": method_distribution(records),
        "response_shapes": response_shapes(records),
        "client_concentration": client_concentration(records),
        "user_agents": user_agent_spread(records),
        "referer_share": referer_share(records),
        "inter_arrival": inter_arrival(records),
        "timespan": timespan(records),
        "category_shares": category_shares(truth_records),
        "attack_share": attack_share(truth_records),
        "episodes": episode_shape(truth_records),
        "attack_overlap": attack_overlap(records, truth_records),
    }
