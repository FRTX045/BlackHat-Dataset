"""Turn arrival instants into a plan of sessions at virtual timestamps.

The plan is made before anything is issued, and it is the authority the
medium-tier timestamp remap uses later. Deciding the shape up front rather than
as requests go out is what makes a run reproducible from its seed and what lets
the remap stretch idle gaps without touching the timing inside a session.

Stdlib only, by project rule.
"""

import random
from datetime import timedelta
from typing import NamedTuple

from shared.timeline.arrivals import arrival_times

#: Personas whose arrivals do not follow the human diurnal curve.
#:
#: An uptime monitor polls on a timer and contributes as many lines at 04:00 as
#: at 20:00. Search, SEO and AI crawlers work to their own schedules. And
#: opportunistic scanning is, if anything, busier at night. Leaving these on
#: the human curve gave a finished log a peak-to-trough ratio of 26.8 against
#: a real-world 5-10, because the small hours came out genuinely empty rather
#: than bot-dominated.
ROUND_THE_CLOCK = frozenset({"monitor", "crawler", "scanner"})

#: Pareto exponent for session length. Chosen so the median visit is a couple
#: of pages and the long tail reaches the dozens: measured over 20,000 draws
#: the median is 2 and the 99th percentile is in the sixties.
_LENGTH_ALPHA = 1.1

#: Nobody's visit is unbounded, and a single session that ran to thousands of
#: requests would distort every per-client statistic in the dataset.
_LENGTH_CAP = 400


class Session(NamedTuple):
    index: int
    persona: str
    started_at: object
    request_count: int


def session_length(rng):
    """Draw a heavy-tailed request count for one visit.

    Most people look at one or two pages and leave; a few work through dozens.
    A normal or uniform draw here would give every visitor about the same
    appetite, which no real log has.
    """
    draw = 1.0 + int(1.0 / (rng.random() ** (1.0 / _LENGTH_ALPHA)))
    return min(draw, _LENGTH_CAP)


def _pick(rng, weights):
    """Weighted choice over a dict, in a fixed key order so seeds reproduce."""
    names = sorted(weights)
    total = sum(weights[n] for n in names)
    point = rng.random() * total
    for name in names:
        point -= weights[name]
        if point <= 0:
            return name
    return names[-1]


def plan_sessions(start, duration_seconds, base_rate, persona_weights, seed):
    """Plan every session in the window, in order.

    Args:
        start: timezone-aware datetime for the beginning of the window.
        duration_seconds: length of the window.
        base_rate: session arrivals per second at a multiplier of 1.0.
        persona_weights: {persona name: relative weight}.
        seed: fixes the whole plan.

    Returns:
        A list of Sessions ordered by start time.
    """
    starts = arrival_times(start, duration_seconds, base_rate, seed)

    # A separate stream from the arrival one, so changing the persona mixture
    # does not shuffle the arrival instants and vice versa. Two runs that
    # differ in one dimension should differ only in that dimension.
    rng = random.Random(seed ^ 0x5F5E1)

    # A third stream, for re-placing the automated personas. Separate again so
    # that adding one does not move any human session.
    flat = random.Random(seed ^ 0xA5A5A5)

    sessions = []
    for index, when in enumerate(starts):
        persona = _pick(rng, persona_weights)
        if persona in ROUND_THE_CLOCK:
            # Redrawn uniformly across the window rather than kept on the
            # diurnal curve. An uptime check does not sleep, a crawler works
            # to its own schedule, and opportunistic scanning is if anything
            # night-heavy.
            #
            # Measured before this existed: every persona on the human curve
            # gave the finished log a peak-to-trough ratio of 26.8. Real
            # e-commerce logs sit nearer 5-10, and the reason is precisely
            # that the small hours are not empty -- they are bot-dominated. A
            # detector trained on genuinely empty nights learns that any 4am
            # traffic is suspicious, which is the opposite of the truth.
            when = start + timedelta(
                seconds=flat.uniform(0, duration_seconds))
        sessions.append(Session(index=index, persona=persona, started_at=when,
                                request_count=session_length(rng)))

    # Back into time order: the redraw moved some of them, and every consumer
    # of this plan expects it ordered by start.
    sessions.sort(key=lambda s: s.started_at)
    return [s._replace(index=index) for index, s in enumerate(sessions)]
