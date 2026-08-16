"""Non-homogeneous Poisson arrivals with a diurnal and a weekly rhythm.

Evenly spaced requests are the loudest tell a generated log has, and a
homogeneous Poisson process fixes only half of that: the gaps become irregular
but the *rate* stays flat, so the log has no night, no weekend, and no rush
hour. Both curves are here for that reason.

Arrivals are produced by thinning (Lewis & Shedler): draw from a homogeneous
process at the highest rate the model ever reaches, then keep each candidate
with probability equal to the ratio of the real intensity to that maximum. The
result is exact rather than an approximation of the intended process, and it
needs nothing but `random`.

Stdlib only, by project rule.
"""

import math
import random
from datetime import timedelta

#: Relative traffic by hour of day, local to the shop. A trough in the small
#: hours, a lunchtime peak, and a larger evening one -- the shape retail
#: traffic actually has. Interpolated between points so the rate moves
#: smoothly rather than in steps, which would itself be a detectable artefact.
_DIURNAL = (
    0.22, 0.15, 0.11, 0.09, 0.09, 0.13,   # 00-05
    0.24, 0.45, 0.68, 0.82, 0.90, 0.96,   # 06-11
    1.02, 1.08, 1.00, 0.94, 0.92, 0.95,   # 12-17
    1.05, 1.18, 1.26, 1.14, 0.82, 0.46,   # 18-23
)

#: Monday is 0. Quieter at the weekend, and Monday a shade busier than the
#: rest of the week.
_WEEKLY = (1.06, 1.00, 1.00, 0.98, 0.95, 0.74, 0.69)

#: The largest multiplier the model can produce, used as the thinning envelope.
_PEAK = max(_DIURNAL) * max(_WEEKLY)


def diurnal(hour, minute=0):
    """Relative intensity at a time of day, interpolated between hours."""
    position = (hour + minute / 60.0) % 24
    low = int(math.floor(position))
    fraction = position - low
    return (_DIURNAL[low] * (1 - fraction)
            + _DIURNAL[(low + 1) % 24] * fraction)


def weekly(weekday):
    """Relative intensity by day of week, Monday being 0."""
    return _WEEKLY[weekday % 7]


def intensity(when, base_rate):
    """Arrivals per second at a given moment."""
    return base_rate * diurnal(when.hour, when.minute) * weekly(when.weekday())


#: Resolution of the cumulative-intensity table used by
#: `arrival_times_for_count`. One minute: the diurnal curve is interpolated
#: between hours, so it moves far too slowly for a finer grid to say anything
#: the coarser one does not.
_GRID_SECONDS = 60


def arrival_times_for_count(start, duration_seconds, count, seed):
    """Return exactly ``count`` arrival instants over a window, in order.

    `arrival_times` runs the process forward and returns however many arrivals
    it produced, which is the right thing when the *rate* is what you know.
    Sometimes the count is what you know instead -- the timestamp remap has one
    session already in hand for every start it needs, and taking a prefix of a
    thinned draw would pile every session into the beginning of the window.

    Conditioned on there being exactly n arrivals, an inhomogeneous Poisson
    process places them as n independent draws from the intensity curve treated
    as a density. So that is what this does: build the cumulative intensity,
    draw n uniforms, push them back through it, and sort. The shape is the same
    curve `arrival_times` follows; only the count is fixed rather than random.
    """
    if count <= 0:
        return []

    steps = max(1, int(math.ceil(duration_seconds / _GRID_SECONDS)))
    step = duration_seconds / steps

    # Cumulative intensity at each grid edge. base_rate cancels out once the
    # table is normalised, so it is left out rather than invented.
    cumulative = [0.0]
    for k in range(steps):
        mid = start + timedelta(seconds=(k + 0.5) * step)
        cumulative.append(cumulative[-1]
                          + diurnal(mid.hour, mid.minute) * weekly(mid.weekday())
                          * step)
    total = cumulative[-1]

    rng = random.Random(seed)
    draws = sorted(rng.random() * total for _ in range(count))

    times = []
    k = 0
    for target in draws:
        while k + 1 < steps and cumulative[k + 1] < target:
            k += 1
        band = cumulative[k + 1] - cumulative[k]
        # Linear within the band: the curve is already linear between hours.
        offset = (k + (target - cumulative[k]) / band if band else k) * step
        times.append(start + timedelta(seconds=min(offset, duration_seconds)))
    return times


def arrival_times(start, duration_seconds, base_rate, seed):
    """Return the arrival instants over a window, in order.

    Args:
        start: a timezone-aware datetime.
        duration_seconds: how long the window runs for.
        base_rate: arrivals per second at a multiplier of 1.0.
        seed: fixes the sequence.

    Returns:
        A list of datetimes. The same seed always returns the same list.
    """
    rng = random.Random(seed)
    envelope = base_rate * _PEAK
    times = []
    elapsed = 0.0

    while True:
        # Homogeneous candidate at the envelope rate.
        elapsed += rng.expovariate(envelope)
        if elapsed >= duration_seconds:
            return times
        when = start + timedelta(seconds=elapsed)
        # Keep it in proportion to how busy the model says that moment is.
        if rng.random() < intensity(when, base_rate) / envelope:
            times.append(when)
