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
