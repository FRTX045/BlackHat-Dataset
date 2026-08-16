"""The arrival model.

Even inter-arrival times are the single loudest tell in a generated log, so the
tests here are about the *shape* of the sequence rather than its mean. They are
statistical, and deliberately loose enough not to be flaky under a fixed seed
while still failing if the model degenerates to something regular.
"""

import math
import statistics
import unittest
from datetime import datetime, timedelta, timezone

from shared.timeline.arrivals import arrival_times, diurnal, weekly

START = datetime(2026, 3, 2, 0, 0, tzinfo=timezone.utc)   # a Monday


class TestDiurnalCurve(unittest.TestCase):

    def test_the_small_hours_are_the_quietest_part_of_the_day(self):
        self.assertLess(diurnal(4), diurnal(9))
        self.assertLess(diurnal(4), diurnal(13))
        self.assertLess(diurnal(4), diurnal(20))

    def test_there_is_a_midday_and_an_evening_peak(self):
        self.assertGreater(diurnal(13), diurnal(17))
        self.assertGreater(diurnal(20), diurnal(17))

    def test_the_curve_is_positive_everywhere(self):
        for hour in range(24):
            with self.subTest(hour=hour):
                self.assertGreater(diurnal(hour), 0)


class TestWeeklyCurve(unittest.TestCase):

    def test_the_weekend_is_quieter_than_midweek(self):
        wednesday, saturday, sunday = 2, 5, 6
        self.assertLess(weekly(saturday), weekly(wednesday))
        self.assertLess(weekly(sunday), weekly(wednesday))

    def test_the_curve_is_positive_everywhere(self):
        for day in range(7):
            with self.subTest(day=day):
                self.assertGreater(weekly(day), 0)


class TestArrivalTimes(unittest.TestCase):

    def setUp(self):
        self.times = arrival_times(START, timedelta(days=3).total_seconds(),
                                   base_rate=0.05, seed=7)

    def test_arrivals_are_produced_in_order_and_inside_the_window(self):
        self.assertGreater(len(self.times), 100)
        self.assertEqual(self.times, sorted(self.times))
        self.assertGreaterEqual(self.times[0], START)
        self.assertLess(self.times[-1], START + timedelta(days=3))

    def test_inter_arrival_times_are_far_from_regular(self):
        # The coefficient of variation of an exponential distribution is 1.0.
        # A metronomic generator scores near 0, and that is exactly the tell
        # this dataset exists to be robust against.
        gaps = [(b - a).total_seconds()
                for a, b in zip(self.times, self.times[1:])]
        cov = statistics.stdev(gaps) / statistics.mean(gaps)
        self.assertGreater(cov, 0.8, f"inter-arrival CoV is only {cov:.2f}")

    def test_the_gap_distribution_is_not_uniform(self):
        # A Kolmogorov-Smirnov statistic against the uniform CDF over the
        # observed range. Exceeding the 5% critical value means "not uniform",
        # which is what we want to be true.
        gaps = sorted((b - a).total_seconds()
                      for a, b in zip(self.times, self.times[1:]))
        n = len(gaps)
        low, high = gaps[0], gaps[-1]
        biggest = max(
            abs((i + 1) / n - (gap - low) / (high - low))
            for i, gap in enumerate(gaps))
        critical = 1.36 / math.sqrt(n)
        self.assertGreater(biggest, critical,
                           f"gaps look uniform: D={biggest:.3f} crit={critical:.3f}")

    def test_nights_are_quieter_than_days(self):
        # The whole point of a non-homogeneous model. Counted over three days
        # so one unusual night cannot carry the assertion.
        night = sum(1 for t in self.times if 2 <= t.hour < 6)
        day = sum(1 for t in self.times if 12 <= t.hour < 16)
        self.assertLess(night, day * 0.6,
                        f"{night} arrivals at night against {day} in the afternoon")

    def test_the_same_seed_gives_the_same_arrivals(self):
        again = arrival_times(START, timedelta(days=3).total_seconds(),
                              base_rate=0.05, seed=7)
        self.assertEqual(self.times, again)

    def test_a_different_seed_gives_different_arrivals(self):
        other = arrival_times(START, timedelta(days=3).total_seconds(),
                              base_rate=0.05, seed=8)
        self.assertNotEqual(self.times, other)


if __name__ == "__main__":
    unittest.main()
