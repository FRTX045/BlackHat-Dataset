"""Session scheduling.

Sessions are planned at virtual timestamps from the start of the run. That plan
is the authority the medium-tier timestamp remap uses later, so it has to be
deterministic and it has to have a realistic shape before anything is issued.
"""

import statistics
import unittest
from datetime import datetime, timedelta, timezone

from shared.timeline.sessions import plan_sessions, session_length

START = datetime(2026, 3, 2, 0, 0, tzinfo=timezone.utc)

PERSONAS = {"casual": 0.35, "shopper": 0.30, "mobile": 0.15,
            "returning": 0.10, "crawler": 0.07, "monitor": 0.03}


class TestSessionLength(unittest.TestCase):

    def setUp(self):
        import random
        rng = random.Random(7)
        self.lengths = sorted(session_length(rng) for _ in range(20000))

    def test_the_typical_visit_is_short(self):
        median = statistics.median(self.lengths)
        self.assertLessEqual(median, 3, f"median visit is {median} requests")

    def test_a_few_visits_are_very_long(self):
        p99 = self.lengths[int(len(self.lengths) * 0.99)]
        self.assertGreater(p99, 40, f"99th percentile is only {p99} requests")

    def test_every_session_makes_at_least_one_request(self):
        self.assertGreaterEqual(self.lengths[0], 1)


class TestPlanSessions(unittest.TestCase):

    def setUp(self):
        self.sessions = plan_sessions(
            START, timedelta(days=3).total_seconds(), base_rate=0.05,
            persona_weights=PERSONAS, seed=7)

    def test_sessions_are_scheduled_in_order_from_the_start(self):
        self.assertGreater(len(self.sessions), 50)
        starts = [s.started_at for s in self.sessions]
        self.assertEqual(starts, sorted(starts))
        self.assertGreaterEqual(starts[0], START)

    def test_every_persona_in_the_mixture_actually_appears(self):
        seen = {s.persona for s in self.sessions}
        self.assertEqual(seen, set(PERSONAS))

    def test_personas_appear_roughly_in_their_configured_proportions(self):
        total = len(self.sessions)
        for persona, weight in PERSONAS.items():
            share = sum(1 for s in self.sessions if s.persona == persona) / total
            with self.subTest(persona=persona):
                self.assertAlmostEqual(share, weight, delta=0.05)

    def test_sessions_carry_a_request_count(self):
        self.assertTrue(all(s.request_count >= 1 for s in self.sessions))

    def test_the_same_seed_gives_an_identical_plan(self):
        again = plan_sessions(
            START, timedelta(days=3).total_seconds(), base_rate=0.05,
            persona_weights=PERSONAS, seed=7)
        self.assertEqual(self.sessions, again)

    def test_the_plan_spans_the_whole_window_not_just_the_beginning(self):
        span = self.sessions[-1].started_at - self.sessions[0].started_at
        self.assertGreater(span, timedelta(days=2))


if __name__ == "__main__":
    unittest.main()
