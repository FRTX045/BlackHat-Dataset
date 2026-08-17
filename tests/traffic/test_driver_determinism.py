"""The plan must not depend on when the build was started.

Found by comparing two builds of the same scenario at the same seed: one
produced 75,474 lines and the next 13,032. Nothing had changed but the clock
on the wall. The driver planned its sessions from `datetime.now()`, and
`arrivals.py` thins by a diurnal curve, so a build started in the evening peak
planned five times the sessions of one started after midnight.

Both READMEs and every dataset README say the same seed reproduces the same
request sequence. It did not, and the size of the dataset was the part that
moved.

The window a run plans against is now the scenario's own -- the same window
the timestamp remap maps onto -- so the plan is a function of the scenario and
the seed and of nothing else.
"""

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "projects" / "apache-shopfront" / "traffic"))

from shared.timeline.sessions import plan_sessions  # noqa: E402
from tools.build import load_scenario  # noqa: E402

WEIGHTS = {"shopper": 0.3, "casual": 0.4, "crawler": 0.3}


def count_at(start, duration=86400, rate=0.02, seed=7):
    return len(plan_sessions(start, duration, rate, WEIGHTS, seed))


class TestThePlanIsAFunctionOfTheScenario(unittest.TestCase):

    def test_the_same_window_and_seed_give_the_same_plan(self):
        start = datetime(2026, 3, 9, tzinfo=timezone.utc)
        first = plan_sessions(start, 86400, 0.02, WEIGHTS, 7)
        second = plan_sessions(start, 86400, 0.02, WEIGHTS, 7)
        self.assertEqual([(s.persona, s.started_at, s.request_count)
                          for s in first],
                         [(s.persona, s.started_at, s.request_count)
                          for s in second])

    def test_starting_the_window_at_a_different_hour_changes_the_size(self):
        # The behaviour that caused the bug, pinned so it is understood rather
        # than rediscovered: this is correct for a *window*, and catastrophic
        # for a *build time*.
        midnight = count_at(datetime(2026, 3, 9, 0, tzinfo=timezone.utc),
                            duration=7200)
        evening = count_at(datetime(2026, 3, 9, 19, tzinfo=timezone.utc),
                           duration=7200)
        self.assertGreater(evening, midnight * 2)

    def test_a_full_day_window_is_stable_wherever_it_starts_in_the_day(self):
        # Planning across a whole day averages the diurnal curve out, so the
        # scenario's declared window gives a stable size even though any two
        # hours within it do not.
        counts = [count_at(datetime(2026, 3, 9, tzinfo=timezone.utc)
                           + timedelta(hours=h)) for h in (0, 6, 12, 18)]
        self.assertLess(max(counts) - min(counts), max(counts) * 0.25)


class TestTheShippedScenariosPlanAcrossTheirOwnWindow(unittest.TestCase):
    """The traffic window and the timeline window have to agree.

    If the driver plans two hours of arrivals and the remap spreads them over
    a week, the sessions are real but their density describes neither.
    """

    def scenarios(self):
        return sorted((REPO / "projects" / "apache-shopfront"
                       / "scenarios").glob("*.toml"))

    def test_the_traffic_window_matches_the_timeline_window(self):
        for path in self.scenarios():
            scenario = load_scenario(path)
            timeline = scenario.get("timeline", {})
            if not timeline.get("remap"):
                continue
            with self.subTest(tier=path.stem):
                self.assertEqual(scenario["traffic"]["duration_seconds"],
                                 timeline["duration_seconds"])

    def test_each_tier_plans_roughly_the_sessions_it_claims(self):
        # A cheap guard on the rate: a scenario whose rate is out by an order
        # of magnitude produces a dataset nothing like its stated target, and
        # the only way to find out was previously to build it.
        for path in self.scenarios():
            scenario = load_scenario(path)
            timeline = scenario.get("timeline", {})
            if not timeline.get("remap"):
                continue
            traffic = scenario["traffic"]
            sessions = len(plan_sessions(
                datetime.fromisoformat(timeline["start"]),
                traffic["duration_seconds"], traffic["session_rate"],
                scenario["personas"], scenario["seed"]))
            # ~53 lines per driver session, measured on a full small build:
            # 120,630 lines from 2,219 planned sessions, less the ~2,000 that
            # came from tools, campaigns and noise rather than from sessions.
            #
            # An earlier version of this constant said 33, from dividing total
            # lines by the *remap's* episode count -- which also counts tool
            # runs and each campaign phase, and is not the number of sessions
            # the driver planned.
            lines = sessions * 53
            target = scenario["target_lines"]
            with self.subTest(tier=path.stem, planned=lines):
                self.assertGreater(lines, target * 0.5)
                self.assertLess(lines, target * 2.0)


if __name__ == "__main__":
    unittest.main()
