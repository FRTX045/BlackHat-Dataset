"""Tests for the Phase B placeholder driver's request plan.

Task 15 replaces this driver with the persona-driven async one. What is worth
asserting even of a placeholder is that the plan it emits cannot produce a
truth file the validator would reject -- otherwise the first end-to-end run
fails for a reason that has nothing to do with the machinery being proved.
"""

import sys
import unittest
from pathlib import Path

from shared.truth.validate import validate_records
from shared.truth.writer import CATEGORIES

sys.path.insert(
    0, str(Path(__file__).resolve().parents[2]
           / "projects" / "apache-shopfront" / "traffic"))

from driver import plan_requests  # noqa: E402


class TestRequestPlan(unittest.TestCase):

    def setUp(self):
        self.plan = list(plan_requests())

    def test_every_category_is_in_the_controlled_vocabulary(self):
        for step in self.plan:
            with self.subTest(path=step.path):
                self.assertIn(step.category, CATEGORIES)

    def test_the_plan_would_satisfy_the_validator(self):
        # The driver states its own instance ids rather than letting the join
        # derive them, so it is the driver's job to keep episodes contiguous.
        records = [
            {"line_no": n, "client_ip": step.client_ip,
             "category": step.category, "instance_id": step.instance_id}
            for n, step in enumerate(self.plan, start=1)
        ]
        ips = [step.client_ip for step in self.plan]
        self.assertEqual(validate_records(records, ips), [])

    def test_a_new_episode_starts_when_the_activity_changes(self):
        by_client = {}
        for step in self.plan:
            previous = by_client.get(step.client_ip)
            if previous and previous.category != step.category:
                self.assertNotEqual(
                    previous.instance_id, step.instance_id,
                    f"{step.client_ip} kept one episode id across "
                    f"{previous.category} -> {step.category}")
            by_client[step.client_ip] = step

    def test_one_client_never_runs_two_sessions_at_once(self):
        # The driver assigns instance ids in its own order, not the log's. Two
        # concurrent sessions for one address would interleave in the log and
        # break episode contiguity -- correctly, and confusingly. Sequential
        # per client is the constraint that prevents it.
        seen_runs = []
        for step in self.plan:
            if not seen_runs or seen_runs[-1] != step.client_ip:
                seen_runs.append(step.client_ip)
        self.assertEqual(len(seen_runs), len(set(seen_runs)),
                         "a client's requests are not contiguous in the plan")


if __name__ == "__main__":
    unittest.main()
