"""Tests for the pure parts of the build entry point.

Everything that shells out to Docker goes through an injected runner, so this
suite is hermetic: no daemon, no network, no containers. What is worth pinning
down here is the scenario contract, the dataset naming, and the one structural
property a half-finished build depends on -- that teardown happens whatever
went wrong above it.
"""

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from tools.build import (BuildError, dataset_dir, load_scenario, run_steps,
                         validate_tier)

NOW = datetime(2026, 8, 16, 9, 0, tzinfo=timezone.utc)

SMALL_TOML = """
kind = "weblog-truth"
seed = 7
target_lines = 50000
duration_seconds = 600
attack_share_target = 0.05

[personas]
shopper = 0.4
casual = 0.4
crawler = 0.2
"""


class TestScenario(unittest.TestCase):

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.path = self.dir / "small.toml"
        self.path.write_text(SMALL_TOML)

    def test_reads_the_fields_the_build_depends_on(self):
        scenario = load_scenario(self.path)
        self.assertEqual(scenario["seed"], 7)
        self.assertEqual(scenario["kind"], "weblog-truth")
        self.assertEqual(scenario["personas"]["crawler"], 0.2)

    def test_a_scenario_without_a_seed_is_refused(self):
        # The seed is the whole reproducibility claim. A build that silently
        # invented one would produce a dataset nobody could rebuild.
        self.path.write_text("target_lines = 10\n")
        with self.assertRaises(BuildError):
            load_scenario(self.path)

    def test_a_missing_scenario_names_the_file_it_wanted(self):
        with self.assertRaises(BuildError) as caught:
            load_scenario(self.dir / "medium.toml")
        self.assertIn("medium.toml", str(caught.exception))


class TestTiers(unittest.TestCase):

    def test_small_and_medium_are_accepted(self):
        validate_tier("small")
        validate_tier("medium")

    def test_large_is_refused_rather_than_attempted(self):
        # Excluded by decision, and never exercised. Accepting it would run for
        # hours and produce something nobody had verified was buildable.
        with self.assertRaises(BuildError) as caught:
            validate_tier("large")
        self.assertIn("large", str(caught.exception))

    def test_an_unknown_tier_is_refused(self):
        with self.assertRaises(BuildError):
            validate_tier("enormous")


class TestDatasetDirectory(unittest.TestCase):

    def test_is_named_by_date_and_tier_under_the_project(self):
        path = dataset_dir(Path("/repo"), "apache-shopfront", "small", NOW)
        self.assertEqual(
            path, Path("/repo/datasets/apache-shopfront/2026-08-16-small"))


class TestRunSteps(unittest.TestCase):

    def test_steps_run_in_order(self):
        done = []
        run_steps([("a", lambda: done.append("a")),
                   ("b", lambda: done.append("b"))],
                  teardown=lambda: done.append("down"))
        self.assertEqual(done, ["a", "b", "down"])

    def test_teardown_runs_even_when_a_step_raises(self):
        # A half-built dataset with the stack still up is how the next run
        # silently inherits the previous run's log file.
        done = []

        def explode():
            raise RuntimeError("driver died")

        with self.assertRaises(RuntimeError):
            run_steps([("a", lambda: done.append("a")),
                       ("boom", explode),
                       ("c", lambda: done.append("c"))],
                      teardown=lambda: done.append("down"))

        self.assertEqual(done, ["a", "down"])

    def test_a_failure_in_teardown_does_not_mask_the_real_error(self):
        def explode():
            raise BuildError("the driver failed")

        def bad_teardown():
            raise RuntimeError("compose down also failed")

        with self.assertRaises(BuildError):
            run_steps([("boom", explode)], teardown=bad_teardown)


if __name__ == "__main__":
    unittest.main()
