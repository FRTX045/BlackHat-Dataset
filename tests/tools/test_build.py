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

from shared.timeline.remap import RemapReport
from tools.build import (BuildError, dataset_dir, load_scenario, run_steps,
                         timestamp_block, validate_tier)

REPO = Path(__file__).resolve().parents[2]

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


class TestTheShippedScenarios(unittest.TestCase):
    """The scenario files that actually ship, not fixtures.

    A tier whose TOML is wrong fails fifteen minutes into a Docker build, on a
    machine that has already started containers. Cheaper to catch here.
    """

    def scenarios(self):
        return sorted(
            (REPO / "projects" / "apache-shopfront" / "scenarios").glob("*.toml"))

    def test_every_tier_named_by_the_build_has_a_file(self):
        from tools.build import TIERS
        names = {p.stem for p in self.scenarios()}
        self.assertEqual(set(TIERS) - names, set())

    def test_each_one_loads_and_declares_a_seed(self):
        for path in self.scenarios():
            with self.subTest(tier=path.stem):
                self.assertIsInstance(load_scenario(path)["seed"], int)

    def test_the_two_tiers_do_not_share_a_seed(self):
        # They would produce the same catalogue and the same session plan at
        # different lengths, and the medium tier would be a longer recording
        # of the small one rather than an independent sample.
        seeds = [load_scenario(p)["seed"] for p in self.scenarios()]
        self.assertEqual(len(seeds), len(set(seeds)))

    def test_a_remapping_tier_gives_the_remap_everything_it_needs(self):
        for path in self.scenarios():
            timeline = load_scenario(path).get("timeline", {})
            if not timeline.get("remap"):
                continue
            with self.subTest(tier=path.stem):
                start = datetime.fromisoformat(timeline["start"])
                self.assertIsNotNone(start.tzinfo,
                                     "the start must carry an offset, because "
                                     "Apache writes one on every line")
                self.assertGreater(timeline["duration_seconds"], 0)

    def test_every_tool_a_scenario_asks_for_is_declared(self):
        # Otherwise the build fails fifteen minutes in, with containers up.
        import sys
        sys.path.insert(0, str(REPO / "projects" / "apache-shopfront"
                               / "attacks"))
        from toolruns import TOOL_RUNS
        declared = {run.name for run in TOOL_RUNS}
        for path in self.scenarios():
            asked = load_scenario(path).get("attacks", {}).get("tools", [])
            with self.subTest(tier=path.stem):
                self.assertEqual(set(asked) - declared, set())

    def test_every_campaign_a_scenario_asks_for_exists(self):
        import sys
        sys.path.insert(0, str(REPO / "projects" / "apache-shopfront"
                               / "attacks"))
        from campaigns import CAMPAIGNS
        known = {c.name for c in CAMPAIGNS}
        for path in self.scenarios():
            asked = load_scenario(path).get("attacks", {}).get("campaigns", [])
            with self.subTest(tier=path.stem):
                self.assertEqual(set(asked) - known, set())

    def test_hydra_is_declared_but_deliberately_not_scheduled(self):
        # Its http-post-form module blocks against a login that answers 401
        # with no WWW-Authenticate header, producing about one request per
        # run. Pinned here so it is not quietly re-added without someone
        # noticing that it contributes nothing.
        import sys
        sys.path.insert(0, str(REPO / "projects" / "apache-shopfront"
                               / "attacks"))
        from toolruns import TOOL_RUNS
        self.assertIn("hydra-login", {r.name for r in TOOL_RUNS})
        for path in self.scenarios():
            asked = load_scenario(path).get("attacks", {}).get("tools", [])
            with self.subTest(tier=path.stem):
                self.assertNotIn("hydra-login", asked)

    def test_persona_weights_are_a_distribution(self):
        for path in self.scenarios():
            weights = load_scenario(path).get("personas", {})
            with self.subTest(tier=path.stem):
                self.assertAlmostEqual(sum(weights.values()), 1.0, places=6)


class TestTheManifestSaysWhatHappenedToTheClock(unittest.TestCase):
    """Whether the clock was rewritten has to be readable from the manifest.

    A remapped log that does not say so will be read as a capture, and every
    timing conclusion drawn from it will be wrong in a way nothing in the file
    contradicts. This is the one place that can be stated once and machine-read.
    """

    REPORT = RemapReport(
        lines=1000, episodes=40, original_span_seconds=203.0,
        new_span_seconds=85_910.0, episodes_pushed=3, unparsed_lines=0,
        start="2026-03-09T00:04:11+00:00", end="2026-03-09T23:56:01+00:00",
        description="Timestamps were rewritten: ...")

    def test_a_captured_clock_says_so_and_names_the_shipped_log(self):
        block = timestamp_block(None)
        self.assertFalse(block["remapped"])
        self.assertEqual(block["capture_file"], "access.log")
        self.assertIn("as Apache wrote them", block["note"])

    def test_a_rewritten_clock_names_the_capture_it_came_from(self):
        block = timestamp_block(self.REPORT)
        self.assertTrue(block["remapped"])
        self.assertEqual(block["capture_file"], "access.raw.log")
        self.assertEqual(block["capture_truth_file"], "truth.raw.jsonl")

    def test_it_publishes_both_spans_so_the_rewrite_can_be_judged(self):
        block = timestamp_block(self.REPORT)
        self.assertEqual(block["captured_span_seconds"], 203.0)
        self.assertEqual(block["span_seconds"], 85_910.0)

    def test_it_publishes_how_many_sessions_had_to_be_pushed(self):
        # Not cosmetic: pushed sessions are ones the arrival curve did not
        # place, so a large share means the window is too short for the
        # traffic and the diurnal shape has been flattened.
        self.assertEqual(timestamp_block(self.REPORT)["sessions_pushed"], 3)

    def test_the_block_is_json_serialisable(self):
        import json
        json.dumps(timestamp_block(self.REPORT))
        json.dumps(timestamp_block(None))


class TestToolRunsAreRecordedHonestly(unittest.TestCase):
    """A tool that ran and reached nothing must not look like one that worked.

    This is the same mistake the attack runner made once: 170 consecutive
    connection timeouts were written into the ledger as completed attacks
    because the OSError was being swallowed, and the dataset claimed attacks
    that had never happened. A tool run is easier to get wrong, because most
    of them exit non-zero on a perfectly good run.
    """

    def run_for(self, name="whatweb-root"):
        import sys
        sys.path.insert(0, str(REPO / "projects" / "apache-shopfront"
                               / "attacks"))
        from toolruns import TOOL_RUNS
        return next(r for r in TOOL_RUNS if r.name == name)

    def record(self, **overrides):
        from tools.build import tool_run_record
        fields = dict(version="0.5.5-1", command="whatweb -a 3 http://...",
                      started_at=NOW, finished_at=NOW, exit_code=0,
                      requests=412)
        fields.update(overrides)
        return tool_run_record(self.run_for(), **fields)

    def test_it_carries_what_the_readme_table_needs(self):
        record = self.record()
        for field in ("tool", "version", "source_ip", "target"):
            self.assertTrue(record[field], f"{field} is empty")

    def test_the_source_address_is_the_declared_one(self):
        self.assertEqual(self.record()["source_ip"], self.run_for().address)

    def test_it_records_how_many_requests_the_proxy_actually_saw(self):
        self.assertEqual(self.record()["requests"], 412)

    def test_being_cut_off_is_recorded_rather_than_smoothed_over(self):
        # 124 is what `timeout` returns. It changes how the line count should
        # be read, so a consumer has to be able to see it.
        self.assertTrue(self.record(exit_code=124)["timed_out"])
        self.assertFalse(self.record(exit_code=1)["timed_out"])

    def test_a_clean_exit_with_no_requests_is_still_a_failure(self):
        from tools.build import tools_that_reached_nothing
        records = [self.record(requests=412), self.record(requests=0)]
        self.assertEqual(len(tools_that_reached_nothing(records)), 1)

    def test_nothing_is_flagged_when_every_tool_reached_the_server(self):
        from tools.build import tools_that_reached_nothing
        self.assertEqual(tools_that_reached_nothing([self.record()]), [])


class TestCountingWhatTheProxySaw(unittest.TestCase):

    def ledger(self, *lines):
        path = Path(tempfile.mkdtemp()) / "tagproxy.jsonl"
        path.write_text("\n".join(lines) + "\n")
        return path

    def test_it_counts_per_source_address(self):
        from tools.build import _requests_by_source
        counts = _requests_by_source(self.ledger(
            '{"client_ip": "192.0.2.31", "path": "/"}',
            '{"client_ip": "192.0.2.31", "path": "/a"}',
            '{"client_ip": "192.0.2.32", "path": "/b"}'))
        self.assertEqual(counts, {"192.0.2.31": 2, "192.0.2.32": 1})

    def test_a_ledger_that_was_never_written_counts_as_nothing(self):
        # Which then trips the reached-nothing check, rather than passing for
        # want of evidence.
        from tools.build import _requests_by_source
        self.assertEqual(_requests_by_source(Path("/nonexistent/x.jsonl")), {})

    def test_a_truncated_final_line_does_not_lose_the_whole_count(self):
        from tools.build import _requests_by_source
        counts = _requests_by_source(self.ledger(
            '{"client_ip": "192.0.2.31"}', '{"client_ip": "192.0'))
        self.assertEqual(counts, {"192.0.2.31": 1})


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
