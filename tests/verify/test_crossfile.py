"""Checks on the relationships *between* the files a dataset ships.

`validate_records` checks a truth file against its own log. That leaves the
questions a remapped dataset actually raises unanswered: is the shipped log
really the capture with only its timestamps changed, do both truth files
describe their own log, is the committed sample genuinely a slice of what it
claims to be.

Every one of these would let a real corruption through. A remap that dropped a
line, reordered within a session, or rewrote something other than the
timestamp field would pass every check that existed before this module.
"""

import json
import tempfile
import unittest
from pathlib import Path

from shared.verify.crossfile import check_dataset

LINE = ('{ip} - - [{ts}] "GET {path} HTTP/1.1" 200 {size} "-" "UA/1"')
TS = "09/Mar/2026:0{h}:00:0{s} +0000"


def line(ip="203.0.113.5", h=1, s=0, path="/", size=1200):
    return LINE.format(ip=ip, ts=TS.format(h=h, s=s), path=path, size=size)


def truth_file(records, source="access.log"):
    header = {"kind": "weblog-truth", "version": 1, "scenario": "x",
              "seed": 7, "source_file_id": source, "granularity": "category",
              "generated_at": "2026-03-09T00:00:00+00:00"}
    return "\n".join([json.dumps(header)] + [json.dumps(r) for r in records]) + "\n"


def a_dataset(*, remapped=True, break_it=None):
    """A minimal but complete dataset. `break_it` corrupts one thing."""
    d = Path(tempfile.mkdtemp())
    ips = ["203.0.113.5", "203.0.113.6", "203.0.113.7", "203.0.113.5"]

    raw = [line(ip=ip, h=1, s=i) for i, ip in enumerate(ips)]
    # The shipped log: same lines, different timestamps. When no remap ran,
    # access.log *is* the capture -- there is no second file and nothing was
    # rewritten.
    shipped = ([line(ip=ip, h=h, s=0) for h, ip in zip((2, 4, 6, 8), ips)]
               if remapped else list(raw))

    if break_it == "extra_line":
        shipped.append(line(ip="203.0.113.9", h=9))
    if break_it == "changed_body":
        shipped[0] = line(ip=ips[0], h=2, path="/tampered")
    if break_it == "backwards":
        shipped = list(reversed(shipped))

    records = [{"line_no": i + 1, "client_ip": ip, "category": "browsing",
                "instance_id": f"{ip}-1"} for i, ip in enumerate(ips)]

    (d / "access.log").write_text("\n".join(shipped) + "\n")
    (d / "truth.jsonl").write_text(truth_file(records))
    (d / "access.apache.log").write_text("\n".join(raw) + "\n")
    (d / "access.tagged.log").write_text(
        "\n".join(f"id{i} {x}" for i, x in enumerate(raw)) + "\n")

    if remapped:
        (d / "access.raw.log").write_text("\n".join(raw) + "\n")
        (d / "truth.raw.jsonl").write_text(
            truth_file(records, "access.raw.log"))

    sample = shipped[1:3]
    if break_it == "sample_not_a_slice":
        sample = [shipped[0], shipped[2]]
    (d / "sample.log").write_text("\n".join(sample) + "\n")
    (d / "sample.truth.jsonl").write_text(truth_file(
        [{"line_no": i + 1, "client_ip": ip, "category": "browsing",
          "instance_id": f"{ip}-1"}
         for i, ip in enumerate(ips[1:3])], "sample.log"))
    return d


class TestACleanDatasetPasses(unittest.TestCase):

    def test_nothing_is_reported(self):
        self.assertEqual(check_dataset(a_dataset()), [])

    def test_a_dataset_without_a_remap_is_still_checked(self):
        problems = check_dataset(a_dataset(remapped=False))
        self.assertEqual(problems, [])


class TestItCatchesCorruption(unittest.TestCase):

    def test_a_line_added_by_the_remap(self):
        problems = check_dataset(a_dataset(break_it="extra_line"))
        self.assertTrue(any("line count" in p for p in problems), problems)

    def test_a_line_whose_body_the_remap_changed(self):
        # The remap must rewrite the timestamp field and nothing else. This is
        # the check that would catch it rewriting anything else.
        problems = check_dataset(a_dataset(break_it="changed_body"))
        self.assertTrue(any("permutation" in p for p in problems), problems)

    def test_a_shipped_log_whose_timestamps_go_backwards(self):
        problems = check_dataset(a_dataset(break_it="backwards"))
        self.assertTrue(any("backwards" in p for p in problems), problems)

    def test_a_sample_that_is_not_a_contiguous_slice(self):
        problems = check_dataset(a_dataset(break_it="sample_not_a_slice"))
        self.assertTrue(any("sample" in p for p in problems), problems)


class TestItDoesNotInventProblems(unittest.TestCase):

    def test_a_missing_optional_file_is_not_a_failure(self):
        # A dataset built before the sample existed, or one whose release
        # assets have been cleaned up, is incomplete rather than corrupt.
        d = a_dataset()
        (d / "sample.log").unlink()
        (d / "sample.truth.jsonl").unlink()
        self.assertEqual(check_dataset(d), [])

    def test_every_problem_names_the_file_it_is_about(self):
        for broken in ("extra_line", "changed_body", "sample_not_a_slice"):
            for problem in check_dataset(a_dataset(break_it=broken)):
                with self.subTest(broken=broken, problem=problem):
                    self.assertTrue(any(name in problem for name in
                                        ("access.log", "access.raw.log",
                                         "sample.log", "truth")),
                                    problem)


if __name__ == "__main__":
    unittest.main()
