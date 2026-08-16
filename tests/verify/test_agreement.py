"""Tests for the comparison between the derived log and Apache's own.

The shipped access.log is derived from the tagged log. Apache independently
writes an ordinary combined log of the same requests. Those two files agreeing
is the evidence that deriving lost nothing -- so the comparison has to be able
to report disagreement precisely, not just say yes or no.
"""

import tempfile
import unittest
from pathlib import Path

from shared.verify.agreement import compare_logs

LINES = [
    '203.0.113.5 - - [16/Aug/2026:09:00:01 +0000] "GET / HTTP/1.1" 200 4210 "-" "UA/1"',
    '203.0.113.5 - - [16/Aug/2026:09:00:01 +0000] "GET /a.css HTTP/1.1" 200 812 "-" "UA/1"',
    '198.51.100.9 - - [16/Aug/2026:09:00:02 +0000] "GET /.env HTTP/1.1" 404 199 "-" "UA/2"',
]


class TestCompareLogs(unittest.TestCase):

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def write(self, name, lines):
        path = self.dir / name
        path.write_text("\n".join(lines) + "\n" if lines else "")
        return path

    def test_identical_files_agree_on_every_line(self):
        result = compare_logs(self.write("a.log", LINES),
                              self.write("b.log", LINES))
        self.assertEqual(result.agreed, 3)
        self.assertEqual(result.derived_lines, 3)
        self.assertEqual(result.reference_lines, 3)
        self.assertIsNone(result.first_divergence)
        self.assertTrue(result.identical)

    def test_a_changed_line_is_reported_with_its_line_number(self):
        altered = list(LINES)
        altered[1] = altered[1].replace("200 812", "304 -")
        result = compare_logs(self.write("a.log", LINES),
                              self.write("b.log", altered))
        self.assertEqual(result.agreed, 2)
        self.assertEqual(result.first_divergence, 2)
        self.assertFalse(result.identical)

    def test_a_reordered_pair_is_a_disagreement_not_a_match(self):
        # The whole point of deriving rather than joining is that ordering
        # between the two files is not guaranteed. A comparison that sorted
        # first, or compared as sets, would report agreement precisely when
        # the hazard had occurred.
        swapped = [LINES[1], LINES[0], LINES[2]]
        result = compare_logs(self.write("a.log", LINES),
                              self.write("b.log", swapped))
        self.assertFalse(result.identical)
        self.assertEqual(result.first_divergence, 1)

    def test_differing_lengths_are_reported_rather_than_truncated(self):
        result = compare_logs(self.write("a.log", LINES),
                              self.write("b.log", LINES[:2]))
        self.assertEqual(result.derived_lines, 3)
        self.assertEqual(result.reference_lines, 2)
        self.assertFalse(result.identical)

    def test_a_missing_reference_file_is_reported_not_treated_as_agreement(self):
        result = compare_logs(self.write("a.log", LINES),
                              self.dir / "absent.log")
        self.assertFalse(result.identical)
        self.assertIsNone(result.reference_lines)

    def test_summary_reads_as_a_number_a_person_can_check(self):
        result = compare_logs(self.write("a.log", LINES),
                              self.write("b.log", LINES))
        self.assertEqual(result.summary(), "3/3 lines agreed, in order")


if __name__ == "__main__":
    unittest.main()
