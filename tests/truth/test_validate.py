import unittest

from shared.truth.validate import validate_records


def rec(n, ip, cat, inst):
    return {"line_no": n, "client_ip": ip, "category": cat, "instance_id": inst}


class TestWellFormed(unittest.TestCase):
    def test_accepts_a_well_formed_stream(self):
        recs = [
            rec(1, "203.0.113.5", "browsing", "203.0.113.5#1"),
            rec(2, "203.0.113.5", "static_asset", "203.0.113.5#1"),
            rec(3, "198.51.100.9", "enumeration", "198.51.100.9#1"),
        ]
        ips = ["203.0.113.5", "203.0.113.5", "198.51.100.9"]
        self.assertEqual(validate_records(recs, ips), [])

    def test_accepts_an_empty_dataset(self):
        self.assertEqual(validate_records([], []), [])


class TestLineNumbering(unittest.TestCase):
    def test_rejects_a_gap(self):
        recs = [rec(1, "203.0.113.5", "browsing", "a#1"),
                rec(3, "203.0.113.5", "browsing", "a#1")]
        errs = validate_records(recs, ["203.0.113.5"] * 2)
        self.assertTrue(any("line_no" in e for e in errs), errs)

    def test_rejects_a_repeat(self):
        recs = [rec(1, "203.0.113.5", "browsing", "a#1"),
                rec(1, "203.0.113.5", "browsing", "a#1")]
        errs = validate_records(recs, ["203.0.113.5"] * 2)
        self.assertTrue(any("line_no" in e for e in errs), errs)

    def test_rejects_a_start_other_than_one(self):
        recs = [rec(0, "203.0.113.5", "browsing", "a#1")]
        errs = validate_records(recs, ["203.0.113.5"])
        self.assertTrue(any("line_no" in e for e in errs), errs)


class TestAgainstTheLog(unittest.TestCase):
    def test_rejects_ip_mismatch(self):
        recs = [rec(1, "203.0.113.5", "browsing", "a#1")]
        errs = validate_records(recs, ["198.51.100.9"])
        self.assertTrue(any("client_ip" in e for e in errs), errs)

    def test_rejects_more_log_lines_than_records(self):
        recs = [rec(1, "203.0.113.5", "browsing", "a#1")]
        errs = validate_records(recs, ["203.0.113.5", "203.0.113.5"])
        self.assertTrue(any("count" in e for e in errs), errs)

    def test_rejects_more_records_than_log_lines(self):
        recs = [rec(1, "203.0.113.5", "browsing", "a#1"),
                rec(2, "203.0.113.5", "browsing", "a#1")]
        errs = validate_records(recs, ["203.0.113.5"])
        self.assertTrue(any("count" in e for e in errs), errs)


class TestVocabulary(unittest.TestCase):
    def test_rejects_a_category_outside_the_vocabulary(self):
        recs = [rec(1, "203.0.113.5", "sqli", "a#1")]
        errs = validate_records(recs, ["203.0.113.5"])
        self.assertTrue(any("category" in e for e in errs), errs)


class TestEpisodeContiguity(unittest.TestCase):
    def test_rejects_an_id_that_reappears_after_another_intervened(self):
        # Same client: episode 1, then episode 2, then episode 1 again. The
        # boundaries are wrong -- either it was one episode all along or the
        # third line belongs to a new one.
        recs = [rec(1, "203.0.113.5", "browsing", "203.0.113.5#1"),
                rec(2, "203.0.113.5", "browsing", "203.0.113.5#2"),
                rec(3, "203.0.113.5", "browsing", "203.0.113.5#1")]
        errs = validate_records(recs, ["203.0.113.5"] * 3)
        self.assertTrue(any("instance_id" in e for e in errs), errs)

    def test_allows_consecutive_runs_of_the_same_id(self):
        recs = [rec(1, "203.0.113.5", "browsing", "203.0.113.5#1"),
                rec(2, "203.0.113.5", "static_asset", "203.0.113.5#1"),
                rec(3, "203.0.113.5", "api_call", "203.0.113.5#2")]
        self.assertEqual(validate_records(recs, ["203.0.113.5"] * 3), [])

    def test_allows_interleaving_between_different_clients(self):
        # Contiguity is per client. Two visitors overlapping in the log is the
        # normal case and must not be flagged.
        recs = [rec(1, "203.0.113.5", "browsing", "203.0.113.5#1"),
                rec(2, "198.51.100.9", "crawling", "198.51.100.9#1"),
                rec(3, "203.0.113.5", "browsing", "203.0.113.5#1")]
        ips = ["203.0.113.5", "198.51.100.9", "203.0.113.5"]
        self.assertEqual(validate_records(recs, ips), [])

    def test_allows_the_same_id_string_under_different_clients(self):
        recs = [rec(1, "203.0.113.5", "browsing", "shared#1"),
                rec(2, "198.51.100.9", "browsing", "shared#1"),
                rec(3, "203.0.113.5", "browsing", "shared#1")]
        ips = ["203.0.113.5", "198.51.100.9", "203.0.113.5"]
        self.assertEqual(validate_records(recs, ips), [])


class TestReporting(unittest.TestCase):
    def test_reports_every_problem_rather_than_the_first(self):
        recs = [rec(1, "203.0.113.5", "nope", "a#1"),
                rec(3, "198.51.100.9", "alsonope", "b#1")]
        errs = validate_records(recs, ["203.0.113.5", "198.51.100.9"])
        self.assertGreaterEqual(len(errs), 3)

    def test_messages_name_the_offending_line(self):
        recs = [rec(1, "203.0.113.5", "browsing", "a#1"),
                rec(2, "203.0.113.5", "sqli", "a#1")]
        errs = validate_records(recs, ["203.0.113.5"] * 2)
        self.assertTrue(any("line 2" in e for e in errs), errs)


if __name__ == "__main__":
    unittest.main()
