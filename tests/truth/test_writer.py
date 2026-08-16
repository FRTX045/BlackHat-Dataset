import io
import json
import unittest

from shared.truth.writer import CATEGORIES, TruthWriter

HDR = dict(
    scenario="apache-shopfront-small",
    seed=7,
    source_file_id="access.log",
    generated_at="2026-08-16T09:00:00+00:00",
)


class TestTruthWriterHeader(unittest.TestCase):
    def test_header_is_the_first_line(self):
        fh = io.StringIO()
        TruthWriter(fh, **HDR)
        header = json.loads(fh.getvalue().splitlines()[0])
        self.assertEqual(header["kind"], "weblog-truth")
        self.assertEqual(header["version"], 1)
        self.assertEqual(header["granularity"], "category")
        self.assertEqual(header["seed"], 7)
        self.assertEqual(header["scenario"], "apache-shopfront-small")
        self.assertEqual(header["source_file_id"], "access.log")

    def test_header_carries_no_total(self):
        # A count derived on read cannot contradict the records it describes.
        fh = io.StringIO()
        TruthWriter(fh, **HDR)
        header = json.loads(fh.getvalue().splitlines()[0])
        for forbidden in ("total", "count", "lines", "n_records"):
            self.assertNotIn(forbidden, header)

    def test_kind_is_configurable_not_hardcoded(self):
        fh = io.StringIO()
        TruthWriter(fh, kind="custom-truth", **HDR)
        header = json.loads(fh.getvalue().splitlines()[0])
        self.assertEqual(header["kind"], "custom-truth")

    def test_granularity_is_configurable_for_imported_binary_datasets(self):
        fh = io.StringIO()
        TruthWriter(fh, granularity="binary", **HDR)
        header = json.loads(fh.getvalue().splitlines()[0])
        self.assertEqual(header["granularity"], "binary")


class TestTruthWriterRecords(unittest.TestCase):
    def test_line_numbers_start_at_one_and_are_contiguous(self):
        fh = io.StringIO()
        w = TruthWriter(fh, **HDR)
        self.assertEqual(
            w.write(client_ip="203.0.113.5", category="browsing",
                    instance_id="203.0.113.5#1"), 1)
        self.assertEqual(
            w.write(client_ip="203.0.113.5", category="static_asset",
                    instance_id="203.0.113.5#1"), 2)
        self.assertEqual(
            w.write(client_ip="198.51.100.9", category="enumeration",
                    instance_id="198.51.100.9#1"), 3)
        recs = [json.loads(l) for l in fh.getvalue().splitlines()[1:]]
        self.assertEqual([r["line_no"] for r in recs], [1, 2, 3])

    def test_record_carries_exactly_the_four_required_fields(self):
        fh = io.StringIO()
        w = TruthWriter(fh, **HDR)
        w.write(client_ip="203.0.113.5", category="browsing",
                instance_id="203.0.113.5#17")
        rec = json.loads(fh.getvalue().splitlines()[1])
        self.assertEqual(
            set(rec), {"line_no", "client_ip", "category", "instance_id"})
        self.assertEqual(rec["client_ip"], "203.0.113.5")
        self.assertEqual(rec["category"], "browsing")
        self.assertEqual(rec["instance_id"], "203.0.113.5#17")

    def test_rejects_category_outside_the_vocabulary(self):
        w = TruthWriter(io.StringIO(), **HDR)
        for bad in ("sqli", "attack", "XSS", "Browsing", ""):
            with self.subTest(category=bad):
                with self.assertRaises(ValueError):
                    w.write(client_ip="203.0.113.5", category=bad,
                            instance_id="x#1")

    def test_a_rejected_write_does_not_consume_a_line_number(self):
        # Otherwise one bad call silently puts every later line_no out of step
        # with the log, and the truth file is wrong from that point on.
        fh = io.StringIO()
        w = TruthWriter(fh, **HDR)
        w.write(client_ip="203.0.113.5", category="browsing", instance_id="a#1")
        with self.assertRaises(ValueError):
            w.write(client_ip="203.0.113.5", category="nonsense",
                    instance_id="a#1")
        self.assertEqual(
            w.write(client_ip="203.0.113.5", category="browsing",
                    instance_id="a#1"), 2)

    def test_line_count_reflects_records_written(self):
        fh = io.StringIO()
        w = TruthWriter(fh, **HDR)
        self.assertEqual(w.line_count, 0)
        w.write(client_ip="203.0.113.5", category="browsing", instance_id="a#1")
        self.assertEqual(w.line_count, 1)

    def test_records_are_compact_single_line_json(self):
        fh = io.StringIO()
        w = TruthWriter(fh, **HDR)
        w.write(client_ip="203.0.113.5", category="browsing", instance_id="a#1")
        line = fh.getvalue().splitlines()[1]
        self.assertNotIn(", ", line)
        self.assertNotIn('": ', line)


class TestTruthWriterStreams(unittest.TestCase):
    class _Spy:
        def __init__(self):
            self.writes = []

        def write(self, s):
            self.writes.append(s)

    def test_header_reaches_the_file_immediately(self):
        spy = self._Spy()
        TruthWriter(spy, **HDR)
        self.assertEqual(len(spy.writes), 1)

    def test_each_record_reaches_the_file_immediately(self):
        # At ten million lines, a truth file you must hold in memory before
        # writing is a truth file you cannot write.
        spy = self._Spy()
        w = TruthWriter(spy, **HDR)
        w.write(client_ip="203.0.113.5", category="browsing", instance_id="a#1")
        self.assertEqual(len(spy.writes), 2)
        w.write(client_ip="203.0.113.5", category="browsing", instance_id="a#1")
        self.assertEqual(len(spy.writes), 3)


class TestVocabulary(unittest.TestCase):
    def test_is_exactly_the_fourteen_controlled_strings(self):
        self.assertEqual(CATEGORIES, frozenset({
            "browsing", "static_asset", "api_call", "authentication",
            "crawling", "reconnaissance", "enumeration", "injection",
            "path_traversal", "access_control", "credential_attack", "ssrf",
            "exploitation", "unknown",
        }))
        self.assertEqual(len(CATEGORIES), 14)


if __name__ == "__main__":
    unittest.main()
