import io
import tempfile
import unittest
from pathlib import Path

from shared.truth.reader import TruthFormatError, read_truth
from shared.truth.writer import TruthWriter

HDR = dict(
    scenario="apache-shopfront-small",
    seed=7,
    source_file_id="access.log",
    generated_at="2026-08-16T09:00:00+00:00",
)


def write_sample(path, n=3):
    with open(path, "w", encoding="utf-8") as fh:
        w = TruthWriter(fh, **HDR)
        for i in range(n):
            w.write(client_ip="203.0.113.5", category="browsing",
                    instance_id=f"203.0.113.5#{i}")


class TestReadTruth(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.path = self.dir / "truth.jsonl"

    def test_round_trips_what_the_writer_produced(self):
        write_sample(self.path)
        header, records = read_truth(self.path)
        self.assertEqual(header["kind"], "weblog-truth")
        self.assertEqual(header["seed"], 7)
        recs = list(records)
        self.assertEqual(len(recs), 3)
        self.assertEqual([r["line_no"] for r in recs], [1, 2, 3])

    def test_records_are_yielded_lazily_not_materialised(self):
        # A ten-million-line truth file must be readable without loading it.
        write_sample(self.path, n=5)
        _, records = read_truth(self.path)
        self.assertFalse(isinstance(records, (list, tuple)))
        self.assertEqual(next(iter(records))["line_no"], 1)

    def test_accepts_a_file_object_as_well_as_a_path(self):
        buf = io.StringIO()
        w = TruthWriter(buf, **HDR)
        w.write(client_ip="203.0.113.5", category="browsing", instance_id="a#1")
        buf.seek(0)
        header, records = read_truth(buf)
        self.assertEqual(header["kind"], "weblog-truth")
        self.assertEqual(len(list(records)), 1)

    def test_rejects_an_empty_file(self):
        self.path.write_text("", encoding="utf-8")
        with self.assertRaises(TruthFormatError):
            read_truth(self.path)

    def test_rejects_a_header_that_is_not_json(self):
        self.path.write_text("not json\n", encoding="utf-8")
        with self.assertRaises(TruthFormatError):
            read_truth(self.path)

    def test_rejects_a_header_missing_required_fields(self):
        self.path.write_text('{"kind":"weblog-truth"}\n', encoding="utf-8")
        with self.assertRaises(TruthFormatError):
            read_truth(self.path)

    def test_rejects_a_header_carrying_a_total(self):
        # Guards the contract from the other side: a file claiming a total is
        # not one of ours, and trusting it would reintroduce the disagreement
        # the format exists to avoid.
        self.path.write_text(
            '{"kind":"weblog-truth","version":1,"scenario":"s","seed":1,'
            '"source_file_id":"access.log","granularity":"category",'
            '"generated_at":"2026-08-16T09:00:00+00:00","total":5}\n',
            encoding="utf-8")
        with self.assertRaises(TruthFormatError):
            read_truth(self.path)

    def test_reports_the_line_number_of_a_malformed_record(self):
        write_sample(self.path, n=2)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write("{broken\n")
        _, records = read_truth(self.path)
        with self.assertRaises(TruthFormatError) as ctx:
            list(records)
        self.assertIn("4", str(ctx.exception))  # header + 2 records + this one


if __name__ == "__main__":
    unittest.main()
