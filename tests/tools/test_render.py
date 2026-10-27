"""Rendering a whole build: every format, its truth, and what was flagged.

The build here is made the way a real one is -- a capture, a tagged twin, and
the remap's rewrite of both -- so the renderer has to recover the same things
from the same files: which captured line each shipped line was, its request
id, and its sub-second time.
"""

import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from shared.render.formats import FORMATS
from shared.timeline.remap import remap_records
from tools.render import RenderRefused, render_dataset

START = datetime(2026, 3, 9, tzinfo=timezone.utc)
TIMELINE = {"start": START.isoformat(), "duration_seconds": 3600}
SEED = 7

CAPTURE = [
    ('100.64.0.1', '"GET / HTTP/1.1" 200 4028 "-" "Mozilla/5.0 (X11)"', "browsing"),
    ('100.64.0.1', '"GET /a.css HTTP/1.1" 200 99 "http://shop.test/" "Mozilla/5.0 (X11)"',
     "static_asset"),
    ('203.0.113.6', '"GARBAGE" 400 352 "-" "-"', "reconnaissance"),
    ('127.0.0.1', '"OPTIONS * HTTP/1.0" 200 - "-" "Apache/2.4 (internal dummy connection)"',
     "unknown"),
    ('100.64.0.2', '"GET /search?q=a%27 HTTP/1.1" 200 12 "-" "curl/8.4.0"', "injection"),
]
IDS = ["a" * 32, "b" * 32, "-", "-", "c" * 32]


def a_build():
    out = Path(tempfile.mkdtemp())
    raw = [f"{ip} - - [09/Mar/2026:00:00:0{i} +0000] {rest}"
           for i, (ip, rest, _) in enumerate(CAPTURE)]
    records = [{"line_no": i, "client_ip": ip, "category": category,
                "instance_id": f"{ip}#1"}
               for i, (ip, _, category) in enumerate(CAPTURE, 1)]
    header = {"kind": "logarc-truth", "version": 1, "scenario": "t", "seed": SEED,
              "source_file_id": "access.log", "granularity": "category",
              "generated_at": "2026-03-09T00:00:00+00:00"}

    def write_truth(path, rows):
        path.write_text("\n".join(json.dumps(r) for r in [header, *rows]) + "\n")

    (out / "access.raw.log").write_text("\n".join(raw) + "\n")
    write_truth(out / "truth.raw.jsonl", records)
    (out / "access.tagged.log").write_text(
        "\n".join(f"{i} {line}" for i, line in zip(IDS, raw)) + "\n")
    shipped, truth, _ = remap_records(raw, records, start=START,
                                      duration_seconds=3600, seed=SEED)
    (out / "access.log").write_text("\n".join(shipped) + "\n")
    write_truth(out / "truth.jsonl", truth)
    return out


def render(build):
    return render_dataset(build, timeline=TIMELINE, seed=SEED,
                          unpaced=frozenset())


class TestEveryFormatIsWritten(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.build = a_build()
        cls.manifest = render(cls.build)
        cls.out = cls.build / "rendered"

    def test_one_file_and_one_truth_per_format(self):
        for fmt in FORMATS:
            with self.subTest(format=fmt.name):
                self.assertTrue((self.out / f"{fmt.name}.log").exists())
                self.assertTrue((self.out / f"{fmt.name}.truth.jsonl").exists())

    def test_records_are_one_to_one_after_the_header_lines(self):
        for fmt in FORMATS:
            with self.subTest(format=fmt.name):
                lines = (self.out / f"{fmt.name}.log").read_text().splitlines()
                entry = self.manifest["formats"][fmt.name]
                self.assertEqual(len(lines), len(CAPTURE) + entry["header_lines"])

    def test_truth_line_numbers_point_past_the_header(self):
        rows = (self.out / "iis-w3c.truth.jsonl").read_text().splitlines()
        header, records = json.loads(rows[0]), [json.loads(r) for r in rows[1:]]
        self.assertEqual(header["source_file_id"], "iis-w3c.log")
        self.assertEqual([r["line_no"] for r in records], [5, 6, 7, 8, 9])
        lines = (self.out / "iis-w3c.log").read_text().splitlines()
        for record in records:
            self.assertIn(record["client_ip"], lines[record["line_no"] - 1])

    def test_the_labels_are_the_shipped_ones(self):
        shipped = [json.loads(r) for r in
                   (self.build / "truth.jsonl").read_text().splitlines()[1:]]
        rendered = [json.loads(r) for r in
                    (self.out / "envoy.truth.jsonl").read_text().splitlines()[1:]]
        self.assertEqual([(r["category"], r["instance_id"]) for r in shipped],
                         [(r["category"], r["instance_id"]) for r in rendered])

    def test_flagged_lines_are_named_by_the_line_a_reader_counts(self):
        flagged = self.manifest["formats"]["cloudfront"]["flagged"]
        lines = (self.out / "cloudfront.log").read_text().splitlines()
        named = sorted(n for numbers in flagged.values() for n in numbers)
        self.assertEqual(len(named), 2)
        clients = sorted(lines[n - 1].split("\t")[4] for n in named)
        self.assertEqual(clients, ["127.0.0.1", "203.0.113.6"])

    def test_the_apache_formats_flag_nothing(self):
        self.assertEqual(self.manifest["formats"]["apache-common"]["flagged"], {})

    def test_the_request_id_follows_its_line_through_the_remap(self):
        for line in (self.out / "ingress-nginx.log").read_text().splitlines():
            if "/a.css" in line:
                self.assertTrue(line.endswith("b" * 32))

    def test_every_file_is_in_the_sums(self):
        sums = dict(reversed(line.split("  ")) for line in
                    (self.out / "SHA256SUMS").read_text().splitlines())
        for name, digest in sums.items():
            self.assertEqual(
                hashlib.sha256((self.out / name).read_bytes()).hexdigest(), digest)
        self.assertIn("MANIFEST.json", sums)
        self.assertEqual(len(sums), 2 * len(FORMATS) + 1)

    def test_the_manifest_says_what_these_files_are(self):
        self.assertIn("rendered from the Apache capture",
                      self.manifest["description"])


class TestItRefusesABuildItCannotReproduce(unittest.TestCase):

    def test_a_shipped_log_the_remap_does_not_produce(self):
        build = a_build()
        shipped = (build / "access.log").read_text().replace("/a.css", "/b.css")
        (build / "access.log").write_text(shipped)
        with self.assertRaises(RenderRefused):
            render(build)


if __name__ == "__main__":
    unittest.main()
