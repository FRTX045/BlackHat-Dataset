"""Packaging a dataset for release.

The repository carries the manifest, the READMEs and a 5,000-line sample. The
full logs are release assets, and this is what builds them.

What matters here is not the compression. It is that a consumer who downloads
an asset, decompresses it and checks the sum gets exactly the bytes the build
produced -- so `SHA256SUMS` has to cover the *contents*, not only the archives.
A checksum over a compressed file proves the download arrived; a checksum over
the contents proves the dataset is the one the manifest describes.
"""

import json
import lzma
import tempfile
import unittest
from pathlib import Path

from tools.package import SUMS_NAME, assets_for, package

MANIFEST = {"kind": "logforge-manifest", "project": "apache-shopfront",
            "tier": "small", "seed": 7, "lines": 3}


def a_dataset(*, remapped=True, extra=()):
    path = Path(tempfile.mkdtemp())
    (path / "MANIFEST.json").write_text(json.dumps(MANIFEST))
    (path / "README.md").write_text("# a dataset\n")
    (path / "access.log").write_text("line one\nline two\nline three\n")
    (path / "access.apache.log").write_text("line one\nline two\nline three\n")
    (path / "access.tagged.log").write_text("id line one\n")
    (path / "error.log").write_text("[error] something\n")
    (path / "truth.jsonl").write_text('{"kind":"weblog-truth"}\n')
    (path / "sample.log").write_text("line two\n")
    (path / "sample.truth.jsonl").write_text('{"kind":"weblog-truth"}\n')
    if remapped:
        (path / "access.raw.log").write_text("raw one\nraw two\nraw three\n")
        (path / "truth.raw.jsonl").write_text('{"kind":"weblog-truth"}\n')
    for name in extra:
        (path / name).write_text("x\n")
    return path


class TestWhichFilesAreAssets(unittest.TestCase):

    def test_the_big_logs_and_truth_files_are_packaged(self):
        names = {p.name for p in assets_for(a_dataset())}
        for expected in ("access.log", "truth.jsonl", "error.log",
                         "access.apache.log", "access.raw.log",
                         "truth.raw.jsonl"):
            self.assertIn(expected, names)

    def test_what_the_repository_already_carries_is_not_packaged(self):
        # Compressing a file that is committed two directories up wastes a
        # release asset and gives a consumer two sources for the same bytes.
        names = {p.name for p in assets_for(a_dataset())}
        for committed in ("MANIFEST.json", "README.md", "sample.log",
                          "sample.truth.jsonl"):
            self.assertNotIn(committed, names)

    def test_a_dataset_that_was_not_remapped_has_no_raw_assets(self):
        names = {p.name for p in assets_for(a_dataset(remapped=False))}
        self.assertNotIn("access.raw.log", names)
        self.assertNotIn("truth.raw.jsonl", names)

    def test_an_unexpected_file_is_left_alone(self):
        # A stray file is not silently swept into a release.
        names = {p.name for p in assets_for(a_dataset(extra=("notes.txt",)))}
        self.assertNotIn("notes.txt", names)

    def test_the_order_is_stable(self):
        dataset = a_dataset()
        self.assertEqual([p.name for p in assets_for(dataset)],
                         [p.name for p in assets_for(dataset)])


class TestPackaging(unittest.TestCase):

    def setUp(self):
        self.dataset = a_dataset()
        self.report = package(self.dataset)

    def test_every_asset_becomes_an_xz_archive(self):
        for name in (p.name for p in assets_for(self.dataset)):
            with self.subTest(asset=name):
                self.assertTrue((self.dataset / f"{name}.xz").is_file())

    def test_the_archive_round_trips_to_the_original_bytes(self):
        original = (self.dataset / "access.log").read_bytes()
        with lzma.open(self.dataset / "access.log.xz") as fh:
            self.assertEqual(fh.read(), original)

    def test_the_originals_are_left_in_place(self):
        # Packaging must not destroy the dataset it packaged.
        self.assertTrue((self.dataset / "access.log").is_file())

    def test_the_report_names_what_it_wrote(self):
        self.assertTrue(self.report.archives)
        self.assertGreater(self.report.original_bytes, 0)
        self.assertGreater(self.report.compressed_bytes, 0)


class TestTheChecksums(unittest.TestCase):

    def setUp(self):
        self.dataset = a_dataset()
        package(self.dataset)
        self.sums = (self.dataset / SUMS_NAME).read_text()

    def test_it_is_in_the_format_sha256sum_reads(self):
        for line in self.sums.strip().splitlines():
            if line.startswith("#") or not line.strip():
                continue
            digest, _, name = line.partition("  ")
            with self.subTest(line=line):
                self.assertEqual(len(digest), 64)
                self.assertTrue(name.strip())

    def test_it_covers_the_archives(self):
        self.assertIn("access.log.xz", self.sums)

    def test_it_covers_the_uncompressed_contents_too(self):
        # The point of the file: a checksum over the archive proves the
        # download arrived. A checksum over the contents proves the dataset
        # is the one the manifest describes.
        self.assertIn("access.log\n", self.sums)

    def test_it_covers_what_the_repository_carries(self):
        # So a release is self-verifying without a git checkout.
        for committed in ("MANIFEST.json", "sample.log", "sample.truth.jsonl"):
            self.assertIn(committed, self.sums)

    def test_the_digests_are_correct(self):
        import hashlib
        expected = hashlib.sha256(
            (self.dataset / "access.log").read_bytes()).hexdigest()
        self.assertIn(f"{expected}  access.log\n", self.sums)

    def test_it_is_not_itself_listed(self):
        self.assertNotIn(f"  {SUMS_NAME}", self.sums)


class TestItRefusesRatherThanGuesses(unittest.TestCase):

    def test_a_directory_with_no_manifest_is_not_a_dataset(self):
        with self.assertRaises(ValueError):
            package(Path(tempfile.mkdtemp()))

    def test_a_dataset_missing_its_log_is_refused(self):
        dataset = a_dataset()
        (dataset / "access.log").unlink()
        with self.assertRaises(ValueError):
            package(dataset)


if __name__ == "__main__":
    unittest.main()
