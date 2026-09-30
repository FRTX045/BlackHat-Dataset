"""Tests for relabelling one capture with a different labeller.

Every fixture here is a real miniature build: the real join writes the capture
and the real remap reorders it, so the tool is tested against the same two
steps it has to replay. The fixture is checked to be reordered by the remap,
because a permutation that happens to be the identity would let a tool that
ignores it pass every other test.
"""

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from shared.timeline.remap import remap_files
from shared.truth.join import join
from shared.truth.reader import read_truth
from shared.truth.validate import validate_records
from tools import relabel
from tools.relabel import RelabelError, check_permutation

BROWSER = "203.0.113.41"
FALLBACK = {"203.0.113.6": "reconnaissance"}
START = datetime(2026, 3, 9, tzinfo=timezone.utc)
DURATION = 86400
SEED = 19

BASELINE_LABELS = '''
def categorise(entry):
    route = (entry.get("path") or "/").split("?", 1)[0]
    if (entry.get("actor") or "").startswith("tool:"):
        return "enumeration"
    if route.endswith(".css"):
        return "static_asset"
    if route.startswith("/account"):
        return "access_control"
    return "browsing"
'''

#: The fix in miniature: the same labeller, except that the browser's click on
#: /account/ is browsing.
CANDIDATE_LABELS = BASELINE_LABELS.replace(
    'return "access_control"', 'return "browsing"')

#: The browser's run under the baseline: browsing, access_control, browsing,
#: static_asset, browsing -- five derived episodes. Under the candidate the
#: first three merge.
BROWSER_PATHS = ["/", "/account/", "/c/tools", "/assets/site.css", "/p/7"]


def _stamp(second):
    return f"09/Mar/2026:00:{second // 60:02d}:{second % 60:02d} +0000"


def _line(rid, ip, second, path, status=200):
    return (f'{rid} {ip} - - [{_stamp(second)}] "GET {path} HTTP/1.1" '
            f'{status} 100 "-" "UA/1"')


def build_fixture(root, tool=None, unpaced=frozenset()):
    """Write a shipped miniature dataset and its ledgers under `root`.

    `tool` is an optional (address, [(request id, second offset, path)]) run
    from the proxy, stamped as given so a test can make it go backwards."""
    dataset, ledgers = root / "dataset", root / "ledger"
    dataset.mkdir()
    ledgers.mkdir()

    tagged, driver, proxy = [], [], []
    second = 0

    def driver_session(ip, n, episode, category="browsing"):
        nonlocal second
        for k in range(n):
            rid = f"d-{ip}-{episode}-{k}"
            tagged.append(_line(rid, ip, second, f"/c/{episode}/{k}"))
            driver.append({"request_id": rid, "client_ip": ip,
                           "category": category,
                           "instance_id": f"{ip}#{episode}"})
            second += 1

    # Several clients, several sessions each, interleaved with the browser, so
    # the remap has sessions to shuffle.
    driver_session("198.51.100.20", 3, 1)
    for index, path in enumerate(BROWSER_PATHS):
        rid = f"b-{index}"
        tagged.append(_line(rid, BROWSER, second, path,
                            302 if path.startswith("/account") else 200))
        proxy.append({"request_id": rid, "client_ip": BROWSER,
                      "actor": "browser", "method": "GET", "path": path})
        second += 1
        if index == 2:
            driver_session("198.51.100.21", 2, 1, "injection")
    driver_session("198.51.100.20", 2, 2)
    tagged.append(f'- 203.0.113.6 - - [{_stamp(second)}] "GARBAGE" 400 0 "-" "-"')
    second += 1
    driver_session("198.51.100.22", 3, 1, "crawling")
    driver_session("198.51.100.21", 2, 2, "injection")
    driver_session("198.51.100.20", 2, 3)
    driver_session("198.51.100.23", 2, 1)
    if tool is not None:
        address, lines = tool
        base = second
        for rid, offset, path in lines:
            tagged.append(_line(rid, address, base + offset, path))
            proxy.append({"request_id": rid, "client_ip": address,
                          "actor": "tool:x", "method": "GET", "path": path})
        second = base + len(lines)

    (root / "access.tagged.log").write_text("\n".join(tagged) + "\n")
    (ledgers / "driver.jsonl").write_text(
        "\n".join(json.dumps(r) for r in driver) + "\n")
    (ledgers / "tagproxy.jsonl").write_text(
        "\n".join(json.dumps(r) for r in proxy) + "\n")

    labels_dir = root / "labels"
    labels_dir.mkdir()
    (labels_dir / "baseline.py").write_text(BASELINE_LABELS)
    (labels_dir / "candidate.py").write_text(CANDIDATE_LABELS)
    baseline = relabel.load_labeller(labels_dir / "baseline.py")

    # Exactly the two steps the build runs, on the same files.
    (dataset / "access.tagged.log").write_bytes(
        (root / "access.tagged.log").read_bytes())
    join(dataset / "access.tagged.log", relabel.ledger_paths(ledgers),
         dataset / "truth.raw.jsonl", dataset / "access.raw.log",
         dict(scenario="t-small", seed=SEED, source_file_id="access.log",
              generated_at="2026-09-07T14:44:38.217757+00:00"),
         labeller=baseline, address_fallback=FALLBACK)
    remap_files(dataset / "access.raw.log", dataset / "truth.raw.jsonl",
                dataset / "access.log", dataset / "truth.jsonl",
                start=START, duration_seconds=DURATION, seed=SEED,
                unpaced=unpaced)
    (dataset / "MANIFEST.json").write_text(json.dumps({"seed": SEED}))
    return dataset, ledgers, labels_dir


class RelabelCase(unittest.TestCase):

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.dataset, self.ledgers, self.labels = build_fixture(self.root)
        self.out = self.root / "out"

    def run_relabel(self, baseline="baseline.py", candidate="candidate.py",
                    out=None, unpaced_override=frozenset(), **kwargs):
        return relabel.relabel(
            self.dataset, self.ledgers,
            self.labels / baseline, self.labels / candidate,
            out or self.out,
            start=START, duration_seconds=DURATION, seed=SEED,
            unpaced=unpaced_override, address_fallback=FALLBACK, **kwargs)

    def records(self, path):
        _, records = read_truth(path)
        return list(records)

    def changes(self, directory=None):
        path = (directory or self.out) / "changes.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()]

    def truth_files(self, directory):
        return sorted(p.name for p in directory.rglob("truth*.jsonl"))


class TestTheFixture(RelabelCase):

    def test_the_remap_actually_reorders_it(self):
        report = self.run_relabel(candidate="baseline.py")
        self.assertGreater(report["permutation"]["moved_lines"], 0)


class TestBaselineReproduction(RelabelCase):

    def test_the_shipped_labeller_reproduces_both_truth_files_exactly(self):
        report = self.run_relabel(candidate="baseline.py")
        self.assertTrue(all(report["gates"].values()), report["gates"])
        self.assertEqual((self.out / "truth.raw.jsonl").read_bytes(),
                         (self.dataset / "truth.raw.jsonl").read_bytes())
        self.assertEqual((self.out / "truth.jsonl").read_bytes(),
                         (self.dataset / "truth.jsonl").read_bytes())
        self.assertEqual(self.changes(), [])

    def test_a_baseline_that_is_not_the_shipped_labeller_is_refused(self):
        with self.assertRaisesRegex(RelabelError, "truth.raw.jsonl"):
            self.run_relabel(baseline="candidate.py")
        failed = self.root / "out.failed"
        self.assertFalse(self.out.exists())
        self.assertTrue((failed / "report.json").is_file())
        self.assertEqual(self.truth_files(failed), [])

    def test_the_labeller_files_given_are_the_ones_used(self):
        report = self.run_relabel()
        self.assertEqual(report["labellers"]["candidate"]["sha256"],
                         relabel.sha256(self.labels / "candidate.py"))
        self.assertEqual(report["labellers"]["baseline"]["sha256"],
                         relabel.sha256(self.labels / "baseline.py"))


class TestACorrectionThatMergesEpisodes(RelabelCase):

    def setUp(self):
        super().setUp()
        self.report = self.run_relabel()
        self.shipped = self.records(self.out / "truth.jsonl")

    def browser_ids(self, records):
        return [r["instance_id"] for r in records if r["client_ip"] == BROWSER]

    def test_the_merged_ids_are_exact(self):
        before = self.browser_ids(self.records(self.dataset / "truth.jsonl"))
        self.assertEqual(before, [f"{BROWSER}#{n}" for n in (1, 2, 3, 4, 5)])
        # One episode for the first three, and the later ones renumbered.
        self.assertEqual(self.browser_ids(self.shipped),
                         [f"{BROWSER}#{n}" for n in (1, 1, 1, 2, 3)])

    def test_one_category_change_and_two_removed_cuts_not_a_renumbering(self):
        kinds = [c["kind"] for c in self.changes()]
        self.assertEqual(sorted(kinds),
                         ["boundary_removed", "boundary_removed", "category"])
        category = next(c for c in self.changes() if c["kind"] == "category")
        self.assertEqual((category["old"], category["new"]),
                         ("access_control", "browsing"))
        self.assertEqual(category["path"], "/account/")
        self.assertEqual(category["request_id"], "b-1")
        self.assertEqual(category["status"], 302)

    def test_the_change_is_at_the_right_shipped_line(self):
        category = next(c for c in self.changes() if c["kind"] == "category")
        line = (self.dataset / "access.log").read_text().splitlines()[
            category["shipped_line_no"] - 1]
        self.assertIn("GET /account/ ", line)
        self.assertEqual(self.shipped[category["shipped_line_no"] - 1]
                         ["category"], "browsing")

    def test_the_projection_validates_against_the_shipped_log(self):
        ips = [line.split(" ", 1)[0] for line in
               (self.dataset / "access.log").read_text().splitlines()]
        self.assertEqual(validate_records(self.shipped, ips), [])

    def test_nothing_else_changed(self):
        before = self.records(self.dataset / "truth.jsonl")
        for old, new in zip(before, self.shipped):
            if old["client_ip"] != BROWSER:
                self.assertEqual(old, new)
        self.assertEqual(self.report["clients_changed"], [BROWSER])

    def test_no_output_carries_the_private_index(self):
        for path in self.out.rglob("*"):
            if path.is_file():
                self.assertNotIn("_src", path.read_text(), path.name)

    def test_the_dataset_is_untouched(self):
        self.assertEqual(self.report["inputs_unchanged"], True)


class TestAClientTheRemapReordersWithinItself(RelabelCase):
    """An unpaced tool run whose capture stamps go backwards, as concurrent
    requests do. Its episode boundaries have to be read in shipped order,
    which is the order the truth file is read in."""

    TOOL = "192.0.2.31"
    #: Capture order a, b.css, c; stamped so the remap ships a, c, b.css.
    TOOL_LINES = [("t-0", 0, "/t/a"), ("t-1", 2, "/t/b.css"),
                  ("t-2", 1, "/t/c")]

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.dataset, self.ledgers, self.labels = build_fixture(
            self.root, tool=(self.TOOL, self.TOOL_LINES),
            unpaced=frozenset({self.TOOL}))
        self.out = self.root / "out"
        # Splits the tool's one episode: its stylesheet request becomes a
        # static_asset instead of part of the enumeration run.
        (self.labels / "tool-split.py").write_text(BASELINE_LABELS.replace(
            'if (entry.get("actor") or "").startswith("tool:"):',
            'if (entry.get("actor") or "").startswith("tool:") '
            'and not route.endswith(".css"):'))

    def run_relabel(self, candidate, **kwargs):
        return super().run_relabel(candidate=candidate,
                                   unpaced_override=frozenset({self.TOOL}),
                                   **kwargs)

    def tool_paths_shipped(self):
        return [line.split('"')[1].split()[1] for line in
                (self.dataset / "access.log").read_text().splitlines()
                if line.startswith(self.TOOL + " ")]

    def test_the_fixture_reorders_the_client(self):
        self.assertEqual(self.tool_paths_shipped(),
                         ["/t/a", "/t/c", "/t/b.css"])

    def test_the_gates_pass(self):
        report = self.run_relabel("baseline.py")
        self.assertTrue(all(report["gates"].values()), report["gates"])
        self.assertEqual(self.changes(), [])

    def test_boundaries_are_the_ones_between_shipped_neighbours(self):
        self.run_relabel("tool-split.py")
        added = sorted(
            tuple(side["shipped_line_no"] for side in change["between"])
            for change in self.changes()
            if change["kind"] == "boundary_added")
        shipped = [n for n, line in enumerate(
            (self.dataset / "access.log").read_text().splitlines(), 1)
            if line.startswith(self.TOOL + " ")]
        # a|c and c|b.css, neighbours in the file -- not a|b.css and b.css|c,
        # which were neighbours only in the capture.
        self.assertEqual(added, [(shipped[0], shipped[1]),
                                 (shipped[1], shipped[2])])


class TestExpectedScope(RelabelCase):

    def test_changes_outside_the_expected_clients_fail(self):
        with self.assertRaisesRegex(RelabelError, BROWSER):
            self.run_relabel(expect_within=frozenset({"192.0.2.99"}))
        failed = self.root / "out.failed"
        self.assertEqual(self.truth_files(failed), [])
        self.assertTrue((failed / "changes.raw.jsonl").is_file())

    def test_changes_inside_the_expected_clients_pass(self):
        self.run_relabel(expect_within=frozenset({BROWSER}))


class TestLedgerIntegrity(RelabelCase):

    def append(self, name, record):
        with open(self.ledgers / name, "a") as fh:
            fh.write(json.dumps(record) + "\n")

    def test_a_conflicting_duplicate_id_fails(self):
        self.append("attack-x.jsonl", {"request_id": "b-1",
                                       "client_ip": BROWSER,
                                       "category": "injection"})
        with self.assertRaisesRegex(RelabelError, "b-1"):
            self.run_relabel()

    def test_ledger_ids_absent_from_the_log_are_listed(self):
        self.append("attack-stale.jsonl", {"request_id": "gone",
                                           "client_ip": "192.0.2.50",
                                           "category": "injection"})
        report = self.run_relabel()
        self.assertEqual(report["ledgers"]["unmatched"]["attack-stale.jsonl"],
                         ["gone"])


class TestTheRemapGate(RelabelCase):

    def test_a_tampered_shipped_log_fails_and_leaves_only_diagnostics(self):
        path = self.dataset / "access.log"
        lines = path.read_text().splitlines()
        lines[0] = lines[0].replace("[09/Mar/2026:", "[10/Mar/2026:", 1)
        path.write_text("\n".join(lines) + "\n")
        with self.assertRaisesRegex(RelabelError, "access.log"):
            self.run_relabel()
        failed = self.root / "out.failed"
        self.assertFalse(self.out.exists())
        self.assertEqual(self.truth_files(failed), [])
        self.assertTrue((failed / "changes.raw.jsonl").is_file())
        raw = [json.loads(line) for line in
               (failed / "changes.raw.jsonl").read_text().splitlines()]
        self.assertIn("category", [c["kind"] for c in raw])


class TestPreservation(RelabelCase):

    def test_an_existing_output_is_refused(self):
        self.out.mkdir()
        with self.assertRaisesRegex(RelabelError, "exists"):
            self.run_relabel()

    def test_output_inside_or_equal_to_an_input_is_refused(self):
        for out in (self.dataset / "relabelled", self.dataset,
                    self.ledgers / "x", self.root):
            with self.subTest(out=out):
                with self.assertRaises(RelabelError):
                    self.run_relabel(out=out)

    def test_overlap_is_found_through_a_link_not_by_spelling(self):
        link = self.root / "alias"
        os.symlink(self.dataset, link)
        with self.assertRaisesRegex(RelabelError, "inside"):
            self.run_relabel(out=link / "relabelled")

    def test_an_input_modified_mid_run_fails_the_end_check(self):
        real = relabel.validate_records

        def tamper(*args, **kwargs):
            with open(self.dataset / "MANIFEST.json", "a") as fh:
                fh.write(" ")
            return real(*args, **kwargs)

        with mock.patch.object(relabel, "validate_records", tamper):
            with self.assertRaisesRegex(RelabelError, "MANIFEST.json"):
                self.run_relabel()
        self.assertFalse(self.out.exists())
        self.assertEqual(self.truth_files(self.root / "out.failed"), [])


class TestPublicationFailures(RelabelCase):
    """Failures after every gate has passed, while the result is being
    published, and failures of the cleanup itself.

    Two expectations are kept apart on purpose. When cleanup succeeds, no
    truth file survives. When cleanup's own deletion fails, that cannot be
    promised; what is promised instead is that the original exception is the
    one raised, its notes name every file left behind, and nothing is
    published at `out`.
    """

    real_write = staticmethod(relabel._write_report)
    real_rename = staticmethod(Path.rename)
    real_unlink = staticmethod(Path.unlink)

    def failed(self):
        return self.root / "out.failed"

    def partial(self):
        return self.root / "out.partial"

    def notes(self, exc):
        return "\n".join(getattr(exc, "__notes__", []))

    def assert_nothing_published(self):
        self.assertFalse(self.out.exists())

    def test_a_failed_report_write_at_publication_leaves_no_truth(self):
        calls = []

        def write(directory, report):
            calls.append(directory)
            if len(calls) == 1:
                raise OSError("disk full")
            return self.real_write(directory, report)

        with mock.patch.object(relabel, "_write_report", write):
            with self.assertRaisesRegex(OSError, "disk full"):
                self.run_relabel()
        self.assert_nothing_published()
        self.assertEqual(self.truth_files(self.failed()), [])
        report = json.loads((self.failed() / "report.json").read_text())
        self.assertIn("disk full", report["failure"])

    def test_a_failed_final_rename_leaves_no_truth(self):
        out = self.out

        def rename(path, target):
            if Path(target) == out:
                raise OSError("rename refused")
            return self.real_rename(path, target)

        with mock.patch.object(Path, "rename", rename):
            with self.assertRaisesRegex(OSError, "rename refused"):
                self.run_relabel()
        self.assert_nothing_published()
        self.assertEqual(self.truth_files(self.failed()), [])
        self.assertTrue((self.failed() / "report.json").is_file())

    def test_an_output_that_appears_before_publication_is_not_replaced(self):
        # An empty directory is the dangerous case: rename(2) replaces an
        # empty target directory without complaint.
        for contents in ((), ("mine.txt",)):
            with self.subTest(contents=contents):
                self.setUp()
                out = self.out

                def write(directory, report, out=out, contents=contents):
                    if directory.name == "out.partial" and not out.exists():
                        out.mkdir()
                        for name in contents:
                            (out / name).write_text("someone else's")
                    return self.real_write(directory, report)

                with mock.patch.object(relabel, "_write_report", write):
                    with self.assertRaisesRegex(RelabelError, "appeared"):
                        self.run_relabel()
                self.assertEqual(sorted(p.name for p in out.iterdir()),
                                 sorted(contents))
                self.assertEqual(self.truth_files(self.failed()), [])

    def test_a_failed_directory_that_appears_is_not_replaced(self):
        # Empty first: that is the case the guard exists for, since rename(2)
        # would replace it silently. A non-empty one would fail on its own.
        for contents in ((), ("mine.txt",)):
            with self.subTest(contents=contents):
                self.setUp()
                failed = self.failed()

                def write(directory, report, failed=failed,
                          contents=contents):
                    if "failure" in report and not failed.exists():
                        failed.mkdir()
                        for name in contents:
                            (failed / name).write_text("someone else's")
                    return self.real_write(directory, report)

                with mock.patch.object(relabel, "_write_report", write):
                    with self.assertRaisesRegex(RelabelError,
                                                "truth.raw.jsonl") as caught:
                        self.run_relabel(baseline="candidate.py")
                self.assertEqual(sorted(p.name for p in failed.iterdir()),
                                 sorted(contents))
                self.assertIn(str(self.partial()),
                              self.notes(caught.exception))
                self.assertEqual(self.truth_files(self.partial()), [])
                self.assert_nothing_published()

    def test_undeletable_truth_files_are_named_and_never_published(self):
        real_validate = relabel.validate_records

        def tamper(*args, **kwargs):
            with open(self.dataset / "MANIFEST.json", "a") as fh:
                fh.write(" ")
            return real_validate(*args, **kwargs)

        def unlink(path, *args, **kwargs):
            if path.name.startswith("truth"):
                raise PermissionError(f"cannot delete {path.name}")
            return self.real_unlink(path, *args, **kwargs)

        with mock.patch.object(relabel, "validate_records", tamper), \
                mock.patch.object(Path, "unlink", unlink):
            with self.assertRaisesRegex(RelabelError,
                                        "MANIFEST.json") as caught:
                self.run_relabel()
        self.assert_nothing_published()
        notes = self.notes(caught.exception)
        left = self.truth_files(self.failed())
        self.assertEqual(left, ["truth.jsonl", "truth.raw.jsonl"])
        for name in left:
            self.assertIn(str(self.failed() / name), notes)
        report = json.loads((self.failed() / "report.json").read_text())
        self.assertEqual(sorted(Path(p).name for p in
                                report["leftover_truth_files"]), left)

    def test_a_cleanup_that_fails_throughout_keeps_the_original_error(self):
        def write(directory, report):
            raise OSError("report write refused")

        def rename(path, target):
            raise OSError("rename refused")

        with mock.patch.object(relabel, "_write_report", write), \
                mock.patch.object(Path, "rename", rename):
            with self.assertRaisesRegex(RelabelError,
                                        "truth.raw.jsonl") as caught:
                self.run_relabel(baseline="candidate.py")
        notes = self.notes(caught.exception)
        self.assertIn("report write refused", notes)
        self.assertIn("rename refused", notes)
        self.assert_nothing_published()
        self.assertEqual(self.truth_files(self.partial()), [])

    def test_undeletable_files_left_in_partial_are_named_there(self):
        # Deletion and the move to .failed both fail, so the leftovers stay in
        # .partial -- and the notes must say .partial, not .failed.
        real_validate = relabel.validate_records
        out = self.out

        def tamper(*args, **kwargs):
            with open(self.dataset / "MANIFEST.json", "a") as fh:
                fh.write(" ")
            return real_validate(*args, **kwargs)

        def unlink(path, *args, **kwargs):
            if path.name.startswith("truth"):
                raise PermissionError(f"cannot delete {path.name}")
            return self.real_unlink(path, *args, **kwargs)

        def rename(path, target):
            if Path(target).name == out.name + ".failed":
                raise OSError("move refused")
            return self.real_rename(path, target)

        with mock.patch.object(relabel, "validate_records", tamper), \
                mock.patch.object(Path, "unlink", unlink), \
                mock.patch.object(Path, "rename", rename):
            with self.assertRaisesRegex(RelabelError,
                                        "MANIFEST.json") as caught:
                self.run_relabel()
        self.assert_nothing_published()
        self.assertFalse(self.failed().exists())
        notes = self.notes(caught.exception)
        left = self.truth_files(self.partial())
        self.assertEqual(left, ["truth.jsonl", "truth.raw.jsonl"])
        for name in left:
            self.assertIn(f"not published: {self.partial() / name}", notes)
        self.assertNotIn(f"not published: {self.failed()}", notes)

    def test_a_failure_before_the_gates_still_leaves_a_report(self):
        class Unprintable:
            def isoformat(self):
                raise ValueError("no start")

        with self.assertRaisesRegex(ValueError, "no start"):
            relabel.relabel(
                self.dataset, self.ledgers, self.labels / "baseline.py",
                self.labels / "candidate.py", self.out, start=Unprintable(),
                duration_seconds=DURATION, seed=SEED, unpaced=frozenset(),
                address_fallback=FALLBACK)
        self.assertFalse(self.partial().exists())
        report = json.loads((self.failed() / "report.json").read_text())
        self.assertIn("no start", report["failure"])

    def test_a_failure_report_claims_no_output_hashes(self):
        out = self.out

        def rename(path, target):
            if Path(target) == out:
                raise OSError("rename refused")
            return self.real_rename(path, target)

        with mock.patch.object(Path, "rename", rename):
            with self.assertRaises(OSError):
                self.run_relabel()
        report = json.loads((self.failed() / "report.json").read_text())
        self.assertNotIn("outputs", report)
        self.assertIn("failure", report)

    def test_a_stale_success_report_does_not_survive_a_failed_rewrite(self):
        out, calls = self.out, []

        def write(directory, report):
            calls.append(1)
            if len(calls) > 1:
                raise OSError("report write refused")
            return self.real_write(directory, report)

        def rename(path, target):
            if Path(target) == out:
                raise OSError("rename refused")
            return self.real_rename(path, target)

        with mock.patch.object(relabel, "_write_report", write), \
                mock.patch.object(Path, "rename", rename):
            with self.assertRaisesRegex(OSError, "rename refused") as caught:
                self.run_relabel()
        self.assertFalse((self.failed() / "report.json").exists())
        self.assertIn("report write refused", self.notes(caught.exception))


class TestInputsAreLeftUntouched(RelabelCase):
    """Checksums cannot see a file added beside an input, so the inventory of
    each input directory is compared as well.

    Bytecode writing is forced on, so that running under `python -B` or
    PYTHONDONTWRITEBYTECODE cannot make these pass against a loader that
    would write it.
    """

    def setUp(self):
        patcher = mock.patch.object(sys, "dont_write_bytecode", False)
        patcher.start()
        self.addCleanup(patcher.stop)
        super().setUp()

    def inventory(self, directory):
        return sorted(str(p.relative_to(directory))
                      for p in directory.rglob("*"))

    def test_loading_a_labeller_writes_nothing_beside_it(self):
        directory = self.root / "solo"
        directory.mkdir()
        (directory / "labels.py").write_text(BASELINE_LABELS)
        relabel.load_labeller(directory / "labels.py")
        self.assertEqual(self.inventory(directory), ["labels.py"])

    def test_a_run_adds_nothing_to_any_input_directory(self):
        before = {d: self.inventory(d)
                  for d in (self.labels, self.ledgers, self.dataset)}
        self.assertEqual(before[self.labels], ["baseline.py", "candidate.py"])
        self.run_relabel()
        for directory, listing in before.items():
            self.assertEqual(self.inventory(directory), listing,
                             directory.name)

    def test_the_ledger_directory_is_recorded(self):
        report = self.run_relabel()
        self.assertEqual(report["ledger_dir"], str(self.ledgers))


class TestFailuresBeforeTheWork(RelabelCase):

    def failed(self):
        return self.root / "out.failed"

    def test_a_failure_minting_the_token_is_cleaned_up(self):
        with mock.patch.object(relabel.secrets, "token_hex",
                               side_effect=OSError("no entropy")):
            with self.assertRaisesRegex(OSError, "no entropy"):
                self.run_relabel()
        self.assertFalse((self.root / "out.partial").exists())
        self.assertTrue((self.failed() / "report.json").is_file())

    def test_an_unprintable_exception_is_still_described(self):
        class Unprintable(Exception):
            def __str__(self):
                raise RuntimeError("cannot print me")

        with mock.patch.object(relabel, "_run", side_effect=Unprintable()):
            with self.assertRaises(Unprintable):
                self.run_relabel()
        report = json.loads((self.failed() / "report.json").read_text())
        self.assertIn("unprintable Unprintable", report["failure"])


class TestAnInterruptAfterPublication(RelabelCase):
    """Ctrl-C landing after the final rename has succeeded, before any later
    statement runs -- including one that would set a flag. Cleanup must
    recognise the published result from the disk and leave it alone."""

    real_rename = staticmethod(Path.rename)

    def interrupt_after_publishing(self, then=None):
        out = self.out

        def rename(path, target):
            result = self.real_rename(path, target)
            if Path(target) == out:
                if then:
                    then()
                raise KeyboardInterrupt
            return result

        return mock.patch.object(Path, "rename", rename)

    def notes(self, exc):
        return "\n".join(getattr(exc, "__notes__", []))

    def test_the_published_result_is_left_intact(self):
        with self.interrupt_after_publishing():
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.run_relabel()
        report = json.loads((self.out / "report.json").read_text())
        self.assertNotIn("failure", report)
        for name, digest in report["outputs"].items():
            self.assertEqual(relabel.sha256(self.out / name), digest)
        self.assertFalse((self.root / "out.failed").exists())
        notes = self.notes(caught.exception)
        self.assertIn(f"published at {self.out}", notes)
        self.assertNotIn("out.partial", notes)

    def test_a_published_report_from_another_run_touches_nothing(self):
        # Readable, but not this run's: the token is what makes it ours.
        def replace():
            report = json.loads((self.out / "report.json").read_text())
            report["run_token"] = "someone-else"
            (self.out / "report.json").write_text(json.dumps(report))

        with self.interrupt_after_publishing(then=replace):
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.run_relabel()
        self.assertEqual(self.truth_files(self.out),
                         ["truth.jsonl", "truth.raw.jsonl"])
        self.assertFalse((self.root / "out.failed").exists())
        notes = self.notes(caught.exception)
        self.assertIn("could not tell whether", notes)
        self.assertNotIn("already been published", notes)

    def test_an_unreadable_published_report_touches_nothing(self):
        def corrupt():
            (self.out / "report.json").write_text("{not json")

        with self.interrupt_after_publishing(then=corrupt):
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.run_relabel()
        self.assertEqual(self.truth_files(self.out),
                         ["truth.jsonl", "truth.raw.jsonl"])
        self.assertEqual((self.out / "report.json").read_text(), "{not json")
        self.assertFalse((self.root / "out.failed").exists())
        self.assertIn("could not tell whether", self.notes(caught.exception))


class TestTheCommandLine(RelabelCase):

    def test_cleanup_notes_reach_the_user(self):
        real_validate = relabel.validate_records

        def tamper(*args, **kwargs):
            with open(self.dataset / "MANIFEST.json", "a") as fh:
                fh.write(" ")
            return real_validate(*args, **kwargs)

        real_unlink = Path.unlink

        def unlink(path, *args, **kwargs):
            if path.name.startswith("truth"):
                raise PermissionError(f"cannot delete {path.name}")
            return real_unlink(path, *args, **kwargs)

        params = dict(start=START, duration_seconds=DURATION, seed=SEED,
                      unpaced=frozenset(), address_fallback=FALLBACK)
        stderr = io.StringIO()
        with mock.patch.object(relabel, "build_parameters",
                               lambda repo, manifest: params), \
                mock.patch.object(relabel, "validate_records", tamper), \
                mock.patch.object(Path, "unlink", unlink), \
                contextlib.redirect_stderr(stderr):
            code = relabel.main([
                str(self.dataset), "--ledgers", str(self.ledgers),
                "--baseline-labels", str(self.labels / "baseline.py"),
                "--labels", str(self.labels / "candidate.py"),
                "--out", str(self.out)])
        self.assertEqual(code, 1)
        printed = stderr.getvalue()
        self.assertIn("inputs changed", printed)
        self.assertIn("not published: "
                      f"{self.root / 'out.failed' / 'truth.jsonl'}", printed)


class TestCheckPermutation(unittest.TestCase):
    """The permutation check on its own, so each defect is seen in isolation
    rather than behind the byte comparison that would usually catch it first."""

    RAW = ['203.0.113.5 - - [09/Mar/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "U"',
           '198.51.100.9 - - [09/Mar/2026:00:00:01 +0000] "GET /x HTTP/1.1" 200 1 "-" "U"',
           'not a combined line']
    SHIPPED = ['198.51.100.9 - - [10/Mar/2026:07:00:00 +0000] "GET /x HTTP/1.1" 200 1 "-" "U"',
               'not a combined line',
               '203.0.113.5 - - [10/Mar/2026:09:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "U"']
    PERM = [1, 2, 0]

    def records(self, lines):
        return [{"client_ip": line.split(" ", 1)[0]} for line in lines]

    def check(self, perm=None, shipped=None):
        shipped = shipped or self.SHIPPED
        return check_permutation(perm or self.PERM, self.RAW, shipped,
                                 self.records(self.RAW),
                                 self.records(shipped))

    def test_a_true_permutation_passes(self):
        self.assertEqual(self.check(), [])

    def test_a_duplicated_index_is_found(self):
        self.assertTrue(self.check(perm=[1, 1, 0]))

    def test_an_out_of_range_index_is_found(self):
        self.assertTrue(self.check(perm=[1, 3, 0]))

    def test_a_short_permutation_is_found(self):
        self.assertTrue(self.check(perm=[1, 2]))

    def test_a_line_changed_beyond_its_timestamp_is_found(self):
        shipped = list(self.SHIPPED)
        shipped[2] = shipped[2].replace("GET / ", "GET /y ")
        self.assertTrue(self.check(shipped=shipped))

    def test_a_client_that_does_not_carry_over_is_found(self):
        records = self.records(self.SHIPPED)
        records[0]["client_ip"] = "192.0.2.1"
        self.assertTrue(check_permutation(self.PERM, self.RAW, self.SHIPPED,
                                          self.records(self.RAW), records))

    def test_a_client_whose_own_order_changes_is_allowed(self):
        # Not a defect: Apache stamps a request when it arrives and writes it
        # when it finishes, so concurrent requests reach the capture out of
        # time order, and the remap keeps an unpaced tool run's captured
        # offsets -- which re-sorts that client's own requests.
        raw = [self.RAW[0], self.RAW[0].replace("GET / ", "GET /z ")]
        shipped = [raw[1], raw[0]]
        self.assertEqual(check_permutation([1, 0], raw, shipped,
                                           self.records(raw),
                                           self.records(shipped)), [])


class TestBuildParameters(unittest.TestCase):

    def test_they_are_the_ones_the_build_passed(self):
        repo = Path(__file__).resolve().parents[2]
        params = relabel.build_parameters(
            repo, {"project": "apache-shopfront", "tier": "medium",
                   "seed": 19})
        self.assertEqual(params["start"],
                         datetime.fromisoformat("2026-03-09T00:00:00+00:00"))
        self.assertEqual(params["duration_seconds"], 604800)
        self.assertEqual(params["seed"], 19)
        self.assertIn("198.51.100.32", params["unpaced"])
        self.assertEqual(params["address_fallback"], FALLBACK)


if __name__ == "__main__":
    unittest.main()
