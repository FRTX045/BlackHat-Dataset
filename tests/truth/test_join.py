"""Tests for the label join -- the step the whole dataset's credibility rests on.

The join takes the tagged log Apache wrote and the ledgers the traffic
components wrote, and produces the two files that ship: access.log and
truth.jsonl. If it is subtly wrong, every line still looks plausible and
nothing downstream notices, which is exactly why these tests are picky about
the boundaries rather than the happy path.
"""

import json
import tempfile
import unittest
from pathlib import Path

from shared.truth.join import join
from shared.truth.reader import read_truth
from shared.truth.validate import validate_records

TAGGED = [
    'r1 203.0.113.5 - - [16/Aug/2026:09:00:01 +0000] "GET / HTTP/1.1" 200 4210 "-" "UA/1"',
    'r2 203.0.113.5 - - [16/Aug/2026:09:00:01 +0000] "GET /assets/css/site.css HTTP/1.1" 200 812 "https://shop.test/" "UA/1"',
    'r3 198.51.100.9 - - [16/Aug/2026:09:00:02 +0000] "GET /.env HTTP/1.1" 404 199 "-" "UA/2"',
]

LEDGER = [
    {"request_id": "r1", "client_ip": "203.0.113.5", "category": "browsing",
     "instance_id": "203.0.113.5#1"},
    {"request_id": "r2", "client_ip": "203.0.113.5", "category": "static_asset",
     "instance_id": "203.0.113.5#1"},
    {"request_id": "r3", "client_ip": "198.51.100.9",
     "category": "reconnaissance", "instance_id": "198.51.100.9#1"},
]

HEADER = dict(scenario="t", seed=1, source_file_id="access.log",
              generated_at="2026-08-16T09:00:00+00:00")


class JoinCase(unittest.TestCase):

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.write_tagged(TAGGED)
        self.write_ledger(LEDGER)

    def write_tagged(self, lines):
        (self.dir / "access.tagged.log").write_text("\n".join(lines) + "\n")

    def write_ledger(self, records, name="ledger.jsonl"):
        (self.dir / name).write_text(
            "\n".join(json.dumps(r) for r in records) + "\n")

    def run_join(self, ledgers=("ledger.jsonl",), **kwargs):
        return join(self.dir / "access.tagged.log",
                    [self.dir / name for name in ledgers],
                    self.dir / "truth.jsonl", self.dir / "access.log",
                    HEADER, **kwargs)

    @property
    def access_lines(self):
        return (self.dir / "access.log").read_text().splitlines()

    @property
    def truth_records(self):
        _, records = read_truth(self.dir / "truth.jsonl")
        return list(records)


class TestDerivedLog(JoinCase):

    def test_derived_log_is_the_tagged_log_minus_the_id_prefix(self):
        self.run_join()
        self.assertEqual(self.access_lines[0], TAGGED[0].split(" ", 1)[1])
        self.assertEqual(len(self.access_lines), 3)
        self.assertNotIn("r1", self.access_lines[0])

    def test_the_remainder_is_copied_verbatim_not_reassembled(self):
        # A line Apache wrote with an escaped quote inside the request must
        # survive byte for byte. Rebuilding it from parsed fields would make
        # the shipped log our reconstruction of Apache's output.
        awkward = (r'r9 192.0.2.9 - - [16/Aug/2026:09:00:03 +0000] '
                   r'"GET /search?q=%22 HTTP/1.1\" x" 400 226 "-" "-"')
        self.write_tagged([awkward])
        self.write_ledger([{"request_id": "r9", "client_ip": "192.0.2.9",
                            "category": "injection", "instance_id": "a#1"}])
        self.run_join()
        self.assertEqual(self.access_lines[0], awkward.split(" ", 1)[1])


class TestTruthRecords(JoinCase):

    def test_truth_has_one_record_per_log_line_in_order(self):
        self.run_join()
        self.assertEqual([r["line_no"] for r in self.truth_records], [1, 2, 3])
        self.assertEqual([r["category"] for r in self.truth_records],
                         ["browsing", "static_asset", "reconnaissance"])

    def test_truth_client_ip_matches_the_log_line_address(self):
        self.run_join()
        for line, record in zip(self.access_lines, self.truth_records):
            self.assertEqual(line.split(" ")[0], record["client_ip"])

    def test_the_output_satisfies_the_validator(self):
        # Closes the loop between the two modules: rather than checking the
        # join against a fixture someone hand-wrote, check it against the rules
        # the verifier will actually apply to the shipped dataset.
        self.run_join()
        ips = [line.split(" ")[0] for line in self.access_lines]
        self.assertEqual(validate_records(self.truth_records, ips), [])

    def test_line_counts_of_the_two_shipped_files_always_agree(self):
        report = self.run_join()
        self.assertEqual(len(self.access_lines), len(self.truth_records))
        self.assertEqual(report.lines, 3)


class TestHardFailures(JoinCase):

    def test_ledger_ip_disagreeing_with_log_ip_is_a_hard_failure(self):
        # Means the trust boundary or the proxy is broken. Every label after it
        # is suspect, so this stops the build rather than annotating a record.
        spoiled = dict(LEDGER[0])
        spoiled["client_ip"] = "192.0.2.1"
        self.write_ledger([spoiled] + LEDGER[1:])
        with self.assertRaises(ValueError):
            self.run_join()

    def test_a_category_outside_the_vocabulary_is_a_hard_failure(self):
        spoiled = dict(LEDGER[0])
        spoiled["category"] = "sqli"
        self.write_ledger([spoiled] + LEDGER[1:])
        with self.assertRaises(ValueError):
            self.run_join()


class TestThingsCountedRatherThanHidden(JoinCase):

    def test_unmatched_request_id_is_reported_not_silently_labelled(self):
        self.write_ledger(LEDGER[:2])
        report = self.run_join()
        self.assertEqual(report.unmatched_ids, 1)
        self.assertEqual(self.truth_records[2]["category"], "unknown")

    def test_a_dash_request_id_counts_as_unmatched(self):
        # Apache writes "-" when the request carried no X-Request-Id: a
        # malformed request rejected before mod_remoteip ran, for instance.
        # Those lines are real and must ship, labelled honestly.
        self.write_tagged(["- " + TAGGED[0].split(" ", 1)[1]])
        report = self.run_join()
        self.assertEqual(report.unmatched_ids, 1)
        self.assertEqual(len(self.access_lines), 1)
        self.assertEqual(self.truth_records[0]["category"], "unknown")

    def test_an_unparseable_line_still_ships_with_a_record(self):
        # Dropping a line Apache wrote would silently shorten the dataset and
        # shift every line number after it.
        self.write_tagged([TAGGED[0], "r2 this is not a combined line at all"])
        self.write_ledger(LEDGER[:1])
        report = self.run_join()
        self.assertEqual(report.unparsed_lines, 1)
        self.assertEqual(len(self.access_lines), 2)
        self.assertEqual(len(self.truth_records), 2)
        self.assertEqual(self.truth_records[1]["category"], "unknown")


class TestDerivedLabels(JoinCase):
    """Ledgers from the proxy carry no category; it comes from the request."""

    def setUp(self):
        super().setUp()
        self.write_ledger([
            {"request_id": "r1", "client_ip": "203.0.113.5", "actor": "tool",
             "method": "GET", "path": "/"},
            {"request_id": "r2", "client_ip": "203.0.113.5", "actor": "tool",
             "method": "GET", "path": "/assets/css/site.css"},
            {"request_id": "r3", "client_ip": "198.51.100.9", "actor": "tool",
             "method": "GET", "path": "/.env"},
        ])

    def label(self, entry):
        return {"/": "browsing", "/assets/css/site.css": "static_asset",
                "/.env": "reconnaissance"}[entry["path"]]

    def test_a_ledger_without_a_category_is_labelled_from_the_request(self):
        self.run_join(labeller=self.label)
        self.assertEqual([r["category"] for r in self.truth_records],
                         ["browsing", "static_asset", "reconnaissance"])

    def test_an_explicit_category_wins_over_the_labeller(self):
        # The driver knows its own intent; the proxy can only infer.
        self.write_ledger([dict(LEDGER[0]), LEDGER[1], LEDGER[2]])
        self.run_join(labeller=lambda entry: "unknown")
        self.assertEqual(self.truth_records[0]["category"], "browsing")

    def test_derived_episodes_change_id_when_the_activity_changes(self):
        self.run_join(labeller=self.label)
        first, second = self.truth_records[0], self.truth_records[1]
        self.assertNotEqual(first["instance_id"], second["instance_id"])

    def test_derived_episodes_keep_one_id_while_the_activity_continues(self):
        self.write_tagged([TAGGED[0], TAGGED[0].replace("r1", "r2", 1)])
        self.write_ledger([
            {"request_id": "r1", "client_ip": "203.0.113.5", "actor": "tool",
             "method": "GET", "path": "/"},
            {"request_id": "r2", "client_ip": "203.0.113.5", "actor": "tool",
             "method": "GET", "path": "/"},
        ])
        self.run_join(labeller=self.label)
        self.assertEqual(self.truth_records[0]["instance_id"],
                         self.truth_records[1]["instance_id"])

    def test_derived_episodes_stay_contiguous_when_two_clients_interleave(self):
        # Two visitors overlapping is normal and must not produce a validator
        # error. Assigning ids in log order is what makes that true.
        self.write_tagged([
            'a1 203.0.113.5 - - [16/Aug/2026:09:00:01 +0000] "GET / HTTP/1.1" 200 1 "-" "U"',
            'b1 198.51.100.9 - - [16/Aug/2026:09:00:01 +0000] "GET /.env HTTP/1.1" 404 1 "-" "U"',
            'a2 203.0.113.5 - - [16/Aug/2026:09:00:02 +0000] "GET / HTTP/1.1" 200 1 "-" "U"',
        ])
        self.write_ledger([
            {"request_id": "a1", "client_ip": "203.0.113.5", "actor": "t",
             "method": "GET", "path": "/"},
            {"request_id": "b1", "client_ip": "198.51.100.9", "actor": "t",
             "method": "GET", "path": "/.env"},
            {"request_id": "a2", "client_ip": "203.0.113.5", "actor": "t",
             "method": "GET", "path": "/"},
        ])
        self.run_join(labeller=self.label)
        ips = [line.split(" ")[0] for line in self.access_lines]
        self.assertEqual(validate_records(self.truth_records, ips), [])


class TestAddressFallback(JoinCase):
    """Lines Apache rejected before mod_remoteip ran carry no request id.

    Measured: a garbage request line, a space in the path, and an HTTP/0.9
    request with no version reach the log with the connection's real address
    and no X-Request-Id. They are real lines and they must ship labelled, so
    the shapes that do it are issued from an address reserved for nothing
    else and the join labels by that address.
    """

    def setUp(self):
        super().setUp()
        self.write_tagged([
            TAGGED[0],
            '- 203.0.113.6 - - [16/Aug/2026:09:00:05 +0000] "GARBAGE" 400 352 "-" "-"',
        ])
        self.write_ledger(LEDGER[:1])

    def test_an_unmatched_line_from_a_reserved_address_is_labelled(self):
        report = self.run_join(address_fallback={"203.0.113.6": "reconnaissance"})
        self.assertEqual([r["category"] for r in self.truth_records],
                         ["browsing", "reconnaissance"])

    def test_fallback_lines_are_counted_separately_from_unknowns(self):
        report = self.run_join(address_fallback={"203.0.113.6": "reconnaissance"})
        self.assertEqual(report.address_fallback_lines, 1)
        self.assertEqual(report.unmatched_ids, 1)

    def test_without_a_fallback_the_same_line_is_unknown(self):
        report = self.run_join()
        self.assertEqual(self.truth_records[1]["category"], "unknown")
        self.assertEqual(report.address_fallback_lines, 0)

    def test_a_fallback_category_outside_the_vocabulary_is_refused(self):
        with self.assertRaises(ValueError):
            self.run_join(address_fallback={"203.0.113.6": "portscan"})

    def test_fallback_output_still_satisfies_the_validator(self):
        self.run_join(address_fallback={"203.0.113.6": "reconnaissance"})
        ips = [line.split(" ")[0] for line in self.access_lines]
        self.assertEqual(validate_records(self.truth_records, ips), [])


class TestMultipleLedgers(JoinCase):

    def test_records_are_found_across_every_ledger_given(self):
        # The driver, the proxy and the noise generator each write their own.
        self.write_ledger(LEDGER[:1], name="driver.jsonl")
        self.write_ledger(LEDGER[1:], name="proxy.jsonl")
        report = self.run_join(ledgers=("driver.jsonl", "proxy.jsonl"))
        self.assertEqual(report.unmatched_ids, 0)
        self.assertEqual([r["category"] for r in self.truth_records],
                         ["browsing", "static_asset", "reconnaissance"])


if __name__ == "__main__":
    unittest.main()
