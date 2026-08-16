"""The timestamp remap.

The driver issues its whole virtual plan as fast as the sockets allow, so a
small run's *sequence* is right and its *timing* is not: sixty thousand
requests inside about two hundred seconds of wall clock, and 99.7% of
consecutive lines sharing a second. Nothing time-based can be studied on that.

The remap rewrites the timestamp field and nothing else. What it must not do is
more interesting than what it does, so most of what follows is a constraint:
the same lines, the same addresses, the same per-client episode structure, the
same order within a session -- only the clock changed.
"""

import random
import unittest
from datetime import datetime, timedelta, timezone

from shared.timeline.arrivals import arrival_times_for_count
from shared.timeline.remap import remap_records
from shared.truth.validate import validate_records
from shared.verify.combined import parse_line

TZ = timezone(timedelta(hours=0))
START = datetime(2026, 3, 9, 0, 0, 0, tzinfo=TZ)
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def line_for(ip, when, path="/", status=200, size=1234):
    stamp = (f"{when.day:02d}/{_MONTHS[when.month - 1]}/{when.year}:"
             f"{when.hour:02d}:{when.minute:02d}:{when.second:02d} +0000")
    return (f'{ip} - - [{stamp}] "GET {path} HTTP/1.1" {status} {size} '
            f'"-" "Mozilla/5.0"')


def strip_timestamp(line):
    head, _, rest = line.partition("[")
    _, _, tail = rest.partition("]")
    return head + tail


def a_run(n_clients=12, seed=1):
    """A log shaped like a real one: sessions of pages plus asset cascades,
    every client's requests crammed into a couple of wall-clock seconds."""
    rng = random.Random(seed)
    lines, records, when = [], [], START
    episode = 0
    for c in range(n_clients):
        ip = f"203.0.113.{10 + c}"
        for _ in range(rng.randint(1, 3)):          # sessions for this client
            episode += 1
            instance = f"ep-{episode}"
            for _ in range(rng.randint(2, 5)):       # page views
                for step, category in enumerate(
                        ["browsing"] + ["static_asset"] * rng.randint(3, 8)):
                    path = "/" if not step else f"/assets/{step}.css"
                    lines.append(line_for(ip, when, path))
                    records.append({"line_no": len(lines), "client_ip": ip,
                                    "category": category,
                                    "instance_id": instance})
                    if rng.random() < 0.004:         # the clock barely moves
                        when += timedelta(seconds=1)
    return lines, records


class TestArrivalsForACount(unittest.TestCase):
    """The remap needs exactly one start per episode, which the thinning
    sampler cannot give -- it returns however many it returns."""

    def test_it_returns_exactly_the_count_asked_for(self):
        times = arrival_times_for_count(START, 86400, 500, seed=3)
        self.assertEqual(len(times), 500)

    def test_they_are_sorted_and_inside_the_window(self):
        times = arrival_times_for_count(START, 86400, 400, seed=3)
        self.assertEqual(times, sorted(times))
        self.assertGreaterEqual(times[0], START)
        self.assertLess(times[-1], START + timedelta(seconds=86400))

    def test_it_follows_the_diurnal_curve(self):
        # Not a formality: an evenly spread remap would give the dataset no
        # night and no rush hour, which is the artefact arrivals.py exists to
        # avoid in the first place.
        times = arrival_times_for_count(START, 86400, 4000, seed=5)
        small_hours = sum(1 for t in times if 2 <= t.hour < 5)
        evening = sum(1 for t in times if 18 <= t.hour < 21)
        self.assertGreater(evening, small_hours * 3)

    def test_the_same_seed_gives_the_same_times(self):
        self.assertEqual(arrival_times_for_count(START, 3600, 50, seed=9),
                         arrival_times_for_count(START, 3600, 50, seed=9))

    def test_asking_for_none_gives_none(self):
        self.assertEqual(arrival_times_for_count(START, 3600, 0, seed=9), [])


class TestNothingButTheClockChanges(unittest.TestCase):

    def setUp(self):
        self.lines, self.records = a_run()
        self.out, self.truth, self.report = remap_records(
            self.lines, self.records, start=START,
            duration_seconds=86400, seed=11)

    def test_the_line_count_is_unchanged(self):
        self.assertEqual(len(self.out), len(self.lines))
        self.assertEqual(self.report.lines, len(self.lines))

    def test_every_line_is_one_of_the_originals_with_a_new_timestamp(self):
        self.assertEqual(sorted(strip_timestamp(x) for x in self.out),
                         sorted(strip_timestamp(x) for x in self.lines))

    def test_the_request_and_the_agent_survive_byte_for_byte(self):
        for line in self.out:
            self.assertIn('"GET ', line)
            self.assertTrue(line.endswith('"Mozilla/5.0"'))

    def test_the_truth_records_are_renumbered_contiguously(self):
        self.assertEqual([r["line_no"] for r in self.truth],
                         list(range(1, len(self.out) + 1)))

    def test_every_line_still_matches_its_truth_record(self):
        for line, record in zip(self.out, self.truth):
            self.assertEqual(parse_line(line)["client_ip"], record["client_ip"])

    def test_the_output_passes_the_validator(self):
        # Closes the loop rather than testing the remap against a hand-written
        # expectation: whatever it produced has to satisfy the same rules every
        # shipped dataset is held to.
        problems = validate_records(
            self.truth, (parse_line(x)["client_ip"] for x in self.out))
        self.assertEqual(problems, [])

    def test_the_categories_travel_with_their_lines(self):
        before = sorted((r["client_ip"], r["category"]) for r in self.records)
        after = sorted((r["client_ip"], r["category"]) for r in self.truth)
        self.assertEqual(before, after)


class TestTheStructureSurvives(unittest.TestCase):

    def setUp(self):
        self.lines, self.records = a_run(n_clients=20, seed=4)
        self.out, self.truth, self.report = remap_records(
            self.lines, self.records, start=START,
            duration_seconds=86400, seed=12)

    def test_order_within_an_episode_is_preserved(self):
        # A session whose asset requests came back reordered would describe a
        # page load that never happened.
        def by_episode(records, lines):
            seen = {}
            for record, line in zip(records, lines):
                key = (record["client_ip"], record["instance_id"])
                seen.setdefault(key, []).append(strip_timestamp(line))
            return seen

        before = by_episode(self.records, self.lines)
        after = by_episode(self.truth, self.out)
        self.assertEqual(set(before), set(after))
        for key in before:
            self.assertEqual(before[key], after[key])

    def test_an_asset_cascade_stays_with_the_page_that_caused_it(self):
        # Assets spread over minutes would not be a page load. Every asset
        # must land within a few seconds of the request before it.
        previous = None
        for line, record in zip(self.out, self.truth):
            ts = parse_line(line)["ts"]
            if record["category"] == "static_asset" and previous is not None:
                gap = (ts - previous[0]).total_seconds()
                if previous[1] == record["instance_id"]:
                    self.assertLessEqual(gap, 5, f"asset {gap}s after its page")
            previous = (ts, record["instance_id"])

    def test_a_client_never_has_two_sessions_running_at_once(self):
        spans = {}
        for line, record in zip(self.out, self.truth):
            key = (record["client_ip"], record["instance_id"])
            ts = parse_line(line)["ts"]
            lo, hi = spans.get(key, (ts, ts))
            spans[key] = (min(lo, ts), max(hi, ts))
        by_client = {}
        for (ip, _), span in spans.items():
            by_client.setdefault(ip, []).append(span)
        for ip, windows in by_client.items():
            windows.sort()
            for earlier, later in zip(windows, windows[1:]):
                self.assertLessEqual(earlier[1], later[0],
                                     f"{ip} has overlapping sessions")


class TestItActuallyFixesTheDefect(unittest.TestCase):
    """The defect is not "consecutive lines share a second" on its own.

    Any busy server produces that: a page load is a dozen requests inside one
    second, and a site doing ten requests a second has almost no consecutive
    pair with a gap in it. Holding that share to a threshold would be tuning
    against a number that is high on real logs too.

    What was actually broken was the rate and the pacing -- sixty thousand
    requests in two hundred seconds, and not one measurable think time
    anywhere in the file. Those are what these check.
    """

    def setUp(self):
        self.lines, self.records = a_run(n_clients=30, seed=6)
        self.out, self.truth, self.report = remap_records(
            self.lines, self.records, start=START,
            duration_seconds=86400, seed=13)

    def _rate(self, lines):
        stamps = [parse_line(x)["ts"] for x in lines]
        span = (stamps[-1] - stamps[0]).total_seconds()
        return len(lines) / span if span else float("inf")

    def test_the_achieved_request_rate_becomes_plausible(self):
        self.assertGreater(self._rate(self.lines), 50,
                           "the fixture is meant to be absurdly fast")
        self.assertLess(self._rate(self.out), 5)

    def test_there_is_think_time_between_one_page_and_the_next(self):
        # Before the remap every gap is zero, so no session can be
        # reconstructed and no dwell time measured. This is the property that
        # makes the rewritten log worth having.
        def page_gaps(lines, records):
            gaps, previous = [], None
            for line, record in zip(lines, records):
                if record["category"] != "browsing":
                    continue
                ts = parse_line(line)["ts"]
                key = (record["client_ip"], record["instance_id"])
                if previous and previous[1] == key:
                    gaps.append((ts - previous[0]).total_seconds())
                previous = (ts, key)
            return sorted(gaps)

        before = page_gaps(self.lines, self.records)
        after = page_gaps(self.out, self.truth)
        self.assertEqual(before[len(before) // 2], 0,
                         "the fixture is meant to have no think time in it")
        self.assertGreater(after[len(after) // 2], 1.0)

    def test_a_session_no_longer_happens_in_a_single_second(self):
        spans = {}
        for line, record in zip(self.out, self.truth):
            key = (record["client_ip"], record["instance_id"])
            ts = parse_line(line)["ts"]
            lo, hi = spans.get(key, (ts, ts))
            spans[key] = (min(lo, ts), max(hi, ts))
        durations = sorted((hi - lo).total_seconds()
                           for lo, hi in spans.values())
        self.assertGreater(durations[len(durations) // 2], 10)

    def test_the_log_spans_the_window_it_was_given(self):
        lines, records = a_run(n_clients=30, seed=6)
        out, _, report = remap_records(lines, records, start=START,
                                       duration_seconds=86400, seed=13)
        span = parse_line(out[-1])["ts"] - parse_line(out[0])["ts"]
        self.assertGreater(span.total_seconds(), 86400 * 0.5)
        self.assertLessEqual(report.new_span_seconds, 86400 + 3600)

    def test_the_timestamps_never_go_backwards(self):
        lines, records = a_run(n_clients=25, seed=8)
        out, _, _ = remap_records(lines, records, start=START,
                                  duration_seconds=86400, seed=14)
        stamps = [parse_line(x)["ts"] for x in out]
        self.assertEqual(stamps, sorted(stamps))


class TestWhenAClientAppearsIsNotDecidedByTheCapture(unittest.TestCase):
    """The capture's order is an artefact of how the harness was scheduled.

    Campaigns start with the driver and finish early; the noise generator runs
    last. Handing out times in capture order therefore stamps that schedule
    onto the clock: every campaign lands in the same hour, and because attack
    sessions are small, the hour they land in gets a hole in its traffic. The
    first build did exactly that -- 44% of all attack lines inside two hours,
    in the middle of the day's deepest trough.

    So a client's place on the clock has to come from the arrival curve, and
    only its *internal* rhythm from the capture.
    """

    def capture(self):
        """Two groups of clients, cleanly separated in capture time: one
        early, one late. That is the correlation the remap must break."""
        lines, records, when = [], [], START
        for group in range(2):
            for c in range(14):
                ip = f"203.0.113.{10 + group * 20 + c}"
                for _ in range(6):
                    lines.append(line_for(ip, when))
                    records.append({"line_no": len(lines), "client_ip": ip,
                                    "category": "browsing",
                                    "instance_id": f"{ip}-1"})
            when += timedelta(seconds=600)
        return lines, records

    def hours_by_group(self, out, truth):
        early, late = [], []
        for line, record in zip(out, truth):
            octet = int(record["client_ip"].rsplit(".", 1)[1])
            (early if octet < 30 else late).append(parse_line(line)["ts"])
        return early, late

    def test_clients_that_started_together_are_spread_over_the_window(self):
        lines, records = self.capture()
        out, truth, _ = remap_records(lines, records, start=START,
                                      duration_seconds=86400, seed=31)
        early, _ = self.hours_by_group(out, truth)
        self.assertGreater(len({t.hour for t in early}), 6,
                           "the early clients all landed in the same few hours")

    def test_the_two_groups_end_up_interleaved_rather_than_in_order(self):
        lines, records = self.capture()
        out, truth, _ = remap_records(lines, records, start=START,
                                      duration_seconds=86400, seed=31)
        early, late = self.hours_by_group(out, truth)
        # If capture order still decided the clock, every early timestamp
        # would precede every late one.
        self.assertGreater(max(early), min(late))
        self.assertGreater(max(late), min(early))


class TestOneAddressAtATime(unittest.TestCase):
    """An address's own sessions must come out in order and never overlap.

    Preserving the *spacing* between them as well was tried and abandoned:
    `ippools` reuses addresses hard, so an address is not one actor but a
    succession of unrelated visitors spanning the whole capture. Anchoring
    each address once and keeping its internal spacing made nearly every
    address as long as the whole window, and pulling them back to fit put 651
    requests on the first second of the log.

    So the gap between an operator's phases is redrawn rather than preserved.
    Their order is not, and that is what these pin down.
    """

    def capture(self):
        lines, records, when = [], [], START
        for phase in range(4):
            for _ in range(5):
                lines.append(line_for("192.0.2.21", when, path="/admin"))
                records.append({"line_no": len(lines),
                                "client_ip": "192.0.2.21",
                                "category": "enumeration",
                                "instance_id": f"phase-{phase}"})
            when += timedelta(seconds=20)
            # Somebody else, so the log is not one client's alone.
            lines.append(line_for("203.0.113.50", when))
            records.append({"line_no": len(lines), "client_ip": "203.0.113.50",
                            "category": "browsing", "instance_id": "other"})
        return lines, records

    def test_the_phases_never_overlap_each_other(self):
        lines, records = self.capture()
        out, truth, _ = remap_records(lines, records, start=START,
                                      duration_seconds=86400, seed=33)
        spans = {}
        for line, record in zip(out, truth):
            if record["client_ip"] != "192.0.2.21":
                continue
            ts = parse_line(line)["ts"]
            lo, hi = spans.get(record["instance_id"], (ts, ts))
            spans[record["instance_id"]] = (min(lo, ts), max(hi, ts))
        ordered = [spans[f"phase-{n}"] for n in range(4)]
        for earlier, later in zip(ordered, ordered[1:]):
            self.assertLessEqual(earlier[1], later[0])

    def test_the_phases_stay_in_the_order_the_operator_worked_them(self):
        lines, records = self.capture()
        out, truth, _ = remap_records(lines, records, start=START,
                                      duration_seconds=86400, seed=33)
        seen = [r["instance_id"] for r in truth
                if r["client_ip"] == "192.0.2.21"]
        firsts = list(dict.fromkeys(seen))
        self.assertEqual(firsts, ["phase-0", "phase-1", "phase-2", "phase-3"])

    def test_a_heavily_reused_address_does_not_pile_up_on_one_second(self):
        # The failure this replaces: every address that spanned the capture
        # was pulled back to the start of the window so it would fit, and 651
        # requests landed on the log's first second.
        lines, records, when = [], [], START
        for n in range(60):
            ip = "203.0.113.7" if n % 2 else f"203.0.113.{100 + n}"
            lines.append(line_for(ip, when))
            records.append({"line_no": len(lines), "client_ip": ip,
                            "category": "browsing",
                            "instance_id": f"{ip}-{n}"})
            when += timedelta(seconds=30)
        out, _, report = remap_records(lines, records, start=START,
                                       duration_seconds=86400, seed=35)
        stamps = [parse_line(x)["ts"] for x in out]
        busiest = max(stamps.count(s) for s in set(stamps))
        self.assertLess(busiest, len(out) // 4)
        self.assertLessEqual(report.new_span_seconds, 86400 + 3600)


class TestReproducibilityAndReporting(unittest.TestCase):

    def test_the_same_seed_gives_the_same_log(self):
        lines, records = a_run(seed=2)
        first, _, _ = remap_records(lines, records, start=START,
                                    duration_seconds=3600, seed=21)
        second, _, _ = remap_records(lines, records, start=START,
                                     duration_seconds=3600, seed=21)
        self.assertEqual(first, second)

    def test_a_different_seed_gives_a_different_log(self):
        lines, records = a_run(seed=2)
        first, _, _ = remap_records(lines, records, start=START,
                                    duration_seconds=3600, seed=21)
        second, _, _ = remap_records(lines, records, start=START,
                                     duration_seconds=3600, seed=22)
        self.assertNotEqual(first, second)

    def test_the_report_says_what_was_done(self):
        lines, records = a_run(seed=2)
        _, _, report = remap_records(lines, records, start=START,
                                     duration_seconds=3600, seed=21)
        self.assertEqual(report.lines, len(lines))
        self.assertGreater(report.episodes, 0)
        self.assertGreater(report.new_span_seconds,
                           report.original_span_seconds)
        self.assertIn("timestamp", report.description.lower())


class TestItRefusesRatherThanGuesses(unittest.TestCase):

    def test_a_truth_file_shorter_than_the_log_is_an_error(self):
        lines, records = a_run(seed=2)
        with self.assertRaises(ValueError):
            remap_records(lines, records[:-1], start=START,
                          duration_seconds=3600, seed=21)

    def test_a_truth_record_naming_a_different_address_is_an_error(self):
        # The pairing is the entire guarantee. If it is already broken the
        # remap must not carry it forward silently.
        lines, records = a_run(seed=2)
        records[5] = dict(records[5], client_ip="198.51.100.9")
        with self.assertRaises(ValueError):
            remap_records(lines, records, start=START,
                          duration_seconds=3600, seed=21)


class TestLinesThatDoNotParse(unittest.TestCase):

    def test_they_are_kept_in_place_and_counted(self):
        lines, records = a_run(seed=2)
        lines.insert(4, "this is not a combined log line at all")
        records.insert(4, {"line_no": 5, "client_ip": "203.0.113.10",
                           "category": "unknown", "instance_id": "ep-1"})
        for n, record in enumerate(records, 1):
            record["line_no"] = n
        out, truth, report = remap_records(lines, records, start=START,
                                           duration_seconds=3600, seed=21)
        self.assertEqual(len(out), len(lines))
        self.assertEqual(report.unparsed_lines, 1)
        self.assertIn("this is not a combined log line at all", out)


if __name__ == "__main__":
    unittest.main()
