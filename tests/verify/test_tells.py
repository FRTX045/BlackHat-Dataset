"""The fake-log audit.

Every statistic elsewhere in this repository describes a dataset. These
describe how it would look to somebody trying to work out whether it was
generated -- which is the question that decides whether research done on it
transfers to a real log.

The audit is pointed at our own datasets first and hardest. A tell it finds in
our data goes in the dataset README; the point of owning the detector is that
it is not somebody else who finds them.

Each test here builds a log with one specific tell in it and checks the audit
names that tell and not the others, because an audit that fires on everything
is the same as one that fires on nothing.
"""

import unittest
from datetime import datetime, timedelta, timezone

from shared.verify.tells import audit, by_name

T0 = datetime(2026, 3, 9, 9, 0, tzinfo=timezone.utc)

REAL_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.3 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148",
    "curl/8.5.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]


def rec(*, ip="203.0.113.5", status=200, method="GET", path="/",
        ua=REAL_AGENTS[0], referer=None, offset=0.0, size=1237,
        request=None):
    return {
        "client_ip": ip, "status": status, "method": method, "path": path,
        "user_agent": ua, "referer": referer, "bytes": size,
        "ts": T0 + timedelta(seconds=offset),
        "request": request if request is not None
        else f"{method} {path} HTTP/1.1",
        "protocol": "HTTP/1.1", "ident": None, "user": None,
    }


def a_plausible_log(n=600, seed=5):
    """A log with none of the tells in it, so a test can show the audit is
    quiet when it should be. Deliberately messy in every dimension the audit
    looks at."""
    import random
    rng = random.Random(seed)
    paths = ["/", "/catalogue", "/product/12", "/product/44", "/about",
             "/basket", "/search?q=oak", "/assets/css/site.css",
             "/assets/js/shop.js", "/assets/img/hero.jpg"]
    out, when = [], 0.0
    for n_line in range(n):
        # Heavy-tailed client population: a few busy, a long tail of one-offs,
        # scattered across the address space rather than counted out of one
        # subnet. Drawing the tail from a single /24 makes the fixture itself
        # trip `sequential_client_addresses`, which is the tell doing its job.
        ip = (f"203.0.113.{rng.randint(2, 9)}" if rng.random() < 0.6
              else f"{rng.randint(12, 210)}.{rng.randint(1, 250)}."
                   f"{rng.randint(1, 250)}.{rng.randint(2, 250)}")
        path = (rng.choice(paths) if rng.random() < 0.85
                else f"/product/{rng.randint(1, 900)}")
        status = rng.choices([200, 304, 404, 302, 500],
                             [0.72, 0.18, 0.06, 0.03, 0.01])[0]
        when += rng.expovariate(1 / 3.0)
        out.append(rec(
            ip=ip, path=path, status=status,
            ua=rng.choice(REAL_AGENTS),
            referer="http://shop.test/" if rng.random() < 0.7 else None,
            offset=when,
            size=None if status == 304 else rng.randint(180, 90_000),
            method=rng.choices(["GET", "POST", "HEAD"], [0.94, 0.05, 0.01])[0]))
    # Real logs always contain some junk, and some out-of-order lines.
    out.append(rec(request="GET /x HTTP/1.1\\x00\\x00", method=None,
                   path=None, status=400, offset=when + 1, size=422))
    out[len(out) // 2], out[len(out) // 2 + 1] = (out[len(out) // 2 + 1],
                                                  out[len(out) // 2])
    return out


class TestTheAuditIsQuietOnAPlausibleLog(unittest.TestCase):

    def test_no_tell_fires_on_the_messy_fixture(self):
        fired = [t.name for t in audit(a_plausible_log()) if t.suspicious]
        self.assertEqual(fired, [], f"false positives: {fired}")

    def test_every_tell_still_reports_its_measurement(self):
        # A tell that did not fire must still publish what it measured, or
        # the audit only ever says what is wrong and never what was checked.
        for tell in audit(a_plausible_log()):
            with self.subTest(tell=tell.name):
                self.assertIsNotNone(tell.measured)
                self.assertTrue(tell.explanation.strip())


class TestRoundNumberResponseSizes(unittest.TestCase):
    """Byte counts of real responses are essentially uniform modulo ten. A
    generator that picked sizes from a list of round numbers leaves the most
    easily checked fingerprint there is."""

    def test_it_fires_when_every_response_is_a_round_number(self):
        log = [rec(size=1000 * (n % 7 + 1), offset=n * 3)
               for n in range(300)]
        self.assertTrue(by_name(audit(log), "round_response_sizes").suspicious)

    def test_it_stays_quiet_on_ordinary_byte_counts(self):
        self.assertFalse(
            by_name(audit(a_plausible_log()), "round_response_sizes").suspicious)

    def test_a_304_carries_no_size_and_is_not_counted_as_round(self):
        log = [rec(status=304, size=None, offset=n * 3) for n in range(200)]
        tell = by_name(audit(log), "round_response_sizes")
        self.assertEqual(tell.measured, 0.0)


class TestImplausibleRequestRate(unittest.TestCase):
    """The defect this project found in its own first datasets: sixty thousand
    requests inside two hundred seconds."""

    def test_it_fires_on_a_log_issued_as_fast_as_the_sockets_allow(self):
        log = [rec(offset=n / 300.0) for n in range(600)]
        self.assertTrue(by_name(audit(log), "implausible_rate").suspicious)

    def test_it_stays_quiet_at_a_rate_a_server_could_actually_serve(self):
        self.assertFalse(
            by_name(audit(a_plausible_log()), "implausible_rate").suspicious)


class TestUserAgentMonoculture(unittest.TestCase):

    def test_it_fires_when_one_agent_makes_almost_every_request(self):
        log = [rec(ip=f"203.0.113.{n % 40 + 2}", offset=n * 3)
               for n in range(400)]
        self.assertTrue(by_name(audit(log), "agent_monoculture").suspicious)

    def test_it_stays_quiet_on_a_realistic_spread(self):
        self.assertFalse(
            by_name(audit(a_plausible_log()), "agent_monoculture").suspicious)


class TestUniformClientVolumes(unittest.TestCase):
    """Real client request counts are heavy-tailed: a handful of crawlers and
    a very long tail of people who looked at one page. A generator that gives
    every client the same number of requests is obvious from the shape."""

    def test_it_fires_when_every_client_makes_the_same_number_of_requests(self):
        log = [rec(ip=f"203.0.113.{n // 10 + 2}", offset=n * 3)
               for n in range(400)]
        self.assertTrue(by_name(audit(log), "uniform_client_volumes").suspicious)

    def test_it_stays_quiet_on_a_heavy_tail(self):
        self.assertFalse(
            by_name(audit(a_plausible_log()),
                    "uniform_client_volumes").suspicious)


class TestMissingResponseClasses(unittest.TestCase):
    """A log of nothing but 200s is not a log of a web server."""

    def test_it_fires_on_an_all_200_log(self):
        log = [rec(offset=n * 3) for n in range(300)]
        tell = by_name(audit(log), "missing_response_classes")
        self.assertTrue(tell.suspicious)
        self.assertIn("304", tell.explanation)

    def test_it_stays_quiet_when_the_usual_classes_are_present(self):
        self.assertFalse(
            by_name(audit(a_plausible_log()),
                    "missing_response_classes").suspicious)


class TestNoMalformedRequests(unittest.TestCase):
    """Every real log that has been on a network for an hour contains junk:
    a truncated request line, a CONNECT probe, a stray non-ASCII byte. A log
    with none has not been on a network."""

    def test_it_fires_on_a_log_with_no_junk_in_it_at_all(self):
        log = [rec(offset=n * 3, status=200) for n in range(400)]
        self.assertTrue(by_name(audit(log), "no_malformed_requests").suspicious)

    def test_it_stays_quiet_when_the_log_has_some(self):
        self.assertFalse(
            by_name(audit(a_plausible_log()),
                    "no_malformed_requests").suspicious)


class TestPerfectlyOrderedTimestamps(unittest.TestCase):
    """A prefork or threaded server interleaves its writes: a large real log
    always contains a few lines whose timestamp precedes the line above.

    This one fires on our own remapped logs, and it is meant to. A rewritten
    clock is sorted by construction, and that is a tell we publish rather than
    one somebody else gets to find.
    """

    def test_it_fires_on_a_perfectly_sorted_log(self):
        log = [rec(offset=n * 3) for n in range(2000)]
        self.assertTrue(
            by_name(audit(log), "perfectly_ordered_timestamps").suspicious)

    def test_it_stays_quiet_when_a_few_lines_are_out_of_order(self):
        self.assertFalse(
            by_name(audit(a_plausible_log(n=2000)),
                    "perfectly_ordered_timestamps").suspicious)

    def test_a_short_log_is_inconclusive_rather_than_suspicious(self):
        # Fifty lines from a quiet server can easily be perfectly ordered.
        log = [rec(offset=n * 3) for n in range(50)]
        tell = by_name(audit(log), "perfectly_ordered_timestamps")
        self.assertFalse(tell.suspicious)
        self.assertTrue(tell.inconclusive)


class TestSequentialClientAddresses(unittest.TestCase):

    def test_it_fires_when_the_client_addresses_are_a_dense_run(self):
        log = [rec(ip=f"203.0.113.{n % 200 + 2}", offset=n * 3)
               for n in range(600)]
        self.assertTrue(
            by_name(audit(log), "sequential_client_addresses").suspicious)

    def test_it_stays_quiet_on_a_scattered_population(self):
        self.assertFalse(
            by_name(audit(a_plausible_log()),
                    "sequential_client_addresses").suspicious)


class TestToyAssetSizes(unittest.TestCase):
    """Response sizes that give away a demo application.

    `%b` is one of the most-used columns in real log analysis -- exfiltration
    volume, anomaly detection on response size, cache-efficiency work all
    start there. A dataset whose stylesheets are 600 bytes and whose front-end
    bundle is 574 is useless for every one of those, and it is invisible in
    the status and category distributions that all looked fine.

    Found by reading twenty-five lines of a shipped log by eye, after every
    aggregate statistic had passed.
    """

    def a_log_with(self, sizes):
        # sizes: {path: bytes}. Repeated enough times to clear both the
        # audit's 150-line floor and this tell's own 20-per-kind minimum.
        out = []
        for n in range(80):
            for path, size in sizes.items():
                out.append(rec(path=path, size=size, offset=n * 3))
        return out

    def test_it_fires_on_a_kilobyte_stylesheet_and_bundle(self):
        log = self.a_log_with({"/assets/css/site.css": 602,
                               "/assets/js/app.js": 574,
                               "/": 1374})
        tell = by_name(audit(log), "toy_asset_sizes")
        self.assertTrue(tell.suspicious)
        self.assertIn("css", tell.explanation)

    def test_it_stays_quiet_on_realistic_sizes(self):
        # Sizes as sent on the wire, so already compressed.
        log = self.a_log_with({"/assets/css/site.css": 11_400,
                               "/assets/js/app.js": 28_900,
                               "/": 9_800,
                               "/assets/img/p/3.jpg": 64_000})
        self.assertFalse(by_name(audit(log), "toy_asset_sizes").suspicious)

    def test_it_names_which_kinds_were_too_small(self):
        log = self.a_log_with({"/assets/css/site.css": 400,
                               "/assets/js/app.js": 41_000,
                               "/": 12_000})
        tell = by_name(audit(log), "toy_asset_sizes")
        self.assertIn("css", tell.explanation)
        self.assertNotIn("js", tell.explanation.split("css")[1])

    def test_a_log_with_no_assets_at_all_is_inconclusive(self):
        log = [rec(path="/api/stock", size=900, offset=n * 3)
               for n in range(200)]
        tell = by_name(audit(log), "toy_asset_sizes")
        self.assertTrue(tell.inconclusive)
        self.assertFalse(tell.suspicious)

    def test_only_successful_responses_with_a_body_are_measured(self):
        # A 404 for a stylesheet is an error page, not a stylesheet, and a 304
        # carries no body at all.
        log = ([rec(path="/assets/css/site.css", size=11_400, offset=n * 3)
                for n in range(60)]
               + [rec(path="/assets/css/gone.css", size=210, status=404,
                      offset=n * 3) for n in range(60)]
               + [rec(path="/assets/css/site.css", size=None, status=304,
                      offset=n * 3) for n in range(60)])
        self.assertFalse(by_name(audit(log), "toy_asset_sizes").suspicious)


class TestTheReport(unittest.TestCase):

    def test_every_tell_publishes_the_threshold_it_used(self):
        # A verdict with no threshold attached is not checkable, and changing
        # the threshold later would silently change what a published audit
        # meant.
        for tell in audit(a_plausible_log()):
            with self.subTest(tell=tell.name):
                self.assertIsNotNone(tell.threshold)

    def test_names_are_unique_so_a_report_can_be_indexed_by_them(self):
        names = [t.name for t in audit(a_plausible_log())]
        self.assertEqual(len(names), len(set(names)))

    def test_an_empty_log_is_inconclusive_everywhere_rather_than_clean(self):
        # The failure mode that matters: an audit that reports "no tells
        # found" on a file it could not read at all.
        for tell in audit([]):
            with self.subTest(tell=tell.name):
                self.assertTrue(tell.inconclusive)
                self.assertFalse(tell.suspicious)

    def test_by_name_raises_on_a_tell_that_does_not_exist(self):
        with self.assertRaises(KeyError):
            by_name(audit(a_plausible_log()), "no_such_tell")


if __name__ == "__main__":
    unittest.main()
