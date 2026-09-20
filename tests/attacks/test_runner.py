"""The operator that actually issues a campaign.

Covered here because nothing else did: until now the runner was exercised only
by a full Docker build, so a change to what it hands back to a playbook would
have been caught an hour later, in a dataset, or not at all.

These talk to a real socket and a real `http.server`. No mocks: the whole point
of the class under test is what it does with a response, and a stubbed response
would be testing the stub.
"""

import io
import json
import random
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "projects" / "apache-shopfront" / "attacks"))

import runner  # noqa: E402
from campaigns import CAMPAIGNS, by_name  # noqa: E402
from playbooks import AttackStep  # noqa: E402

BODY = "<p class=\"lede\">3 result(s) for <q>oak</q></p>" + "." * 20000


class _Handler(BaseHTTPRequestHandler):

    def _answer(self, status, payload=b""):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    #: Every request this server was sent, so a test can assert on what
    #: actually went over the wire rather than on what was meant to.
    seen = []

    def do_GET(self):
        _Handler.seen.append((self.path, dict(self.headers)))
        self._answer(200, BODY.encode())

    def do_HEAD(self):
        self._answer(200)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        # A server that folds: the sign-in takes, everything else answers.
        self._answer(302 if self.path == "/login" else 200,
                     b"" if self.path == "/login" else BODY.encode())

    def log_message(self, *args):
        pass


class TestWhatTheOperatorHandsBack(unittest.TestCase):
    """A playbook decides what to send next from this, so it has to be real."""

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()
        cls.host, cls.port = runner.HOST, runner.PORT
        runner.HOST, runner.PORT = cls.server.server_address[:2]

    @classmethod
    def tearDownClass(cls):
        runner.HOST, runner.PORT = cls.host, cls.port
        cls.server.shutdown()
        cls.server.server_close()

    def issue(self):
        operator = runner.Operator(by_name("patient_operator"), io.StringIO(),
                                   pace=1000.0, rng=random.Random(0))
        return operator.send(
            AttackStep("GET", "/search?q=oak", "browsing", "probe", 0.0))

    def test_it_reports_the_status_the_server_answered(self):
        self.assertEqual(self.issue().status, 200)

    def test_it_reports_what_the_page_said(self):
        # The marker a playbook branches on lives in the body and nowhere else.
        self.assertIn("result(s)", self.issue().body)

    def test_it_keeps_only_a_prefix_of_a_long_page(self):
        # Whole pages, held for a campaign's worth of requests, buy nothing --
        # every success marker in VULNERABILITIES.md appears near the top.
        self.assertLess(len(self.issue().body), len(BODY))

    def test_it_reports_how_long_the_request_took(self):
        # A time-based injection has no other signal: SQLite has no SLEEP(),
        # so the payload is a heavy query and ~1.0s against ~0.03s is all of it.
        self.assertGreater(self.issue().elapsed, 0.0)


class TestTheLedgerRecordsWhatHappened(TestWhatTheOperatorHandsBack):
    """`expects` is a prediction; the ledger has to carry the observation too.

    Recording only the declaration is how a dataset ends up asserting that a
    campaign succeeded when the run it came from achieved nothing -- and the
    truth file is the one artefact that must never do that.
    """

    def run_one(self, name):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "attack.jsonl"
            runner.run_campaign(name, ledger, pace=10000.0, seed=7)
            return [json.loads(line)
                    for line in ledger.read_text().splitlines() if line.strip()]

    def test_every_record_carries_the_prediction_and_the_observation(self):
        records = self.run_one("credential_hunter")
        self.assertTrue(records)
        for record in records:
            self.assertIn("expects", record)
            self.assertIn("achieved", record)

    def test_what_it_achieved_is_taken_from_the_run(self):
        # This server admits anybody, so the credential attack works out a
        # login it was never given -- something only the run can know.
        self.assertIn("credentials", self.run_one("credential_hunter")[0]["achieved"])

    def test_two_operators_on_one_server_do_not_report_the_same_thing(self):
        # The same server, and one comes away with a break-in while the other
        # comes away with nothing. If `achieved` echoed the declaration rather
        # than the run, these would not be able to differ.
        got = self.run_one("credential_hunter")[0]["achieved"]
        nothing = self.run_one("greedy_scraper")[0]["achieved"]
        self.assertTrue(got)
        self.assertFalse(nothing)


class TestWhatGoesOverTheWire(TestWhatTheOperatorHandsBack):
    """Every attacker line carries `"-"` for Referer today, all 189 of them.

    The interludes are the worst of it: steps written to look like a customer
    looking at the site, which a single field separates from real customers.
    """

    def walk(self, sends_referer):
        _Handler.seen.clear()
        operator = runner.Operator(
            by_name("patient_operator"), io.StringIO(), pace=10000.0,
            rng=random.Random(0), agent="test-agent",
            sends_referer=sends_referer)
        for path in ("/", "/about"):
            operator.send(AttackStep("GET", path, "browsing", "lull-1", 0.0))
        return [headers for _, headers in _Handler.seen]

    def test_a_browser_client_leaves_the_chain_it_walked(self):
        self.assertEqual(self.walk(True)[1].get("Referer"),
                         "http://shop.test/")

    def test_its_first_request_has_nowhere_to_have_come_from(self):
        self.assertIsNone(self.walk(True)[0].get("Referer"))

    def test_a_library_client_sends_none_at_all(self):
        self.assertTrue(all(h.get("Referer") is None for h in self.walk(False)))

    def test_the_agent_on_the_wire_is_the_one_the_operator_was_given(self):
        self.assertEqual(self.walk(False)[0].get("User-Agent"), "test-agent")


class TestOperatorIdentity(unittest.TestCase):
    """Six operators presenting one string is not a thing a real log contains.

    The corpus the ordinary traffic draws from is right here and was simply
    not being used on the attack side. It matters for the same reason the
    single hardcoded agent was chosen in the first place: a hand-written
    attack must not be separable from ordinary traffic by user agent alone.
    """

    def agents(self):
        return {c.name: runner.operator_agent(c.name, 7)[0]
                for c in CAMPAIGNS}

    def test_operators_do_not_all_present_the_same_agent(self):
        self.assertGreater(len(set(self.agents().values())), 1,
                           "every operator sent the same user agent")

    def test_an_operator_keeps_one_agent_across_a_run(self):
        # An agent that changed mid-campaign is an impossible client.
        self.assertEqual(runner.operator_agent("patient_operator", 7),
                         runner.operator_agent("patient_operator", 7))

    def test_a_different_scenario_seed_gives_a_different_cast(self):
        self.assertNotEqual(
            {c.name: runner.operator_agent(c.name, 7)[0] for c in CAMPAIGNS},
            {c.name: runner.operator_agent(c.name, 11)[0] for c in CAMPAIGNS})

    def test_no_operator_announces_itself_as_a_scanner(self):
        # Real opportunistic attack traffic is dominated by libraries and
        # stale browser strings, not by tools that name themselves.
        for name, agent in self.agents().items():
            with self.subTest(campaign=name):
                for banner in ("sqlmap", "nikto", "nmap", "dirb", "gobuster",
                               "hydra", "Nessus", "Acunetix"):
                    self.assertNotIn(banner.lower(), agent.lower())

    def test_most_operators_run_through_a_library_not_a_browser(self):
        # The corpus weights describe ordinary web traffic, where current
        # Chrome is most of everything. Attack traffic is not ordinary web
        # traffic: `useragents.py` says so itself -- "real opportunistic
        # scanning is dominated by libraries and stale browser strings, not
        # current builds" -- and drawing attackers on the browsing weights
        # gave a whole build five browsers and no library at all.
        clients = [runner.operator_agent(c.name, seed)[1]
                   for c in CAMPAIGNS for seed in range(20)]
        browsers = sum(1 for sends_referer in clients if sends_referer)
        self.assertLess(browsers / len(clients), 0.5,
                        "most operators are driving a browser")

    def test_whether_it_sends_a_referer_follows_from_what_it_is(self):
        # Someone proxying a real browser leaves a click chain behind them and
        # someone driving curl does not. Giving every operator the same answer
        # throws away one of the few things in a log that tells them apart.
        answers = {runner.operator_agent(c.name, seed)[1]
                   for c in CAMPAIGNS for seed in (7, 11, 19, 23)}
        self.assertEqual(answers, {True, False})


if __name__ == "__main__":
    unittest.main()
