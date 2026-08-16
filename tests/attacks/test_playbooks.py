"""The hand-written attack playbooks.

What matters here is not that the payloads are clever. It is that every step
carries a label the join can use, that the labels are honest about what each
request was, and that the episodes a playbook produces are contiguous -- the
same constraint every other traffic source is held to.
"""

import sys
import unittest
from pathlib import Path

from shared.truth.writer import CATEGORIES

sys.path.insert(
    0, str(Path(__file__).resolve().parents[2]
           / "projects" / "apache-shopfront" / "attacks"))

from playbooks import PLAYBOOKS, AttackStep  # noqa: E402

ATTACK_CATEGORIES = {
    "reconnaissance", "enumeration", "injection", "path_traversal",
    "access_control", "credential_attack", "ssrf", "exploitation",
}


class TestEveryPlaybook(unittest.TestCase):

    def test_all_playbooks_produce_steps(self):
        for name, make in PLAYBOOKS.items():
            with self.subTest(playbook=name):
                self.assertGreaterEqual(len(make()), 1)

    def test_every_category_is_in_the_controlled_vocabulary(self):
        for name, make in PLAYBOOKS.items():
            for step in make():
                with self.subTest(playbook=name, path=step.path):
                    self.assertIn(step.category, CATEGORIES)

    def test_every_step_is_a_real_http_method(self):
        allowed = {"GET", "POST", "HEAD", "OPTIONS", "DELETE", "PUT"}
        for name, make in PLAYBOOKS.items():
            for step in make():
                with self.subTest(playbook=name, path=step.path):
                    self.assertIn(step.method, allowed)

    def test_every_step_targets_the_lab_application(self):
        # A payload naming an outside host is a bug in the payload, not a
        # feature. The SSRF playbook names external hosts inside a query
        # string on purpose; the request itself still goes to the lab.
        for name, make in PLAYBOOKS.items():
            for step in make():
                with self.subTest(playbook=name, path=step.path):
                    self.assertTrue(step.path.startswith("/"))

    def test_episodes_within_a_playbook_are_contiguous(self):
        # Same rule as the personas: an activity is a run, and a playbook that
        # returned to an earlier activity would produce episodes that validate
        # and mean nothing.
        for name, make in PLAYBOOKS.items():
            runs = []
            for step in make():
                if not runs or runs[-1] != step.activity:
                    runs.append(step.activity)
            with self.subTest(playbook=name):
                self.assertEqual(len(runs), len(set(runs)),
                                 f"{name} returns to an earlier activity: {runs}")

    def test_every_step_carries_a_thinking_time(self):
        for name, make in PLAYBOOKS.items():
            for step in make():
                with self.subTest(playbook=name, path=step.path):
                    self.assertGreater(step.think, 0)


class TestTheyLookHuman(unittest.TestCase):

    def test_the_attacks_are_paced_far_slower_than_a_tool(self):
        # A tool fires as fast as the socket allows. If these did too, an
        # analyst could separate hand-written attacks from tool runs on
        # inter-arrival time alone and the distinction would teach nothing.
        for name in ("sqli_probing", "path_traversal", "ssrf", "ssti"):
            steps = PLAYBOOKS[name]()
            mean = sum(s.think for s in steps) / len(steps)
            with self.subTest(playbook=name):
                self.assertGreater(mean, 1.5, f"{name} is paced like a script")

    def test_the_injection_playbook_gets_the_column_count_wrong_first(self):
        # Real UNION injection is guesswork. A playbook that hits eight columns
        # immediately produces a log with none of the failed attempts that make
        # up most of what an analyst actually sees.
        paths = [s.path for s in PLAYBOOKS["sqli_probing"]()]
        union = [p for p in paths if "UNION" in p or "union" in p.lower()]
        self.assertGreaterEqual(len(union), 3,
                                "no failed column-count guesses")

    def test_the_traversal_playbook_counts_the_levels_wrong_first(self):
        paths = [s.path for s in PLAYBOOKS["path_traversal"]()]
        self.assertTrue(any("..%2F..%2Fetc" in p or "%2E%2E" in p.upper()
                            or p.count("..") == 2 for p in paths),
                        "no under-counted traversal attempt")

    def test_a_playbook_establishes_a_baseline_before_attacking(self):
        # Looking at the normal response first is what an operator does and a
        # scanner does not.
        for name in ("sqli_probing", "path_traversal", "command_injection",
                     "ssti", "ssrf"):
            first = PLAYBOOKS[name]()[0]
            with self.subTest(playbook=name):
                self.assertNotIn(first.category, {"exploitation"})


class TestLabellingHonesty(unittest.TestCase):

    def test_baseline_requests_are_not_labelled_as_attacks(self):
        # The first request of the traversal playbook fetches a real document.
        # Labelling it path_traversal because of the company it keeps would
        # make the truth file claim something the request does not support.
        first = PLAYBOOKS["path_traversal"]()[0]
        self.assertEqual(first.category, "browsing")

    def test_signing_in_is_authentication_even_inside_an_attack(self):
        for name in ("idor_walk", "upload_webshell"):
            steps = PLAYBOOKS[name]()
            logins = [s for s in steps if s.path == "/login"]
            with self.subTest(playbook=name):
                self.assertTrue(logins)
                for step in logins:
                    self.assertEqual(step.category, "authentication")

    def test_the_payoff_steps_are_labelled_exploitation(self):
        for name in ("sqli_extraction", "upload_webshell", "ssti",
                     "command_injection"):
            cats = {s.category for s in PLAYBOOKS[name]()}
            with self.subTest(playbook=name):
                self.assertIn("exploitation", cats)

    def test_ssrf_steps_are_labelled_ssrf_and_not_something_vaguer(self):
        cats = {s.category for s in PLAYBOOKS["ssrf"]()}
        self.assertEqual(cats, {"ssrf"})

    def test_credential_attacks_are_labelled_as_such(self):
        for name in ("brute_force", "credential_stuffing"):
            cats = {s.category for s in PLAYBOOKS[name]()}
            with self.subTest(playbook=name):
                self.assertEqual(cats, {"credential_attack"})

    def test_the_idor_walk_is_access_control_not_browsing(self):
        walk = [s for s in PLAYBOOKS["idor_walk"]()
                if s.path.startswith("/account/orders/")]
        self.assertGreaterEqual(len(walk), 5)
        self.assertTrue(all(s.category == "access_control" for s in walk))


if __name__ == "__main__":
    unittest.main()
