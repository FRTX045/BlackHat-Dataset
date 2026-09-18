"""The hand-written attack playbooks.

What matters here is not that the payloads are clever. It is that every step
carries a label the join can use, that the labels are honest about what each
request was, and that the episodes a playbook produces are contiguous -- the
same constraint every other traffic source is held to.
"""

import collections
import random
import sys
import unittest
from pathlib import Path
from urllib.parse import unquote

from shared.truth.writer import CATEGORIES

sys.path.insert(
    0, str(Path(__file__).resolve().parents[2]
           / "projects" / "apache-shopfront" / "attacks"))

from playbooks import (PLAYBOOKS, AttackStep,  # noqa: E402
                       Outcome, operator_style)

from tests.attacks.driving import (drive,  # noqa: E402
                                   everything_works,
                                   nothing_works)

ATTACK_CATEGORIES = {
    "reconnaissance", "enumeration", "injection", "path_traversal",
    "access_control", "credential_attack", "ssrf", "exploitation",
}


def drive_play(name, seed, respond):
    """A playbook and the habits of the operator running it."""
    rng = random.Random(seed)
    return drive(PLAYBOOKS[name](rng, operator_style(rng), frozenset()),
                 respond)


def steps_of(name, seed=0, respond=nothing_works):
    """What a playbook sends. By default, against a server that gives nothing.

    A playbook now stops where a real operator would, so the steps it issues
    depend on what it is told. Anything asserting on a payoff step has to say
    which run it means.
    """
    rng = random.Random(seed)
    steps, _ = drive(PLAYBOOKS[name](rng, operator_style(rng),
                                     frozenset()), respond)
    return steps


class TestEveryPlaybook(unittest.TestCase):

    def test_all_playbooks_produce_steps(self):
        for name in PLAYBOOKS:
            with self.subTest(playbook=name):
                self.assertGreaterEqual(len(steps_of(name)), 1)

    def test_every_category_is_in_the_controlled_vocabulary(self):
        for name in PLAYBOOKS:
            for step in steps_of(name):
                with self.subTest(playbook=name, path=step.path):
                    self.assertIn(step.category, CATEGORIES)

    def test_every_step_is_a_real_http_method(self):
        allowed = {"GET", "POST", "HEAD", "OPTIONS", "DELETE", "PUT"}
        for name in PLAYBOOKS:
            for step in steps_of(name):
                with self.subTest(playbook=name, path=step.path):
                    self.assertIn(step.method, allowed)

    def test_every_step_targets_the_lab_application(self):
        # A payload naming an outside host is a bug in the payload, not a
        # feature. The SSRF playbook names external hosts inside a query
        # string on purpose; the request itself still goes to the lab.
        for name in PLAYBOOKS:
            for step in steps_of(name):
                with self.subTest(playbook=name, path=step.path):
                    self.assertTrue(step.path.startswith("/"))

    def test_episodes_within_a_playbook_are_contiguous(self):
        # Same rule as the personas: an activity is a run, and a playbook that
        # returned to an earlier activity would produce episodes that validate
        # and mean nothing.
        for name in PLAYBOOKS:
            runs = []
            for step in steps_of(name):
                if not runs or runs[-1] != step.activity:
                    runs.append(step.activity)
            with self.subTest(playbook=name):
                self.assertEqual(len(runs), len(set(runs)),
                                 f"{name} returns to an earlier activity: {runs}")

    def test_every_step_carries_a_thinking_time(self):
        for name in PLAYBOOKS:
            for step in steps_of(name):
                with self.subTest(playbook=name, path=step.path):
                    self.assertGreater(step.think, 0)


class TestTheyLookHuman(unittest.TestCase):

    def test_the_attacks_are_paced_far_slower_than_a_tool(self):
        # A tool fires as fast as the socket allows. If these did too, an
        # analyst could separate hand-written attacks from tool runs on
        # inter-arrival time alone and the distinction would teach nothing.
        for name in ("sqli_probing", "path_traversal", "ssrf", "ssti"):
            steps = steps_of(name)
            mean = sum(s.think for s in steps) / len(steps)
            with self.subTest(playbook=name):
                self.assertGreater(mean, 1.5, f"{name} is paced like a script")

    def test_the_injection_playbook_gets_the_column_count_wrong_first(self):
        # Real UNION injection is guesswork. A playbook that hits eight columns
        # immediately produces a log with none of the failed attempts that make
        # up most of what an analyst actually sees.
        paths = [s.path for s in steps_of("sqli_probing")]
        union = [p for p in paths if "UNION" in p or "union" in p.lower()]
        self.assertGreaterEqual(len(union), 3,
                                "no failed column-count guesses")

    def test_the_traversal_playbook_counts_the_levels_wrong_first(self):
        paths = [s.path for s in steps_of("path_traversal")]
        self.assertTrue(any("..%2F..%2Fetc" in p or "%2E%2E" in p.upper()
                            or p.count("..") == 2 for p in paths),
                        "no under-counted traversal attempt")

    def test_a_playbook_establishes_a_baseline_before_attacking(self):
        # Looking at the normal response first is what an operator does and a
        # scanner does not.
        for name in ("sqli_probing", "path_traversal", "command_injection",
                     "ssti", "ssrf"):
            first = steps_of(name)[0]
            with self.subTest(playbook=name):
                self.assertNotIn(first.category, {"exploitation"})


class TestLabellingHonesty(unittest.TestCase):

    def test_baseline_requests_are_not_labelled_as_attacks(self):
        # The first request of the traversal playbook fetches a real document.
        # Labelling it path_traversal because of the company it keeps would
        # make the truth file claim something the request does not support.
        first = steps_of("path_traversal")[0]
        self.assertEqual(first.category, "browsing")

    def test_signing_in_is_authentication_even_inside_an_attack(self):
        for name in ("idor_walk", "upload_webshell"):
            steps = steps_of(name)
            logins = [s for s in steps if s.path == "/login"]
            with self.subTest(playbook=name):
                self.assertTrue(logins)
                for step in logins:
                    self.assertEqual(step.category, "authentication")

    def test_the_payoff_steps_are_labelled_exploitation(self):
        # Against a server that folds: the payoff steps only exist on a run
        # that earned them, which is the point of the whole exercise.
        for name in ("sqli_extraction", "upload_webshell", "ssti",
                     "command_injection"):
            cats = {s.category for s in steps_of(name, respond=everything_works)}
            with self.subTest(playbook=name):
                self.assertIn("exploitation", cats)

    def test_ssrf_steps_are_labelled_ssrf_and_not_something_vaguer(self):
        cats = {s.category for s in steps_of("ssrf")}
        self.assertEqual(cats, {"ssrf"})

    def test_credential_attacks_are_labelled_as_such(self):
        for name in ("brute_force", "credential_stuffing"):
            cats = {s.category for s in steps_of(name)}
            with self.subTest(playbook=name):
                self.assertEqual(cats, {"credential_attack"})

    def test_the_idor_walk_is_access_control_not_browsing(self):
        walk = [s for s in steps_of("idor_walk", respond=everything_works)
                if s.path.startswith("/account/orders/")]
        self.assertGreaterEqual(len(walk), 5)
        self.assertTrue(all(s.category == "access_control" for s in walk))


class TestReactingToWhatComesBack(unittest.TestCase):
    """An operator reads the response before choosing the next request.

    The difference is invisible in a single line -- a successful injection is
    the same status and within a few bytes of a failed one. What reaches the
    log is the *behaviour* that follows: someone who got what they wanted
    stops probing and escalates, and someone who did not keeps guessing.
    """

    #: What `app/search.php` renders when the statement raised. A UNION with
    #: the wrong column count lands here; the endpoint swallows the error and
    #: answers 200 either way, so this notice is the whole difference.
    REFUSED = "0 result(s) for <q></q> That search could not be run."
    #: The same page when the statement ran, whatever it returned.
    RENDERED = "1 result(s) for <q></q>"

    def unions_sent(self, respond):
        rng = random.Random(1)
        steps, facts = drive(
            PLAYBOOKS["sqli_probing"](rng, operator_style(rng), frozenset()),
            respond)
        return [s for s in steps if "UNION" in unquote(s.path)], facts

    def test_it_keeps_guessing_column_counts_until_one_fits(self):
        def respond(step):
            query = unquote(step.path)
            wrong = "UNION" in query and "1,2,3,4,5,6,7,8" not in query
            return Outcome(200, self.REFUSED if wrong else self.RENDERED, 0.03)

        unions, _ = self.unions_sent(respond)
        self.assertEqual(len(unions), 3,
                         "it gave up before reaching the count that fits")

    def test_it_stops_guessing_as_soon_as_one_fits(self):
        # Same playbook, but the first count happens to be right.
        unions, _ = self.unions_sent(
            lambda step: Outcome(200, self.RENDERED, 0.03))
        self.assertEqual(len(unions), 1,
                         "it kept guessing column counts after one had worked")

    def test_the_brute_force_stops_when_the_login_locks_out(self):
        # /login answers 429 after five failures. Carrying on through the
        # wordlist against a locked account is a script; a person sees the
        # 429 and stops. Today it sends all twelve regardless.
        sent = []

        def respond(step):
            sent.append(step)
            return Outcome(429 if len(sent) > 5 else 401, "", 0.05)

        steps, facts = drive_play("brute_force", 1,
                             respond)
        self.assertLess(len(steps), 12,
                        "it kept guessing after the account locked out")
        self.assertIn("locked_out", facts)

    def test_it_does_not_fetch_a_shell_it_never_managed_to_upload(self):
        # A 415 means the file was refused. Requesting /uploads/ afterwards is
        # asking for something the operator knows is not there -- and it would
        # put exploitation-labelled lines in the log for an exploit that never
        # landed.
        def refuse_uploads(step):
            if step.method == "POST" and step.path == "/account/avatar":
                return Outcome(415, "Pictures only, please.", 0.05)
            return Outcome(200, "", 0.05)

        steps, facts = drive_play("upload_webshell", 1,
                             refuse_uploads)
        self.assertFalse([s for s in steps if s.path.startswith("/uploads/")],
                         "it went looking for a shell it never uploaded")
        self.assertNotIn("shell", facts)

    def test_forced_browsing_reports_an_admin_path_that_answered(self):
        # /admin/users and /admin/orders enforce the role check; /admin/ping
        # and /admin/template do not. Finding out which is which is the whole
        # point of the phase, and what unlocks the ones worth attacking.
        def role_check(step):
            refused = step.path.startswith(("/admin/users", "/admin/orders"))
            return Outcome(403 if refused else 200, "", 0.05)

        _, facts = drive_play("forced_browsing", 1,
                         role_check)
        self.assertIn("admin_reachable", facts)

    def test_forced_browsing_reports_nothing_when_the_admin_area_holds(self):
        _, facts = drive_play("forced_browsing", 1,
                         lambda step: Outcome(403, "", 0.05))
        self.assertNotIn("admin_reachable", facts)


class TestTwoOperatorsDoNotDoTheSameThing(unittest.TestCase):
    """Six people with the same wordlist, in the same order, is one person.

    Real operators carry different lists and work them in different orders.
    Until now the only thing that varied across a whole build was which of
    four browsing paths appeared between phases, so roughly four fifths of the
    attacker traffic was byte-identical from one dataset to the next.
    """

    def paths(self, name, seed):
        return [s.path for s in steps_of(name, seed=seed)]

    def test_two_operators_walk_different_directories(self):
        self.assertNotEqual(self.paths("directory_enumeration", 1),
                            self.paths("directory_enumeration", 2))

    def test_two_operators_guess_different_passwords(self):
        self.assertNotEqual(self.paths("brute_force", 1) and
                            [s.body for s in steps_of("brute_force", seed=1)],
                            [s.body for s in steps_of("brute_force", seed=2)])

    def test_the_wordlist_is_bigger_than_any_one_operator_walks(self):
        # Otherwise every operator walks all of it and the order is the only
        # thing that differs, which a detector sees straight through.
        walked = set()
        for seed in range(12):
            walked |= set(self.paths("directory_enumeration", seed))
        self.assertGreater(len(walked),
                           len(self.paths("directory_enumeration", 0)))

    def test_the_same_seed_still_walks_the_same_list(self):
        # Determinism is a published claim; variety has to come off the seed.
        self.assertEqual(self.paths("directory_enumeration", 5),
                         self.paths("directory_enumeration", 5))


class TestGuessingTheSyntaxWrong(unittest.TestCase):
    """The operators guessed the column count wrong and never the syntax.

    `#` comments in MySQL and raises in SQLite; `||` only runs the second
    command when the first failed, and `ping 127.0.0.1` succeeds. Somebody who
    does not know what they are talking to reaches for these, gets nothing and
    thinks again -- and that failed attempt is the majority of what an analyst
    actually sees.
    """

    def test_it_tries_another_separator_when_the_first_appends_nothing(self):
        # Only `;` runs the second command on this server.
        def only_semicolon(step):
            path = unquote(step.path)
            worked = "127.0.0.1;" in path
            return Outcome(200, "uid=0(root)" if worked else "PING 127.0.0.1",
                           0.05)

        for seed in range(8):
            steps, facts = drive_play("command_injection", seed,
                                      only_semicolon)
            with self.subTest(seed=seed):
                self.assertIn("rce", facts,
                              "it gave up on the first separator that failed")

    def test_it_gives_up_when_no_separator_appends_anything(self):
        _, facts = drive_play("command_injection", 0,
                              lambda step: Outcome(200, "PING 127.0.0.1", 0.05))
        self.assertNotIn("rce", facts)

    def test_it_tries_another_climb_when_the_first_reads_nothing(self):
        # Only a plain ../ climb reaches anything here.
        def only_plain(step):
            path = unquote(step.path)
            worked = "../" in path and "etc/passwd" in path
            return Outcome(200 if worked else 404,
                           "root:x:0:" if worked else "", 0.05)

        for seed in range(8):
            _, facts = drive_play("path_traversal", seed, only_plain)
            with self.subTest(seed=seed):
                self.assertIn("file_read", facts)

    def test_two_operators_reach_for_different_separators_first(self):
        first = set()
        for seed in range(20):
            steps, _ = drive_play("command_injection", seed, nothing_works)
            probes = [unquote(s.path) for s in steps if "127.0.0.1" in s.path
                      and s.category == "injection"]
            if probes:
                first.add(probes[0].split("127.0.0.1")[1][:2])
        self.assertGreater(len(first), 1, f"everybody reached for {first}")


class TestALockoutClosesAnAccountNotTheCampaign(unittest.TestCase):
    """429 means "this account is closed", not "go home".

    Grinding a wordlist against an account you watched lock out is a script.
    Abandoning a list of *other people's* accounts because one of them locked
    is not a behaviour anyone has either -- and lockouts are historically the
    reason attackers moved from brute force to spraying in the first place.
    """

    def usernames_tried(self, name, respond, seed=1):
        steps, facts = drive_play(name, seed, respond)
        return [(s.body or "").split("username=")[-1].split("&")[0]
                for s in steps if s.path == "/login"], facts

    def test_stuffing_skips_a_locked_account_and_keeps_going(self):
        # Every pair names a different account; one being closed says nothing
        # about the others.
        def lock_agatha(step):
            body = step.body or ""
            return Outcome(429 if "username=agatha" in body else 401, "", 0.05)

        tried, _ = self.usernames_tried("credential_stuffing", lock_agatha)
        # `agatha` sits in the middle of the list; the accounts after it must
        # still be tried, or one closed door ended the whole run.
        after = [u for u in ("rmarsh", "pcollis", "administrator")
                 if u in tried]
        self.assertEqual(len(after), 3,
                         f"it gave up after one lockout: {tried}")

    def test_brute_force_still_stops_on_the_account_it_locked(self):
        # One account, so a lockout really is the end of this line of attack.
        tried, facts = self.usernames_tried(
            "brute_force", lambda step: Outcome(429, "", 0.05))
        self.assertEqual(len(tried), 1)
        self.assertIn("locked_out", facts)

    def test_spraying_uses_few_passwords_across_many_accounts(self):
        # The point of a spray is to stay under the per-account threshold, so
        # it must be wide and shallow or it is just a slow brute force.
        steps, _ = drive_play("password_spray", 1, nothing_works)
        users = [(s.body or "").split("username=")[-1].split("&")[0]
                 for s in steps]
        passwords = {(s.body or "").split("password=")[-1] for s in steps}
        self.assertGreater(len(set(users)), 8)
        self.assertLessEqual(len(passwords), 3)
        self.assertLessEqual(max(collections.Counter(users).values()), 3,
                             "it hit one account often enough to lock it")

    def test_a_guessed_login_is_not_the_same_fact_as_a_known_one(self):
        # `idor_walk` signs in with a password it was given; a credential
        # attack signs in with one it worked out. Reporting both as `session`
        # loses the only part that matters -- one of them is a break-in.
        def let_them_in(step):
            return Outcome(302 if step.path == "/login" else 200, "", 0.05)

        _, facts = drive_play("credential_stuffing", 1, let_them_in)
        self.assertIn("credentials", facts)

    def test_a_run_that_locks_an_account_and_gets_in_reports_both(self):
        # Returning early on the way in threw away what it had already learnt.
        def lock_then_admit(step):
            body = step.body or ""
            if "username=admin&" in body:
                return Outcome(429, "", 0.05)
            return Outcome(302 if "brassneck" in body else 401, "", 0.05)

        _, facts = drive_play("credential_stuffing", 1, lock_then_admit)
        self.assertEqual(facts, frozenset({"locked_out", "credentials"}))

    def test_spraying_is_labelled_a_credential_attack(self):
        cats = {s.category for s in steps_of("password_spray")}
        self.assertEqual(cats, {"credential_attack"})


class TestCampaignsDoNotTripEachOther(unittest.TestCase):
    """Two operators on one target interfere, and a build measured it.

    `/login` locks an account after five failures. While `credential_hunter`
    worked `demo`, `webshell_operator` signed in three seconds later, got a
    429 and stopped -- so one campaign's outcome depended on another
    campaign's timing, and two builds of one seed would not agree.
    """

    def usernames(self, name, seed):
        return {(s.body or "").split("username=")[-1].split("&")[0]
                for s in steps_of(name, seed=seed) if s.path == "/login"
                and s.method == "POST"}

    def test_no_credential_attack_touches_the_account_operators_sign_in_with(self):
        from playbooks import OPERATOR_ACCOUNT
        for name in ("brute_force", "credential_stuffing", "password_spray"):
            for seed in range(12):
                with self.subTest(playbook=name, seed=seed):
                    self.assertNotIn(OPERATOR_ACCOUNT,
                                     self.usernames(name, seed))

    def test_the_operators_that_need_a_session_still_use_that_account(self):
        from playbooks import OPERATOR_ACCOUNT
        for name in ("idor_walk", "upload_webshell"):
            with self.subTest(playbook=name):
                self.assertEqual(self.usernames(name, 0), {OPERATOR_ACCOUNT})

    def test_two_operators_do_not_pick_the_same_account_to_break(self):
        targets = {tuple(self.usernames("brute_force", seed))
                   for seed in range(20)}
        self.assertGreater(len(targets), 1)


if __name__ == "__main__":
    unittest.main()
