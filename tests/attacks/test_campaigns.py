"""Campaigns.

The properties tested here are the ones that make a campaign worth having in
the dataset at all: it tells a story in order, it is interleaved with ordinary
browsing, its episodes are contiguous, and at least one of them fails.
"""

import os
import random
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path
from urllib.parse import unquote

from shared.truth.writer import CATEGORIES

REPO = Path(__file__).resolve().parents[2]
ATTACKS = REPO / "projects" / "apache-shopfront" / "attacks"

sys.path.insert(0, str(ATTACKS))

from campaigns import (CAMPAIGNS, by_name,  # noqa: E402
                       campaign_plan, campaign_seed,
                       achievements, succeeded)
from playbooks import Outcome  # noqa: E402

from tests.attacks.driving import (drive,  # noqa: E402
                                   everything_works,
                                   nothing_works)

ATTACK_CATEGORIES = {
    "reconnaissance", "enumeration", "injection", "path_traversal",
    "access_control", "credential_attack", "ssrf", "exploitation",
}





def plan_for(campaign, seed=7):
    """The campaign's plan, seeded the way the runner seeds it.

    Through `campaign_seed`, not `random.Random(seed)` directly: a helper that
    builds its own rng tests a derivation the build never uses, which is how
    the hash-seeding defect survived a determinism test for as long as it did.
    """
    return campaign_plan(campaign, random.Random(
        campaign_seed(campaign.name, seed)))


def steps_for(campaign, seed=7):
    """What a campaign issues when nothing it tries works."""
    steps, _ = drive(plan_for(campaign, seed), nothing_works)
    return steps


class TestEveryCampaign(unittest.TestCase):

    def test_all_campaigns_expand_to_steps(self):
        for campaign in CAMPAIGNS:
            with self.subTest(campaign=campaign.name):
                self.assertGreater(len(steps_for(campaign)), 5)

    def test_every_category_is_in_the_controlled_vocabulary(self):
        for campaign in CAMPAIGNS:
            for step in steps_for(campaign):
                with self.subTest(campaign=campaign.name, path=step.path):
                    self.assertIn(step.category, CATEGORIES)

    def test_episodes_are_contiguous(self):
        # Interleaved browsing must not make an attacker's episodes look like
        # they resume an earlier activity. Each lull is its own episode.
        for campaign in CAMPAIGNS:
            runs = []
            for step in steps_for(campaign):
                if not runs or runs[-1] != step.activity:
                    runs.append(step.activity)
            with self.subTest(campaign=campaign.name):
                self.assertEqual(len(runs), len(set(runs)),
                                 f"{campaign.name} revisits an activity: {runs}")

    def test_phases_appear_in_the_order_the_campaign_declares(self):
        for campaign in CAMPAIGNS:
            steps = steps_for(campaign)
            # The first step of each phase is recognisable by its long pause.
            activities = []
            for step in steps:
                if not activities or activities[-1] != step.activity:
                    activities.append(step.activity)
            without_lulls = [a for a in activities if not a.startswith("lull-")]
            with self.subTest(campaign=campaign.name):
                self.assertEqual(without_lulls, sorted(set(without_lulls),
                                                       key=without_lulls.index))

    def test_ordinary_browsing_is_interleaved_between_phases(self):
        # Asserted as a shape rather than a count: how many phases run is now
        # decided by what the application gave up, so pinning the number would
        # only be pinning one particular run.
        for campaign in CAMPAIGNS:
            for server, respond in (("holds", nothing_works),
                                    ("folds", everything_works)):
                steps, _ = drive(plan_for(campaign), respond)
                lulls = [s for s in steps if s.activity.startswith("lull-")]
                with self.subTest(campaign=campaign.name, server=server):
                    self.assertFalse(steps[0].activity.startswith("lull-"),
                                     "the campaign opened with a lull")
                    for step in lulls:
                        self.assertEqual(step.category, "browsing")
                    # Numbered from one with no gaps, so no two lulls share an
                    # activity and each stays its own episode.
                    seen = sorted({int(s.activity.split("-")[1]) for s in lulls})
                    self.assertEqual(seen, list(range(1, len(seen) + 1)))

    def test_a_multi_phase_operator_pauses_between_phases(self):
        # A campaign whose phases run back to back at machine speed is a
        # script, and would be separable from a real intrusion on timing.
        #
        # Only asked of the operators who have more than one phase to pause
        # between. The sweepers are scripts, openly: they arrive with a list,
        # try it at machine speed and leave, which is what most of what
        # reaches a small shop actually does.
        for campaign in CAMPAIGNS:
            if len(campaign.repertoire) < 2:
                continue
            steps = steps_for(campaign)
            with self.subTest(campaign=campaign.name):
                self.assertTrue(any(s.think > 30 for s in steps),
                                f"{campaign.name} never pauses between phases")


class TestOutcomes(unittest.TestCase):
    """What a campaign achieved is a property of the run, not of its definition.

    These used to read `campaign.succeeds` off the declaration and inspect one
    fixed step list. There is no fixed list any more and no declared outcome:
    the run against an application that holds and the run against one that
    folds are different runs, and the interesting claims are about both.
    """

    def facts(self, campaign, respond):
        return drive(plan_for(campaign), respond)[1]

    def categories(self, campaign, respond):
        return {s.category for s in drive(plan_for(campaign), respond)[0]}

    def test_nothing_reaches_exploitation_against_an_application_that_holds(self):
        # The point of the whole change. Exploitation-labelled lines used to
        # appear whatever the server did, which made the truth file assert
        # exploits that had not happened.
        for campaign in CAMPAIGNS:
            with self.subTest(campaign=campaign.name):
                self.assertNotIn("exploitation",
                                 self.categories(campaign, nothing_works))

    #: The two operators whose traffic is deliberately not hostile. Every
    #: request either makes could be made by a customer; only the rate and the
    #: breadth give them away. They are in the roster precisely because the
    #: line between a rude client and a dangerous one is where false positives
    #: come from, and a dataset of clear-cut cases never tests it.
    NOT_HOSTILE = {"greedy_scraper", "api_abuser"}

    def test_every_hostile_campaign_still_attacks_when_nothing_works(self):
        # Giving up early must not mean giving up before trying: a campaign
        # that issues no attack traffic is not in the dataset at all.
        for campaign in CAMPAIGNS:
            if campaign.name in self.NOT_HOSTILE:
                continue
            with self.subTest(campaign=campaign.name):
                self.assertTrue(self.categories(campaign, nothing_works)
                                & ATTACK_CATEGORIES)

    def test_the_borderline_campaigns_are_labelled_by_what_they_are(self):
        # Their traffic is rude, not hostile, and the truth file has to say so
        # -- labelling it as an attack because of who sent it would be the
        # dataset asserting something no request in it supports.
        for name in self.NOT_HOSTILE:
            with self.subTest(campaign=name):
                cats = self.categories(by_name(name), nothing_works)
                self.assertFalse(cats & ATTACK_CATEGORIES, sorted(cats))
                self.assertTrue(cats)

    def test_a_campaign_achieves_nothing_against_an_application_that_holds(self):
        for campaign in CAMPAIGNS:
            with self.subTest(campaign=campaign.name):
                self.assertFalse(self.facts(campaign, nothing_works))

    def test_a_campaign_we_expect_to_succeed_does_when_the_application_folds(self):
        # `expects` is a prediction. This is the check that it is a reasonable
        # one -- that the campaign is at least capable of what we said.
        for campaign in CAMPAIGNS:
            if not campaign.expects:
                continue
            with self.subTest(campaign=campaign.name):
                self.assertTrue(self.facts(campaign, everything_works))

    def test_at_least_one_campaign_is_expected_to_get_nothing(self):
        # The common case in reality, and almost absent from published datasets
        # because those are usually recordings of successful exercises.
        self.assertTrue(any(not c.expects for c in CAMPAIGNS))

    def test_the_fruitless_prober_touches_only_hardened_ground(self):
        # True even when everything else folds: nothing in its repertoire
        # reaches an endpoint that gives anything up.
        cats = self.categories(by_name("fruitless_prober"), everything_works)
        self.assertNotIn("exploitation", cats)
        self.assertIn("access_control", cats)

    def test_the_credential_hunter_is_all_credential_work_and_recon(self):
        cats = self.categories(by_name("credential_hunter"), nothing_works)
        self.assertIn("credential_attack", cats)
        self.assertNotIn("exploitation", cats)


class TestGettingSomewhereIsNotTheSameAsLearningSomething(unittest.TestCase):

    def test_a_locked_out_account_is_not_a_success(self):
        self.assertFalse(succeeded({"locked_out"}))

    def test_progress_towards_a_payoff_is_not_the_payoff(self):
        self.assertFalse(succeeded({"session", "admin_reachable",
                                    "upload_accepted", "sqli_confirmed"}))

    def test_taking_something_is(self):
        self.assertTrue(succeeded({"session", "shell"}))

    def test_a_run_that_learned_nothing_succeeded_at_nothing(self):
        self.assertFalse(succeeded(frozenset()))

    def test_working_notes_are_not_published_as_achievements(self):
        # Which comment marker parsed is the operator remembering, not
        # something it came away with.
        self.assertEqual(achievements({"shell", "sql_comment=--"}), ["shell"])

    def test_the_real_achievements_survive(self):
        self.assertEqual(achievements({"data", "session"}),
                         ["data", "session"])


class TestAttackerIdentity(unittest.TestCase):

    def test_every_campaign_draws_from_a_scanner_or_datacentre_pool(self):
        for campaign in CAMPAIGNS:
            with self.subTest(campaign=campaign.name):
                self.assertIn(campaign.role, ("cloud", "datacenter"))

    def test_campaign_names_are_unique(self):
        names = [c.name for c in CAMPAIGNS]
        self.assertEqual(len(names), len(set(names)))

    def test_the_same_seed_expands_a_campaign_identically(self):
        for campaign in CAMPAIGNS:
            with self.subTest(campaign=campaign.name):
                self.assertEqual(steps_for(campaign, 11), steps_for(campaign, 11))


class TestTheSeedSurvivesLeavingTheProcess(unittest.TestCase):
    """The scenario seed has to reproduce a campaign next year, on another box.

    Every other determinism test here stays inside one interpreter, where
    anything derived from `hash()` on a string looks perfectly stable. It is
    not: str hashing is salted per process unless PYTHONHASHSEED is fixed, and
    nothing in this repository fixes it. So the property is checked the only
    way it can be -- from outside, under two different hash seeds.
    """

    def _run(self, hashseed, expression):
        script = textwrap.dedent(f"""
            import sys
            sys.path.insert(0, {str(REPO)!r})
            sys.path.insert(0, {str(ATTACKS)!r})
            from campaigns import CAMPAIGNS, campaign_seed, campaign_plan
            from playbooks import Outcome
            from tests.attacks.driving import drive
            import random
            NOTHING_WORKS = Outcome(404, "", 0.01)
            EVERYTHING_WORKS = Outcome(
                200, "1 result(s) uid=0(root) root: Fetched SHELLOK: 62874",
                1.4)

            def expand(campaign, answer):
                plan = campaign_plan(campaign, random.Random(
                    campaign_seed(campaign.name, 7)))
                return [tuple(s) for s in drive(plan, lambda step: answer)[0]]

            print({expression})
        """)
        outcome = subprocess.run(
            [sys.executable, "-c", script],
            env={**os.environ, "PYTHONHASHSEED": hashseed},
            capture_output=True, text=True, check=False)
        if outcome.returncode:
            self.fail(f"subprocess failed under PYTHONHASHSEED={hashseed}:\n"
                      f"{outcome.stderr.strip()}")
        return outcome.stdout.strip()

    def test_the_derived_seed_ignores_the_interpreters_hash_seed(self):
        expression = "campaign_seed('patient_operator', 7)"
        self.assertEqual(self._run("0", expression),
                         self._run("12345", expression))

    def test_a_campaign_expands_identically_under_a_different_hash_seed(self):
        expression = "expand(CAMPAIGNS[0], NOTHING_WORKS)"
        self.assertEqual(self._run("0", expression),
                         self._run("12345", expression))

    def test_a_campaign_that_gets_somewhere_also_expands_identically(self):
        """The branches have to be stable too, not just the unbranched path.

        Answering everything with a failure walks each playbook straight down
        its list and never exercises a decision. A seed that reproduces only
        that reproduces the least interesting run there is.
        """
        expression = "expand(CAMPAIGNS[0], EVERYTHING_WORKS)"
        self.assertEqual(self._run("0", expression),
                         self._run("12345", expression))

    def test_what_came_back_actually_changes_the_plan(self):
        # Guards the two tests above: if the outcome were ignored, they would
        # both pass while proving nothing about reactive expansion.
        self.assertNotEqual(self._run("0", "expand(CAMPAIGNS[0], NOTHING_WORKS)"),
                            self._run("0", "expand(CAMPAIGNS[0], EVERYTHING_WORKS)"))

    def test_the_runner_plans_its_campaign_from_the_same_stable_seed(self):
        """The fix has to reach the code the build actually runs.

        `campaign_seed` being stable is worth nothing if `run_campaign` still
        derives its own rng from `hash()`, so this asks the runner for the rng
        it would really use and makes it draw.
        """
        expression = ("__import__('runner').campaign_rng("
                      "'patient_operator', 7).random()")
        self.assertEqual(self._run("0", expression),
                         self._run("12345", expression))

    def test_two_campaigns_do_not_collapse_onto_one_seed(self):
        seeds = self._run(
            "0", "[campaign_seed(c.name, 7) for c in CAMPAIGNS]")
        self.assertEqual(len(set(eval(seeds))), len(CAMPAIGNS))


class TestPlaysAreGatedOnWhatTheOperatorKnows(unittest.TestCase):
    """An operator does not escalate to something it has no reason to try.

    Extracting through an injection it never confirmed, or attacking an admin
    endpoint it never found, is a script working through a list. What makes a
    campaign look like a person is that the later phases are *earned*.
    """

    def facts_and_activities(self, name, answer):
        steps, facts = drive(plan_for(by_name(name)), answer)
        return facts, [s.activity for s in steps]

    def test_a_play_whose_requirement_is_unmet_never_runs(self):
        _, activities = self.facts_and_activities("patient_operator",
                                                  nothing_works)
        self.assertNotIn("extract", activities,
                         "it extracted through an injection it never confirmed")

    def test_a_play_runs_once_its_requirement_is_met(self):
        _, activities = self.facts_and_activities("patient_operator",
                                                  everything_works)
        self.assertIn("extract", activities,
                      "it confirmed the injection and then did not use it")

    def test_what_a_campaign_achieved_is_observed_not_declared(self):
        # The same campaign, same seed, against an application that holds and
        # one that folds. If `succeeded` were a property of the definition
        # these would agree.
        held, _ = self.facts_and_activities("patient_operator", nothing_works)
        folded, _ = self.facts_and_activities("patient_operator",
                                              everything_works)
        self.assertFalse(held)
        self.assertTrue(folded)


class TestTheInterludesAreNotFourPaths(unittest.TestCase):
    """The lulls were the only varying thing in the whole attacker side.

    Four fixed paths, one of them a literal `?q=brass`, drawn one to three at
    a time. Every campaign in every dataset browsed the same four pages.
    """

    def lull_paths(self, seed):
        return {s.path for s in steps_for(by_name("fruitless_prober"), seed)
                if s.activity.startswith("lull-")}

    def test_the_browsing_pool_is_wider_than_a_handful(self):
        seen = set()
        for seed in range(40):
            seen |= self.lull_paths(seed)
        self.assertGreater(len(seen), 8,
                           f"the whole browsing pool is {sorted(seen)}")

    def test_two_builds_browse_differently(self):
        self.assertNotEqual(self.lull_paths(1), self.lull_paths(2))


#: Longest first, so `--+` is not read as `--`.
SQL_COMMENTS = ("/**/", "--+", "--", "#")


def comment_marker(path):
    """The SQL comment an injected path ends with, if any."""
    query = unquote(path).rstrip()
    for marker in SQL_COMMENTS:
        if query.endswith(marker):
            return marker
    return None


class TestAnOperatorKeepsItsOwnHabits(unittest.TestCase):
    """Which syntax someone reaches for is a habit, not a per-request choice.

    Two people testing the same injection point genuinely differ -- one types
    `--`, another `#` -- but neither changes their mind halfway through their
    own run. An operator whose comment marker shifts between phases is exactly
    as impossible as one whose user agent does.
    """

    def markers(self, campaign, seed, respond):
        steps, _ = drive(plan_for(campaign, seed), respond)
        return {comment_marker(s.path) for s in steps} - {None}

    def test_one_operator_uses_one_comment_marker_throughout(self):
        # patient_operator injects in two separate phases: it probes, and then
        # it extracts through what the probing found.
        used = self.markers(by_name("patient_operator"), 7, everything_works)
        self.assertEqual(len(used), 1,
                         f"the operator changed cheat sheets mid-run: {used}")

    def test_the_phases_that_inject_actually_do_inject(self):
        # Guards the test above: it would pass trivially on an empty set.
        self.assertTrue(
            self.markers(by_name("patient_operator"), 7, everything_works))

    def test_two_operators_do_not_share_one_habit(self):
        seen = set()
        for seed in range(24):
            seen |= self.markers(by_name("patient_operator"), seed,
                                 everything_works)
        self.assertGreater(len(seen), 1,
                           f"every operator in every build wrote {seen}")


class TestFeedbackReachesThePlaybook(unittest.TestCase):
    """The spine's whole job.

    A phase decides what to send next from the response to its own last
    request. If the campaign driver swallows that on the way through, every
    playbook silently reverts to sending its full fixed list and the
    reactivity is decorative.
    """

    def test_a_phase_sees_the_response_to_its_own_request(self):
        # sqli_probing stops guessing column counts once one fits.
        plan = plan_for(by_name("patient_operator"))
        steps, _ = drive(plan, lambda step: Outcome(200, "1 result(s)", 0.03))
        guesses = [s for s in steps
                   if s.activity == "probe" and "UNION" in unquote(s.path)]
        self.assertEqual(len(guesses), 1,
                         "the outcome never reached the playbook")


if __name__ == "__main__":
    unittest.main()
