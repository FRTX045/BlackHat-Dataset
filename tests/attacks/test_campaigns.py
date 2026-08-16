"""Campaigns.

The properties tested here are the ones that make a campaign worth having in
the dataset at all: it tells a story in order, it is interleaved with ordinary
browsing, its episodes are contiguous, and at least one of them fails.
"""

import random
import sys
import unittest
from pathlib import Path

from shared.truth.writer import CATEGORIES

sys.path.insert(
    0, str(Path(__file__).resolve().parents[2]
           / "projects" / "apache-shopfront" / "attacks"))

from campaigns import CAMPAIGNS, campaign_steps, by_name  # noqa: E402

ATTACK_CATEGORIES = {
    "reconnaissance", "enumeration", "injection", "path_traversal",
    "access_control", "credential_attack", "ssrf", "exploitation",
}


def steps_for(campaign, seed=7):
    return campaign_steps(campaign, random.Random(seed))


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
        for campaign in CAMPAIGNS:
            if len(campaign.phases) < 2:
                continue
            steps = steps_for(campaign)
            lulls = {s.activity for s in steps if s.activity.startswith("lull-")}
            with self.subTest(campaign=campaign.name):
                self.assertEqual(len(lulls), len(campaign.phases) - 1)
                for step in steps:
                    if step.activity.startswith("lull-"):
                        self.assertEqual(step.category, "browsing")

    def test_the_operator_pauses_between_phases(self):
        # A campaign whose phases run back to back at machine speed is a
        # script, and would be separable from a real intrusion on timing.
        for campaign in CAMPAIGNS:
            steps = steps_for(campaign)
            self.assertTrue(any(s.think > 30 for s in steps),
                            f"{campaign.name} never pauses between phases")


class TestOutcomes(unittest.TestCase):

    def test_at_least_one_campaign_fails(self):
        # The common case in reality, and almost absent from published
        # datasets because those are usually recordings of successful
        # exercises.
        self.assertTrue(any(not c.succeeds for c in CAMPAIGNS))

    def test_a_failing_campaign_never_reaches_exploitation(self):
        for campaign in CAMPAIGNS:
            if campaign.succeeds:
                continue
            cats = {s.category for s in steps_for(campaign)}
            with self.subTest(campaign=campaign.name):
                self.assertNotIn("exploitation", cats,
                                 f"{campaign.name} is marked as failing but "
                                 f"reaches exploitation")

    def test_a_succeeding_campaign_does_reach_something(self):
        for campaign in CAMPAIGNS:
            if not campaign.succeeds:
                continue
            cats = {s.category for s in steps_for(campaign)}
            with self.subTest(campaign=campaign.name):
                self.assertTrue(cats & ATTACK_CATEGORIES)

    def test_the_fruitless_prober_only_ever_touches_hardened_ground(self):
        cats = {s.category for s in steps_for(by_name("fruitless_prober"))}
        self.assertNotIn("exploitation", cats)
        self.assertIn("access_control", cats)

    def test_the_credential_hunter_is_all_credential_work_and_recon(self):
        cats = {s.category for s in steps_for(by_name("credential_hunter"))}
        self.assertIn("credential_attack", cats)
        self.assertNotIn("exploitation", cats)


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


if __name__ == "__main__":
    unittest.main()
