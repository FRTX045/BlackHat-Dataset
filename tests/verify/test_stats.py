"""Realism statistics.

None of these has a pass mark -- the verifier prints them whether they flatter
the dataset or not. What is tested here is that each one measures what it
claims to, because a statistic that quietly computes the wrong thing is worse
than one that is absent.
"""

import unittest
from datetime import datetime, timedelta, timezone

from shared.verify.stats import (attack_overlap, attack_share,
                                 client_concentration, episode_shape,
                                 inter_arrival, referer_share,
                                 response_shapes, summarise,
                                 user_agent_spread)

T0 = datetime(2026, 8, 16, 9, 0, tzinfo=timezone.utc)


def rec(ip="203.0.113.5", status=200, method="GET", path="/", ua="UA/1",
        referer=None, offset=0, size=100):
    return {"client_ip": ip, "status": status, "method": method, "path": path,
            "user_agent": ua, "referer": referer, "bytes": size,
            "ts": T0 + timedelta(seconds=offset)}


def truth(category="browsing", instance="a#1"):
    return {"category": category, "instance_id": instance}


class TestClientConcentration(unittest.TestCase):

    def test_a_heavy_client_shows_in_the_top_share(self):
        records = [rec(ip="203.0.113.5") for _ in range(9)] + [rec(ip="198.51.100.9")]
        result = client_concentration(records)
        self.assertEqual(result["distinct_clients"], 2)
        self.assertEqual(result["top_1_share"], 0.9)
        self.assertEqual(result["busiest_client_requests"], 9)

    def test_single_request_clients_are_counted_over_clients_not_lines(self):
        # Three clients, one of which appears once: a third of clients, not a
        # third of lines. Getting this backwards would make every dataset look
        # like it had a long tail.
        records = ([rec(ip="a")] * 5) + ([rec(ip="b")] * 4) + [rec(ip="c")]
        self.assertEqual(
            client_concentration(records)["single_request_share"], round(1 / 3, 4))


class TestUserAgents(unittest.TestCase):

    def test_absent_agents_are_reported_rather_than_ignored(self):
        records = [rec(ua="UA/1"), rec(ua=None), rec(ua=None), rec(ua="UA/2")]
        result = user_agent_spread(records)
        self.assertEqual(result["distinct_agents"], 2)
        self.assertEqual(result["absent_share"], 0.5)


class TestReferer(unittest.TestCase):

    def test_asset_and_non_asset_shares_are_reported_separately(self):
        # Assets almost always carry a Referer, so a single blended number
        # hides whether page requests do.
        records = [
            rec(path="/", referer=None),
            rec(path="/c/tools", referer="http://shop.test/"),
            rec(path="/assets/css/site.css", referer="http://shop.test/"),
            rec(path="/assets/js/app.js", referer="http://shop.test/"),
        ]
        result = referer_share(records)
        self.assertEqual(result["all_requests"], 0.75)
        self.assertEqual(result["non_asset_requests"], 0.5)


class TestResponseShapes(unittest.TestCase):

    def test_the_classes_a_generated_log_usually_lacks_are_counted(self):
        records = [rec(status=304, size=None), rec(status=206),
                   rec(method="HEAD", size=None), rec(method="OPTIONS"),
                   rec(method=None), rec()]
        result = response_shapes(records)
        for key in ("not_modified_304", "partial_206", "head_requests",
                    "options_requests", "malformed_requests"):
            with self.subTest(key=key):
                self.assertAlmostEqual(result[key], 1 / 6, places=3)
        self.assertAlmostEqual(result["no_body_bytes"], 2 / 6, places=3)


class TestInterArrival(unittest.TestCase):

    def test_a_metronome_scores_near_zero(self):
        records = [rec(offset=n) for n in range(50)]
        self.assertLess(inter_arrival(records)["coefficient_of_variation"], 0.01)

    def test_bursty_traffic_scores_high(self):
        offsets = [0, 0, 0, 0, 30, 30, 30, 120, 400, 400]
        records = [rec(offset=o) for o in offsets]
        self.assertGreater(inter_arrival(records)["coefficient_of_variation"], 0.8)

    def test_zero_gaps_are_reported_because_the_clock_is_coarse(self):
        # %t has one-second resolution, so simultaneous requests are common
        # and the statistic should say so rather than look suspiciously smooth.
        records = [rec(offset=0), rec(offset=0), rec(offset=1)]
        self.assertGreater(inter_arrival(records)["zero_gap_share"], 0)


class TestAttackMeasures(unittest.TestCase):

    def test_attack_share_counts_only_hostile_categories(self):
        records = [truth("browsing"), truth("static_asset"),
                   truth("injection"), truth("ssrf")]
        self.assertEqual(attack_share(records), 0.5)

    def test_crawling_and_authentication_are_not_attacks(self):
        self.assertEqual(
            attack_share([truth("crawling"), truth("authentication")]), 0.0)

    def test_overlap_measures_attacks_sharing_a_second_with_normal_traffic(self):
        # An attack alone in its own second is separable on timestamp alone.
        records = [rec(offset=0), rec(offset=0), rec(offset=90)]
        truths = [truth("browsing"), truth("injection"), truth("injection")]
        result = attack_overlap(records, truths)
        self.assertEqual(result["attack_lines"], 2)
        self.assertEqual(result["overlapping_share"], 0.5)

    def test_a_dataset_with_no_attacks_reports_zero_rather_than_failing(self):
        result = attack_overlap([rec()], [truth("browsing")])
        self.assertEqual(result["attack_lines"], 0)


class TestEpisodes(unittest.TestCase):

    def test_episode_lengths_are_summarised(self):
        truths = ([truth(instance="a#1")] * 3 + [truth(instance="a#2")]
                  + [truth(instance="b#1")] * 10)
        result = episode_shape(truths)
        self.assertEqual(result["episodes"], 3)
        self.assertEqual(result["longest"], 10)


class TestSummary(unittest.TestCase):

    def test_every_statistic_appears_in_the_summary(self):
        records = [rec(offset=n) for n in range(5)]
        truths = [truth() for _ in range(5)]
        result = summarise(records, truths)
        for key in ("lines", "status_distribution", "method_distribution",
                    "response_shapes", "client_concentration", "user_agents",
                    "referer_share", "inter_arrival", "category_shares",
                    "attack_share", "episodes", "attack_overlap"):
            with self.subTest(key=key):
                self.assertIn(key, result)


if __name__ == "__main__":
    unittest.main()
