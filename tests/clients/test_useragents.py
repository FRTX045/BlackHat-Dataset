import unittest
from collections import Counter

from shared.clients.useragents import (CORPUS, PERSONA_UA_CLASSES,
                                       UserAgentPool)


class TestCorpus(unittest.TestCase):
    def test_has_enough_distinct_agents(self):
        # Too few user agents, or a suspiciously flat distribution across
        # them, is one of the clearest signs of a generated log.
        strings = [ua for ua, _, _ in CORPUS]
        self.assertGreaterEqual(len(strings), 40)
        self.assertEqual(len(set(strings)), len(strings), "duplicate UA string")

    def test_every_entry_has_a_class_and_a_positive_weight(self):
        for ua, cls, weight in CORPUS:
            with self.subTest(ua=ua[:40]):
                self.assertTrue(ua)
                self.assertIn(cls, PERSONA_UA_CLASSES["__all__"])
                self.assertGreater(weight, 0)

    def test_covers_desktop_mobile_and_bot_classes(self):
        classes = {cls for _, cls, _ in CORPUS}
        for required in ("desktop_chrome", "desktop_firefox", "desktop_safari",
                         "mobile_android", "mobile_ios", "bot_search",
                         "feed_reader", "uptime_monitor"):
            self.assertIn(required, classes)


# A representative persona mixture. The realism statistic the verifier
# reports is the user-agent distribution across the whole log, not within one
# persona -- a desktop-only persona is dominated by the current Chrome build
# in reality too, and it is mobile and bot traffic that dilutes it. Refined
# against the real arrival weights in shared/clients/personas.py.
PERSONA_MIX = (
    ("casual_browser", 30), ("shopper", 22), ("returning_customer", 8),
    ("mobile_user", 25), ("crawler", 6), ("feed_reader", 2),
    ("uptime_monitor", 3), ("scanner", 3), ("attacker", 1),
)


class TestDistributionShape(unittest.TestCase):
    def setUp(self):
        import random
        rng = random.Random(23)
        personas = [p for p, _ in PERSONA_MIX]
        weights = [w for _, w in PERSONA_MIX]
        pool = UserAgentPool(seed=13)
        self.draws = [pool.draw(rng.choices(personas, weights=weights, k=1)[0])
                      for _ in range(8000)]
        self.counts = Counter(self.draws)

    def test_no_single_agent_dominates(self):
        top = self.counts.most_common(1)[0][1] / len(self.draws)
        self.assertLess(top, 0.20, f"top agent holds {top:.3f} of requests")

    def test_the_top_ten_do_not_account_for_everything(self):
        top10 = sum(c for _, c in self.counts.most_common(10)) / len(self.draws)
        self.assertLess(top10, 0.75, f"top-10 share {top10:.3f}")

    def test_most_of_the_corpus_actually_appears(self):
        # A corpus of 50 strings of which 12 ever get drawn is a corpus of 12.
        self.assertGreater(len(self.counts) / len(CORPUS), 0.80)

    def test_the_distribution_is_not_flat(self):
        ordered = sorted(self.counts.values(), reverse=True)
        self.assertGreater(ordered[0], 3 * ordered[-1])


class TestPersonaCoherence(unittest.TestCase):
    """A mobile visitor sending a desktop user agent, or Googlebot appearing
    on a shopper's session, is an impossible journey at the client level."""

    def _classes_for(self, persona, n=400):
        pool = UserAgentPool(seed=17)
        lookup = {ua: cls for ua, cls, _ in CORPUS}
        return {lookup[pool.draw(persona)] for _ in range(n)}

    def test_a_mobile_visitor_never_sends_a_desktop_agent(self):
        classes = self._classes_for("mobile_user")
        self.assertTrue(classes)
        for cls in classes:
            self.assertTrue(cls.startswith("mobile_"), f"got {cls}")

    def test_a_crawler_only_ever_sends_a_bot_agent(self):
        classes = self._classes_for("crawler")
        self.assertTrue(classes)
        for cls in classes:
            self.assertTrue(cls.startswith("bot_"), f"got {cls}")

    def test_a_search_engine_agent_never_appears_on_a_human_persona(self):
        for persona in ("casual_browser", "shopper", "returning_customer",
                        "mobile_user"):
            with self.subTest(persona=persona):
                for cls in self._classes_for(persona):
                    self.assertFalse(cls.startswith("bot_"),
                                     f"{persona} drew {cls}")

    def test_a_monitor_sends_a_monitoring_agent(self):
        self.assertEqual(self._classes_for("uptime_monitor"),
                         {"uptime_monitor"})

    def test_rejects_an_unknown_persona(self):
        with self.assertRaises(ValueError):
            UserAgentPool(seed=1).draw("nonsense")


class TestStickiness(unittest.TestCase):
    def test_the_same_client_keeps_the_same_agent(self):
        # A visitor's user agent does not change between requests, and a
        # session whose agent changes mid-way is an impossible journey.
        pool = UserAgentPool(seed=19)
        first = pool.for_client("203.0.113.5", "shopper")
        for _ in range(20):
            self.assertEqual(pool.for_client("203.0.113.5", "shopper"), first)

    def test_different_clients_get_different_agents(self):
        pool = UserAgentPool(seed=19)
        agents = {pool.for_client(f"203.0.113.{i}", "shopper")
                  for i in range(1, 60)}
        self.assertGreater(len(agents), 5)


class TestDeterminism(unittest.TestCase):
    def test_same_seed_gives_the_same_sequence(self):
        a = [UserAgentPool(seed=5).draw("shopper") for _ in range(1)]
        first = [UserAgentPool(seed=5).draw("shopper") for _ in range(20)]
        second = [UserAgentPool(seed=5).draw("shopper") for _ in range(20)]
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
