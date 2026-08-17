"""Persona journeys.

The property that matters is that every journey is one a person could actually
have made. A product page reached without a listing before it, or a checkout
with nothing in the basket, produces Referer chains that cannot be true --
which is exactly the kind of thing a researcher studying journey plausibility
would find, and would be right to distrust the whole dataset over.
"""

import collections
import random
import unittest

from shared.clients.ippools import ROLES
from shared.clients.personas import PERSONA_IDENTITY, PERSONAS, journey
from shared.clients.useragents import PERSONA_UA_CLASSES
from shared.truth.writer import CATEGORIES

CATALOGUE = {
    "categories": [
        {"slug": f"cat-{c}", "products": list(range(c * 13 + 1, c * 13 + 14))}
        for c in range(10)
    ],
}

PRODUCT_CATEGORY = {
    product: category["slug"]
    for category in CATALOGUE["categories"]
    for product in category["products"]
}


def journeys(persona, count=200, seed=7):
    rng = random.Random(seed)
    return [journey(persona, rng, CATALOGUE) for _ in range(count)]


class TestEveryPersona(unittest.TestCase):

    def test_the_named_personas_all_plan_something(self):
        for persona in PERSONAS:
            with self.subTest(persona=persona):
                steps = journey(persona, random.Random(7), CATALOGUE)
                self.assertGreaterEqual(len(steps), 1)

    def test_every_category_emitted_is_in_the_controlled_vocabulary(self):
        for persona in PERSONAS:
            for steps in journeys(persona, count=50):
                for step in steps:
                    with self.subTest(persona=persona, path=step.path):
                        self.assertIn(step.category, CATEGORIES)

    def test_every_method_is_a_real_http_method(self):
        allowed = {"GET", "POST", "DELETE", "HEAD"}
        for persona in PERSONAS:
            for steps in journeys(persona, count=50):
                for step in steps:
                    self.assertIn(step.method, allowed)


class TestJourneysArePossible(unittest.TestCase):

    def test_no_product_is_visited_without_a_listing_that_contains_it(self):
        for persona in PERSONAS:
            for steps in journeys(persona, count=100):
                seen_listings = set()
                for step in steps:
                    if step.path.startswith("/c/"):
                        seen_listings.add(step.path[3:])
                    elif step.path.startswith("/p/"):
                        product = int(step.path[3:].split("?")[0])
                        slug = PRODUCT_CATEGORY[product]
                        with self.subTest(persona=persona, product=product):
                            self.assertIn(
                                slug, seen_listings,
                                f"{persona} opened /p/{product} with no listing "
                                f"for {slug} before it")

    def test_nobody_checks_out_without_putting_something_in_the_basket(self):
        for persona in PERSONAS:
            for steps in journeys(persona, count=100):
                added = False
                for step in steps:
                    if step.path == "/api/cart" and step.method == "POST":
                        added = True
                    if step.path == "/checkout":
                        with self.subTest(persona=persona):
                            self.assertTrue(
                                added, f"{persona} checked out with an empty basket")

    def test_nobody_reaches_the_account_area_without_signing_in(self):
        for persona in PERSONAS:
            for steps in journeys(persona, count=100):
                signed_in = False
                for step in steps:
                    if step.path == "/login" and step.method == "POST":
                        signed_in = True
                    if step.path.startswith("/account"):
                        with self.subTest(persona=persona, path=step.path):
                            self.assertTrue(
                                signed_in,
                                f"{persona} opened {step.path} without signing in")

    def test_a_crawler_asks_for_robots_before_anything_else(self):
        for steps in journeys("crawler", count=50):
            self.assertEqual(steps[0].path, "/robots.txt")

    def test_a_crawler_never_touches_paths_robots_disallows(self):
        disallowed = ("/account/", "/admin/", "/cart", "/checkout", "/api/")
        for steps in journeys("crawler", count=100):
            for step in steps:
                with self.subTest(path=step.path):
                    self.assertFalse(step.path.startswith(disallowed))


class TestActivityBoundaries(unittest.TestCase):

    def test_a_journey_reports_the_activity_of_every_step(self):
        for persona in PERSONAS:
            for steps in journeys(persona, count=25):
                for step in steps:
                    self.assertTrue(step.activity)

    def test_the_activity_only_changes_between_coherent_runs(self):
        # instance_id is derived from activity, and episode groups have to be
        # contiguous. If a journey alternated activity every other step, the
        # episodes it produced would be meaningless even though they would
        # still validate.
        for persona in PERSONAS:
            for steps in journeys(persona, count=50):
                runs = []
                for step in steps:
                    if not runs or runs[-1] != step.activity:
                        runs.append(step.activity)
                with self.subTest(persona=persona):
                    self.assertEqual(
                        len(runs), len(set(runs)),
                        f"{persona} returns to an earlier activity: {runs}")


class TestClientCoherence(unittest.TestCase):
    """Every journey persona must map onto a real agent class and address role."""

    def test_every_persona_has_an_identity(self):
        self.assertEqual(set(PERSONA_IDENTITY), set(PERSONAS))

    def test_each_identity_names_a_known_agent_persona_and_address_role(self):
        for persona, (ua_persona, role) in PERSONA_IDENTITY.items():
            with self.subTest(persona=persona):
                self.assertIn(ua_persona, PERSONA_UA_CLASSES)
                self.assertIn(role, ROLES)

    def test_a_mobile_visitor_gets_mobile_space_and_a_mobile_agent(self):
        ua_persona, role = PERSONA_IDENTITY["mobile"]
        self.assertEqual(role, "mobile")
        self.assertTrue(all(cls.startswith("mobile_")
                            for cls in PERSONA_UA_CLASSES[ua_persona]))

    def test_a_crawler_gets_cloud_space_and_only_bot_agents(self):
        # Asserted as a property, not as a literal tuple. The point is that a
        # crawler never presents a human browser string; which families of bot
        # it may present is a modelling choice that should be free to change,
        # and pinning the tuple made adding the SEO and AI crawlers -- which
        # are a large share of real crawl traffic -- look like a regression.
        ua_persona, role = PERSONA_IDENTITY["crawler"]
        self.assertEqual(role, "cloud")
        classes = PERSONA_UA_CLASSES[ua_persona]
        self.assertTrue(classes)
        for cls in classes:
            with self.subTest(ua_class=cls):
                self.assertTrue(cls.startswith("bot_"),
                                f"a crawler may present {cls!r}")


class TestTheUrlSpaceHasALongTail(unittest.TestCase):
    """Real logs are full of URLs seen once and never again.

    Measured on a medium build without this: 1.95% of paths were requested
    exactly once. A closed URL vocabulary is the cause, and it makes the data
    easier than the real thing -- path normalisation and cardinality handling
    are a standard first problem in real log analysis, and a dataset with a
    hundred distinct URLs never poses it.

    The two big real sources are inbound tracking parameters and on-site
    search, so those are what these check.
    """

    def paths(self, persona, count=400, seed=5):
        return [step.path
                for journey in journeys(persona, count=count, seed=seed)
                for step in journey]

    def test_some_arrivals_carry_a_tracking_query(self):
        landings = [p for p in self.paths("shopper") if p.startswith("/?")]
        self.assertTrue(landings, "no inbound tracking parameters at all")

    def test_the_tracking_values_are_mostly_unique(self):
        # A click id repeated across visitors would be a single URL wearing a
        # disguise, and would not lengthen the tail at all.
        landings = [p for p in self.paths("shopper") if p.startswith("/?")]
        self.assertGreater(len(set(landings)), len(landings) * 0.5)

    def test_a_visit_that_was_not_referred_has_a_clean_landing_url(self):
        # Somebody who typed the address in has nothing to append.
        for journey in journeys("casual", count=300, seed=5):
            first = journey[0]
            with self.subTest(path=first.path):
                if first.referer is None:
                    self.assertEqual(first.path, "/")

    def test_on_site_search_covers_many_distinct_terms(self):
        searches = {p for p in self.paths("shopper") if p.startswith("/search?")}
        self.assertGreater(len(searches), 30)

    def test_search_terms_are_url_encoded(self):
        # Multi-word queries are most of real search traffic, and a raw space
        # in a request line would make Apache log something no parser expects.
        for path in self.paths("shopper"):
            with self.subTest(path=path):
                self.assertNotIn(" ", path)

    def test_autocomplete_walks_the_prefixes_a_typist_produces(self):
        # One call per keystroke after the second, which is where a shop's
        # autocomplete volume actually comes from.
        prefixes = [p for p in self.paths("shopper")
                    if p.startswith("/api/autocomplete?")]
        self.assertTrue(prefixes)
        self.assertGreater(len(set(prefixes)), 20)

    def test_the_tracking_source_usually_agrees_with_the_referer(self):
        # A Google referer carrying utm_source=reddit is real -- somebody
        # copied a tracked link -- but it should be the exception. Coherence
        # between the address, the agent and the journey is a property this
        # project holds everywhere else; the query string is no different.
        agree = mismatch = 0
        for journey in journeys("shopper", count=500, seed=5):
            first = journey[0]
            if not first.referer or "utm_source=" not in first.path:
                continue
            host = first.referer.split("//", 1)[-1].split("/", 1)[0]
            expected = {"www.google.com": "google", "www.google.co.uk": "google",
                        "www.bing.com": "bing", "duckduckgo.com": "duckduckgo"}
            want = expected.get(host)
            if want is None:
                continue
            if f"utm_source={want}" in first.path:
                agree += 1
            else:
                mismatch += 1
        self.assertGreater(agree + mismatch, 20, "not enough tracked arrivals")
        self.assertGreater(agree / (agree + mismatch), 0.6)

    def test_a_google_click_id_only_arrives_from_google(self):
        for journey in journeys("shopper", count=500, seed=5):
            first = journey[0]
            if "gclid=" not in first.path:
                continue
            with self.subTest(referer=first.referer):
                self.assertIsNotNone(first.referer)
                self.assertIn("google", first.referer)

    def test_the_tail_is_a_real_share_of_the_paths(self):
        counts = collections.Counter(self.paths("shopper", count=600))
        once = sum(1 for v in counts.values() if v == 1)
        self.assertGreater(once / len(counts), 0.20)


class TestDeterminism(unittest.TestCase):

    def test_the_same_seed_gives_the_same_journeys(self):
        for persona in PERSONAS:
            with self.subTest(persona=persona):
                self.assertEqual(journeys(persona, count=20, seed=7),
                                 journeys(persona, count=20, seed=7))


if __name__ == "__main__":
    unittest.main()
