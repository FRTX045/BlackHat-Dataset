"""The driver's pure logic.

Anything that issues a request needs the driver image and is exercised by the
end-to-end build. What is tested here is the part that decides what the truth
file will say, which is plain data and must not need a container to check:
episode assignment, and which subresources count as assets.

The journey planning these drive is tested in tests/clients/test_personas.py.
"""

import sys
import unittest
from pathlib import Path

import random

from shared.clients.personas import NO_REFERER, PERSONAS, Step, journey

sys.path.insert(
    0, str(Path(__file__).resolve().parents[2]
           / "projects" / "apache-shopfront" / "traffic"))

from driver import _ASSET, _ASSET_SUFFIXES, Episodes, navigates  # noqa: E402


class TestEpisodes(unittest.TestCase):
    """Episode ids must be contiguous per client or the validator rejects them."""

    def setUp(self):
        self.episodes = Episodes()

    def test_one_activity_keeps_one_id(self):
        first = self.episodes.id_for("203.0.113.5", "browse")
        second = self.episodes.id_for("203.0.113.5", "browse")
        self.assertEqual(first, second)

    def test_changing_activity_starts_a_new_id(self):
        browse = self.episodes.id_for("203.0.113.5", "browse")
        basket = self.episodes.id_for("203.0.113.5", "basket")
        self.assertNotEqual(browse, basket)

    def test_ids_are_namespaced_by_client(self):
        mine = self.episodes.id_for("203.0.113.5", "browse")
        theirs = self.episodes.id_for("198.51.100.9", "browse")
        self.assertNotEqual(mine, theirs)
        self.assertTrue(mine.startswith("203.0.113.5#"))

    def test_two_clients_interleaving_do_not_disturb_each_others_episodes(self):
        # The case the validator cares about: overlapping visitors are normal
        # and must not each other's episodes look discontiguous.
        a1 = self.episodes.id_for("203.0.113.5", "browse")
        self.episodes.id_for("198.51.100.9", "crawl")
        a2 = self.episodes.id_for("203.0.113.5", "browse")
        self.assertEqual(a1, a2)

    def test_returning_to_an_earlier_activity_gets_a_fresh_id(self):
        # Not a reused id: reusing one after another intervened is exactly what
        # validate_records rejects.
        first = self.episodes.id_for("203.0.113.5", "browse")
        self.episodes.id_for("203.0.113.5", "basket")
        again = self.episodes.id_for("203.0.113.5", "browse")
        self.assertNotEqual(first, again)


class TestAssetSelection(unittest.TestCase):

    def test_stylesheets_scripts_and_images_are_picked_out_of_markup(self):
        html = ('<link rel="stylesheet" href="/assets/css/site.css">'
                '<script src="/assets/js/app.js" defer></script>'
                '<img src="/assets/img/p/17.jpg" width="240">')
        found = _ASSET.findall(html)
        self.assertIn("/assets/css/site.css", found)
        self.assertIn("/assets/js/app.js", found)
        self.assertIn("/assets/img/p/17.jpg", found)

    def test_internal_page_links_are_not_treated_as_assets(self):
        # An <a href> is navigation, not a subresource. Fetching those would
        # turn one page view into a crawl of the whole site.
        html = '<a href="/c/hand-tools">Hand Tools</a><a href="/p/17">Chisel</a>'
        self.assertEqual(_ASSET.findall(html), [])

    def test_only_known_asset_extensions_are_fetched(self):
        for path, expected in (("/assets/css/site.css", True),
                               ("/assets/fonts/inter-400.woff2", True),
                               ("/favicon.ico", True),
                               ("/c/hand-tools", False),
                               ("/api/cart", False)):
            with self.subTest(path=path):
                self.assertEqual(
                    path.lower().split("?")[0].endswith(_ASSET_SUFFIXES),
                    expected)


class TestRefererPolicy(unittest.TestCase):

    def test_the_personas_that_send_no_referer_are_all_real_personas(self):
        self.assertTrue(NO_REFERER)
        for persona in NO_REFERER:
            with self.subTest(persona=persona):
                self.assertIn(persona, PERSONAS)

    def test_human_personas_do_send_a_referer(self):
        # A log where nothing carries a Referer is as wrong as one where
        # everything does.
        for persona in ("casual", "shopper", "returning", "mobile"):
            with self.subTest(persona=persona):
                self.assertNotIn(persona, NO_REFERER)


class TestOnlyANavigationMovesThePage(unittest.TestCase):
    """The page a request is made from is the last page navigated to.

    Every GET used to become the current page, the page script's own XHRs
    included. So a page view after a stock check claimed to come from
    /api/stock?id=N, and the next XHR from the previous XHR: about 3.6% of
    every tier through 2026-10-05, driver traffic only. A browser never sends
    either; the Chromium personas had none.
    """

    def test_a_page_view_is_a_navigation(self):
        self.assertTrue(navigates(Step("GET", "/p/12", "browsing", "browse")))

    def test_the_page_scripts_calls_are_not(self):
        for path in ("/api/stock?id=12", "/api/stock?id=${id}&watch=1",
                     "/api/autocomplete?q=oa"):
            with self.subTest(path=path):
                self.assertFalse(navigates(Step("GET", path, "api_call", "browse")))

    def test_a_post_is_not(self):
        self.assertFalse(navigates(Step("POST", "/api/cart", "api_call", "basket")))

    def test_no_shopper_request_claims_an_api_call_as_its_page(self):
        rng = random.Random(7)
        catalogue = {"categories": [{"slug": f"c{c}", "products":
                                     list(range(c * 13 + 1, c * 13 + 14))}
                                    for c in range(10)],
                     "users": [], "low_stock": [5, 18, 31]}
        for persona in ("shopper", "casual", "returning", "mobile"):
            for _ in range(100):
                previous = None
                for step in journey(persona, rng, catalogue):
                    if previous is not None:
                        with self.subTest(persona=persona, path=step.path):
                            self.assertFalse(previous.startswith("/api/"),
                                             f"{step.path} sent from {previous}")
                    if navigates(step):
                        previous = step.path


if __name__ == "__main__":
    unittest.main()
