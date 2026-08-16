"""Tests for apache-shopfront's mapping from a request onto the vocabulary.

Only used for traffic whose ledger carries no category of its own -- which is
to say the tag proxy's, because a proxy can see what was requested but not why.
The driver states its own intent and is never labelled by guesswork.
"""

import sys
import unittest
from pathlib import Path

from shared.truth.writer import CATEGORIES

sys.path.insert(
    0, str(Path(__file__).resolve().parents[2] / "projects" / "apache-shopfront"))

from labels import categorise  # noqa: E402


def entry(path, actor="tool", method="GET"):
    return {"actor": actor, "method": method, "path": path,
            "client_ip": "192.0.2.60", "request_id": "x"}


class TestCategorise(unittest.TestCase):

    def test_every_result_is_in_the_controlled_vocabulary(self):
        paths = ["/", "/assets/css/site.css", "/api/cart", "/login", "/.env",
                 "/admin/users", "/search?q=1' UNION SELECT 1,2--",
                 "/download?file=../../../../etc/passwd", "/wp-login.php"]
        for path in paths:
            with self.subTest(path=path):
                self.assertIn(categorise(entry(path)), CATEGORIES)

    def test_ordinary_page_requests_are_browsing(self):
        self.assertEqual(categorise(entry("/")), "browsing")
        self.assertEqual(categorise(entry("/c/tools")), "browsing")

    def test_asset_extensions_are_static_assets(self):
        for path in ("/assets/css/site.css", "/assets/js/app.js",
                     "/assets/img/p/17.jpg", "/favicon.ico",
                     "/assets/fonts/x.woff2"):
            with self.subTest(path=path):
                self.assertEqual(categorise(entry(path)), "static_asset")

    def test_json_endpoints_are_api_calls(self):
        self.assertEqual(categorise(entry("/api/cart", method="POST")),
                         "api_call")
        self.assertEqual(categorise(entry("/api/autocomplete?q=dr")), "api_call")

    def test_credential_paths_are_authentication(self):
        for path in ("/login", "/logout", "/register", "/password-reset"):
            with self.subTest(path=path):
                self.assertEqual(categorise(entry(path)), "authentication")

    def test_probing_for_what_exists_is_reconnaissance(self):
        for path in ("/.env", "/.git/config", "/robots.txt", "/.aws/credentials",
                     "/actuator/health", "/config.json"):
            with self.subTest(path=path):
                self.assertEqual(categorise(entry(path)), "reconnaissance")

    def test_admin_areas_are_access_control(self):
        self.assertEqual(categorise(entry("/admin/users")), "access_control")
        self.assertEqual(categorise(entry("/account/orders/41")),
                         "access_control")

    def test_traversal_markers_beat_the_path_they_appear_in(self):
        # The endpoint is an ordinary one; what makes the request what it is
        # sits in the query string.
        self.assertEqual(
            categorise(entry("/download?file=../../../../etc/passwd")),
            "path_traversal")
        self.assertEqual(
            categorise(entry("/download?file=%2e%2e%2fetc%2fpasswd")),
            "path_traversal")

    def test_injection_markers_beat_the_path_they_appear_in(self):
        # A payload aimed at /api/ is injection, not an api_call. Precedence
        # here is the difference between a useful label and a misleading one.
        for path in ("/search?q=1' UNION SELECT 1,2--",
                     "/api/stock?id=1 OR 1=1",
                     "/admin/ping?host=127.0.0.1;id",
                     "/admin/template?tpl={{7*7}}"):
            with self.subTest(path=path):
                self.assertEqual(categorise(entry(path)), "injection")

    def test_brute_forcing_tools_are_enumeration_whatever_they_ask_for(self):
        # gobuster walking a wordlist hits /admin/ and /login and /.env, but
        # the activity is one thing: systematic brute-forcing. No single
        # request reveals that -- the actor is the only honest signal.
        for path in ("/admin/", "/login", "/backup.zip"):
            with self.subTest(path=path):
                self.assertEqual(
                    categorise(entry(path, actor="tool:gobuster")),
                    "enumeration")

    def test_search_engine_crawlers_are_crawling(self):
        self.assertEqual(categorise(entry("/robots.txt", actor="crawler:googlebot")),
                         "crawling")
        self.assertEqual(categorise(entry("/c/tools", actor="crawler:googlebot")),
                         "crawling")

    def test_an_unrecognised_actor_on_an_ordinary_path_still_resolves(self):
        self.assertIn(categorise(entry("/", actor="")), CATEGORIES)


if __name__ == "__main__":
    unittest.main()
