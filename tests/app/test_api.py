"""The JSON API, the avatar upload, and the server-side image importer.

These are what put api_call lines in the log interleaved with page views, and
what stop the method column being entirely GET. Both matter: an access log
where every request is a GET for an HTML page is not one anybody can practise
on.

Skipped unless LOGFORGE_DOCKER=1.
"""

import json
import unittest

from tests.lab import (DOCKER_AVAILABLE, WEB_RES, compose, fetch, in_container,
                       wait_for_web)

BASE = f"http://{WEB_RES}"
JAR = "/tmp/jar"


@unittest.skipUnless(DOCKER_AVAILABLE,
                     "needs Docker; set LOGFORGE_DOCKER=1 to run")
class TestJsonApi(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        wait_for_web()

    @classmethod
    def tearDownClass(cls):
        compose("down", "-v")

    def test_stock_returns_json_for_a_real_product(self):
        status, body = fetch(f"{BASE}/api/stock?id=17")
        self.assertEqual(status, "200")
        self.assertIsInstance(json.loads(body)["stock"], int)

    def test_autocomplete_returns_matches(self):
        status, body = fetch(f"{BASE}/api/autocomplete?q=oak")
        self.assertEqual(status, "200")
        self.assertIsInstance(json.loads(body)["matches"], list)

    def test_autocomplete_is_hardened_against_injection(self):
        # Prepared statements here on purpose: the dataset needs injection
        # attempts that fail as well as ones that succeed.
        status, body = fetch(f"{BASE}/api/autocomplete?q=%27+OR+%271%27%3D%271")
        self.assertEqual(status, "200")
        self.assertEqual(json.loads(body)["matches"], [])

    def test_posting_to_the_cart_mutates_it_and_returns_the_count(self):
        out = in_container(
            f"curl -s -c {JAR} -b {JAR} -X POST -H 'Content-Type: application/json' "
            f"-d '{{\"id\":17,\"quantity\":1}}' {BASE}/api/cart; echo; "
            f"curl -s -c {JAR} -b {JAR} -X POST -H 'Content-Type: application/json' "
            f"-d '{{\"id\":18,\"quantity\":2}}' {BASE}/api/cart")
        first, second = [json.loads(line) for line in out.strip().splitlines() if line]
        self.assertEqual(first["count"], 1)
        self.assertEqual(second["count"], 3)

    def test_the_cart_supports_delete_so_the_verb_column_is_not_all_get(self):
        out = in_container(
            f"curl -s -c {JAR} -b {JAR} -X POST -H 'Content-Type: application/json' "
            f"-d '{{\"id\":17,\"quantity\":1}}' {BASE}/api/cart >/dev/null; "
            f"curl -s -c {JAR} -b {JAR} -X DELETE '{BASE}/api/cart?id=17'")
        self.assertEqual(json.loads(out.strip())["count"], 0)

    def test_an_unknown_product_is_a_404_in_json(self):
        status, body = fetch(f"{BASE}/api/stock?id=999999")
        self.assertEqual(status, "404")
        self.assertIn("error", json.loads(body))


@unittest.skipUnless(DOCKER_AVAILABLE,
                     "needs Docker; set LOGFORGE_DOCKER=1 to run")
class TestUploadAndImport(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        wait_for_web()

    @classmethod
    def tearDownClass(cls):
        compose("down", "-v")

    def test_uploading_an_avatar_succeeds_for_a_signed_in_customer(self):
        out = in_container(
            f"curl -s -o /dev/null -c {JAR} -d 'username=demo&password=demo123' {BASE}/login; "
            "head -c 900 /var/www/html/assets/img/p/3.jpg > /tmp/face.jpg 2>/dev/null "
            "|| dd if=/dev/urandom of=/tmp/face.jpg bs=900 count=1 2>/dev/null; "
            f"curl -s -b {JAR} -o /dev/null -w '%{{http_code}}' "
            f"-F 'avatar=@/tmp/face.jpg;type=image/jpeg' {BASE}/account/avatar")
        self.assertIn(out.strip(), ("200", "302"))

    def test_the_importer_fetches_a_url_the_server_can_reach(self):
        # Server-side fetch of a user-supplied URL: the SSRF surface. Pointed
        # at the lab's own application, which is the only thing it may ever be
        # pointed at.
        out = in_container(
            "curl -s -o /dev/null -w '%{http_code}' "
            f"'{BASE}/admin/import-image?url=http://203.0.113.2/assets/css/site.css'")
        self.assertEqual(out.strip(), "200")


if __name__ == "__main__":
    unittest.main()
