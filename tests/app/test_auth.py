"""Authentication, the account area, and the admin area.

The dataset needs both outcomes present: attacks that succeed and attacks that
bounce. So some admin routes enforce their role check and some deliberately do
not, and the difference is asserted here rather than left to be discovered by
whoever reads the log.

Skipped unless LOGFORGE_DOCKER=1.
"""

import re
import unittest

from tests.lab import (DOCKER_AVAILABLE, WEB_RES, compose, fetch, in_container,
                       wait_for_web)

BASE = f"http://{WEB_RES}"
JAR = "/tmp/jar"

# Seeded, fake, and documented as such. No credential here is real.
USER = ("demo", "demo123")
ADMIN = ("agatha", "brassneck")


def login_then(username, password, script):
    """Log in, then run further curl commands sharing the same cookie jar."""
    return in_container(
        f"curl -s -o /dev/null -c {JAR} -d 'username={username}&password={password}' "
        f"{BASE}/login; " + script)


@unittest.skipUnless(DOCKER_AVAILABLE,
                     "needs Docker; set LOGFORGE_DOCKER=1 to run")
class TestAuthentication(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        wait_for_web()

    @classmethod
    def tearDownClass(cls):
        compose("down", "-v")

    def test_the_login_page_is_served(self):
        status, body = fetch(f"{BASE}/login")
        self.assertEqual(status, "200")
        self.assertIn("password", body.lower())

    def test_a_good_password_redirects_and_sets_a_session_cookie(self):
        out = in_container(
            f"curl -s -o /dev/null -c {JAR} -w '%{{http_code}}' "
            f"-d 'username={USER[0]}&password={USER[1]}' {BASE}/login; "
            f"echo; grep -c PHPSESSID {JAR} || true")
        status, _, cookies = out.strip().partition("\n")
        self.assertEqual(status, "302")
        self.assertEqual(cookies.strip(), "1")

    def test_a_bad_password_does_not_redirect(self):
        status = in_container(
            f"curl -s -o /dev/null -w '%{{http_code}}' "
            f"-d 'username={USER[0]}&password=wrong' {BASE}/login").strip()
        self.assertEqual(status, "401")

    def test_repeated_failures_lock_the_account_out(self):
        # A hardened control, so brute-force traffic in the dataset has
        # somewhere to fail rather than succeeding everywhere it is tried.
        out = in_container(
            "for i in 1 2 3 4 5 6 7 8; do "
            f"curl -s -o /dev/null -w '%{{http_code}} ' -c {JAR} -b {JAR} "
            f"-d 'username=lockme&password=wrong' {BASE}/login; done")
        self.assertIn("429", out, f"no lockout after eight attempts: {out}")

    def test_logout_clears_the_session(self):
        out = login_then(*USER, (
            f"curl -s -o /dev/null -b {JAR} -c {JAR} {BASE}/logout; "
            f"curl -s -o /dev/null -b {JAR} -w '%{{http_code}}' {BASE}/account/"))
        self.assertEqual(out.strip(), "302")

    def test_registration_is_reachable(self):
        status, _ = fetch(f"{BASE}/register")
        self.assertEqual(status, "200")

    def test_password_reset_is_reachable(self):
        status, _ = fetch(f"{BASE}/password-reset")
        self.assertEqual(status, "200")


@unittest.skipUnless(DOCKER_AVAILABLE,
                     "needs Docker; set LOGFORGE_DOCKER=1 to run")
class TestAccountArea(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        wait_for_web()

    @classmethod
    def tearDownClass(cls):
        compose("down", "-v")

    def test_the_account_area_redirects_when_signed_out(self):
        for path in ("/account/", "/account/orders", "/account/addresses"):
            with self.subTest(path=path):
                status, _ = fetch(f"{BASE}{path}")
                self.assertEqual(status, "302")

    def test_a_signed_in_customer_sees_their_orders(self):
        out = login_then(*USER,
                         f"curl -s -b {JAR} -w '\\n%{{http_code}}' {BASE}/account/orders")
        body, _, status = out.rpartition("\n")
        self.assertEqual(status.strip(), "200")
        self.assertIn("/account/orders/", body)

    def test_one_customers_order_ids_have_gaps_between_them(self):
        # The IDOR surface Task 12 opens up. Order ids are globally sequential,
        # which is what makes walking them a plausible thing to try -- but they
        # are interleaved across customers on purpose, so the ids between one
        # customer's own orders belong to somebody else. Contiguous-per-customer
        # ids would leave an attacker walking the sequence finding only their
        # own orders, and the surface would prove nothing.
        out = login_then(*USER, f"curl -s -b {JAR} {BASE}/account/orders")
        ids = sorted(int(n) for n in re.findall(r"/account/orders/(\d+)", out))
        self.assertGreaterEqual(len(ids), 3)
        self.assertGreater(ids[-1] - ids[0] + 1, len(ids),
                           f"ids {ids} are contiguous, so walking them never "
                           f"crosses an ownership boundary")


@unittest.skipUnless(DOCKER_AVAILABLE,
                     "needs Docker; set LOGFORGE_DOCKER=1 to run")
class TestAdminArea(unittest.TestCase):
    """Some routes enforce the role check; some deliberately do not."""

    @classmethod
    def setUpClass(cls):
        wait_for_web()

    @classmethod
    def tearDownClass(cls):
        compose("down", "-v")

    def test_admin_is_not_reachable_when_signed_out(self):
        # A redirect to the login page, carrying where it was going. Not a
        # refusal: require_login() answers before require_admin() ever runs, so
        # an anonymous visitor never reaches the role check at all.
        #
        # That distinction is the whole reason attack traffic has to sign in
        # before it can be refused, and this assertion used to accept either
        # answer -- `assertIn(status, ("302", "403"))` -- so it could not fail
        # while the forced-browsing playbook produced no 403s in 1.25 million
        # shipped lines. An assertion that accepts both answers to the question
        # cannot report the wrong one.
        status, head = fetch(f"{BASE}/admin/", extra=["-i"])
        self.assertEqual(status, "302")
        self.assertIn("location: /login?next=%2fadmin%2f", head.lower(),
                      "the bounce must say where it was going, because that is "
                      "what makes it a redirect to sign in rather than a refusal")

    def test_the_importer_wants_a_session_even_though_it_wants_no_role(self):
        # `import-image.php` says in its own docblock, and VULNERABILITIES.md
        # says in section 4, that this endpoint is reachable by "any signed-in
        # customer". It required no sign-in at all: it pulled in auth.php and
        # never called require_login(), so the property was written down twice
        # and enforced nowhere.
        #
        # It matters beyond tidiness. Every SSRF attempt in the corpus was
        # answered 200 without a session, so the traffic showed an anonymous
        # client reaching an admin endpoint -- which is not the weakness this
        # section documents, and not a shape a real deployment produces.
        status, head = fetch(f"{BASE}/admin/import-image", extra=["-i"])
        self.assertEqual(status, "302")
        self.assertIn("location: /login?next=%2fadmin%2fimport-image",
                      head.lower())

    def test_an_ordinary_customer_reaches_the_importer(self):
        # The other half, and the reason the fix above must not become
        # require_admin(). Weakness 4 is that the role check is missing here;
        # a customer reaching it is the vulnerability working as documented.
        out = login_then(*USER,
                         f"curl -s -o /dev/null -b {JAR} "
                         f"-w '%{{http_code}}' '{BASE}/admin/import-image'")
        self.assertEqual(out.strip(), "200")

    def test_the_hardened_admin_routes_refuse_an_ordinary_customer(self):
        # These are where forced-browsing attacks in the dataset fail. A lab
        # where every attack succeeds teaches something false.
        for path in ("/admin/users", "/admin/orders"):
            with self.subTest(path=path):
                out = login_then(*USER,
                                 f"curl -s -o /dev/null -b {JAR} "
                                 f"-w '%{{http_code}}' {BASE}{path}")
                self.assertEqual(out.strip(), "403")

    def test_an_administrator_reaches_the_hardened_routes(self):
        out = login_then(*ADMIN,
                         f"curl -s -o /dev/null -b {JAR} "
                         f"-w '%{{http_code}}' {BASE}/admin/users")
        self.assertEqual(out.strip(), "200")


if __name__ == "__main__":
    unittest.main()
