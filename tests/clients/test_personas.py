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
from urllib.parse import unquote_plus

from shared.clients.ippools import INFRASTRUCTURE_ADDRESSES, ROLES
from shared.clients.personas import (NO_REFERER, PERSONA_IDENTITY,
                                     PERSONAS, SITE, journey)
from shared.clients.useragents import PERSONA_UA_CLASSES
from shared.truth.writer import CATEGORIES

CATALOGUE = {
    "categories": [
        {"slug": f"cat-{c}", "products": list(range(c * 13 + 1, c * 13 + 14))}
        for c in range(10)
    ],
    # The shape the seeder publishes, including the admin account. The admin
    # journey looks its credentials up here rather than hardcoding them, so a
    # fixture without a `users` key made that journey plan nothing at all --
    # which is how this key came to be missing from the fixture for a month
    # without anybody noticing.
    "users": [
        {"username": "demo", "password": "demo123", "role": "customer",
         "orders": [1, 5, 9]},
        {"username": "rmarsh", "password": "hunter2", "role": "customer",
         "orders": [2, 6]},
        {"username": "agatha", "password": "brassneck", "role": "admin",
         "orders": [4]},
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


class TestTheAdministratorJourney(unittest.TestCase):
    """The shop's own staff, doing ordinary administration.

    This exists because a downstream detection project measured that every
    request to an admin path in this corpus came from an attacker. A rule
    flagging `GET /admin -> 302` therefore scored perfectly, and would have
    scored perfectly whether or not it also flagged the shop's owner. A
    measurement that cannot fail is not evidence.

    What these pin down is the part that makes the addition worth anything: the
    unauthenticated bounce is present, and none of it is labelled with the
    category the attackers' admin requests use.
    """

    def journeys(self, count=300, seed=11):
        return journeys("admin", count=count, seed=seed)

    def test_the_first_request_is_an_unauthenticated_admin_path(self):
        # The whole point. Starting from an already-authenticated session would
        # leave the corpus exactly as unable to tell a legitimate
        # administrator from somebody rattling the handle.
        for journey in self.journeys():
            with self.subTest(first=journey[0].path):
                self.assertTrue(journey[0].path.startswith("/admin"))
                self.assertEqual(journey[0].method, "GET")

    def test_nothing_in_it_is_labelled_access_control(self):
        # `access_control` is what the attackers' admin requests carry. If
        # these landed there too, the corpus still could not distinguish the
        # two cases and the exercise would have bought nothing.
        for journey in self.journeys():
            for step in journey:
                with self.subTest(path=step.path):
                    self.assertNotEqual(step.category, "access_control")

    def test_every_step_is_authentication_or_browsing(self):
        allowed = {"authentication", "browsing"}
        for journey in self.journeys():
            for step in journey:
                with self.subTest(path=step.path, category=step.category):
                    self.assertIn(step.category, allowed)

    def test_the_bounce_and_the_login_page_are_authentication(self):
        for journey in self.journeys():
            self.assertEqual(journey[0].category, "authentication")
            self.assertEqual(journey[1].category, "authentication")
            self.assertIn("/login", journey[1].path)

    def test_a_wrong_password_comes_before_a_correct_one(self):
        # Real people mistype. A corpus where every legitimate sign-in succeeds
        # first time cannot tell a typo from the start of a credential attack.
        for journey in self.journeys():
            logins = [s for s in journey
                      if s.method == "POST" and s.path == "/login"]
            with self.subTest(n=len(logins)):
                self.assertEqual(len(logins), 2)
                self.assertTrue(logins[0].login_as[1].startswith("wrong-"))
                self.assertEqual(logins[1].login_as,
                                 ("agatha", "brassneck"))

    def test_the_signed_in_work_is_browsing(self):
        for journey in self.journeys():
            work = [s for s in journey if s.activity == "admin-work"]
            self.assertTrue(work)
            for step in work:
                with self.subTest(path=step.path):
                    self.assertEqual(step.category, "browsing")
                    self.assertTrue(step.path.startswith("/admin"))

    def test_some_visits_end_with_an_expired_session_bouncing_again(self):
        # The case an analyst is most likely to mistake for an attacker
        # returning: the same 302 from the same admin path, hours later.
        expired = [j for j in self.journeys()
                   if any(s.activity == "expired" for s in j)]
        self.assertTrue(expired)
        for journey in expired:
            step = next(s for s in journey if s.activity == "expired")
            self.assertTrue(step.path.startswith("/admin"))
            self.assertEqual(step.category, "authentication")

    def test_activities_stay_contiguous(self):
        # The same rule every other persona is held to: an activity is a run,
        # and returning to one would produce episodes that validate and mean
        # nothing.
        for journey in self.journeys():
            runs = []
            for step in journey:
                if not runs or runs[-1] != step.activity:
                    runs.append(step.activity)
            with self.subTest(runs=runs):
                self.assertEqual(len(runs), len(set(runs)))

    def test_it_plans_nothing_when_the_catalogue_has_no_admin(self):
        # Deliberate, and better than the alternative: a journey that signs in
        # as somebody who does not exist would fill the log with 401s and 403s
        # labelled as ordinary administration.
        from shared.clients.personas import journey as plan
        import random
        catalogue = dict(CATALOGUE, users=[
            {"username": "demo", "password": "x", "role": "customer",
             "orders": []}])
        self.assertEqual(plan("admin", random.Random(1), catalogue), [])


class TestTheAdminAddresses(unittest.TestCase):

    def test_they_are_fixed_and_distinct(self):
        from shared.clients.personas import ADMIN_ADDRESSES
        self.assertGreaterEqual(len(ADMIN_ADDRESSES), 2,
                                "a second admin keeps the pattern from being "
                                "one client's quirk")
        self.assertEqual(len(set(ADMIN_ADDRESSES)), len(ADMIN_ADDRESSES))

    def test_the_session_driver_can_never_draw_one(self):
        # Two sources writing episodes for one address would break the
        # contiguity the truth file promises, and it would surface after a
        # full build with nothing pointing at the cause.
        from shared.clients.ippools import ClientPool
        from shared.clients.personas import ADMIN_ADDRESSES
        pool = ClientPool(seed=7)
        drawn = {pool.draw(role) for role in ROLES for _ in range(3000)}
        self.assertEqual(set(ADMIN_ADDRESSES) & drawn, set())

    def test_they_are_inside_the_reserved_ranges(self):
        from shared.clients.ippools import is_allowed
        from shared.clients.personas import ADMIN_ADDRESSES
        for address in ADMIN_ADDRESSES:
            with self.subTest(address=address):
                self.assertTrue(is_allowed(address))

    def test_they_collide_with_nothing_else_reserved(self):
        import sys
        from pathlib import Path as P
        root = P(__file__).resolve().parents[2]
        sys.path.insert(0, str(root / "projects" / "apache-shopfront" / "attacks"))
        sys.path.insert(0, str(root / "projects" / "apache-shopfront" / "traffic"))
        from shared.clients.personas import ADMIN_ADDRESSES
        from toolruns import TOOL_RUNS
        from browser import BROWSER_PERSONAS
        taken = ({r.address for r in TOOL_RUNS}
                 | {p.address for p in BROWSER_PERSONAS}
                 | INFRASTRUCTURE_ADDRESSES)
        self.assertEqual(set(ADMIN_ADDRESSES) & taken, set())


class TestNothingNamesTheLabItself(unittest.TestCase):
    """No generated request may name a lab container by address.

    Half of this property was already enforced: no *client* may claim an
    infrastructure address, because browser traffic logged under the server's
    own identity would be incoherent. Nothing enforced the other half, that no
    request *content* may name one either, and one step had been quietly
    breaking it since the admin journey was written.

    It is the same server twice. The shipped log calls it `shop.test` in every
    Referer; a `url=` parameter calling it `203.0.113.2` names one host two
    ways and puts this lab's bridge layout into a field a visitor is supposed
    to have typed.

    What it cost is specific. The benign `import-image` step exists to be the
    harmless counterpart of the attackers' metadata-hunting version -- the
    comment on it says so. A bare IP in the parameter is exactly what a rule
    keying on "IP address in a URL parameter" fires on, so the benign example
    was indistinguishable from the hostile one on the one feature that
    separates them, and a downstream detection project measured 73 false
    alarms off this single step.
    """

    def test_no_step_names_an_infrastructure_address(self):
        leaked = {}
        for persona in PERSONAS:
            for steps in journeys(persona, count=100):
                for step in steps:
                    target = unquote_plus(step.path)
                    for address in INFRASTRUCTURE_ADDRESSES:
                        if address in target:
                            leaked.setdefault((persona, address), step.path)
        self.assertEqual(
            {}, leaked,
            "these requests name a lab container by address, which is not "
            "something any visitor could have typed: " + "; ".join(
                f"{persona} -> {address} in {path}"
                for (persona, address), path in sorted(leaked.items())))

    def test_the_benign_image_import_names_the_site_a_browser_would_show(self):
        # The positive form of the test above. Absence of an address is not
        # the property that matters; naming the server the way the address bar
        # does is, because that is where an administrator gets a URL to paste.
        imports = [unquote_plus(step.path)
                   for steps in journeys("admin", count=300)
                   for step in steps
                   if step.path.startswith("/admin/import-image")]
        self.assertTrue(imports, "the admin journey generated no image import")
        for target in imports:
            with self.subTest(target=target):
                self.assertIn(f"url={SITE}/", target)


class TestTheHttpLibraryClient(unittest.TestCase):
    """Something benign has to speak through an HTTP library.

    Every request in this corpus carrying a `python-requests`, `curl`, `wget`
    or `Go-http-client` User-Agent came from a scanner or an attacker. A
    detector keying on that string alone therefore scored perfectly here, and
    would have gone on scoring perfectly no matter how wrong it was -- the
    same defect as `admin_area_redirect` scoring 13 out of 13 in a corpus
    where no legitimate administrator existed, and the same as the role check
    that could not answer because nothing ever signed in.

    Real shops of this size are polled constantly by partner systems, price
    feeds and deploy checks, all of which use exactly those libraries. So the
    corpus needs one that behaves itself: documented endpoints, no session, no
    Referer, and nothing it asks for missing.
    """

    def test_a_benign_persona_presents_an_http_library_user_agent(self):
        hostile = {"scanner", "attacker"}
        library = {identity for identity, classes in PERSONA_UA_CLASSES.items()
                   if identity != "__all__" and "library" in classes}
        benign = library - hostile
        self.assertTrue(
            benign,
            "every persona presenting an HTTP library is hostile, so a rule "
            "keying on the User-Agent cannot be wrong in this corpus")

        # And it must be a persona that actually runs. `feed_reader` is mapped
        # in PERSONA_UA_CLASSES and belongs to nothing in PERSONAS, so it
        # contributes no traffic at all -- a declaration is not a counter-case.
        running = {PERSONA_IDENTITY[name][0] for name in PERSONAS}
        self.assertTrue(
            benign & running,
            f"{sorted(benign)} is declared but no persona in PERSONAS uses "
            f"it, so no request in any build would carry it")

    def test_it_asks_only_for_things_that_are_there(self):
        # A benign client whose requests 404 is not a counter-case, it is a
        # second scanner. Every product id it polls has to be real.
        for steps in journeys("integration", count=200):
            for step in steps:
                if step.path.startswith("/api/stock"):
                    product = int(step.path.split("id=")[1])
                    with self.subTest(product=product):
                        self.assertIn(product, PRODUCT_CATEGORY)

    def test_it_never_reaches_for_anything_private(self):
        forbidden = ("/admin", "/account", "/cart", "/checkout", "/login")
        for steps in journeys("integration", count=200):
            for step in steps:
                with self.subTest(path=step.path):
                    self.assertFalse(step.path.startswith(forbidden),
                                     f"an integration asked for {step.path}")

    def test_nothing_it_does_is_labelled_as_probing(self):
        # If its own traffic were labelled reconnaissance the corpus would be
        # agreeing with the rule it exists to contradict.
        allowed = {"api_call", "browsing"}
        for steps in journeys("integration", count=200):
            for step in steps:
                with self.subTest(path=step.path):
                    self.assertIn(step.category, allowed)

    def test_it_sends_no_referer(self):
        # A script has no page it came from. Inventing one would be the same
        # kind of impossible chain the journey tests exist to rule out.
        self.assertIn("integration", NO_REFERER)
