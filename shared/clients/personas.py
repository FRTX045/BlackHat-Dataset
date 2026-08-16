"""What each kind of visitor does, as a plan of navigation steps.

Two rules shape everything here.

**Journeys must be possible.** A product page is only ever reached after a
listing that contains it, checkout only after something went in the basket, the
account area only after a sign-in. Getting this wrong produces Referer chains
that cannot be true, and a researcher studying journey plausibility would be
right to distrust the whole dataset over it.

**An activity is a contiguous run.** `instance_id` is derived from the activity
of each step, and episode groups must be contiguous per client. A journey that
browsed, searched, then browsed again would produce episodes that validate and
mean nothing, so a journey moves through its activities and does not return to
one it has left.

Only navigation is planned here. Asset requests are not: the driver fetches a
page and then requests the subresources that page actually references, the way
a browser does, so the cascade in the log is the real one rather than a list
somebody wrote down.

Stdlib only, by project rule.
"""

from typing import NamedTuple

PERSONAS = ("casual", "shopper", "returning", "mobile", "crawler", "monitor",
            "scanner")

#: What opportunistic scanning asks for. These are the paths real internet
#: background noise hits constantly and this shop has none of them, so they all
#: 404 -- which is the point. Split by intent: a handful of known-file probes,
#: then a systematic sweep.
_PROBE_PATHS = (
    "/.env", "/.git/config", "/.aws/credentials", "/config.json",
    "/server-status", "/actuator/health", "/.well-known/security.txt",
)
_SWEEP_PATHS = (
    "/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/phpmyadmin/",
    "/admin.php", "/administrator/", "/shell.php", "/backup.zip",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/cgi-bin/test.cgi", "/.svn/entries", "/db.sql", "/old/", "/test.php",
)

#: How a journey persona maps onto the user-agent corpus and the address pool.
#:
#: This is where client coherence is enforced. A mobile visitor has to arrive
#: from a mobile CGNAT address carrying a mobile agent; a crawler from cloud
#: space carrying a bot string. Any other combination is an impossible client,
#: and one wrong pairing here would be invisible in the log but obvious to
#: anyone who cross-referenced address ranges against user agents.
PERSONA_IDENTITY = {
    "casual": ("casual_browser", "residential"),
    "shopper": ("shopper", "residential"),
    "returning": ("returning_customer", "residential"),
    "mobile": ("mobile_user", "mobile"),
    "crawler": ("crawler", "cloud"),
    "monitor": ("uptime_monitor", "cloud"),
    "scanner": ("scanner", "datacenter"),
}

#: Where an arriving visitor says they came from. Search engines dominate real
#: referrer data for a shop this size.
SEARCH_REFERERS = (
    "https://www.google.com/",
    "https://www.google.co.uk/",
    "https://duckduckgo.com/",
    "https://www.bing.com/",
)


class Step(NamedTuple):
    method: str
    path: str
    category: str
    #: What the visitor is doing. Consecutive steps sharing an activity are one
    #: episode; the driver turns changes of activity into new instance_ids.
    activity: str
    #: Set on the first request of a visit only, and never invented for
    #: internal navigation -- the driver fills those in from the page it came
    #: from, because that is where a real Referer comes from.
    referer: str = None


def _category(rng, catalogue):
    return rng.choice(catalogue["categories"])


def _browse(rng, catalogue, pages, referer=None):
    """Enter, open a listing, then open products from that listing."""
    category = _category(rng, catalogue)
    steps = [
        Step("GET", "/", "browsing", "browse", referer),
        Step("GET", f"/c/{category['slug']}", "browsing", "browse"),
    ]
    for _ in range(max(0, pages)):
        if rng.random() < 0.25:
            category = _category(rng, catalogue)
            steps.append(Step("GET", f"/c/{category['slug']}", "browsing", "browse"))
        product = rng.choice(category["products"])
        steps.append(Step("GET", f"/p/{product}", "browsing", "browse"))
        steps.append(Step("GET", f"/api/stock?id={product}", "api_call", "browse"))
    return steps, category


#: Personas that never send a Referer, on any request.
#:
#: Search-engine crawlers, uptime monitors and opportunistic scanners do not
#: set the header at all -- they are not navigating, they are fetching a list.
#: Letting the driver synthesise one for them from the previous page produced a
#: measured 99% Referer share across the whole log, which no real access log
#: has.
NO_REFERER = frozenset({"crawler", "monitor", "scanner"})

#: Share of visits that arrive with no Referer at all -- typed in, bookmarked,
#: opened from an app, or sent with the header stripped. A log where every
#: arrival carries a search-engine Referer is as wrong as one where none does;
#: a measured run without this sat at 100%.
_DIRECT_ARRIVAL = 0.38


def _arrival_referer(rng):
    return None if rng.random() < _DIRECT_ARRIVAL else rng.choice(SEARCH_REFERERS)


def _casual(rng, catalogue):
    referer = _arrival_referer(rng)
    steps, _ = _browse(rng, catalogue, rng.randint(1, 4), referer)
    if rng.random() < 0.3:
        steps.append(Step("GET", "/about", "browsing", "browse"))
    return steps


def _shopper(rng, catalogue):
    referer = _arrival_referer(rng)
    steps, category = _browse(rng, catalogue, rng.randint(2, 6), referer)

    if rng.random() < 0.6:
        term = rng.choice(("oak", "brass", "forged", "stainless", "copper"))
        steps.append(Step("GET", f"/search?q={term}", "browsing", "search"))
        steps.append(Step("GET", f"/api/autocomplete?q={term[:2]}", "api_call", "search"))

    basket = 0
    for _ in range(rng.randint(1, 3)):
        product = rng.choice(category["products"])
        steps.append(Step("POST", "/api/cart", "api_call", "basket"))
        basket += 1
    steps.append(Step("GET", "/cart", "browsing", "basket"))

    if basket and rng.random() < 0.35:
        steps.append(Step("GET", "/checkout", "browsing", "basket"))
    return steps


def _returning(rng, catalogue):
    steps = [
        Step("GET", "/", "browsing", "arrive"),
        Step("GET", "/login", "authentication", "signin"),
        Step("POST", "/login", "authentication", "signin"),
        Step("GET", "/account/", "browsing", "account"),
        Step("GET", "/account/orders", "browsing", "account"),
    ]
    for _ in range(rng.randint(1, 3)):
        steps.append(Step("GET", "/account/orders/{order}", "browsing", "account"))
    if rng.random() < 0.4:
        steps.append(Step("GET", "/account/addresses", "browsing", "account"))
    if rng.random() < 0.3:
        steps.append(Step("GET", "/logout", "authentication", "signout"))
    return steps


def _mobile(rng, catalogue):
    # Same journeys, fewer pages: mobile visitors abandon sooner.
    referer = _arrival_referer(rng)
    steps, category = _browse(rng, catalogue, rng.randint(0, 2), referer)
    if rng.random() < 0.25:
        steps.append(Step("POST", "/api/cart", "api_call", "basket"))
        steps.append(Step("GET", "/cart", "browsing", "basket"))
    return steps


def _crawler(rng, catalogue):
    # Asks for robots.txt first and honours it: a well-behaved bot never
    # touches /account/, /admin/, /cart, /checkout or /api/.
    steps = [
        Step("GET", "/robots.txt", "crawling", "crawl"),
        Step("GET", "/sitemap.xml", "crawling", "crawl"),
        Step("GET", "/", "crawling", "crawl"),
    ]
    for _ in range(rng.randint(3, 12)):
        category = _category(rng, catalogue)
        steps.append(Step("GET", f"/c/{category['slug']}", "crawling", "crawl"))
        for _ in range(rng.randint(1, 3)):
            steps.append(Step("GET", f"/p/{rng.choice(category['products'])}",
                              "crawling", "crawl"))
    return steps


def _monitor(rng, catalogue):
    # An uptime check or a feed reader: one or two URLs, metronomically.
    path = rng.choice(("/", "/about"))
    return [Step("GET", path, "crawling", "monitor")
            for _ in range(rng.randint(1, 2))]


def _scanner(rng, catalogue):
    """Opportunistic background scanning: known files, then a sweep.

    Two activities, in that order and never back again, so the episodes it
    produces are contiguous. Nothing here exists on this shop, so every line
    is a 404 -- which is what makes this traffic legible in the log and what
    makes it a useful negative class to practise on.
    """
    steps = [Step("GET", path, "reconnaissance", "probe")
             for path in rng.sample(_PROBE_PATHS, rng.randint(2, 5))]
    steps += [Step("GET", path, "enumeration", "sweep")
              for path in rng.sample(_SWEEP_PATHS, rng.randint(4, 12))]
    return steps


_PLANNERS = {
    "casual": _casual,
    "shopper": _shopper,
    "returning": _returning,
    "mobile": _mobile,
    "crawler": _crawler,
    "monitor": _monitor,
    "scanner": _scanner,
}


def journey(persona, rng, catalogue):
    """Plan one visit. Returns a list of Steps in the order they are made."""
    try:
        planner = _PLANNERS[persona]
    except KeyError:
        raise ValueError(f"no such persona: {persona!r}") from None
    return planner(rng, catalogue)
