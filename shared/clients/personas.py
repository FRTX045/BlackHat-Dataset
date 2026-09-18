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
from urllib.parse import quote_plus

PERSONAS = ("casual", "shopper", "returning", "mobile", "crawler", "monitor",
            "admin",
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
    # Staff at a desk on the office connection.
    "admin": ("admin_browser", "residential"),
    "scanner": ("scanner", "datacenter"),
}

#: What people type into the shop's own search box.
#:
#: Long and varied on purpose. An earlier version offered five fixed terms,
#: which made `/search?q=` a closed set of five URLs; real on-site search is
#: one of the biggest sources of once-only URLs in any shop's log, because
#: most queries are typed by one person once. Misspellings, plurals, part
#: numbers and multi-word phrases are all in here because they are all in real
#: search logs.
SEARCH_TERMS = (
    "oak", "brass", "forged", "stainless", "copper", "galvanised",
    "hammer", "claw hammer", "lump hammer", "hamer", "ball pein",
    "screwdriver", "screwdrivers", "pozi 2", "ph2 bits", "torx set",
    "spanner", "spanner set", "combination spanner", "adjustable spanner",
    "socket set", "1/2 drive", "torque wrench", "impact driver",
    "cordless drill", "drill bits", "masonry bit", "sds plus", "hole saw",
    "wood screws", "decking screws", "coach bolts", "wall plugs", "rawlplug",
    "m6 bolt", "m8 washer", "nyloc nut", "threaded rod", "penny washers",
    "tape measure", "5m tape", "spirit level", "laser level", "chalk line",
    "hand saw", "tenon saw", "hacksaw blades", "jigsaw blades",
    "chisel set", "wood chisel", "sharpening stone", "honing guide",
    "workwear", "work trousers", "knee pads", "steel toe boots", "size 11",
    "hi vis", "hi-vis vest", "gloves", "nitrile gloves", "safety glasses",
    "ear defenders", "dust mask", "ffp3", "knee pad inserts",
    "paint brush", "roller sleeve", "masking tape", "dust sheet",
    "white gloss", "undercoat", "wood stain", "danish oil", "linseed",
    "secateurs", "loppers", "garden fork", "spade", "wheelbarrow",
    "hose fittings", "watering can", "compost bin",
    "pipe cutter", "compression fitting", "ptfe tape", "flux", "solder",
    "isolating valve", "22mm elbow", "15mm pipe",
    "junction box", "twin and earth", "2.5mm cable", "consumer unit",
    "cable clips", "back box", "grommets", "conduit",
    "tool box", "tool bag", "site chest", "van racking", "shelf brackets",
    "storage tubs", "small parts organiser",
    "clearance", "trade prices", "next day", "click and collect",
    "gift voucher", "returns policy", "warranty claim",
)

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
    #: (username, password) for a POST /login that must use specific
    #: credentials. Without it the driver picks a random valid customer, which
    #: is right for an ordinary returning visitor and useless for an
    #: administrator -- a random customer signing in would be answered 403 by
    #: the role-gated admin routes, not 200. Also how a deliberately wrong
    #: password gets into the data.
    login_as: tuple = None


def _category(rng, catalogue):
    return rng.choice(catalogue["categories"])


def _browse(rng, catalogue, pages, referer=None):
    """Enter, open a listing, then open products from that listing."""
    category = _category(rng, catalogue)
    steps = [
        Step("GET", _landing(rng, referer), "browsing", "browse", referer),
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


#: Campaign names a shop this size would actually run, for the `utm_campaign`
#: half of an inbound tracking query.
_CAMPAIGNS = (
    "spring-clearance", "trade-account", "brand-generic", "shopping-feed",
    "retargeting-30d", "newsletter-mar", "dynamic-search", "pmax-tools",
    "workwear-push", "garden-season", "bank-holiday", "abandoned-basket",
)
_SOURCES = (("google", "cpc"), ("google", "organic"), ("bing", "cpc"),
            ("facebook", "social"), ("instagram", "social"),
            ("newsletter", "email"), ("pricerunner", "referral"),
            ("reddit", "social"))

#: Share of referred arrivals carrying a tracking query string.
#:
#: Measured on a medium build without this: only 1.95% of paths in the whole
#: log were requested exactly once, where a real log has a long tail of URLs
#: seen once and never again. A closed URL vocabulary is the cause, and
#: tracking parameters are the largest single source of that tail on a real
#: shop -- every paid click, every emailed link and every shared URL arrives
#: with one, and normalising them away is a standard first step in real log
#: analysis. Their absence made the data easier than the real thing.
_TRACKED_ARRIVAL = 0.55


#: Which tracking source goes with which referring host. A visitor arriving
#: from Google carrying `utm_source=reddit` is a real thing -- somebody copied
#: a tracked link and posted it -- but it should be the exception, not the
#: default. Client identity is coherent everywhere else in this project and
#: this is the same rule applied to the query string.
_REFERER_SOURCE = {
    "www.google.com": ("google", ("cpc", "organic")),
    "www.google.co.uk": ("google", ("cpc", "organic")),
    "www.bing.com": ("bing", ("cpc", "organic")),
    "duckduckgo.com": ("duckduckgo", ("organic",)),
}

#: How often the tracking parameters disagree with the referring host.
_MISMATCHED_SOURCE = 0.18


def _tracking_query(rng, referer=None):
    """A tracking query string, of the kind every inbound link carries."""
    host = None
    if referer:
        host = referer.split("//", 1)[-1].split("/", 1)[0]

    roll = rng.random()
    if roll < 0.45:
        known = _REFERER_SOURCE.get(host)
        if known and rng.random() > _MISMATCHED_SOURCE:
            source, mediums = known
            medium = rng.choice(mediums)
        else:
            source, medium = rng.choice(_SOURCES)
        query = (f"utm_source={source}&utm_medium={medium}"
                 f"&utm_campaign={rng.choice(_CAMPAIGNS)}")
        if rng.random() < 0.4:
            query += f"&utm_content=v{rng.randrange(1, 40)}"
        if rng.random() < 0.25:
            query += f"&utm_term={rng.choice(SEARCH_TERMS).replace(' ', '+')}"
        return query
    if roll < 0.70:
        # A Google Ads click id only comes from a Google click. Anywhere else
        # it would be a link somebody copied, which the utm branch above
        # already covers.
        if host and not host.startswith("www.google"):
            source, medium = rng.choice(_SOURCES)
            return (f"utm_source={source}&utm_medium={medium}"
                    f"&utm_campaign={rng.choice(_CAMPAIGNS)}")
        # Opaque, and unique to the click.
        return "gclid=" + "".join(
            rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                       "0123456789_-") for _ in range(rng.randrange(52, 71)))
    if roll < 0.85:
        return "fbclid=IwAR" + "".join(
            rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                       "0123456789_-") for _ in range(rng.randrange(40, 60)))
    if roll < 0.93:
        return f"mc_cid={rng.randrange(10**7, 10**8):x}&mc_eid={rng.randrange(10**7, 10**8):x}"
    return f"ref={rng.choice(('nav', 'footer', 'promo', 'email', 'partner'))}"


def _arrival_referer(rng):
    return None if rng.random() < _DIRECT_ARRIVAL else rng.choice(SEARCH_REFERERS)


def _landing(rng, referer):
    """The first URL of a visit, with a tracking query when it was referred.

    Only referred arrivals get one: somebody who typed the address in or
    opened a bookmark has nothing to append.
    """
    if referer and rng.random() < _TRACKED_ARRIVAL:
        return "/?" + _tracking_query(rng, referer)
    return "/"


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
        term = rng.choice(SEARCH_TERMS)
        encoded = quote_plus(term)
        # The autocomplete calls a real browser makes as somebody types: one
        # per keystroke after the second character, debounced. That is where
        # a shop's `/api/autocomplete` volume actually comes from, and it is
        # another genuine source of once-only URLs.
        for cut in range(2, min(len(term), 2 + rng.randint(1, 4))):
            steps.append(Step("GET",
                              f"/api/autocomplete?q={quote_plus(term[:cut])}",
                              "api_call", "search"))
        steps.append(Step("GET", f"/search?q={encoded}", "browsing", "search"))
        if rng.random() < 0.3:
            steps.append(Step("GET", f"/search?q={encoded}&page=2",
                              "browsing", "search"))

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


#: Addresses reserved for the shop's own administrators.
#:
#: Fixed rather than drawn, for the same reason the tool runs and the browser
#: personas have fixed addresses: the manifest names them, so a later reader
#: can tell this traffic was deliberate rather than a labelling slip. Low in
#: the residential range, clear of the lab's own containers and below the block
#: `ippools` draws its recurring clients from, so the session driver can never
#: hand one of these to an ordinary visitor.
ADMIN_ADDRESSES = ("203.0.113.61", "203.0.113.62")

#: What the administrators do, for the manifest to record in words.
ADMIN_DESCRIPTION = (
    "The shop's own staff doing ordinary administration: an unauthenticated "
    "request to an admin path that is answered 302 to the login page, one "
    "wrong password, a correct one, signed-in work answered 200, and a "
    "session that has expired by the time they come back so the bounce "
    "happens again.")


def _admin_user(catalogue):
    """The seeded account with the admin role, and its password.

    Taken from the catalogue the seeder publishes rather than hardcoded, so a
    change of seed or of the account list cannot leave this journey signing in
    as somebody who no longer exists.
    """
    for user in catalogue.get("users", []):
        if user.get("role") == "admin":
            return user["username"], user["password"]
    return None


def _admin(rng, catalogue):
    """One of the shop's staff doing ordinary administration.

    This exists because of a gap a downstream detection project measured and
    reported: every request to an admin path in this corpus came from an
    attacker, so a rule that flags `GET /admin -> 302` scored perfectly and
    would have scored perfectly whether or not it also flagged innocent
    people. A measurement that cannot fail is not evidence.

    A redirect away from an admin path is not evidence of anything on its own.
    It is what every cookie-session admin panel answers anybody not signed in
    yet, **including the owner of the shop**:

        GET /admin/    -> 302 to /login      the owner, not yet signed in
        POST /login    -> 302 to /admin
        GET /admin/    -> 200                signed in, ordinary work

    The first line is indistinguishable in an access log from somebody
    rattling the handle. So the unauthenticated request is the point of this
    journey and is never skipped -- starting from an already-authenticated
    session would leave the corpus exactly as unable to tell the two cases
    apart as it was before.

    **Labelled `authentication` and `browsing`, never `access_control`.** That
    is the whole value of it. `access_control` is what the attackers' admin
    requests carry, and putting these under the same category would mean the
    corpus still cannot distinguish a legitimate administrator from a forced
    browsing attempt, and nothing would have been gained.
    """
    credentials = _admin_user(catalogue)
    if credentials is None:
        # No admin account in this catalogue: emit nothing rather than a
        # journey that cannot succeed and would put misleading 403s in the log.
        return []

    landing = rng.choice(("/admin/", "/admin/orders", "/admin/users"))
    steps = [
        # The bounce. 302 to /login?next=<landing>, and the reason this
        # journey exists.
        Step("GET", landing, "authentication", "signin"),
        Step("GET", f"/login?next={quote_plus(landing)}", "authentication",
             "signin"),
        # A wrong password first. Real people mistype, and a corpus where every
        # legitimate sign-in succeeds on the first attempt cannot tell a typo
        # from the start of a credential attack.
        Step("POST", "/login", "authentication", "signin",
             login_as=(credentials[0], "wrong-" + str(rng.randrange(100, 999)))),
        Step("POST", "/login", "authentication", "signin",
             login_as=credentials),
        # Arrived. Ordinary work from here, answered 200.
        Step("GET", landing, "browsing", "admin-work"),
    ]
    for path in rng.sample(["/admin/orders", "/admin/users", "/admin/"],
                           rng.randint(1, 3)):
        steps.append(Step("GET", path, "browsing", "admin-work"))
    if rng.random() < 0.45:
        # Importing a product image is ordinary administration. It is also the
        # SSRF surface, which is exactly why a benign example of it matters:
        # the attackers' version points at cloud metadata, and this one does
        # not.
        steps.append(Step("GET", "/admin/import-image?url=" + quote_plus(
            "http://203.0.113.2/assets/img/logo.png"),
            "browsing", "admin-work"))
    if rng.random() < 0.5:
        steps.append(Step("GET", "/admin/orders", "browsing", "admin-work"))

    # The session ends, and they come back to find it gone. The second bounce
    # is the same shape as the first and is the case an analyst is most likely
    # to mistake for an attacker returning.
    if rng.random() < 0.55:
        steps.append(Step("GET", "/logout", "authentication", "signout"))
        steps.append(Step("GET", rng.choice(("/admin/", "/admin/orders")),
                          "authentication", "expired"))
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
    "admin": _admin,
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
