"""Map an apache-shopfront request onto the controlled vocabulary.

Used only for traffic whose ledger carries no category of its own -- which in
practice means the tag proxy's, because a proxy can see what was requested but
not why. The driver states its own intent and is never labelled by guesswork.

Two things drive the decision, and the order between them matters:

The **actor** settles activities no single request can reveal. gobuster walking
a wordlist asks for /admin/, /login and /.env in turn; every one of those has a
sensible per-request label and all of them would be wrong, because the activity
is one thing -- systematic brute-forcing. Only the actor knows that.

The **request** settles the rest, and payload markers take precedence over the
endpoint they appear in. A UNION SELECT aimed at /api/stock is injection, not
an api_call. Getting that precedence backwards is the difference between a
useful label and a misleading one.

Everything here is a judgement about this project's URL vocabulary, which is
why it lives beside the project rather than in shared/.
"""

import re
from urllib.parse import unquote

#: Actors whose whole run is one activity, whatever the individual requests
#: look like.
#:
#: Every tool that can appear in a ledger must be here. An actor this table
#: does not recognise falls through to per-request guessing, and for a tool
#: that guessing is reliably wrong: a shipped dataset once carried 9,293 tool
#: requests of which 98% were labelled `browsing`, because the proxy stamped
#: the generic actor `tool` and none of these prefixes ever matched.
#:
#: `tool:sqlmap` is `injection` for its whole run rather than per request.
#: Its boolean payloads look like `q=oak%' AND 7889=7889 AND 'NOey%'='NOey`,
#: which carries no UNION and no `or 1=1`, so the payload regex below catches
#: roughly one request in forty-five. The run is an injection attempt from its
#: first request to its last, and labelling it by what each request happens to
#: contain describes the syntax rather than the activity.
_ACTOR_CATEGORIES = (
    (("tool:gobuster", "tool:ffuf", "tool:dirb"), "enumeration"),
    (("tool:sqlmap",), "injection"),
    (("tool:whatweb", "tool:nmap", "tool:nikto"), "reconnaissance"),
    (("tool:hydra",), "credential_attack"),
    (("crawler:",), "crawling"),
)

_ASSET_SUFFIXES = (
    ".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".map",
)

#: Paths that exist to find out what exists. Distinct from enumeration, which
#: is the systematic version of the same instinct.
_RECON_MARKERS = (
    "/.env", "/.git", "/.aws", "/.ssh", "/robots.txt", "/sitemap.xml",
    "/config.json", "/actuator", "/server-status", "/.well-known",
)

_AUTH_PATHS = frozenset({
    "/login", "/logout", "/register", "/password-reset",
})

_TRAVERSAL = re.compile(r"\.\./|\.\.\\|/etc/passwd|\\windows\\win\.ini",
                        re.IGNORECASE)

_INJECTION = re.compile(
    r"union\s+select|\bor\s+1\s*=\s*1|'\s*or\s*'|--\s*$|;\s*id\b|\|\s*id\b"
    r"|<script|javascript:|\{\{.*\}\}|\$\{.*\}|\bexec\s*\(|randomblob\s*\(",
    re.IGNORECASE)


def _actor_category(actor):
    for prefixes, category in _ACTOR_CATEGORIES:
        if any(actor.startswith(prefix) for prefix in prefixes):
            return category
    return None


def categorise(entry):
    """Return the vocabulary category for one tag-proxy ledger entry.

    Args:
        entry: a ledger record with at least `actor` and `path`.

    Returns:
        One of the fourteen category strings. Never None: a request that
        reaches here was really made and really logged, so it gets a label, and
        `browsing` is the honest default for a request that looks like one.
    """
    actor = entry.get("actor") or ""
    path = entry.get("path") or "/"

    # Decoded once for payload matching only. The raw path is what was
    # requested and what the log records; this copy exists so that an encoded
    # traversal is not read as an ordinary filename.
    decoded = unquote(path)

    if _TRAVERSAL.search(decoded):
        return "path_traversal"
    if _INJECTION.search(decoded):
        return "injection"

    from_actor = _actor_category(actor)
    if from_actor:
        return from_actor

    route = path.split("?", 1)[0]

    if route.lower().endswith(_ASSET_SUFFIXES):
        return "static_asset"
    if route.startswith("/api/"):
        return "api_call"
    if route.rstrip("/") in _AUTH_PATHS:
        return "authentication"
    if any(marker in route for marker in _RECON_MARKERS):
        return "reconnaissance"
    if route.startswith("/admin") or route.startswith("/account"):
        return "access_control"

    return "browsing"
