"""Real browser sessions, through a real Chromium.

Every other traffic source in this project decides for itself what to request.
This one does not: it hands a URL to Chromium and records what the browser
chose to ask for. That is the whole point, and it is the one thing the
hand-rolled driver cannot do honestly.

What only a real browser produces:

- **Subresource order as a browser actually orders it.** The driver parses the
  markup and issues the assets it finds. Chromium runs the preload scanner,
  prioritises the stylesheet ahead of images below the fold, starts fonts only
  once the CSS that references them has parsed, and interleaves across six
  connections. The driver's cascades are real requests for real subresources
  and their *sequence* is a program's, not a browser's.
- **The requests it does not make.** A second page view asks for nothing it
  already holds. Absence is as much a part of a real log as presence, and it
  is very hard to fake convincingly.
- **Genuine conditional revalidation.** The 304s here come from Chromium's own
  cache deciding to check, not from a coin flip.
- **The favicon**, asked for once per origin, unprompted by any markup.

**No request interception.** Playwright can rewrite headers per request with
`page.route`, which would let this script mint its own `X-Request-Id` and
write an explicit ledger. It also disables the HTTP cache -- Playwright says
so outright -- and the cache is most of why a browser is worth running at all.
So the tag proxy mints the ids instead, exactly as it does for the security
tools, and these requests are labelled per request by `labels.py`.

One consequence worth stating: because the labels are derived rather than
declared, a browser `instance_id` is a run of one activity, not a whole
session. That is what `instance_id` already means for every proxy-labelled
source in this project.

**Identity.** One container serves every persona. Each persona connects to its
own tag-proxy port, and that port is configured in **fixed** mode, so the
address the proxy declares to Apache is the persona's rather than the
container's. The addresses are in the residential documentation range, below
the block `ippools` draws its recurring clients from and clear of the lab's
own containers -- a persona sharing an address with a driver session would
interleave two sources' episodes for one client and break the contiguity the
truth file promises.

Runs only in its own container. Playwright is imported behind a guard so the
host test suite can read the declarations without it.
"""

import argparse
import json
import random
import sys
import time
from typing import NamedTuple
from urllib.parse import urlsplit

try:  # pragma: no cover - present only inside the browser container
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover
    sync_playwright = None

#: The tag proxy on lab_res. Browsers are residential clients and reach it
#: there; they are never pointed at Apache directly, because a request that
#: does not pass through the proxy carries no request id and cannot be
#: labelled at all.
PROXY = "203.0.113.3"


class BrowserPersona(NamedTuple):
    name: str
    #: The tag-proxy port this persona connects to. Fixed mode, so the port
    #: is what carries the identity.
    port: int
    #: The address the proxy declares for it.
    address: str
    viewport: tuple
    #: How many separate visits this persona makes. A visit is one browser
    #: context: its own cookie jar and its own cache.
    sessions: int
    #: Pages deep per visit, before the assets each of them pulls in.
    depth: tuple
    #: None means Chromium's own string with the headless marker removed.
    #: A real browser is running either way; announcing HeadlessChrome would
    #: be the loudest tell in the file.
    user_agent: str = None
    #: Passed to Chromium so the persona reports a coherent language.
    locale: str = "en-GB"
    #: Emulated as a touch device with a mobile viewport.
    mobile: bool = False


BROWSER_PERSONAS = (
    BrowserPersona(
        name="desktop-wide",
        port=8090, address="203.0.113.41",
        viewport=(1680, 1050), sessions=3, depth=(3, 7)),
    BrowserPersona(
        name="desktop-laptop",
        port=8091, address="203.0.113.42",
        viewport=(1440, 900), sessions=3, depth=(2, 5)),
    BrowserPersona(
        name="mobile-android",
        port=8092, address="203.0.113.43",
        viewport=(412, 915), sessions=2, depth=(2, 4), mobile=True,
        user_agent=("Mozilla/5.0 (Linux; Android 15; Pixel 9) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/141.0.0.0 Mobile Safari/537.36")),
    BrowserPersona(
        name="tablet",
        port=8093, address="203.0.113.44",
        viewport=(834, 1112), sessions=2, depth=(2, 4), mobile=True),
    BrowserPersona(
        # Comes back to a site it has already seen. Its second and third
        # visits reuse the cache from the first, which is what produces
        # conditional requests rather than fresh ones.
        name="desktop-returning",
        port=8094, address="203.0.113.45",
        viewport=(1512, 945), sessions=4, depth=(2, 4)),
)


def port_map_entries():
    """Tag-proxy configuration these personas rely on.

    Fixed mode, not peer: one container serves every persona, so peer mode
    would declare that container's single address for all of them and the five
    identities would collapse into one.

    The actor is plain `browser`. Deliberately not a `tool:` actor -- a tool's
    whole run is one activity and is labelled from the actor, whereas a
    browser session is genuinely a mixture and every request in it can be read
    on its own. A blanket category would put one wrong label on all of it.
    """
    return {p.port: {"mode": "fixed", "client_ip": p.address,
                     "actor": "browser"}
            for p in BROWSER_PERSONAS}


def target_for(persona):
    return f"http://{PROXY}:{persona.port}"


def _agent_for(persona, browser):
    """The persona's agent string, or Chromium's own with `Headless` removed.

    Removing the marker is a claim about the engine that is true: this *is*
    that Chromium build, driving a real renderer. Leaving it in would put a
    string in the dataset that no ordinary visitor has ever sent.
    """
    if persona.user_agent:
        return persona.user_agent
    version = browser.version  # e.g. "141.0.7390.37"
    return (f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{version} Safari/537.36")


def _internal_links(page, base):
    """Same-origin hrefs on the current page, deduplicated, in document order.

    Taken from the page the browser actually rendered, so a link added by
    script is followed and a link removed by script is not.
    """
    host = urlsplit(base).netloc
    try:
        hrefs = page.eval_on_selector_all(
            "a[href]", "els => els.map(e => e.href)")
    except Exception:  # noqa: BLE001 - a navigation mid-evaluation is normal
        return []

    seen, out = set(), []
    for href in hrefs:
        parts = urlsplit(href)
        if parts.scheme not in ("http", "https") or parts.netloc != host:
            continue
        if parts.path in seen or parts.path in ("", "/logout"):
            continue
        seen.add(parts.path)
        out.append(href)
    return out


def _browse(page, base, rng, depth, pace):
    """One visit: land on the site and follow links like a person."""
    reached = 0
    try:
        page.goto(base + "/", wait_until="load", timeout=30_000)
        reached += 1
    except Exception as exc:  # noqa: BLE001
        print(f"    first navigation failed: {exc}", file=sys.stderr)
        return reached

    links = _internal_links(page, base)
    for step in range(depth):
        if not links:
            break
        # Reading time before the next click. Short by real standards because
        # the whole run is compressed; the timestamp remap is what puts these
        # sessions back onto a plausible clock.
        time.sleep(rng.uniform(0.2, 1.2) / max(pace, 0.001))
        target = rng.choice(links)
        try:
            page.goto(target, wait_until="load", timeout=30_000)
            reached += 1
        except Exception as exc:  # noqa: BLE001
            print(f"    navigation to {target} failed: {exc}",
                  file=sys.stderr)
            continue

        # Going back is a real thing browsers do, and it is interesting here
        # precisely because it usually produces no requests at all.
        if step and rng.random() < 0.25:
            try:
                page.go_back(wait_until="load", timeout=15_000)
            except Exception:  # noqa: BLE001
                pass

        found = _internal_links(page, base)
        if found:
            links = found
    return reached


def run(personas, *, seed, pace, headless=True):
    """Drive every persona through its visits. Returns requests reached."""
    if sync_playwright is None:
        raise SystemExit(
            "playwright is not installed; browser.py runs in its own "
            "container, not on the host")

    rng = random.Random(seed)
    reached = {}

    with sync_playwright() as play:
        # --no-sandbox because the image runs as root, which Chromium's
        # sandbox refuses. The container is the isolation boundary here.
        browser = play.chromium.launch(
            headless=headless,
            args=["--no-sandbox", "--disable-dev-shm-usage"])
        try:
            for persona in personas:
                base = target_for(persona)
                agent = _agent_for(persona, browser)
                landed = 0
                print(f"==> {persona.name} -> {base} as {persona.address}",
                      flush=True)

                for visit in range(persona.sessions):
                    # A fresh context per visit is a fresh cache and a fresh
                    # cookie jar -- a new visitor. The returning persona is
                    # the exception and keeps one, which is what makes its
                    # later visits produce conditional requests.
                    keep = persona.name.endswith("returning") and visit
                    if not keep or visit == 0:
                        context = browser.new_context(
                            viewport={"width": persona.viewport[0],
                                      "height": persona.viewport[1]},
                            user_agent=agent,
                            locale=persona.locale,
                            is_mobile=persona.mobile,
                            has_touch=persona.mobile,
                            ignore_https_errors=True)
                    page = context.new_page()
                    landed += _browse(
                        page, base, rng,
                        rng.randint(*persona.depth), pace)
                    page.close()
                    if not (persona.name.endswith("returning")
                            and visit < persona.sessions - 1):
                        context.close()

                reached[persona.name] = landed
                print(f"    {landed} page loads", flush=True)
        finally:
            browser.close()

    return reached


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--pace", type=float, default=1.0,
                        help="divide every reading pause by this")
    parser.add_argument("--personas", default=None,
                        help="comma-separated names; default is all of them")
    args = parser.parse_args(argv)

    wanted = BROWSER_PERSONAS
    if args.personas:
        names = {n.strip() for n in args.personas.split(",") if n.strip()}
        wanted = tuple(p for p in BROWSER_PERSONAS if p.name in names)
        unknown = names - {p.name for p in BROWSER_PERSONAS}
        if unknown:
            raise SystemExit(f"unknown persona(s): {', '.join(sorted(unknown))}")

    reached = run(wanted, seed=args.seed, pace=args.pace)

    # Refuse to look successful having done nothing. The same rule the attack
    # runner and the tool runs are held to: a source that reached the server
    # zero times must not be recorded as a source that ran.
    if not any(reached.values()):
        raise SystemExit(
            "no browser persona completed a single page load; recording this "
            "as browser traffic would put sessions in the dataset that never "
            "happened")
    print(json.dumps(reached))
    return 0


if __name__ == "__main__":
    sys.exit(main())
