"""The persona-driven traffic driver.

Executes the session plan against the real Apache, one request at a time per
visitor and many visitors at once. Every request declares its client address in
X-Forwarded-For and carries a unique X-Request-Id, and every request writes a
ledger record saying what it was meant to be. The driver is a trusted proxy as
far as Apache is concerned, which is why 203.0.113.4 is in RemoteIPTrustedProxy.

Three properties are not negotiable:

**One client, one session at a time.** Episode ids are assigned in driver order,
not log order. Two concurrent sessions from one address would interleave in the
log and the validator would reject the result -- correctly, and only after the
run. A per-address lock prevents it.

**Assets are discovered, not scripted.** After fetching an HTML page the driver
requests the subresources that page actually references, the way a browser
does. A list of asset URLs written down in advance would drift from the markup
and would produce cascades that do not match the pages they came from.

**Referer comes from where the visitor actually was.** Internal navigation
carries the previous page as its Referer; only the first request of a visit
carries an external one.

Runs inside a container, so httpx is available here even though the host
entry points are stdlib-only.
"""

import argparse
import asyncio
import json
import random
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import httpx
except ImportError:  # pragma: no cover - the host has no third-party packages
    # httpx lives in the driver image, not on the host. Guarding the import
    # keeps the pure logic below -- episode assignment, asset selection --
    # importable and testable by the ordinary suite, which has to run on a
    # bare python3. Anything that actually issues a request needs the image.
    httpx = None

sys.path.insert(0, "/opt/logforge")

from shared.clients.ippools import ClientPool  # noqa: E402
from shared.clients.personas import (NO_REFERER, PERSONA_IDENTITY,  # noqa: E402
                                     journey)
from shared.clients.useragents import UserAgentPool  # noqa: E402
from shared.timeline.sessions import plan_sessions  # noqa: E402
from shared.truth.ids import new_request_id  # noqa: E402

BASE = "http://203.0.113.2"
SITE = "http://shop.test"
ACTOR = "driver"

#: Subresources referenced by a page. Deliberately literal: this is what a
#: browser would fetch, taken from the markup the server actually returned.
_ASSET = re.compile(
    r'<(?:link[^>]+href|script[^>]+src|img[^>]+src)="(/[^"]+)"', re.IGNORECASE)

_ASSET_SUFFIXES = (".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".webp",
                   ".svg", ".ico", ".woff", ".woff2")

#: How often a cached asset is revalidated rather than used silently. Real
#: browsers revalidate on a mixture of cache headers, reloads and expiry; this
#: is the single knob that stands in for all of it, and it is what puts 304s in
#: the dataset at all.
_REVALIDATE_CHANCE = 0.18


class Ledger:
    """One record per issued request, flushed as it goes."""

    def __init__(self, fh):
        self._fh = fh
        self._lock = asyncio.Lock()

    async def record(self, **fields):
        async with self._lock:
            self._fh.write(json.dumps(fields, separators=(",", ":")) + "\n")
            self._fh.flush()


class Episodes:
    """Per-client episode ids, incremented when the activity changes."""

    def __init__(self):
        self._seq = defaultdict(int)
        self._current = {}

    def id_for(self, client_ip, activity):
        if self._current.get(client_ip) != activity:
            self._seq[client_ip] += 1
            self._current[client_ip] = activity
        return f"{client_ip}#{self._seq[client_ip]}"


class Driver:

    def __init__(self, catalogue, ledger, seed, concurrency):
        self.catalogue = catalogue
        self.ledger = ledger
        self.clients = ClientPool(seed)
        self.agents = UserAgentPool(seed)
        self.episodes = Episodes()
        self.rng = random.Random(seed ^ 0xA5A5)
        self.gate = asyncio.Semaphore(concurrency)
        # One lock per client address: a visitor cannot be in two places at
        # once, and their episode ids would interleave in the log if they were.
        self.per_client = defaultdict(asyncio.Lock)
        self.issued = 0

    async def fetch(self, client, step_path, method, client_ip, agent,
                    category, activity, referer, extra_headers=None):
        request_id = new_request_id()
        headers = {
            "X-Forwarded-For": client_ip,
            "X-Request-Id": request_id,
            "User-Agent": agent,
        }
        if referer:
            headers["Referer"] = referer
        if extra_headers:
            headers.update(extra_headers)

        body = None
        if method == "POST" and step_path == "/api/cart":
            headers["Content-Type"] = "application/json"
            body = json.dumps({"id": self._any_product(), "quantity": 1})
        elif method == "POST" and step_path == "/login":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            user = self.rng.choice(self.catalogue["users"])
            body = f"username={user['username']}&password={user['password']}"

        try:
            response = await client.request(
                method, BASE + step_path, headers=headers, content=body)
        except httpx.HTTPError:  # type: ignore[union-attr]
            # The request was still made and Apache may still have logged it.
            # The ledger records it either way; the join is what decides.
            response = None

        await self.ledger.record(
            request_id=request_id, client_ip=client_ip, actor=ACTOR,
            ts=datetime.now(timezone.utc).isoformat(),
            method=method, path=step_path, category=category,
            instance_id=self.episodes.id_for(client_ip, activity))
        self.issued += 1
        return response

    def _any_product(self):
        category = self.rng.choice(self.catalogue["categories"])
        return self.rng.choice(category["products"])

    async def assets_for(self, client, html, page_path, client_ip, agent,
                         activity, cache):
        """Request the subresources the page references, the way a browser would.

        A browser holds what it already fetched. Refetching the stylesheet on
        every page view is what pushed static assets to 91% of a measured run
        -- far above any real log -- so an asset already seen in this visit is
        either served from cache and never requested at all, or revalidated
        with a conditional GET that comes back 304. Both are what actually
        happens, and the 304s are a response class the dataset otherwise had
        none of.
        """
        wanted = [path for path in _ASSET.findall(html)
                  if path.lower().split("?")[0].endswith(_ASSET_SUFFIXES)]

        for path in wanted[:40]:
            if path in cache:
                if self.rng.random() >= _REVALIDATE_CHANCE:
                    continue          # straight from cache; no request is made
                response = await self.fetch(
                    client, path, "GET", client_ip, agent, "static_asset",
                    activity, SITE + page_path,
                    extra_headers={"If-Modified-Since": cache[path]})
            else:
                response = await self.fetch(
                    client, path, "GET", client_ip, agent, "static_asset",
                    activity, SITE + page_path)

            if response is not None:
                last_modified = response.headers.get("last-modified")
                if last_modified:
                    cache[path] = last_modified

    async def run_session(self, client, session):
        ua_persona, role = PERSONA_IDENTITY[session.persona]
        client_ip = self.clients.draw(role)
        agent = self.agents.for_client(client_ip, ua_persona)

        async with self.per_client[client_ip]:
            steps = journey(session.persona, self.rng, self.catalogue)
            previous = None
            # One browser cache per visit, holding the Last-Modified of every
            # asset already fetched. Reset between visits, which is why a
            # returning client pays for the cascade again.
            cache = {}

            for step in steps:
                path = step.path
                if "{order}" in path:
                    user = self.rng.choice(self.catalogue["users"])
                    if not user["orders"]:
                        continue
                    path = path.replace("{order}",
                                        str(self.rng.choice(user["orders"])))

                if session.persona in NO_REFERER:
                    referer = None
                else:
                    referer = (step.referer if previous is None
                               else SITE + previous)
                async with self.gate:
                    response = await self.fetch(
                        client, path, step.method, client_ip, agent,
                        step.category, step.activity, referer)

                if step.method == "GET":
                    previous = path

                # Only HTML pages have a cascade, and only clients that render
                # them pull it. A scanner and an uptime monitor fetch the
                # document and nothing else; the per-visit cache then decides
                # how much of the cascade a real browser actually requests.
                if (response is not None
                        and session.persona not in NO_REFERER
                        and response.status_code == 200
                        and "text/html" in response.headers.get("content-type", "")):
                    async with self.gate:
                        await self.assets_for(client, response.text, path,
                                              client_ip, agent, step.activity,
                                              cache)


async def main_async(args):
    catalogue = json.loads(Path(args.catalogue).read_text())
    # The scenario's window, never the wall clock.
    #
    # `arrivals.py` thins by a diurnal curve, so planning from
    # `datetime.now()` made the size of the dataset a function of what time
    # the build was started. Two builds of the same scenario at the same seed
    # came out at 75,474 and 13,032 lines -- one ran in the evening peak and
    # the other just after midnight. Both READMEs claimed the seed reproduced
    # the request sequence, and the volume was the part that moved.
    sessions = plan_sessions(
        datetime.fromisoformat(args.start), args.duration, args.rate,
        json.loads(args.personas), args.seed)

    args.ledger.parent.mkdir(parents=True, exist_ok=True)
    with open(args.ledger, "w", encoding="utf-8") as fh:
        ledger = Ledger(fh)
        driver = Driver(catalogue, ledger, args.seed, args.concurrency)

        limits = httpx.Limits(max_connections=args.concurrency * 2,
                              max_keepalive_connections=args.concurrency)
        async with httpx.AsyncClient(timeout=15.0, limits=limits,
                                     follow_redirects=False) as client:
            await asyncio.gather(*(driver.run_session(client, s)
                                   for s in sessions))

    print(f"issued {driver.issued} requests across {len(sessions)} sessions")
    return driver.issued


def main(argv=None):
    parser = argparse.ArgumentParser(description="persona-driven traffic")
    parser.add_argument("--ledger", required=True, type=Path)
    parser.add_argument("--catalogue", required=True, type=Path)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--start", required=True,
                        help="ISO 8601 start of the window to plan across, "
                             "with an offset. Required rather than defaulted "
                             "to now: the arrival model has a diurnal curve, "
                             "so planning from the wall clock made the size "
                             "of the dataset depend on what time the build "
                             "was run.")
    parser.add_argument("--duration", type=float, default=600.0,
                        help="virtual seconds of arrivals to plan")
    parser.add_argument("--rate", type=float, default=0.05,
                        help="session arrivals per virtual second")
    parser.add_argument("--concurrency", type=int, default=48)
    parser.add_argument("--personas", default=json.dumps(
        {"casual": 0.35, "shopper": 0.30, "mobile": 0.15,
         "returning": 0.10, "crawler": 0.07, "monitor": 0.03}))
    args = parser.parse_args(argv)
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
