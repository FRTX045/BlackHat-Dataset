"""Phase B placeholder traffic driver.

Ten requests with a fixed shape, issued sequentially, to prove the labelling
machinery end to end. Task 15 replaces this with the persona-driven async
driver; what it must not change is the two properties this one already has.

The driver is a **trusted proxy** as far as Apache is concerned: it declares
each request's client address in X-Forwarded-For, and 203.0.113.4 is named in
RemoteIPTrustedProxy. It also mints its own request id, so its traffic needs no
tag proxy.

It states its own categories and episode ids rather than letting the join
derive them, because unlike the proxy it knows what it meant. That makes
episode contiguity its responsibility: ids are assigned in driver order, not
log order, so **one client's sessions must never run concurrently**. Two
overlapping sessions from one address would interleave in the log and the
validator would reject the result -- correctly, and after the run.

Stdlib only, by project rule.
"""

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from shared.truth.ids import new_request_id  # noqa: E402

UPSTREAM = "http://203.0.113.2"

ACTOR = "driver"


class Step(NamedTuple):
    client_ip: str
    method: str
    path: str
    category: str
    instance_id: str


#: (client address, [(method, path, category)]). Each client appears once and
#: its requests run to completion before the next client starts.
_SESSIONS = (
    ("203.0.113.50", (
        ("GET", "/", "browsing"),
        ("GET", "/assets/css/site.css", "static_asset"),
        ("GET", "/favicon.ico", "static_asset"),
        ("GET", "/no-such-page", "browsing"),
        ("GET", "/", "browsing"),
    )),
    # A CGNAT address, so the first end-to-end run exercises the range the
    # mobile personas will use rather than only the easy one.
    ("100.64.3.7", (
        ("GET", "/", "browsing"),
        ("GET", "/assets/css/site.css", "static_asset"),
        ("HEAD", "/", "browsing"),
    )),
    ("198.51.100.20", (
        ("GET", "/robots.txt", "crawling"),
        ("GET", "/", "crawling"),
    )),
)


def plan_requests():
    """Yield the Steps this driver will issue, in order.

    Pure, so the plan can be checked against the validator's rules without a
    server: a plan that cannot produce a valid truth file should fail a test,
    not a build.
    """
    for client_ip, steps in _SESSIONS:
        episode = 0
        current = None
        for method, path, category in steps:
            if category != current:
                episode += 1
                current = category
            yield Step(client_ip=client_ip, method=method, path=path,
                       category=category,
                       instance_id=f"{client_ip}#{episode}")


def run(ledger_path, base_url=UPSTREAM):
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    issued = 0
    with open(ledger_path, "a", encoding="utf-8") as fh:
        for step in plan_requests():
            request_id = new_request_id()
            request = urllib.request.Request(
                base_url + step.path, method=step.method)
            request.add_header("X-Forwarded-For", step.client_ip)
            request.add_header("X-Request-Id", request_id)
            request.add_header("User-Agent", "logforge-driver/0 (phase-b)")

            try:
                urllib.request.urlopen(request, timeout=10).read()
            except urllib.error.HTTPError:
                # A 404 is a perfectly good log line and a deliberate part of
                # the plan. Only a failure to reach the server at all matters.
                pass

            # Written after the request, so the ledger never claims a label for
            # a request that was never made.
            fh.write(json.dumps({
                "request_id": request_id,
                "client_ip": step.client_ip,
                "actor": ACTOR,
                "ts": datetime.now(timezone.utc).isoformat(),
                "method": step.method,
                "path": step.path,
                "category": step.category,
                "instance_id": step.instance_id,
            }, separators=(",", ":")) + "\n")
            fh.flush()
            issued += 1
    return issued


def main(argv=None):
    parser = argparse.ArgumentParser(description="Phase B placeholder driver")
    parser.add_argument("--ledger", required=True, type=Path)
    parser.add_argument("--base-url", default=UPSTREAM)
    args = parser.parse_args(argv)
    print(f"issued {run(args.ledger, args.base_url)} requests")


if __name__ == "__main__":
    main()
