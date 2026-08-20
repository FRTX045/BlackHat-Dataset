"""Execute a campaign against the lab, at a human pace, and record what it did.

The attacker container is deliberately **not** in `RemoteIPTrustedProxy`, so it
cannot declare an address and Apache logs the one it is really connecting from.
That is what we want: a tool must not be able to choose what appears in `%h`.

It can still stamp `X-Request-Id`, because Apache reads the header regardless of
whether `mod_remoteip` trusts the sender -- measured in
`tests/server/test_apache_logging.py`. So hand-written attacks get the same
per-line exactness as driver traffic without needing the tag proxy, and the
ledger records the address the socket actually used rather than one we assumed.

Everything here targets the lab's own application. There is no route off the
three lab networks from this container.

Stdlib only, so the attacker image needs nothing installed to run it.
"""

import argparse
import http.client
import json
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/opt/logforge")
sys.path.insert(0, str(Path(__file__).resolve().parent))

from campaigns import (by_name, campaign_seed,  # noqa: E402
                       campaign_steps)
from playbooks import WEBSHELL_BODY  # noqa: E402
from shared.truth.ids import new_request_id  # noqa: E402

#: Resolved by Docker's DNS to whichever of the server's three addresses is on
#: the network this attacker is attached to.
#:
#: Not a literal address. Attackers sit on lab_dc and lab_cloud; Docker keeps
#: bridges isolated from one another, so a hardcoded 203.0.113.2 is
#: unreachable from either and every request times out. That mistake produced
#: 170 consecutive failures that looked like a completed campaign, which is
#: why connect_or_die below refuses to continue past the first one.
HOST, PORT = "web", 80
ACTOR_PREFIX = "attacker"

#: What the operator's client announces itself as. Deliberately a plain, dated
#: browser string rather than a scanner banner: hand-written attacks should not
#: be separable from ordinary traffic by user agent alone.
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

_BOUNDARY = "----LogForgeBoundary7f3a1c2e"


def _multipart(filename):
    """Build a file upload body by hand, so the filename survives verbatim."""
    body = (
        f"--{_BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="avatar"; filename="{filename}"\r\n'
        f"Content-Type: image/jpeg\r\n\r\n"
        f"{WEBSHELL_BODY}\r\n"
        f"--{_BOUNDARY}--\r\n"
    )
    return body, f"multipart/form-data; boundary={_BOUNDARY}"


class Operator:
    """One attacker: one connection source, one cookie jar, one ledger."""

    def __init__(self, campaign, ledger, pace, rng):
        self.campaign = campaign
        self.ledger = ledger
        self.pace = max(pace, 1.0)
        self.rng = rng
        self.cookies = {}
        self.source_ip = None
        self.issued = 0
        #: False until one request has actually reached the server. Until then
        #: a connection error is a misconfiguration, not an attack outcome.
        self.reached = False
        self.failures = 0

    def _cookie_header(self):
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def _remember(self, response):
        for name, value in response.getheaders():
            if name.lower() == "set-cookie":
                pair = value.split(";", 1)[0]
                if "=" in pair:
                    key, _, val = pair.partition("=")
                    self.cookies[key.strip()] = val.strip()

    def send(self, step):
        request_id = new_request_id()
        headers = {"Host": "shop.test",
                   "User-Agent": USER_AGENT,
                   "X-Request-Id": request_id,
                   "Connection": "close"}

        body = step.body
        if body and body.startswith("@upload:"):
            body, content_type = _multipart(body.split(":", 1)[1])
            headers["Content-Type"] = content_type
        elif step.method == "POST":
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        for name, value in step.headers:
            headers[name] = value
        if self.cookies and "Cookie" not in headers:
            headers["Cookie"] = self._cookie_header()

        connection = http.client.HTTPConnection(HOST, PORT, timeout=20)
        try:
            connection.connect()
            # Authoritative: this is the address Apache will log, taken from
            # the socket rather than from configuration that could drift.
            if self.source_ip is None:
                self.source_ip = connection.sock.getsockname()[0]

            connection.request(step.method, step.path, body=body,
                               headers=headers)
            response = connection.getresponse()
            self._remember(response)
            response.read()
            status = response.status
        except OSError as exc:
            # A request that never reached the server is not an attack that
            # failed -- it is a broken run, and it must not be recorded as
            # though it happened. If nothing has ever succeeded, the target is
            # wrong and continuing would write a whole ledger of fiction.
            if self.reached is False:
                raise SystemExit(
                    f"cannot reach {HOST}:{PORT} from this container: {exc}. "
                    f"Attackers are on lab_dc and lab_cloud; the server must "
                    f"be addressed by service name, not by its lab_res address."
                ) from exc
            self.failures += 1
            status = None
        else:
            self.reached = True
        finally:
            connection.close()

        self.ledger.write(json.dumps({
            "request_id": request_id,
            "client_ip": self.source_ip,
            "actor": f"{ACTOR_PREFIX}:{self.campaign.name}",
            "ts": datetime.now(timezone.utc).isoformat(),
            "method": step.method,
            "path": step.path,
            "category": step.category,
            # Episodes are stamped in a second pass, once the source address
            # the socket chose is known. The activity is what groups them --
            # not the category, because two different phases can share one.
            "instance_id": None,
            "activity": step.activity,
            "campaign": self.campaign.name,
            "succeeds": self.campaign.succeeds,
            "note": step.note,
            "status": status,
        }, separators=(",", ":")) + "\n")
        self.ledger.flush()
        self.issued += 1
        return status


def campaign_rng(name, seed):
    """The rng a campaign run uses, which is to say the one its interludes use.

    Seeded through `campaign_seed` rather than from `hash(name)` directly: str
    hashing is salted per process, so the old derivation quietly gave every
    build a different plan from the same scenario seed.
    """
    return random.Random(campaign_seed(name, seed))


def run_campaign(name, ledger_path, pace, seed):
    campaign = by_name(name)
    rng = campaign_rng(name, seed)
    steps = campaign_steps(campaign, rng)

    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    with open(ledger_path, "w", encoding="utf-8") as fh:
        operator = Operator(campaign, fh, pace, rng)
        for step in steps:
            # The pauses are what make this look like a person rather than a
            # script, divided by the pace factor so a small tier does not take
            # the hour the timings describe.
            time.sleep(min(step.think / operator.pace, 5.0))
            operator.send(step)

    # Episodes are stamped in a second pass. The source address comes from the
    # socket rather than from configuration, so it is not known until the first
    # request has gone out -- and rewriting a few hundred lines is cheaper than
    # guessing the address up front and being wrong about it.
    _stamp_episodes(ledger_path)
    print(f"{name}: issued {operator.issued} requests from "
          f"{operator.source_ip} ({operator.failures} did not complete)")
    return operator.issued


def _stamp_episodes(path):
    """Assign contiguous per-client episode ids to a finished ledger.

    Grouped by activity, in the order the requests were issued -- which is the
    order they reach the log, because one operator makes one request at a time.
    """
    records = [json.loads(line) for line in
               path.read_text(encoding="utf-8").splitlines() if line.strip()]
    sequence = 0
    current = None
    out = []
    for record in records:
        if record["activity"] != current:
            sequence += 1
            current = record["activity"]
        record["instance_id"] = f"{record['client_ip']}#{sequence}"
        out.append(json.dumps(record, separators=(",", ":")))
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign")
    parser.add_argument("--ledger", required=True, type=Path)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--pace", type=float, default=20.0,
                        help="divide every pause by this; 1.0 is real time")
    args = parser.parse_args(argv)
    run_campaign(args.campaign, args.ledger, args.pace, args.seed)


if __name__ == "__main__":
    main()
