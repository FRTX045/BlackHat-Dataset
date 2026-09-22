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

from campaigns import (by_name, campaign_plan,  # noqa: E402
                       campaign_seed)
from playbooks import WEBSHELL_BODY, Outcome  # noqa: E402
from shared.clients.useragents import CORPUS  # noqa: E402
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

#: Which class each agent in the shared corpus belongs to, so an operator can
#: behave like the client it claims to be.
_AGENT_CLASS = {agent: cls for agent, cls, _ in CORPUS}

#: The mix of clients hand-written attacks arrive through, and it is not the
#: mix ordinary traffic arrives through. The corpus weights describe the open
#: web, where current Chrome is most of everything; drawing attackers on those
#: weights gave a whole build five browser operators and no library at all.
#: `useragents.py` states the real shape beside the `attacker` persona: real
#: opportunistic work is dominated by libraries and stale browser strings.
_ATTACKER_CLIENTS = (("library", 60), ("desktop_chrome", 27),
                     ("desktop_firefox", 13))

_BY_CLASS = {
    name: ([ua for ua, cls, _ in CORPUS if cls == name],
           [w for _, cls, w in CORPUS if cls == name])
    for name, _ in _ATTACKER_CLIENTS}

#: The site these attacks are aimed at, for the Referer of a client that sends
#: one. Matches the Host header, because a browser's referrer is a real URL on
#: the site the reader was already looking at. Imported rather than repeated:
#: one server with two names in one log is the defect this came from.
from playbooks import SITE  # noqa: E402,F401


def operator_agent(campaign_name, seed):
    """The client one operator runs its whole campaign through.

    Drawn from the corpus the ordinary traffic uses, through the `attacker`
    persona -- plain browser strings and libraries, never a scanner banner.
    Six unrelated operators presenting one hardcoded string is not something a
    real log contains, and a banner that names a tool would make hand-written
    attacks separable by user agent alone, which is the one thing the original
    hardcoded string was chosen to avoid.

    Returns the agent and whether it sends a `Referer`. That follows from what
    the client *is*: someone proxying a real browser leaves a click chain
    behind them and someone driving a library does not. It is one of the few
    things in an access log that tells the two apart, and answering it the
    same way for everybody throws the distinction away.
    """
    rng = random.Random(campaign_seed(campaign_name, seed))
    kind = rng.choices([name for name, _ in _ATTACKER_CLIENTS],
                       weights=[w for _, w in _ATTACKER_CLIENTS], k=1)[0]
    agents, weights = _BY_CLASS[kind]
    agent = rng.choices(agents, weights=weights, k=1)[0]
    return agent, kind != "library"

_BOUNDARY = "----LogForgeBoundary7f3a1c2e"

#: How much of a response the operator keeps to decide what to send next.
#: Every success marker in `app/VULNERABILITIES.md` is near the top of the
#: page -- an injected username in the first product card, `root:` on the
#: first line of /etc/passwd, `uid=` inside the first <pre>. Holding whole
#: pages for a campaign's worth of requests would buy none of them.
#:
#: 16K rather than 8K, and the difference was measured rather than guessed: an
#: ordinary search page is 8150 bytes uncompressed, which left 42 bytes of
#: headroom under an 8K cap. The marker sat inside it, but a slightly wordier
#: page would have truncated the evidence and the operator would have read its
#: own success as a failure.
BODY_PREFIX = 16384


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

    def __init__(self, campaign, ledger, pace, rng, agent=None,
                 sends_referer=False):
        self.campaign = campaign
        self.ledger = ledger
        self.pace = max(pace, 1.0)
        self.rng = rng
        self.agent = agent or operator_agent(campaign.name, 7)[0]
        self.sends_referer = sends_referer
        #: Where this client was last, for the Referer of the next request.
        #: Only ever a path it actually asked for, so the chain a browser
        #: leaves is one it really walked.
        self.came_from = None
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
                   "User-Agent": self.agent,
                   "X-Request-Id": request_id,
                   "Connection": "close"}
        if self.sends_referer and self.came_from:
            headers["Referer"] = SITE + self.came_from

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

            started = time.monotonic()
            connection.request(step.method, step.path, body=body,
                               headers=headers)
            response = connection.getresponse()
            self._remember(response)
            # Decoded leniently: a traversal that lands reads a system file,
            # not a UTF-8 page, and the operator still has to read what of it
            # came back rather than falling over on it.
            seen = response.read(BODY_PREFIX).decode("utf-8", "replace")
            elapsed = time.monotonic() - started
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
            status, seen, elapsed = None, "", 0.0
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
            # What we predicted this campaign would manage. A prediction and
            # nothing more -- `achieved` below is what the run actually got,
            # stamped once the run is over and the answer is known.
            "expects": self.campaign.expects,
            "objective": self.campaign.objective,
            "achieved": None,
            "note": step.note,
            "status": status,
        }, separators=(",", ":")) + "\n")
        self.ledger.flush()
        self.issued += 1
        self.came_from = step.path
        # Back to the playbook that asked for it. A step's successor is chosen
        # from this and nothing else, which is what keeps one campaign's branch
        # independent of what the others did to the application.
        return Outcome(status, seen, elapsed)


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
    plan = campaign_plan(campaign, rng)

    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    learned = frozenset()
    agent, sends_referer = operator_agent(name, seed)
    with open(ledger_path, "w", encoding="utf-8") as fh:
        operator = Operator(campaign, fh, pace, rng, agent, sends_referer)
        # No list of steps: what the operator sends next depends on what the
        # last request returned, so the plan is walked one answer at a time.
        reply = None
        while True:
            try:
                step = plan.send(reply)
            except StopIteration as stop:
                learned = stop.value or frozenset()
                break
            # The pauses are what make this look like a person rather than a
            # script, divided by the pace factor so a small tier does not take
            # the hour the timings describe.
            time.sleep(min(step.think / operator.pace, 5.0))
            reply = operator.send(step)

    # Episodes are stamped in a second pass. The source address comes from the
    # socket rather than from configuration, so it is not known until the first
    # request has gone out -- and rewriting a few hundred lines is cheaper than
    # guessing the address up front and being wrong about it.
    _stamp_episodes(ledger_path, sorted(learned))
    print(f"{name}: issued {operator.issued} requests from "
          f"{operator.source_ip} ({operator.failures} did not complete); "
          f"expected {'to get somewhere' if campaign.expects else 'nothing'}, "
          f"achieved {', '.join(sorted(learned)) or 'nothing'}")
    return operator.issued


def _stamp_episodes(path, achieved):
    """Assign episode ids, and record what the run turned out to achieve.

    Grouped by activity, in the order the requests were issued -- which is the
    order they reach the log, because one operator makes one request at a time.

    `achieved` is stamped in the same pass because it is not knowable until the
    campaign has finished: whether an operator got anywhere is the outcome of
    the run, not a property of its definition, and writing the definition into
    every line is how a dataset comes to claim exploits that never happened.
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
        record["achieved"] = achieved
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
