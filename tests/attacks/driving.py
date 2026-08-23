"""Driving a playbook or a campaign from a script of responses.

A playbook is a generator: it yields a step and is handed back what that step
returned, so it can decide what to send next. Tests drive it with responses
they write themselves, which is what makes the branching checkable without a
server -- and what lets the determinism tests still compare two expansions
across processes now that no full expansion exists until something answers.

Not a test itself, so it carries no assertions. Kept out of the test modules
because both of them need it and a copy in each would drift.
"""


import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]
                       / "projects" / "apache-shopfront" / "attacks"))

from playbooks import Outcome  # noqa: E402

#: Every success marker in `app/VULNERABILITIES.md` at once. No page the lab
#: could serve carries all of these; it is the shortest way to ask what an
#: operator would do if everything it tried landed.
_MARKERS = ("1 result(s) for <q></q> uid=0(root) root:x:0:root Fetched "
            "OK: Order #2 62674 agatha")


def nothing_works(step):
    """The application holds against everything.

    Not a 500 and not silence: a plain miss, which is what most of a real
    campaign gets. Every playbook treats an answer it does not recognise as a
    failure, so this produces the fullest expansion a campaign has -- every
    play it is willing to try without having earned anything.
    """
    return Outcome(404, "", 0.01)


def everything_works(step):
    """The application folds at every turn.

    Has to be a function rather than one Outcome: `/login` signals success by
    redirecting, so the response that satisfies the sign-in is the one status
    that would fail every other check.
    """
    if step.method == "POST" and step.path == "/login":
        return Outcome(302, "", 0.05)
    return Outcome(200, _MARKERS, 1.4)


def drive(plan, respond):
    """Run `plan` to the end, answering each step with `respond(step)`.

    Returns the steps it issued and the facts it finished holding.
    """
    steps, reply = [], None
    while True:
        try:
            step = plan.send(reply)
        except StopIteration as stop:
            return steps, stop.value or frozenset()
        steps.append(step)
        reply = respond(step)
