"""Campaigns: one attacker, one address, a story told over time.

A dataset of isolated attack bursts teaches a detector to spot bursts. Real
intrusions have a shape -- look around, map the application, probe, get in,
take something, come back later -- and the interesting question for an analyst
is whether they can follow that shape across hours of unrelated traffic.

Three things here exist because synthetic datasets usually lack them:

**Ordinary browsing between phases.** Attackers look at the site like anyone
else: they read the product pages, they use the search box for real. An
attacker whose every request is hostile is trivially separable and nothing like
the real thing.

**A campaign that fails.** `fruitless_prober` spends its whole run on hardened
endpoints and leaves with nothing. That case is the majority of real attack
traffic and is almost absent from published datasets, which are usually built
by recording successful exercises.

**Attacks that overlap normal traffic in time.** The build runs campaigns
concurrently with the driver, not before or after it. An attack against an
otherwise idle server is separable by timestamp alone.

Stdlib only.
"""

import sys
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

from playbooks import PLAYBOOKS, AttackStep  # noqa: E402


class Campaign(NamedTuple):
    name: str
    #: Which address pool the attacker draws from.
    role: str
    #: Playbook names, in the order the operator works through them.
    phases: tuple
    #: Whether this campaign is expected to get anything. Recorded so the
    #: dataset README can say how many did and did not, rather than leaving a
    #: consumer to infer it.
    succeeds: bool
    #: Seconds the operator waits between phases. Long, because they are
    #: reading what came back and deciding what to do next.
    phase_gap: float = 45.0


CAMPAIGNS = (
    Campaign(
        name="patient_operator",
        role="datacenter",
        phases=("recon", "directory_enumeration", "sqli_probing",
                "sqli_extraction", "idor_walk"),
        succeeds=True),
    Campaign(
        name="webshell_operator",
        role="datacenter",
        phases=("recon", "forced_browsing", "upload_webshell"),
        succeeds=True),
    Campaign(
        name="blind_injector",
        role="cloud",
        phases=("sqli_time_based", "path_traversal", "command_injection",
                "ssti"),
        succeeds=True),
    Campaign(
        name="metadata_hunter",
        role="cloud",
        phases=("recon", "forced_browsing", "ssrf"),
        succeeds=True),
    Campaign(
        name="credential_hunter",
        role="datacenter",
        # Both playbooks run against the hardened login, which locks out after
        # five failures. It gets 429s and nothing else.
        phases=("recon", "brute_force", "credential_stuffing"),
        succeeds=False),
    Campaign(
        name="fruitless_prober",
        role="cloud",
        # An hour of work against endpoints that all hold. No exploitation, no
        # data, nothing taken. This is what most attack traffic looks like.
        phases=("recon", "directory_enumeration", "verb_tampering",
                "session_tampering", "xss"),
        succeeds=False,
        phase_gap=70.0),
)

#: Ordinary requests an attacker makes between phases, because they are also
#: just looking at the site. Kept deliberately dull.
_BROWSING = (
    ("GET", "/"),
    ("GET", "/about"),
    ("GET", "/search?q=brass"),
    ("GET", "/contact"),
)


def _interlude(rng, index):
    """A short run of ordinary browsing between two attack phases.

    Its activity name carries the index so it never collides with an earlier
    interlude. Episode groups must be contiguous per client, and reusing one
    activity name would make the second run look like a continuation of the
    first with a different phase wedged in between.
    """
    picks = rng.sample(_BROWSING, rng.randint(1, 3))
    return [AttackStep(method, path, "browsing", f"lull-{index}",
                       rng.uniform(4.0, 12.0),
                       note="looking at the site like a customer")
            for method, path in picks]


def campaign_steps(campaign, rng):
    """Expand a campaign into the full ordered list of steps it will issue."""
    steps = []
    for index, phase in enumerate(campaign.phases):
        if index:
            steps.extend(_interlude(rng, index))
        phase_steps = PLAYBOOKS[phase]()
        # The first request of a phase carries the operator's pause for
        # thought after the last one.
        if phase_steps:
            head = phase_steps[0]
            phase_steps = [head._replace(think=head.think + campaign.phase_gap)]
            phase_steps += PLAYBOOKS[phase]()[1:]
        steps.extend(phase_steps)
    return steps


def by_name(name):
    for campaign in CAMPAIGNS:
        if campaign.name == name:
            return campaign
    raise KeyError(f"no campaign called {name!r}")
