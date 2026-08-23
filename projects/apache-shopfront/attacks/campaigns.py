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
import zlib
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

from playbooks import (PLAYBOOKS, AttackStep,  # noqa: E402
                       operator_style)


class Play(NamedTuple):
    """One line of attack in an operator's repertoire, and what it presupposes.

    `requires` is the whole cross-phase model. An operator does not extract
    through an injection it never confirmed, and does not attack an admin
    endpoint it never found answering -- so a later phase is reached only when
    an earlier one earned it. What a phase teaches is not declared here; the
    playbook reports that itself, from what it saw, which keeps the two from
    drifting apart.
    """

    play: str
    requires: frozenset = frozenset()


class Campaign(NamedTuple):
    name: str
    #: Which address pool the attacker draws from.
    role: str
    #: What this operator came for. Recorded so the manifest can say what each
    #: one was after, rather than leaving a consumer to infer it from paths.
    objective: str
    #: The plays it knows, in the order it would prefer to try them. Which of
    #: them actually run depends on what the application gives up.
    repertoire: tuple
    #: What we expect this campaign to achieve. A **prediction**, not a fact:
    #: the run either bears it out or does not, and the build records which.
    #: Declaring the outcome and then labelling traffic by the declaration is
    #: how a dataset ends up asserting exploitation that never happened.
    expects: bool = False
    #: Seconds the operator waits between phases. Long, because they are
    #: reading what came back and deciding what to do next.
    phase_gap: float = 45.0

    @property
    def phases(self):
        """Every play it might run, in preference order."""
        return tuple(p.play for p in self.repertoire)


#: What an operator can come to know during a run. A play is unlocked by these
#: and nothing else, so the vocabulary is deliberately small and concrete --
#: every one of them corresponds to something the operator can actually read in
#: a response, documented in `app/VULNERABILITIES.md`.
#:
#:   session          signed in as a customer
#:   sqli_confirmed   the search endpoint takes injection
#:   admin_reachable  an /admin/ path answered instead of refusing
#:   upload_accepted  the avatar upload took a file it should not have
#:   locked_out       the login started answering 429
#:
#: Plus the payoffs, which unlock nothing further and exist so the build can
#: report what a run achieved: data, shell, rce, file_read, idor_confirmed,
#: ssrf_confirmed, reflected.

#: The facts that mean an operator got what it came for. Everything else a
#: run can learn is a step along the way or a door closing: `session` and
#: `admin_reachable` are progress, `locked_out` is the opposite, and
#: `found_path` is a bot noting that a 404 was not a 404.
#:
#: This is what `expects` is a prediction about, so that "achieved something"
#: and "succeeded" do not get quietly conflated -- a campaign that ends with
#: nothing but `locked_out` did not succeed at anything.
PAYOFFS = frozenset({
    "data", "shell", "rce", "file_read", "idor_confirmed", "ssrf_confirmed",
    # A session the operator worked out rather than one it was handed. `session`
    # is deliberately not here: signing in with a password the playbook already
    # had is a step on the way, not an achievement.
    "credentials",
})


def succeeded(facts):
    """Did a run get what its operator came for?"""
    return bool(PAYOFFS & frozenset(facts))


def achievements(facts):
    """What a run got, without the operator's working notes.

    A phase may hand the next one a value as well as a fact -- which comment
    marker parsed, say. That is the operator remembering, not something it
    came away with, and publishing it in the manifest beside `shell` and
    `data` would read as though it were.
    """
    return sorted(f for f in facts if "=" not in f)


CAMPAIGNS = (
    Campaign(
        name="patient_operator",
        role="datacenter",
        objective="data",
        repertoire=(
            Play("recon"),
            Play("directory_enumeration"),
            Play("sqli_probing"),
            # Only worth doing once the search endpoint has actually answered
            # an injection. Extracting first and confirming afterwards is not
            # a thing an operator does.
            Play("sqli_extraction", requires=frozenset({"sqli_confirmed"})),
            Play("idor_walk"),
        ),
        expects=True),
    Campaign(
        name="webshell_operator",
        role="datacenter",
        objective="shell",
        repertoire=(
            Play("recon"),
            Play("forced_browsing"),
            Play("upload_webshell"),
        ),
        expects=True),
    Campaign(
        name="blind_injector",
        role="cloud",
        objective="rce",
        repertoire=(
            Play("sqli_time_based"),
            Play("path_traversal"),
            # /admin/ping and /admin/template carry no role check while
            # /admin/users and /admin/orders do. Which is which is something
            # this operator has to find out before it can use it.
            Play("forced_browsing"),
            Play("command_injection",
                 requires=frozenset({"admin_reachable"})),
            Play("ssti", requires=frozenset({"admin_reachable"})),
        ),
        expects=True),
    Campaign(
        name="metadata_hunter",
        role="cloud",
        objective="ssrf",
        repertoire=(
            Play("recon"),
            Play("forced_browsing"),
            Play("ssrf", requires=frozenset({"admin_reachable"})),
        ),
        expects=True),
    Campaign(
        name="credential_hunter",
        role="datacenter",
        objective="credentials",
        # The stuffing list carries one pair that works, which is the whole
        # reason credential stuffing works in reality. So we expect this one
        # to get in -- unless the brute force locks that account first, which
        # it sometimes does. The run decides, not this line.
        repertoire=(
            Play("recon"),
            Play("brute_force"),
            Play("credential_stuffing"),
            # A lockout is what teaches this. Brute force trips the counter in
            # five tries; spraying stays under it by never asking one account
            # twice in a row. The failure is the unlock.
            Play("password_spray", requires=frozenset({"locked_out"})),
        ),
        expects=True),
    Campaign(
        name="fruitless_prober",
        role="cloud",
        objective="anything at all",
        # An hour of work against endpoints that all hold. No exploitation, no
        # data, nothing taken. This is what most attack traffic looks like.
        repertoire=(
            Play("recon"),
            Play("directory_enumeration"),
            Play("verb_tampering"),
            Play("session_tampering"),
            Play("xss"),
        ),
        expects=False,
        phase_gap=70.0),

    # ---------------------------------------------------------------------
    # Operators that never recon.
    #
    # Six of the campaigns above are patient people working an application
    # they have decided to attack. That is the interesting case and it is not
    # the common one: most of what arrives at a small shop is a list, tried
    # fast, by something that never looked at the site first.
    # ---------------------------------------------------------------------
    Campaign(
        name="cms_bot",
        role="cloud",
        objective="a CMS that is not here",
        repertoire=(Play("cms_probe"),),
        expects=False,
        phase_gap=0.0),
    Campaign(
        name="cve_sweeper",
        role="cloud",
        objective="anything on the list",
        repertoire=(Play("cve_sweep"),),
        expects=False,
        phase_gap=0.0),
    Campaign(
        name="greedy_scraper",
        role="datacenter",
        # Nothing it does is an attack. It is here because the line between
        # a rude crawler and a hostile one is where false positives live, and
        # a dataset with only clear-cut cases does not test that line.
        objective="the catalogue",
        repertoire=(Play("aggressive_scrape"),),
        expects=False,
        phase_gap=0.0),
    Campaign(
        name="api_abuser",
        role="datacenter",
        objective="whatever the API gives up",
        repertoire=(Play("api_abuse"),),
        expects=False,
        phase_gap=0.0),
)

#: Ordinary requests an attacker makes between phases, because they are also
#: just looking at the site. Kept deliberately dull, and deliberately wide:
#: with four paths every campaign in every dataset browsed the same four
#: pages, which made the one varying part of the attacker side a tell of its
#: own. Every path here is one the application really serves.
_BROWSING = (
    ("GET", "/"),
    ("GET", "/about"),
    ("GET", "/contact"),
    ("GET", "/cart"),
    ("GET", "/c/fasteners"),
    ("GET", "/c/power-tools"),
    ("GET", "/c/electrical"),
    ("GET", "/c/lighting"),
    ("GET", "/c/hand-tools"),
    ("GET", "/c/kitchen"),
    ("GET", "/c/decorating"),
    ("GET", "/c/safety"),
    ("GET", "/c/garden"),
    ("GET", "/c/storage"),
    ("GET", "/p/3"),
    ("GET", "/p/8"),
    ("GET", "/p/17"),
    ("GET", "/p/24"),
    ("GET", "/search?q=brass"),
    ("GET", "/search?q=hinge"),
    ("GET", "/search?q=drill"),
    ("GET", "/search?q=socket"),
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


def campaign_seed(name, seed):
    """Derive one campaign's rng seed from the scenario seed and its name.

    `zlib.crc32` rather than the builtin `hash`: str hashing is salted per
    process unless PYTHONHASHSEED is fixed, and nothing here fixes it. A
    derivation built on it gives every build a different set of interludes
    while passing any determinism test that stays inside one interpreter --
    which is precisely what happened, and why the check for this one spawns
    subprocesses.
    """
    return seed ^ (zlib.crc32(name.encode("utf-8")) & 0xFFFF)


def campaign_plan(campaign, rng):
    """Work a campaign, letting each phase read the answers to its own requests.

    A generator rather than a list: what the operator sends next depends on
    what came back, so there is no full expansion until something answers, and
    which phases run at all depends on what the earlier ones learned.

    Returns everything the operator finished knowing, which is what the build
    reports as the run's achievement.
    """
    # Drawn once, before anything is sent, and handed to every phase. Two
    # operators reach for different syntax; neither changes their mind halfway
    # through their own campaign.
    style = operator_style(rng)
    known, ran = set(), 0
    for entry in campaign.repertoire:
        if not entry.requires <= known:
            # Nothing it learned justifies trying this. A real operator does
            # not work through a checklist regardless of what came back, and a
            # dataset where they do teaches a detector the checklist.
            continue
        if ran:
            for step in _interlude(rng, ran):
                yield step
        ran += 1

        # `known` as well as `style`: a later phase uses the syntax an
        # earlier one settled on. Re-trying a marker the operator just
        # watched fail is the sort of thing this work exists to remove.
        play = PLAYBOOKS[entry.play](rng, style, frozenset(known))
        reply, first = None, True
        while True:
            try:
                step = play.send(reply)
            except StopIteration as stop:
                known |= (stop.value or frozenset())
                break
            if first:
                # The first request of a phase carries the operator's pause
                # for thought after the last one.
                step = step._replace(think=step.think + campaign.phase_gap)
                first = False
            # Straight back to the phase that asked for it. Anything else --
            # a response to somebody else's request, or an aggregate over the
            # run -- would make one campaign's branch depend on another
            # campaign's effects, and two builds of one seed would diverge.
            reply = yield step
    return frozenset(known)


def by_name(name):
    for campaign in CAMPAIGNS:
        if campaign.name == name:
            return campaign
    raise KeyError(f"no campaign called {name!r}")
