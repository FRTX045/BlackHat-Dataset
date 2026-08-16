"""Client address allocation.

Two constraints shape this module, and they pull against each other.

The first is safety: no address in a published dataset may belong to an
identifiable person or company, so every address comes from documentation
space (RFC 5737) or shared address space (RFC 6598) and nowhere else.

The second is realism: a log whose addresses are spread evenly over a small
fixed set is obviously generated. Real traffic has a handful of clients that
appear constantly and a long tail of visitors seen exactly once.

The three documentation /24s hold only 254 addresses each, which is nowhere
near enough tail for a million-line dataset, so the tail is drawn from
100.64.0.0/10 carved into disjoint per-role blocks. Each role therefore has a
small set of recurring heavy clients from its /24 and a wide tail from its
shared-space block. This is recorded in every dataset's Known limitations:
real residential traffic does not originate from carrier-grade NAT space, so
address-based geographic or ASN analysis on this data is meaningless.
"""

import ipaddress
import random

ROLES = ("residential", "mobile", "cloud", "datacenter")

#: Heavy, recurring clients per role -- the visitors a real server sees again
#: and again. Small on purpose.
_HEAVY_NETS = {
    "residential": ipaddress.ip_network("203.0.113.0/24"),
    "cloud": ipaddress.ip_network("198.51.100.0/24"),
    "datacenter": ipaddress.ip_network("192.0.2.0/24"),
    # Mobile has no documentation /24 of its own; it takes a slice of shared
    # space so the four roles stay disjoint.
    "mobile": ipaddress.ip_network("100.127.0.0/24"),
}

#: The long tail per role, disjoint by construction.
_TAIL_NETS = {
    "residential": ipaddress.ip_network("100.64.0.0/12"),
    "mobile": ipaddress.ip_network("100.80.0.0/12"),
    "cloud": ipaddress.ip_network("100.96.0.0/12"),
    "datacenter": ipaddress.ip_network("100.112.0.0/13"),
}

ALLOWED_NETWORKS = (
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("100.64.0.0/10"),
)

#: Share of requests coming from the recurring heavy clients. Tuned so the
#: top-10 share lands in the range real access logs show without collapsing
#: the tail -- see tests/clients/test_ippools.py.
_HEAVY_SHARE = 0.35

#: Number of recurring clients per role.
_HEAVY_COUNT = 24

#: Concentration for the tail's preferential-attachment draw.
#:
#: Minting a fresh address for every non-heavy draw produces a tail that is
#: ~99% one-request visitors, which is as unrealistic as a flat distribution
#: in the other direction -- it means nobody ever came back. Reusing an
#: address with probability proportional to how often it has already been seen
#: gives the power law real logs show: many visitors seen once, a decent
#: middle seen a handful of times, no hard boundary between the tail and the
#: heavy clients. Higher alpha means more distinct clients.
_TAIL_ALPHA = 2000.0


def is_allowed(ip):
    """True if the address is in reserved documentation or shared space."""
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in ALLOWED_NETWORKS)


class ClientPool:
    """Draws client addresses with a realistic heavy-tailed shape.

    Deterministic under a fixed seed: the same seed produces the same
    sequence, which is what makes a build's request sequence reproducible.
    """

    def __init__(self, seed):
        self._rng = random.Random(seed)
        self._heavy = {}
        self._heavy_weights = {}
        self._reserved = set()
        self._reserve_cursor = {}
        # Preferential-attachment state for the tail, per role.
        self._tail_seen = {role: [] for role in ROLES}
        self._tail_counts = {role: [] for role in ROLES}
        self._tail_total = {role: 0 for role in ROLES}
        for role in ROLES:
            net = _HEAVY_NETS[role]
            hosts = list(net.hosts())
            # Take the heavy clients from the top of the range and reserve
            # addresses from the bottom, so a reserved address can never
            # collide with a recurring client.
            self._heavy[role] = [str(h) for h in hosts[-_HEAVY_COUNT:]]
            # Zipf-ish weights: the busiest client is an order of magnitude
            # busier than the twentieth, as in a real log.
            self._heavy_weights[role] = [
                1.0 / (i + 1) for i in range(_HEAVY_COUNT)]
            self._reserve_cursor[role] = 0

    def draw(self, role):
        """Return a client address for the given role."""
        if role not in ROLES:
            raise ValueError(f"unknown role {role!r}; expected one of {ROLES}")
        if self._rng.random() < _HEAVY_SHARE:
            return self._rng.choices(
                self._heavy[role], weights=self._heavy_weights[role], k=1)[0]
        return self._draw_tail(role)

    def _draw_tail(self, role):
        """Preferential attachment: return a visitor, sometimes a returning one.

        With probability alpha/(n+alpha) a previously unseen address is minted;
        otherwise an address already seen is reused, weighted by how often it
        has been seen. That is what puts a genuine middle between the heavy
        clients and the one-request tail.
        """
        total = self._tail_total[role]
        if self._rng.random() < _TAIL_ALPHA / (total + _TAIL_ALPHA):
            net = _TAIL_NETS[role]
            # Skip network and broadcast without materialising the range --
            # these blocks hold millions of addresses.
            offset = self._rng.randrange(1, net.num_addresses - 1)
            address = str(net.network_address + offset)
            self._tail_seen[role].append(address)
            self._tail_counts[role].append(1)
        else:
            index = self._rng.choices(
                range(len(self._tail_seen[role])),
                weights=self._tail_counts[role], k=1)[0]
            address = self._tail_seen[role][index]
            self._tail_counts[role][index] += 1
        self._tail_total[role] += 1
        return address

    def reserve(self, role):
        """Return an address dedicated to one activity and nothing else.

        Tool runs and the malformed-request noise need this: their lines are
        labelled by address plus time window, which is only exact while the
        address belongs to that run alone.
        """
        if role not in ROLES:
            raise ValueError(f"unknown role {role!r}; expected one of {ROLES}")
        hosts = list(_HEAVY_NETS[role].hosts())
        while True:
            index = self._reserve_cursor[role]
            self._reserve_cursor[role] += 1
            if index >= len(hosts) - _HEAVY_COUNT:
                raise RuntimeError(
                    f"exhausted reservable addresses for role {role!r}")
            candidate = str(hosts[index])
            if candidate not in self._reserved:
                self._reserved.add(candidate)
                return candidate
