import ipaddress
import unittest
from collections import Counter

import re
from pathlib import Path

from shared.clients.ippools import (INFRASTRUCTURE_ADDRESSES, ROLES,
                                    ClientPool, infrastructure_named_in,
                                    is_allowed)


class TestAddressSpace(unittest.TestCase):
    def test_every_drawn_address_is_in_a_reserved_range(self):
        # No address in this dataset may belong to an identifiable person or
        # company. Documentation and shared-address space only.
        pool = ClientPool(seed=7)
        for role in ROLES:
            for _ in range(500):
                ip = pool.draw(role)
                self.assertTrue(is_allowed(ip),
                                f"{ip} (role {role}) is outside reserved space")

    def test_is_allowed_rejects_routable_addresses(self):
        for ip in ("8.8.8.8", "1.1.1.1", "93.184.216.34", "172.217.16.14"):
            with self.subTest(ip=ip):
                self.assertFalse(is_allowed(ip))

    def test_is_allowed_accepts_each_reserved_range(self):
        for ip in ("203.0.113.7", "198.51.100.7", "192.0.2.7", "100.64.0.7"):
            with self.subTest(ip=ip):
                self.assertTrue(is_allowed(ip))

    def test_roles_occupy_disjoint_address_space(self):
        # A consumer must be able to tell a scanner from a shopper by address
        # alone, so the roles cannot overlap.
        seen = {}
        pool = ClientPool(seed=7)
        for role in ROLES:
            for _ in range(400):
                ip = pool.draw(role)
                previous = seen.setdefault(ip, role)
                self.assertEqual(previous, role,
                                 f"{ip} was drawn for both {previous} and {role}")


class TestDistributionShape(unittest.TestCase):
    """Real logs have a few heavy clients and a long tail of one-request
    visitors. A flat distribution across a fixed set of addresses is one of the
    clearest tells that a log was generated."""

    def setUp(self):
        pool = ClientPool(seed=11)
        self.draws = [pool.draw("residential") for _ in range(5000)]
        self.counts = Counter(self.draws)

    def test_a_few_clients_carry_a_meaningful_share(self):
        top10 = sum(c for _, c in self.counts.most_common(10))
        share = top10 / len(self.draws)
        self.assertGreater(share, 0.15, f"top-10 share {share:.3f} too flat")
        self.assertLess(share, 0.60, f"top-10 share {share:.3f} too concentrated")

    def test_most_clients_appear_exactly_once(self):
        singletons = sum(1 for c in self.counts.values() if c == 1)
        share = singletons / len(self.counts)
        self.assertGreater(share, 0.50,
                           f"only {share:.3f} of clients are one-request visitors")
        # An all-singleton tail is as unrealistic as a flat distribution: it
        # would mean no visitor ever came back.
        self.assertLess(share, 0.85,
                        f"{share:.3f} of clients are singletons; nobody returns")

    def test_there_is_a_middle_between_the_heavy_clients_and_the_tail(self):
        middle = sum(1 for c in self.counts.values() if 2 <= c <= 9)
        share = middle / len(self.counts)
        self.assertGreater(share, 0.15,
                           f"only {share:.3f} of clients were seen 2-9 times; "
                           f"the distribution is bimodal, not heavy-tailed")

    def test_the_distribution_is_not_uniform(self):
        counts = sorted(self.counts.values(), reverse=True)
        self.assertGreater(counts[0], 5 * counts[len(counts) // 2])


class TestDeterminism(unittest.TestCase):
    def test_same_seed_gives_the_same_sequence(self):
        a = [ClientPool(seed=3).draw("datacenter") for _ in range(1)]
        first = [ClientPool(seed=3).draw("datacenter") for _ in range(20)]
        second = [ClientPool(seed=3).draw("datacenter") for _ in range(20)]
        self.assertEqual(first, second)

    def test_different_seeds_give_different_sequences(self):
        first = [ClientPool(seed=3).draw("cloud") for _ in range(20)]
        second = [ClientPool(seed=4).draw("cloud") for _ in range(20)]
        self.assertNotEqual(first, second)


class TestRoles(unittest.TestCase):
    def test_rejects_an_unknown_role(self):
        with self.assertRaises(ValueError):
            ClientPool(seed=1).draw("nonsense")

    def test_the_four_roles_are_present(self):
        self.assertEqual(set(ROLES),
                         {"residential", "mobile", "cloud", "datacenter"})

    def test_addresses_are_returned_as_strings_not_objects(self):
        ip = ClientPool(seed=1).draw("residential")
        self.assertIsInstance(ip, str)
        ipaddress.ip_address(ip)  # raises if malformed

    def test_reserve_returns_an_address_used_by_nothing_else(self):
        # Tool runs and the malformed-request noise need an address that
        # belongs to that run alone, otherwise the fallback label by address
        # and time window is not exact.
        pool = ClientPool(seed=5)
        reserved = pool.reserve("datacenter")
        drawn = {pool.draw("datacenter") for _ in range(2000)}
        self.assertNotIn(reserved, drawn)

    def test_reserved_addresses_are_unique(self):
        pool = ClientPool(seed=5)
        reserved = [pool.reserve("datacenter") for _ in range(20)]
        self.assertEqual(len(set(reserved)), 20)


if __name__ == "__main__":
    unittest.main()


class TestTheInfrastructureSetMatchesTheLab(unittest.TestCase):
    """`INFRASTRUCTURE_ADDRESSES` is a hand-written list, so pin it.

    Three hand-written copies of this set existed before this test and one of
    them had drifted -- it omitted the browser container's own address, which
    is the machine most likely to leak its identity into the data. A constant
    that describes the lab has to be checked against the lab.
    """

    #: The lab's own plumbing. Every other service in the compose file stands
    #: in for a visitor, and its address is supposed to appear in the data.
    MACHINERY = {"web", "tagproxy", "driver", "browser", "noise"}

    def compose(self):
        text = (Path(__file__).resolve().parents[2] / "projects"
                / "apache-shopfront" / "docker-compose.yml").read_text()
        owner, service = {}, None
        for line in text.splitlines():
            named = re.match(r"^  ([\w-]+):", line)
            if named:
                service = named.group(1)
            address = re.search(r"ipv4_address:\s*(\S+)", line)
            if address:
                owner.setdefault(service, set()).add(address.group(1))
        return owner

    def test_the_compose_file_was_actually_parsed(self):
        # Without this the two tests below pass on an empty parse.
        owner = self.compose()
        self.assertGreater(len(owner), 20, f"only parsed {sorted(owner)}")
        self.assertEqual(self.MACHINERY, self.MACHINERY & set(owner),
                         f"missing from compose: {self.MACHINERY - set(owner)}")

    def test_it_holds_every_address_the_lab_machinery_has(self):
        owner = self.compose()
        expected = {a for s in self.MACHINERY for a in owner[s]}
        self.assertEqual(expected, set(INFRASTRUCTURE_ADDRESSES))

    def test_it_holds_no_address_that_stands_in_for_a_visitor(self):
        # attacker-* and tool-* addresses belong in the data. Listing one here
        # would quietly delete that traffic from every generated dataset.
        owner = self.compose()
        actors = {a for s, addrs in owner.items() if s not in self.MACHINERY
                  for a in addrs}
        self.assertEqual(set(), actors & set(INFRASTRUCTURE_ADDRESSES))


class TestFindingTheLabInText(unittest.TestCase):
    """One matcher for "does this text name a lab container".

    The generator tests and verify.py both ask this question, and they asked it
    with `address in text` -- which is wrong in a way that happened not to
    bite yet. 198.51.100.3 is the tag proxy and 198.51.100.32 is an nmap run,
    so a substring test calls every nmap probe a leak; 203.0.113.2 is the
    server and 203.0.113.234 is an ordinary visitor.
    """

    def test_it_finds_an_address_named_outright(self):
        self.assertEqual({"203.0.113.3"},
                         infrastructure_named_in("http://203.0.113.3:8090/"))

    def test_it_finds_one_that_has_been_url_encoded(self):
        # The benign import carried it as http%3A%2F%2F203.0.113.2%2F...
        self.assertEqual({"203.0.113.2"}, infrastructure_named_in(
            "/admin/import-image?url=http%3A%2F%2F203.0.113.2%2Fassets"))

    def test_an_address_that_merely_begins_with_one_is_not_it(self):
        for text in ("X-Forwarded-For: 198.51.100.32",
                     "GET / HTTP/1.1 from 203.0.113.234",
                     "http://192.0.2.21/"):
            with self.subTest(text=text):
                self.assertEqual(set(), infrastructure_named_in(text))

    def test_an_address_that_merely_ends_with_one_is_not_it(self):
        self.assertEqual(set(), infrastructure_named_in("http://1203.0.113.2/"))

    def test_the_attack_payloads_are_not_the_lab(self):
        for text in ("http://127.0.0.1/admin/users",
                     "http://169.254.169.254/latest/meta-data/",
                     "file:///etc/passwd", "http://shop.test/robots.txt"):
            with self.subTest(text=text):
                self.assertEqual(set(), infrastructure_named_in(text))

    def test_nothing_is_nothing(self):
        self.assertEqual(set(), infrastructure_named_in(None))
        self.assertEqual(set(), infrastructure_named_in(""))
