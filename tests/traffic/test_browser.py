"""Headless-browser personas.

Every other traffic source here builds its requests itself. This one hands a
URL to a real Chromium and records what the browser decided to ask for -- the
subresource order, the preloads, the conditional revalidation, the requests it
declines to make because the response is already in its cache.

The runner needs Playwright and only runs in its container. What is tested on
the host is the part that has to be right before any container starts: the
persona declarations, the addresses they claim, and the proxy ports that give
those addresses meaning. Every one of these has already been the cause of a
build that failed after the stack was up.
"""

import json
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "projects" / "apache-shopfront" / "traffic"))
sys.path.insert(0, str(REPO / "projects" / "apache-shopfront" / "attacks"))

from browser import (BROWSER_PERSONAS, PROXY,  # noqa: E402
                     port_map_entries, target_for)
from shared.clients.ippools import (ALLOWED_NETWORKS,  # noqa: E402
                                    ClientPool, is_allowed)

#: Addresses the lab's own containers hold. A persona claiming one of these
#: would put browser traffic under the server's or the proxy's identity.
INFRASTRUCTURE = {"203.0.113.2", "203.0.113.3", "203.0.113.4", "203.0.113.6",
                  "198.51.100.2", "198.51.100.3", "192.0.2.2", "192.0.2.3"}


class TestThePersonasAreDeclaredCoherently(unittest.TestCase):

    def test_there_are_personas(self):
        self.assertTrue(BROWSER_PERSONAS)

    def test_names_are_unique(self):
        names = [p.name for p in BROWSER_PERSONAS]
        self.assertEqual(len(names), len(set(names)))

    def test_addresses_are_unique(self):
        # Two personas on one address would interleave their sessions, and the
        # episode groups the truth file promises are contiguous per client
        # would stop being contiguous.
        addresses = [p.address for p in BROWSER_PERSONAS]
        self.assertEqual(len(addresses), len(set(addresses)))

    def test_ports_are_unique(self):
        ports = [p.port for p in BROWSER_PERSONAS]
        self.assertEqual(len(ports), len(set(ports)))

    def test_every_persona_asks_for_at_least_one_session(self):
        for persona in BROWSER_PERSONAS:
            with self.subTest(persona=persona.name):
                self.assertGreater(persona.sessions, 0)

    def test_every_persona_declares_a_viewport(self):
        for persona in BROWSER_PERSONAS:
            with self.subTest(persona=persona.name):
                width, height = persona.viewport
                self.assertGreater(width, 100)
                self.assertGreater(height, 100)


class TestTheAddressesTheyClaim(unittest.TestCase):

    def test_they_are_inside_the_reserved_documentation_ranges(self):
        for persona in BROWSER_PERSONAS:
            with self.subTest(persona=persona.name):
                self.assertTrue(is_allowed(persona.address),
                                f"{persona.address} is outside {ALLOWED_NETWORKS}")

    def test_none_of_them_is_an_infrastructure_address(self):
        for persona in BROWSER_PERSONAS:
            with self.subTest(persona=persona.name):
                self.assertNotIn(persona.address, INFRASTRUCTURE)

    def test_the_driver_never_draws_one_of_them(self):
        # The whole guarantee. If the session driver drew a browser persona's
        # address, two sources would write episodes for one client and the
        # contiguity check would fail -- after a full build, with no clue
        # pointing at the cause.
        claimed = {p.address for p in BROWSER_PERSONAS}
        pool = ClientPool(seed=7)
        drawn = {pool.draw(role) for role in ("residential", "mobile",
                                              "cloud", "datacenter")
                 for _ in range(3000)}
        self.assertEqual(claimed & drawn, set())

    def test_no_tool_run_claims_one_of_them(self):
        from toolruns import TOOL_RUNS
        claimed = {p.address for p in BROWSER_PERSONAS}
        self.assertEqual(claimed & {r.address for r in TOOL_RUNS}, set())


class TestTheProxyPorts(unittest.TestCase):

    def test_browser_ports_are_fixed_mode_not_peer(self):
        # Peer mode would declare the browser container's own address, and one
        # container serves every persona. Fixed mode is what gives each
        # persona an identity of its own.
        entries = port_map_entries()
        for persona in BROWSER_PERSONAS:
            with self.subTest(persona=persona.name):
                self.assertEqual(entries[persona.port]["mode"], "fixed")
                self.assertEqual(entries[persona.port]["client_ip"],
                                 persona.address)

    def test_the_actor_is_browser_so_labelling_stays_per_request(self):
        # Deliberately not a `tool:` actor. A tool's whole run is one activity
        # and is labelled from the actor; a browser session is genuinely a
        # mixture, and every request in it can be read on its own -- an image
        # is a static_asset, /api/stock is an api_call, /login is
        # authentication. Giving browsers a blanket actor category would put
        # one wrong label on all of it.
        for entry in port_map_entries().values():
            self.assertEqual(entry["actor"], "browser")

    def test_browser_ports_do_not_collide_with_the_tool_ports(self):
        from toolruns import port_map_entries as tool_ports
        self.assertEqual(set(port_map_entries()) & set(tool_ports()), set())

    def test_the_committed_ports_file_carries_both(self):
        from toolruns import port_map_entries as tool_ports
        path = REPO / "projects" / "apache-shopfront" / "traffic" / "ports.json"
        committed = {int(k): v for k, v in json.loads(path.read_text()).items()}
        expected = {**tool_ports(), **port_map_entries()}
        self.assertEqual(committed, expected)


class TestWhereTheBrowserIsPointed(unittest.TestCase):

    def test_it_navigates_to_the_tag_proxy_never_to_apache(self):
        # Straight at Apache the requests would carry no request id and every
        # line the browser produced would be unlabelled.
        for persona in BROWSER_PERSONAS:
            with self.subTest(persona=persona.name):
                self.assertEqual(target_for(persona),
                                 f"http://{PROXY}:{persona.port}")

    def test_the_target_names_no_host_outside_the_lab(self):
        for persona in BROWSER_PERSONAS:
            with self.subTest(persona=persona.name):
                self.assertTrue(is_allowed(PROXY))
                self.assertNotIn("://example.", target_for(persona))


class TestTheUserAgents(unittest.TestCase):

    def test_no_persona_announces_itself_as_headless(self):
        # Playwright's Chromium sends HeadlessChrome/... by default, which is
        # the single loudest tell a generated log can carry.
        for persona in BROWSER_PERSONAS:
            with self.subTest(persona=persona.name):
                if persona.user_agent:
                    self.assertNotIn("Headless", persona.user_agent)

    def test_a_declared_agent_is_a_plausible_browser_string(self):
        for persona in BROWSER_PERSONAS:
            if not persona.user_agent:
                continue
            with self.subTest(persona=persona.name):
                self.assertTrue(persona.user_agent.startswith("Mozilla/5.0"))


if __name__ == "__main__":
    unittest.main()
