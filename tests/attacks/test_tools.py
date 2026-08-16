"""The declared tool runs.

These are data rather than code so the manifest can record each invocation
verbatim. What is checked here is that the declarations are internally
consistent and that nothing in them points outside the lab -- a tool aimed at a
real host would be a serious bug, and it is cheap to make impossible.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parents[2]
           / "projects" / "apache-shopfront" / "attacks"))

from toolruns import (PROXY, TOOL_RUNS, argv_for,  # noqa: E402
                      command_line, container_argv, port_map_entries,
                      service_for)

LAB_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.", "100.")

#: The categories a tool run's traffic may honestly carry.
ATTACK_CATEGORIES = {
    "reconnaissance", "enumeration", "injection", "path_traversal",
    "access_control", "credential_attack", "ssrf", "exploitation",
}


class TestToolDeclarations(unittest.TestCase):

    def test_there_are_tool_runs_declared(self):
        self.assertTrue(TOOL_RUNS)

    def test_names_are_unique(self):
        names = [run.name for run in TOOL_RUNS]
        self.assertEqual(len(names), len(set(names)))

    def test_source_addresses_are_unique(self):
        # One address per tool run, so the manifest's source column identifies
        # exactly one invocation and an analyst can follow it.
        addresses = [run.address for run in TOOL_RUNS]
        self.assertEqual(len(addresses), len(set(addresses)))

    def test_every_source_address_is_lab_space(self):
        for run in TOOL_RUNS:
            with self.subTest(tool=run.name):
                self.assertTrue(run.address.startswith(LAB_PREFIXES),
                                f"{run.name} claims {run.address}")

    def test_every_run_names_a_network_the_proxy_is_on(self):
        for run in TOOL_RUNS:
            with self.subTest(tool=run.name):
                self.assertIn(run.network, PROXY)

    def test_every_run_describes_what_it_was_pointed_at(self):
        # The manifest table has a column for this, and the provenance gate
        # will not accept a blank one.
        for run in TOOL_RUNS:
            with self.subTest(tool=run.name):
                self.assertTrue(run.target.strip())


class TestNothingLeavesTheLab(unittest.TestCase):

    def test_every_target_url_is_the_tag_proxy(self):
        # Tools go through the proxy so their requests acquire a request id.
        # One pointed straight at Apache would produce unlabelled lines.
        #
        # Matched on "http://" rather than "http", because hydra's
        # http-post-form and nmap's http-headers are service and script names,
        # not addresses.
        for run in TOOL_RUNS:
            for url in (a for a in argv_for(run) if a.startswith("http://")):
                with self.subTest(tool=run.name, url=url):
                    self.assertTrue(
                        url.startswith(
                            f"http://{PROXY[run.network]}:{run.port}"),
                        f"{run.name} points at {url}")

    def test_tools_that_take_a_bare_host_are_given_the_proxy(self):
        # hydra and nmap take an address rather than a URL, so the URL check
        # above cannot see them at all.
        for run in TOOL_RUNS:
            proxy = PROXY[run.network]
            bare = [a for a in argv_for(run)
                    if a.count(".") == 3 and a.replace(".", "").isdigit()]
            for address in bare:
                with self.subTest(tool=run.name, address=address):
                    self.assertEqual(address, proxy,
                                     f"{run.name} targets {address}, not the proxy")

    def test_no_argument_names_a_host_outside_the_lab(self):
        for run in TOOL_RUNS:
            for argument in argv_for(run):
                if argument.startswith("http") or "." in argument:
                    lowered = argument.lower()
                    with self.subTest(tool=run.name, argument=argument):
                        self.assertNotIn("://example.com", lowered)
                        self.assertNotIn("://google", lowered)
                        self.assertNotIn(".onion", lowered)

    def test_the_proxy_placeholder_is_always_substituted(self):
        for run in TOOL_RUNS:
            with self.subTest(tool=run.name):
                self.assertNotIn("{proxy}", command_line(run))


class TestCommandLines(unittest.TestCase):

    def test_a_command_line_is_reproducible_from_the_declaration(self):
        for run in TOOL_RUNS:
            with self.subTest(tool=run.name):
                self.assertEqual(command_line(run), " ".join(argv_for(run)))

    def test_the_binary_is_the_first_argument(self):
        for run in TOOL_RUNS:
            with self.subTest(tool=run.name):
                self.assertEqual(argv_for(run)[0], run.binary)

    def test_hydra_is_given_a_wordlist_that_exists(self):
        run = next(r for r in TOOL_RUNS if r.binary == "hydra")
        wordlist = next(a for a in argv_for(run) if a.endswith(".txt"))
        local = (Path(__file__).resolve().parents[2]
                 / wordlist.replace("/opt/logforge/", ""))
        self.assertTrue(local.is_file(), f"missing wordlist: {local}")


class TestEachToolIsDistinguishableInTheLedger(unittest.TestCase):
    """One tag-proxy port per tool, so the ledger says which tool sent what.

    The failure this prevents, found by reading the labels of a shipped
    dataset: every tool arrived on one shared port carrying the generic actor
    `tool`, `labels.py` never saw the `tool:dirb` prefix it was written to
    match, and **98% of 9,293 tool requests were labelled `browsing`**.
    Directory brute-forcing recorded as ordinary browsing is precisely the
    kind of confidently-wrong label this project exists not to produce.
    """

    def test_every_run_has_its_own_port(self):
        ports = [run.port for run in TOOL_RUNS]
        self.assertEqual(len(ports), len(set(ports)))

    def test_the_actor_names_the_tool_not_just_that_it_is_one(self):
        for run in TOOL_RUNS:
            with self.subTest(tool=run.name):
                self.assertTrue(run.actor.startswith("tool:"))
                self.assertIn(run.binary, run.actor)

    def test_the_port_map_gives_every_port_that_actor(self):
        entries = port_map_entries()
        for run in TOOL_RUNS:
            with self.subTest(tool=run.name):
                self.assertEqual(entries[run.port]["actor"], run.actor)
                self.assertEqual(entries[run.port]["mode"], "peer")

    def test_the_invocation_targets_its_own_port_and_nobody_else_s(self):
        # Not `:{port}`: hydra takes it as `-s` and nmap as `-p`, so the shape
        # varies. What must hold is that the port in the invocation is this
        # run's -- pointing a tool at another tool's port would file both
        # under one actor and lose exactly the distinction the ports exist to
        # make.
        for run in TOOL_RUNS:
            argv = " ".join(argv_for(run))
            with self.subTest(tool=run.name):
                self.assertIn(str(run.port), argv)
                for other in (r.port for r in TOOL_RUNS if r.port != run.port):
                    self.assertNotIn(str(other), argv)

    def test_the_committed_ports_file_matches_the_declarations(self):
        # The proxy reads ports.json and the build reads toolruns.py. If they
        # disagree the proxy rejects the connection on an unconfigured port,
        # which surfaces as a tool that reached nothing.
        import json
        path = (Path(__file__).resolve().parents[2] / "projects"
                / "apache-shopfront" / "traffic" / "ports.json")
        committed = {int(k): v for k, v in
                     json.loads(path.read_text()).items()}
        for port, entry in port_map_entries().items():
            with self.subTest(port=port):
                self.assertEqual(committed.get(port), entry)

    def test_every_actor_resolves_to_an_attack_category(self):
        # An actor the labeller does not recognise falls through to
        # per-request guessing, which is how the browsing bug happened.
        import sys as _sys
        _sys.path.insert(
            0, str(Path(__file__).resolve().parents[2]
                   / "projects" / "apache-shopfront"))
        from labels import categorise
        for run in TOOL_RUNS:
            with self.subTest(tool=run.name):
                category = categorise(
                    {"actor": run.actor, "method": "GET", "path": "/index.php"})
                self.assertIn(category, ATTACK_CATEGORIES,
                              f"{run.actor} falls through to guesswork")


class TestEveryRunIsBounded(unittest.TestCase):
    """A tool with no ceiling on its runtime can hang a build indefinitely.

    sqlmap and dirb in particular will keep going for as long as they are
    given, and a build that never returns is worse than one that records a
    tool as having been cut off -- which is a true fact about the run and
    belongs in the manifest.
    """

    def test_every_run_declares_a_timeout(self):
        for run in TOOL_RUNS:
            with self.subTest(tool=run.name):
                self.assertGreater(run.timeout_seconds, 0)

    def test_no_single_tool_can_take_more_than_five_minutes(self):
        for run in TOOL_RUNS:
            with self.subTest(tool=run.name):
                self.assertLessEqual(run.timeout_seconds, 300)

    def test_the_container_argv_enforces_the_timeout(self):
        for run in TOOL_RUNS:
            argv = container_argv(run)
            with self.subTest(tool=run.name):
                self.assertEqual(argv[0], "timeout")
                self.assertIn(str(run.timeout_seconds), argv[:4])

    def test_the_tool_itself_is_still_run_verbatim(self):
        # The timeout wrapper must not change the invocation the manifest
        # publishes, or the command line in the dataset would not be the
        # command line that ran.
        for run in TOOL_RUNS:
            argv = container_argv(run)
            with self.subTest(tool=run.name):
                self.assertEqual(tuple(argv[-len(argv_for(run)):]),
                                 argv_for(run))

    def test_a_kill_follows_the_timeout(self):
        # A tool that ignores SIGTERM would otherwise sit there holding the
        # static address the next run needs.
        for run in TOOL_RUNS:
            with self.subTest(tool=run.name):
                self.assertTrue(any(a.startswith("--kill-after")
                                    for a in container_argv(run)))


class TestTheyMatchTheComposeFile(unittest.TestCase):
    """Declarations and compose services have to agree, or the build starts a
    service that does not exist and fails after the stack is already up."""

    COMPOSE = (Path(__file__).resolve().parents[2] / "projects"
               / "apache-shopfront" / "docker-compose.yml").read_text()

    def test_every_run_has_a_compose_service(self):
        for run in TOOL_RUNS:
            with self.subTest(tool=run.name):
                self.assertIn(f"  {service_for(run)}:", self.COMPOSE)

    def test_the_compose_address_is_the_declared_one(self):
        for run in TOOL_RUNS:
            block = self.COMPOSE.split(f"  {service_for(run)}:", 1)[1]
            with self.subTest(tool=run.name):
                self.assertIn(f"ipv4_address: {run.address}",
                              block.split("\n\n", 1)[0])

    def test_the_compose_network_is_the_declared_one(self):
        for run in TOOL_RUNS:
            block = self.COMPOSE.split(f"  {service_for(run)}:", 1)[1]
            with self.subTest(tool=run.name):
                self.assertIn(f"{run.network}:", block.split("\n\n", 1)[0])

    def test_no_tool_service_publishes_a_host_port(self):
        for run in TOOL_RUNS:
            block = self.COMPOSE.split(f"  {service_for(run)}:", 1)[1]
            with self.subTest(tool=run.name):
                self.assertNotIn("ports:", block.split("\n\n", 1)[0])


if __name__ == "__main__":
    unittest.main()
