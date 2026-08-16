"""Tests for the tag proxy's pure request-rewriting logic.

The socket handling is deliberately not exercised here. Everything that decides
what Apache will see -- and therefore what the truth file will claim -- lives in
`build_forward` and `TagLedger`, which are plain functions over plain data and
can be tested without a server, a network or a container.
"""

import io
import json
import unittest

import sys
from pathlib import Path

# The traffic modules live under projects/, which is not a package: a project
# is a self-contained unit and importing across projects would be a mistake we
# would rather make impossible than merely discourage.
sys.path.insert(
    0, str(Path(__file__).resolve().parents[1].parent
           / "projects" / "apache-shopfront" / "traffic"))

from tagproxy import TagLedger, UnknownPortError, build_forward  # noqa: E402

PORT_MAP = {
    8080: {"mode": "peer", "actor": "tool"},
    8101: {"mode": "fixed", "client_ip": "100.64.3.7", "actor": "browser:mobile-1"},
}

HEADERS = [
    "Host: shop.test",
    "User-Agent: Mozilla/5.0 (X11; Linux x86_64)",
    "Accept: text/html",
    "Referer: http://shop.test/c/tools",
]


def forward(request_line="GET /p/17 HTTP/1.1", headers=None, peer="198.51.100.11",
            port=8080):
    return build_forward(request_line, HEADERS if headers is None else headers,
                         peer, PORT_MAP, port)


class TestBuildForward(unittest.TestCase):

    def test_assigns_a_different_request_id_to_every_request(self):
        self.assertNotEqual(forward().request_id, forward().request_id)

    def test_request_id_contains_no_whitespace(self):
        # The id is the first field of every tagged log line, and the join
        # splits that line on its first space. An id containing a space would
        # shift every field of the parse without producing anything that looks
        # malformed.
        request_id = forward().request_id
        self.assertTrue(request_id)
        self.assertEqual(request_id.split(), [request_id])

    def test_peer_mode_declares_the_connecting_containers_address(self):
        result = forward(peer="198.51.100.11", port=8080)
        self.assertEqual(result.client_ip, "198.51.100.11")
        self.assertIn("X-Forwarded-For: 198.51.100.11", result.headers)

    def test_fixed_mode_declares_the_address_configured_for_the_port(self):
        # Browser personas get one proxy port each; the port is how a headless
        # Chromium context, which cannot set the header itself, gets an address.
        result = forward(peer="203.0.113.5", port=8101)
        self.assertEqual(result.client_ip, "100.64.3.7")
        self.assertIn("X-Forwarded-For: 100.64.3.7", result.headers)

    def test_a_client_supplied_forwarded_for_is_replaced_not_appended(self):
        # A tool that sends its own X-Forwarded-For must not be able to choose
        # what lands in %h. Appending would leave the spoofed value in the list
        # for mod_remoteip to walk.
        result = forward(headers=HEADERS + ["X-Forwarded-For: 203.0.113.99"])
        forwarded = [h for h in result.headers if h.lower().startswith("x-forwarded-for")]
        self.assertEqual(forwarded, ["X-Forwarded-For: 198.51.100.11"])

    def test_a_client_supplied_request_id_is_replaced(self):
        result = forward(headers=HEADERS + ["x-request-id: attacker-chosen"])
        ids = [h for h in result.headers if h.lower().startswith("x-request-id")]
        self.assertEqual(ids, [f"X-Request-Id: {result.request_id}"])

    def test_every_other_header_survives_byte_for_byte_and_in_order(self):
        odd = ["Host: shop.test",
               "User-Agent:  curl/8.14.1  (odd spacing)",
               "Accept-Encoding: gzip,deflate"]
        result = forward(headers=odd)
        self.assertEqual(result.headers[:len(odd)], odd)

    def test_an_unconfigured_port_is_refused_rather_than_guessed(self):
        # A request arriving on a port we did not configure is a request whose
        # origin we cannot name. Labelling it anyway is how a truth file
        # becomes confidently wrong.
        with self.assertRaises(UnknownPortError):
            forward(port=9999)


class TestForwardProxyRequestLine(unittest.TestCase):
    """Tools that support http_proxy send an absolute-form request line."""

    def test_absolute_form_is_rewritten_to_origin_form(self):
        # Apache would otherwise log the whole absolute URI in %r, which is not
        # what an origin server's access log looks like.
        result = forward("GET http://shop.test/p/17?q=1 HTTP/1.1")
        self.assertEqual(result.request_line, "GET /p/17?q=1 HTTP/1.1")

    def test_absolute_form_sets_host_from_the_uri(self):
        result = forward("GET http://shop.test/p/17 HTTP/1.1",
                         headers=["User-Agent: nikto/2.5.0"])
        self.assertIn("Host: shop.test", result.headers)

    def test_absolute_form_with_no_path_becomes_a_root_request(self):
        result = forward("GET http://shop.test HTTP/1.1")
        self.assertEqual(result.request_line, "GET / HTTP/1.1")

    def test_origin_form_is_left_exactly_as_it_arrived(self):
        # Tools with no proxy support are pointed straight at us instead, and
        # their request line must reach Apache untouched.
        result = forward("GET /.env HTTP/1.1", headers=HEADERS)
        self.assertEqual(result.request_line, "GET /.env HTTP/1.1")
        self.assertIn("Host: shop.test", result.headers)

    def test_path_is_reported_for_the_ledger(self):
        self.assertEqual(forward("GET /a/b?c=d HTTP/1.1").path, "/a/b?c=d")
        self.assertEqual(forward("POST /api/cart HTTP/1.1").method, "POST")


class TestTagLedger(unittest.TestCase):

    def test_writes_one_record_per_request(self):
        fh = io.StringIO()
        ledger = TagLedger(fh)
        ledger.record(request_id="r1", client_ip="198.51.100.11", actor="tool",
                      method="GET", path="/.env")
        ledger.record(request_id="r2", client_ip="198.51.100.11", actor="tool",
                      method="GET", path="/.git/config")

        records = [json.loads(line) for line in fh.getvalue().splitlines()]
        self.assertEqual([r["request_id"] for r in records], ["r1", "r2"])
        self.assertEqual(records[0]["client_ip"], "198.51.100.11")
        self.assertEqual(records[0]["path"], "/.env")
        self.assertIn("ts", records[0])

    def test_each_record_reaches_the_file_immediately(self):
        # A proxy killed at the end of a run must not take the last requests'
        # labels with it.
        writes = []

        class Spy:
            def write(self, text):
                writes.append(text)

            def flush(self):
                writes.append("<flush>")

        ledger = TagLedger(Spy())
        ledger.record(request_id="r1", client_ip="203.0.113.5", actor="tool",
                      method="GET", path="/")
        self.assertIn("<flush>", writes)


if __name__ == "__main__":
    unittest.main()
