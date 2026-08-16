"""The tag proxy in front of the real Apache.

The unit tests prove build_forward decides the right things. This proves the
decisions survive the socket layer and arrive at Apache: that a tool which
sends no header of ours still produces a log line carrying a request id, that
the id can be joined back to a ledger record, and that the tool's own address
is what Apache records.

Skipped unless LOGFORGE_DOCKER=1.
"""

import json
import re
import unittest

from shared.verify.combined import parse_line, parse_tagged
from tests.lab import (
    ACCESS, DOCKER_AVAILABLE, LEDGERS, PROXY_DC, PROXY_PORT, TAGGED, compose,
    docker, lines, wait_for_lines, wait_for_web)

IMAGE = "logforge/apache-shopfront-web:dev"
LEDGER = LEDGERS / "tagproxy.jsonl"
REQUEST_ID = re.compile(r"^[0-9a-f]{32}$")

TOOL_IP = "192.0.2.60"


def _through_proxy(url, proxied=True):
    """Issue a request from an untrusted address via the tag proxy."""
    argv = ["run", "--rm", "--network", "lab_dc", "--ip", TOOL_IP,
            "--entrypoint", "curl", IMAGE, "-s", "-o", "/dev/null",
            "-w", "%{http_code}"]
    if proxied:
        argv += ["-x", f"http://{PROXY_DC}:{PROXY_PORT}"]
    argv.append(url)
    result = docker(*argv)
    if result.returncode != 0:
        raise RuntimeError(f"proxied request failed: {result.stderr}")
    return result.stdout.strip()


def _ledger_entry(request_id):
    for line in lines(LEDGER):
        record = json.loads(line)
        if record["request_id"] == request_id:
            return record
    return None


@unittest.skipUnless(DOCKER_AVAILABLE,
                     "needs Docker; set LOGFORGE_DOCKER=1 to run")
class TestTagProxyAgainstApache(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        wait_for_web(services=("web", "tagproxy"))

    @classmethod
    def tearDownClass(cls):
        compose("down", "-v")

    def setUp(self):
        self.access_before = len(lines(ACCESS))
        self.tagged_before = len(lines(TAGGED))

    def test_a_tool_that_sends_no_header_still_gets_a_request_id(self):
        # This is the entire reason the proxy exists. sqlmap and nikto will not
        # set X-Request-Id, and labelling their lines by address and time
        # window is only as exact as the clock.
        self.assertEqual(_through_proxy("http://shop.test/.env"), "404")

        tagged = wait_for_lines(TAGGED, self.tagged_before)[0]
        request_id, record = parse_tagged(tagged)
        self.assertRegex(request_id, REQUEST_ID)
        self.assertEqual(record["path"], "/.env")

    def test_the_request_id_joins_to_a_ledger_record_naming_the_tool(self):
        _through_proxy("http://shop.test/.git/config")
        tagged = wait_for_lines(TAGGED, self.tagged_before)[0]
        request_id, record = parse_tagged(tagged)

        entry = _ledger_entry(request_id)
        self.assertIsNotNone(entry, f"no ledger record for {request_id}")
        self.assertEqual(entry["client_ip"], record["client_ip"])
        self.assertEqual(entry["path"], "/.git/config")
        self.assertEqual(entry["actor"], "tool")

    def test_apache_records_the_tools_own_address_not_the_proxys(self):
        # The proxy declares the tool's real container address, and Apache
        # trusts the proxy to do so. Without this every tool in the dataset
        # would appear to come from 203.0.113.3.
        _through_proxy("http://shop.test/phpmyadmin/")
        line = wait_for_lines(ACCESS, self.access_before)[0]
        self.assertEqual(parse_line(line)["client_ip"], TOOL_IP)

    def test_the_logged_request_line_is_origin_form_not_the_absolute_uri(self):
        # curl -x sends "GET http://shop.test/x HTTP/1.1". Forwarded unchanged
        # that is what Apache would log, and an origin server's access log does
        # not contain absolute URIs -- the dataset would be visibly wrong.
        _through_proxy("http://shop.test/admin.php?id=1")
        line = wait_for_lines(ACCESS, self.access_before)[0]
        record = parse_line(line)
        self.assertEqual(record["path"], "/admin.php?id=1")
        self.assertNotIn("://", record["request"])

    def test_a_tool_with_no_proxy_support_can_point_straight_at_us(self):
        # hydra and nmap's NSE scripts have no usable proxy setting, so the
        # proxy has to answer origin-form requests too.
        status = _through_proxy(
            f"http://{PROXY_DC}:{PROXY_PORT}/wp-login.php", proxied=False)
        self.assertEqual(status, "404")
        tagged = wait_for_lines(TAGGED, self.tagged_before)[0]
        request_id, record = parse_tagged(tagged)
        self.assertRegex(request_id, REQUEST_ID)
        self.assertEqual(record["path"], "/wp-login.php")
        self.assertEqual(record["client_ip"], TOOL_IP)

    def test_a_tool_cannot_choose_its_own_logged_address(self):
        argv = ["run", "--rm", "--network", "lab_dc", "--ip", TOOL_IP,
                "--entrypoint", "curl", IMAGE, "-s", "-o", "/dev/null",
                "-H", "X-Forwarded-For: 203.0.113.77",
                f"http://{PROXY_DC}:{PROXY_PORT}/spoof-attempt"]
        docker(*argv)
        line = wait_for_lines(ACCESS, self.access_before)[0]
        self.assertEqual(parse_line(line)["client_ip"], TOOL_IP)


if __name__ == "__main__":
    unittest.main()
