"""Behavioural tests for the Apache container itself.

These need Docker and a built image, so the whole module is skipped unless
``LOGFORGE_DOCKER=1``. The ordinary suite has to stay runnable on a bare
python3 with no daemon and no network, and it does.

What is proved here is not "Apache starts". It is the trust boundary the entire
client-address distribution rests on: that a container we have not named as a
proxy cannot decide what address appears in ``%h``, and that one we have named
can. Every later claim about who issued a request is downstream of that, so it
is measured rather than assumed -- and measured again on every change to the
server configuration, not once by hand.
"""

import time
import unittest

from shared.verify.combined import parse_line, parse_tagged
from tests.lab import (
    ACCESS, DOCKER_AVAILABLE, ERROR, TAGGED, TRUSTED, UNTRUSTED, WEB_DC,
    WEB_RES, compose, lines, request, response_headers, wait_for_lines,
    wait_for_web)


@unittest.skipUnless(DOCKER_AVAILABLE,
                     "needs Docker; set LOGFORGE_DOCKER=1 to run")
class TestApacheLogging(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        wait_for_web()

    @classmethod
    def tearDownClass(cls):
        compose("down", "-v")

    def setUp(self):
        self.access_before = len(lines(ACCESS))
        self.tagged_before = len(lines(TAGGED))

    def test_a_request_writes_one_line_to_each_access_log(self):
        request("lab_res", TRUSTED, f"http://{WEB_RES}/",
                ["X-Request-Id: probe-one"])
        self.assertEqual(len(wait_for_lines(ACCESS, self.access_before)), 1)
        self.assertEqual(len(wait_for_lines(TAGGED, self.tagged_before)), 1)

    def test_tagged_line_is_the_combined_line_prefixed_with_the_request_id(self):
        request("lab_res", TRUSTED, f"http://{WEB_RES}/",
                ["X-Request-Id: probe-two"])
        combined = wait_for_lines(ACCESS, self.access_before)[0]
        tagged = wait_for_lines(TAGGED, self.tagged_before)[0]

        request_id, record, remainder = parse_tagged(tagged, with_remainder=True)
        self.assertEqual(request_id, "probe-two")
        # The whole design rests on this: strip the prefix and you have the
        # shipped log, byte for byte, with no reassembly.
        self.assertEqual(remainder, combined)
        self.assertEqual(record["path"], "/")

    def test_missing_request_id_header_logs_a_dash_and_still_parses(self):
        request("lab_res", TRUSTED, f"http://{WEB_RES}/")
        tagged = wait_for_lines(TAGGED, self.tagged_before)[0]
        request_id, record = parse_tagged(tagged)
        self.assertEqual(request_id, "-")
        self.assertIsNotNone(record)

    def test_untrusted_source_cannot_declare_its_own_address(self):
        request("lab_dc", UNTRUSTED, f"http://{WEB_DC}/",
                ["X-Forwarded-For: 203.0.113.99"])
        line = wait_for_lines(ACCESS, self.access_before)[0]
        self.assertEqual(parse_line(line)["client_ip"], UNTRUSTED)

    def test_trusted_proxy_may_declare_the_client_address(self):
        request("lab_res", TRUSTED, f"http://{WEB_RES}/",
                ["X-Forwarded-For: 203.0.113.99"])
        line = wait_for_lines(ACCESS, self.access_before)[0]
        self.assertEqual(parse_line(line)["client_ip"], "203.0.113.99")

    def test_trusted_proxy_may_declare_a_cgnat_address(self):
        # 100.64.0.0/10 is a range ippools.py actually allocates from, and
        # mod_remoteip treats non-public addresses differently under
        # RemoteIPTrustedProxy than under RemoteIPInternalProxy. Not a
        # formality: if this fails the mobile personas have no valid addresses.
        request("lab_res", TRUSTED, f"http://{WEB_RES}/",
                ["X-Forwarded-For: 100.64.3.7"])
        line = wait_for_lines(ACCESS, self.access_before)[0]
        self.assertEqual(parse_line(line)["client_ip"], "100.64.3.7")

    def test_trusted_proxy_sending_no_header_logs_its_own_address(self):
        request("lab_res", TRUSTED, f"http://{WEB_RES}/")
        line = wait_for_lines(ACCESS, self.access_before)[0]
        self.assertEqual(parse_line(line)["client_ip"], TRUSTED)

    def test_health_probe_path_is_not_logged(self):
        self.assertEqual(
            request("lab_res", "203.0.113.91", f"http://{WEB_RES}/.lab-health"),
            "200")
        # Give Apache the same grace it gets everywhere else, then require
        # nothing to have arrived. The build polls this path before every run;
        # logging it would seed each dataset with harness traffic carrying no
        # request id.
        time.sleep(0.5)
        self.assertEqual(lines(ACCESS)[self.access_before:], [])
        self.assertEqual(lines(TAGGED)[self.tagged_before:], [])

    def test_a_head_response_logs_a_dash_rather_than_the_header_size(self):
        # This is what separates %b from Debian's stock %O: a HEAD sends no
        # body, so %b is "-" while %O would report the size of the headers.
        # Getting this wrong would put a plausible-looking number in every
        # bodyless line and nothing would flag it.
        request("lab_res", TRUSTED, f"http://{WEB_RES}/", extra=["-I"])
        record = parse_line(wait_for_lines(ACCESS, self.access_before)[0])
        self.assertEqual(record["method"], "HEAD")
        self.assertEqual(record["status"], 200)
        self.assertIsNone(record["bytes"])

    def test_a_conditional_get_returns_304_with_a_dash_for_the_byte_count(self):
        # A real conditional GET, using the Last-Modified Apache itself just
        # sent. An If-Modified-Since dated in the future is discarded as bogus
        # by Apache and answered with a 200, so a hardcoded far-future date
        # would test nothing.
        url = f"http://{WEB_RES}/assets/css/site.css"
        last_modified = response_headers("lab_res", TRUSTED, url)["last-modified"]

        before = len(lines(ACCESS))
        status = request("lab_res", TRUSTED, url,
                         [f"If-Modified-Since: {last_modified}"])
        self.assertEqual(status, "304")
        record = parse_line(wait_for_lines(ACCESS, before)[0])
        self.assertEqual(record["status"], 304)
        self.assertIsNone(record["bytes"])

    def test_error_log_is_a_real_file_and_not_the_stderr_symlink(self):
        # The base image symlinks /var/log/apache2/*.log to stdout and stderr.
        # If those symlinks survived into our image the dataset's error log
        # would be silently empty, because every line went to Docker's log
        # driver instead. Apache's own startup notices prove the file is real.
        #
        # Deliberately not asserting that a 404 appears here: at LogLevel warn
        # Apache logs "File does not exist" at info, and a production server
        # runs at warn. That is realistic, so the config stays and the test
        # claims only what it should.
        self.assertTrue(ERROR.exists())
        self.assertFalse(ERROR.is_symlink())
        self.assertTrue(
            any("resuming normal operations" in line for line in lines(ERROR)),
            "error.log holds no Apache startup notice")


if __name__ == "__main__":
    unittest.main()
