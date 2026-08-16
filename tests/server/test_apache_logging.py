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

import os
import subprocess
import time
import unittest
from pathlib import Path

from shared.verify.combined import parse_line, parse_tagged

REPO = Path(__file__).resolve().parents[2]
PROJECT = REPO / "projects" / "apache-shopfront"
COMPOSE = PROJECT / "docker-compose.yml"
LOGS = PROJECT / "server" / "logs"
IMAGE = "logforge/apache-shopfront-web:dev"

ACCESS = LOGS / "access.log"
TAGGED = LOGS / "access.tagged.log"
ERROR = LOGS / "error.log"

# Where the server answers on each of the three lab networks.
WEB_RES = "203.0.113.2"
WEB_DC = "192.0.2.2"

# An address inside RemoteIPTrustedProxy (the driver's), and one outside it.
TRUSTED = "203.0.113.4"
UNTRUSTED = "192.0.2.50"


def _docker(*args, **kwargs):
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, **kwargs)


def _compose(*args):
    result = _docker("compose", "-f", str(COMPOSE), *args)
    if result.returncode != 0:
        raise RuntimeError(
            f"docker compose {' '.join(args)} failed:\n{result.stderr}")
    return result


def _request(network, source_ip, url, headers=(), extra=()):
    """Issue one request from a container with a chosen address.

    Reuses the server image because it already carries curl; a separate client
    image would be one more version to pin and to name in the manifest.
    """
    argv = ["run", "--rm", "--network", network, "--ip", source_ip,
            "--entrypoint", "curl", IMAGE, "-s", "-o", "/dev/null",
            "-w", "%{http_code}", *extra]
    for header in headers:
        argv += ["-H", header]
    argv.append(url)
    result = _docker(*argv)
    if result.returncode != 0:
        raise RuntimeError(f"request from {source_ip} failed: {result.stderr}")
    return result.stdout.strip()


def _response_headers(network, source_ip, url):
    """Return the response headers of one request, lowercased by name."""
    result = _docker(
        "run", "--rm", "--network", network, "--ip", source_ip,
        "--entrypoint", "curl", IMAGE, "-s", "-o", "/dev/null", "-D", "-", url)
    if result.returncode != 0:
        raise RuntimeError(f"request from {source_ip} failed: {result.stderr}")
    headers = {}
    for line in result.stdout.splitlines():
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    return headers


def _lines(path):
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def _wait_for_lines(path, previous_count, expected=1, timeout=5.0):
    """Return the lines appended since ``previous_count``.

    Apache writes its log line after the response is complete, so curl can
    return marginally before the line lands. Polling rather than sleeping keeps
    the suite fast when it is not racing and honest when it is.
    """
    deadline = time.monotonic() + timeout
    while True:
        lines = _lines(path)
        if len(lines) >= previous_count + expected:
            return lines[previous_count:]
        if time.monotonic() > deadline:
            return lines[previous_count:]
        time.sleep(0.05)


@unittest.skipUnless(
    os.environ.get("LOGFORGE_DOCKER") == "1",
    "needs Docker; set LOGFORGE_DOCKER=1 to run")
class TestApacheLogging(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        _compose("up", "-d", "--build", "web")
        deadline = time.monotonic() + 60
        while True:
            try:
                if _request("lab_res", "203.0.113.90",
                            f"http://{WEB_RES}/.lab-health") == "200":
                    return
            except RuntimeError:
                pass
            if time.monotonic() > deadline:
                raise RuntimeError("web never became healthy")
            time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        _compose("down", "-v")

    def setUp(self):
        self.access_before = len(_lines(ACCESS))
        self.tagged_before = len(_lines(TAGGED))
        self.error_before = len(_lines(ERROR))

    def test_a_request_writes_one_line_to_each_access_log(self):
        _request("lab_res", TRUSTED, f"http://{WEB_RES}/",
                 ["X-Request-Id: probe-one"])
        self.assertEqual(len(_wait_for_lines(ACCESS, self.access_before)), 1)
        self.assertEqual(len(_wait_for_lines(TAGGED, self.tagged_before)), 1)

    def test_tagged_line_is_the_combined_line_prefixed_with_the_request_id(self):
        _request("lab_res", TRUSTED, f"http://{WEB_RES}/",
                 ["X-Request-Id: probe-two"])
        combined = _wait_for_lines(ACCESS, self.access_before)[0]
        tagged = _wait_for_lines(TAGGED, self.tagged_before)[0]

        request_id, record, remainder = parse_tagged(tagged, with_remainder=True)
        self.assertEqual(request_id, "probe-two")
        # The whole design rests on this: strip the prefix and you have the
        # shipped log, byte for byte, with no reassembly.
        self.assertEqual(remainder, combined)
        self.assertEqual(record["path"], "/")

    def test_missing_request_id_header_logs_a_dash_and_still_parses(self):
        _request("lab_res", TRUSTED, f"http://{WEB_RES}/")
        tagged = _wait_for_lines(TAGGED, self.tagged_before)[0]
        request_id, record = parse_tagged(tagged)
        self.assertEqual(request_id, "-")
        self.assertIsNotNone(record)

    def test_untrusted_source_cannot_declare_its_own_address(self):
        _request("lab_dc", UNTRUSTED, f"http://{WEB_DC}/",
                 ["X-Forwarded-For: 203.0.113.99"])
        line = _wait_for_lines(ACCESS, self.access_before)[0]
        self.assertEqual(parse_line(line)["client_ip"], UNTRUSTED)

    def test_trusted_proxy_may_declare_the_client_address(self):
        _request("lab_res", TRUSTED, f"http://{WEB_RES}/",
                 ["X-Forwarded-For: 203.0.113.99"])
        line = _wait_for_lines(ACCESS, self.access_before)[0]
        self.assertEqual(parse_line(line)["client_ip"], "203.0.113.99")

    def test_trusted_proxy_may_declare_a_cgnat_address(self):
        # 100.64.0.0/10 is a range ippools.py actually allocates from, and
        # mod_remoteip treats non-public addresses differently under
        # RemoteIPTrustedProxy than under RemoteIPInternalProxy. Not a
        # formality: if this fails the mobile persona has no valid addresses.
        _request("lab_res", TRUSTED, f"http://{WEB_RES}/",
                 ["X-Forwarded-For: 100.64.3.7"])
        line = _wait_for_lines(ACCESS, self.access_before)[0]
        self.assertEqual(parse_line(line)["client_ip"], "100.64.3.7")

    def test_trusted_proxy_sending_no_header_logs_its_own_address(self):
        _request("lab_res", TRUSTED, f"http://{WEB_RES}/")
        line = _wait_for_lines(ACCESS, self.access_before)[0]
        self.assertEqual(parse_line(line)["client_ip"], TRUSTED)

    def test_health_probe_path_is_not_logged(self):
        self.assertEqual(
            _request("lab_res", "203.0.113.91", f"http://{WEB_RES}/.lab-health"),
            "200")
        # Give Apache the same grace it gets everywhere else, then require
        # nothing to have arrived. The build polls this path before every run;
        # logging it would seed each dataset with harness traffic carrying no
        # request id.
        time.sleep(0.5)
        self.assertEqual(_lines(ACCESS)[self.access_before:], [])
        self.assertEqual(_lines(TAGGED)[self.tagged_before:], [])

    def test_a_head_response_logs_a_dash_rather_than_the_header_size(self):
        # This is what separates %b from Debian's stock %O: a HEAD sends no
        # body, so %b is "-" while %O would report the size of the headers.
        # Getting this wrong would put a plausible-looking number in every
        # bodyless line and nothing would flag it.
        _request("lab_res", TRUSTED, f"http://{WEB_RES}/", extra=["-I"])
        record = parse_line(_wait_for_lines(ACCESS, self.access_before)[0])
        self.assertEqual(record["method"], "HEAD")
        self.assertEqual(record["status"], 200)
        self.assertIsNone(record["bytes"])

    def test_a_conditional_get_returns_304_with_a_dash_for_the_byte_count(self):
        # A real conditional GET, using the Last-Modified Apache itself just
        # sent. An If-Modified-Since dated in the future is discarded as bogus
        # by Apache and answered with a 200, so a hardcoded far-future date
        # would test nothing.
        url = f"http://{WEB_RES}/assets/css/site.css"
        last_modified = _response_headers("lab_res", TRUSTED, url)["last-modified"]

        before = len(_lines(ACCESS))
        status = _request("lab_res", TRUSTED, url,
                          [f"If-Modified-Since: {last_modified}"])
        self.assertEqual(status, "304")
        record = parse_line(_wait_for_lines(ACCESS, before)[0])
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
            any("resuming normal operations" in line for line in _lines(ERROR)),
            "error.log holds no Apache startup notice")


if __name__ == "__main__":
    unittest.main()
