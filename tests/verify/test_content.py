"""A shipped line may not name a lab container.

The generator tests hold each traffic source to this, one source at a time,
and that is exactly how it leaked: the benign admin import named the server
by its bridge address for a month, and when that was fixed, the real-browser
personas turned out to be sending the tag proxy's address and port as their
Referer on every subresource. Each generator had its own test or none. This is
the check on the shipped artifact, which catches the next leak whichever
generator produces it.
"""

import unittest

from shared.verify.combined import parse_line
from shared.verify.content import lab_addresses_in_content

TS = "[09/Mar/2026:07:28:01 +0000]"
UA = '"Mozilla/5.0 (X11; Linux x86_64) Chrome/140.0.7339.16 Safari/537.36"'


def line(client="203.0.113.41", request="GET / HTTP/1.1", referer="-"):
    return f'{client} - - {TS} "{request}" 200 512 "{referer}" {UA}'


def check(*lines):
    return lab_addresses_in_content([parse_line(text) for text in lines])


class TestWhatALineMayName(unittest.TestCase):

    def test_ordinary_lines_raise_nothing(self):
        self.assertEqual([], check(
            line(),
            line(request="GET /p/12 HTTP/1.1", referer="http://shop.test/c/oak"),
            line(request="GET /search?q=pipe+cutter HTTP/1.1")))

    def test_a_request_naming_the_server_by_its_bridge_address_fails(self):
        problems = check(line(), line(request=(
            "GET /admin/import-image?url=http%3A%2F%2F203.0.113.2%2Fassets"
            "%2Fimg%2Flogo.png HTTP/1.1")))
        self.assertEqual(1, len(problems), problems)
        self.assertIn("request", problems[0])
        self.assertIn("203.0.113.2", problems[0])
        self.assertIn("line 2", problems[0])

    def test_a_referer_naming_the_tag_proxy_fails(self):
        # The real-browser personas' leak: Chromium browsed the proxy's
        # address and port, so that is the page every subresource came from.
        problems = check(line(request="GET /assets/css/site.css HTTP/1.1",
                              referer="http://203.0.113.3:8090/"))
        self.assertEqual(1, len(problems), problems)
        self.assertIn("Referer", problems[0])
        self.assertIn("203.0.113.3", problems[0])

    def test_it_counts_every_offending_line_not_just_the_first(self):
        problems = check(*[line(referer="http://203.0.113.3:8091/")] * 7)
        self.assertEqual(1, len(problems), problems)
        self.assertIn("7 line", problems[0])

    def test_the_server_fetching_itself_is_not_a_leak(self):
        # A successful SSRF against a lab host leaves a line from the server's
        # own address. VULNERABILITIES.md documents that line as the tell, so
        # the client field is deliberately not checked.
        self.assertEqual([], check(line(client="203.0.113.2",
                                        request="GET /robots.txt HTTP/1.1")))

    def test_the_ssrf_payloads_are_not_the_lab(self):
        self.assertEqual([], check(*[line(request=(
            f"GET /admin/import-image?url={target} HTTP/1.1"))
            for target in ("http%3A%2F%2F127.0.0.1%2Fadmin%2Fusers",
                           "http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F",
                           "file%3A%2F%2F%2Fetc%2Fpasswd")]))

    def test_a_malformed_request_is_still_read(self):
        # The noise generator sends request lines that are not requests. Four
        # tokens leave parse_line with no path at all, so only a check reading
        # the whole request field -- what the client actually sent -- sees it.
        problems = check(line(client="203.0.113.3",
                              request="GET http://192.0.2.2/ HTTP/1.1 junk"))
        self.assertEqual(1, len(problems), problems)

    def test_an_nmap_address_is_not_the_tag_proxy(self):
        # 198.51.100.32 begins with 198.51.100.3. The noise generator really
        # does send this line.
        self.assertEqual([], check(line(client="203.0.113.3",
                                        request="X-Forwarded-For: 198.51.100.32")))

    def test_an_unparsed_line_is_skipped_but_still_counted(self):
        problems = check("not a log line at all",
                         line(referer="http://203.0.113.3:8090/"))
        self.assertIn("line 2", problems[0])
