import unittest

from shared.verify.combined import parse_line, parse_tagged

NORMAL = (
    '203.0.113.5 - - [16/Aug/2026:09:00:01 +0000] "GET /p/17 HTTP/1.1" '
    '200 5312 "https://shop.test/c/tools" "Mozilla/5.0 (X11; Linux x86_64)"'
)


class TestNormalLines(unittest.TestCase):
    def test_parses_every_field(self):
        r = parse_line(NORMAL)
        self.assertEqual(r["client_ip"], "203.0.113.5")
        self.assertIsNone(r["ident"])
        self.assertIsNone(r["user"])
        self.assertEqual(r["method"], "GET")
        self.assertEqual(r["path"], "/p/17")
        self.assertEqual(r["protocol"], "HTTP/1.1")
        self.assertEqual(r["status"], 200)
        self.assertEqual(r["bytes"], 5312)
        self.assertEqual(r["referer"], "https://shop.test/c/tools")
        self.assertEqual(r["user_agent"], "Mozilla/5.0 (X11; Linux x86_64)")

    def test_parses_the_timestamp_with_its_offset(self):
        ts = parse_line(NORMAL)["ts"]
        self.assertEqual((ts.year, ts.month, ts.day), (2026, 8, 16))
        self.assertEqual((ts.hour, ts.minute, ts.second), (9, 0, 1))
        self.assertEqual(ts.utcoffset().total_seconds(), 0)

    def test_parses_an_authenticated_user(self):
        line = NORMAL.replace("203.0.113.5 - - [", "203.0.113.5 - demo [")
        self.assertEqual(parse_line(line)["user"], "demo")

    def test_trailing_newline_is_tolerated(self):
        self.assertIsNotNone(parse_line(NORMAL + "\n"))


class TestDashes(unittest.TestCase):
    def test_dash_bytes_becomes_none(self):
        # A 304 sends no body. Treating "-" as 0 would understate nothing and
        # overstate the count of zero-byte responses.
        line = NORMAL.replace(" 200 5312 ", " 304 - ")
        r = parse_line(line)
        self.assertEqual(r["status"], 304)
        self.assertIsNone(r["bytes"])

    def test_dash_referer_becomes_none(self):
        line = NORMAL.replace('"https://shop.test/c/tools"', '"-"')
        self.assertIsNone(parse_line(line)["referer"])

    def test_dash_user_agent_becomes_none(self):
        line = NORMAL.replace('"Mozilla/5.0 (X11; Linux x86_64)"', '"-"')
        self.assertIsNone(parse_line(line)["user_agent"])


class TestAwkwardRequestLines(unittest.TestCase):
    def test_handles_an_escaped_quote_inside_the_request(self):
        line = ('192.0.2.9 - - [16/Aug/2026:09:00:02 +0000] '
                '"GET /search?q=%22 HTTP/1.1\\" x" 400 226 "-" "-"')
        r = parse_line(line)
        self.assertIsNotNone(r)
        self.assertEqual(r["status"], 400)

    def test_handles_a_malformed_request_line(self):
        line = ('192.0.2.9 - - [16/Aug/2026:09:00:03 +0000] '
                '"GARBAGE" 400 226 "-" "-"')
        r = parse_line(line)
        self.assertEqual(r["status"], 400)
        self.assertIsNone(r["method"])
        self.assertEqual(r["request"], "GARBAGE")

    def test_handles_a_request_apache_could_not_record(self):
        line = ('192.0.2.9 - - [16/Aug/2026:09:00:03 +0000] '
                '"-" 408 0 "-" "-"')
        r = parse_line(line)
        self.assertEqual(r["status"], 408)
        self.assertIsNone(r["method"])

    def test_handles_a_request_with_no_protocol(self):
        line = ('192.0.2.9 - - [16/Aug/2026:09:00:03 +0000] '
                '"GET /" 200 100 "-" "-"')
        r = parse_line(line)
        self.assertEqual(r["method"], "GET")
        self.assertEqual(r["path"], "/")
        self.assertIsNone(r["protocol"])

    def test_handles_connect_head_and_options(self):
        for verb, target in (("CONNECT", "example.test:443"),
                             ("OPTIONS", "*"),
                             ("HEAD", "/")):
            with self.subTest(verb=verb):
                line = (f'192.0.2.9 - - [16/Aug/2026:09:00:04 +0000] '
                        f'"{verb} {target} HTTP/1.1" 405 199 "-" "-"')
                r = parse_line(line)
                self.assertEqual(r["method"], verb)
                self.assertEqual(r["path"], target)

    def test_handles_a_percent_escaped_control_character(self):
        # Apache renders non-printables in %r as \xHH.
        line = ('192.0.2.9 - - [16/Aug/2026:09:00:05 +0000] '
                '"GET /\\x00 HTTP/1.1" 400 226 "-" "-"')
        self.assertIsNotNone(parse_line(line))


class TestRejection(unittest.TestCase):
    def test_rejects_a_non_combined_line(self):
        self.assertIsNone(parse_line("this is not a log line"))

    def test_rejects_a_blank_line(self):
        self.assertIsNone(parse_line(""))

    def test_rejects_a_line_missing_the_user_agent_field(self):
        line = ('203.0.113.5 - - [16/Aug/2026:09:00:01 +0000] '
                '"GET / HTTP/1.1" 200 100 "-"')
        self.assertIsNone(parse_line(line))


class TestTagged(unittest.TestCase):
    def test_splits_the_id_from_the_combined_remainder(self):
        rid, rec = parse_tagged("7f3a1c2e " + NORMAL)
        self.assertEqual(rid, "7f3a1c2e")
        self.assertEqual(rec["path"], "/p/17")

    def test_a_request_without_the_header_logs_a_dash_id(self):
        # Apache writes "-" for an absent %{X-Request-Id}i. Those lines are
        # real and must parse; the join decides what to do about them.
        rid, rec = parse_tagged("- " + NORMAL)
        self.assertEqual(rid, "-")
        self.assertIsNotNone(rec)

    def test_the_remainder_is_returned_verbatim_for_derivation(self):
        # The shipped access.log is built from this remainder, so it must come
        # back byte-identical rather than reassembled from parsed fields.
        rid, rec, remainder = parse_tagged("abc " + NORMAL, with_remainder=True)
        self.assertEqual(remainder, NORMAL)


if __name__ == "__main__":
    unittest.main()
