"""Rendering one captured request into another server's log format.

Every expected line here is written out by hand from docs/rendered-formats.md,
not produced by the code and pasted back: the point is that each format comes
out the way that server writes it, and a test copied from the renderer would
only prove the renderer agrees with itself.

Three requests cover what the formats disagree about: a page view with a
query, a Referer and a User-Agent with spaces in it; a 304 with no body, no
Referer and no query; and the noise client's `GARBAGE`, which no server but
Apache and nginx writes down as it came.
"""

import calendar
import json
import unittest
from datetime import datetime, timezone

from shared.render.formats import FORMATS, Request, by_name

UTC = timezone.utc

PAGE = Request.from_line(
    '198.51.100.23 - - [13/Mar/2026:06:10:52 +0000] '
    '"GET /search?q=oak%27&page=2 HTTP/1.1" 200 4028 "http://shop.test/" '
    '"Mozilla/5.0 (X11; Linux x86_64)"',
    n=7, when=datetime(2026, 3, 13, 6, 10, 52, 123456, tzinfo=UTC),
    request_id="95ec4fa14ae91a124df1a176da634f8e")

ASSET = Request.from_line(
    '100.64.1.9 - - [13/Mar/2026:06:10:53 +0000] '
    '"GET /assets/css/site.css HTTP/1.1" 304 - "-" "curl/8.4.0"',
    n=8, when=datetime(2026, 3, 13, 6, 10, 53, 0, tzinfo=UTC),
    request_id="78448ab00f7b40d1b1a8d4d129e1ae24")

GARBAGE = Request.from_line(
    '203.0.113.6 - - [13/Mar/2026:06:10:54 +0000] "GARBAGE" 400 352 "-" "-"',
    n=9, when=datetime(2026, 3, 13, 6, 10, 54, 500000, tzinfo=UTC),
    request_id=None)

DUMMY = Request.from_line(
    '127.0.0.1 - - [13/Mar/2026:06:10:55 +0000] "OPTIONS * HTTP/1.0" 200 - '
    '"-" "Apache/2.4.68 (Debian) PHP/8.3.33 (internal dummy connection)"',
    n=10, when=datetime(2026, 3, 13, 6, 10, 55, 0, tzinfo=UTC),
    request_id=None)

#: Request line + CRLF, the two headers the capture holds, the blank line.
#: 38 + 28 + 45 + 2. The lower bound written wherever a format wants a request
#: size, since the rest of the request was never recorded.
PAGE_REQUEST_BYTES = 113

EPOCH = calendar.timegm((2026, 3, 13, 6, 10, 52))


class TestTheRequestAsCaptured(unittest.TestCase):

    def test_the_target_splits_at_its_first_question_mark(self):
        self.assertEqual((PAGE.path, PAGE.query), ("/search", "q=oak%27&page=2"))

    def test_no_question_mark_means_no_query(self):
        self.assertIsNone(ASSET.query)

    def test_a_dash_means_absent(self):
        self.assertIsNone(ASSET.referer)
        self.assertIsNone(ASSET.body)

    def test_only_method_target_and_http_version_is_well_formed(self):
        self.assertTrue(PAGE.well_formed)
        self.assertFalse(GARBAGE.well_formed)
        for text in ("GET /.env x", "GET /backup.zip"):
            line = f'203.0.113.6 - - [13/Mar/2026:06:10:54 +0000] "{text}" 400 1 "-" "-"'
            self.assertFalse(Request.from_line(line, n=1, when=GARBAGE.when,
                                               request_id=None).well_formed)

    def test_apache_escapes_are_undone(self):
        line = ('203.0.113.9 - - [13/Mar/2026:06:10:54 +0000] "GET /a HTTP/1.1"'
                ' 200 1 "-" "x \\"y\\" \\\\ \\x7f"')
        self.assertEqual(
            Request.from_line(line, n=1, when=GARBAGE.when,
                              request_id=None).user_agent, 'x "y" \\ \x7f')

    def test_the_lower_bound_on_the_request_size(self):
        self.assertEqual(PAGE.request_bytes_lower_bound, PAGE_REQUEST_BYTES)


class TestEveryFormatIsHere(unittest.TestCase):

    def test_the_twenty_agreed_formats(self):
        self.assertEqual(
            {f.name for f in FORMATS},
            {"apache-common", "apache-vhost-common", "apache-vhost-combined",
             "apache-combined-io", "nginx-main", "nginx-combined-forwarded",
             "ingress-nginx", "traefik-common", "nginx-json", "caddy-json",
             "traefik-json", "cloudflare-json", "gcp-http-json", "ecs-http",
             "iis-w3c", "cloudfront", "haproxy", "envoy", "istio", "aws-alb"})


class FormatCase(unittest.TestCase):
    name = None

    def line(self, request):
        return by_name(self.name).line(request)

    def flag(self, request):
        return by_name(self.name).flag(request)


class TestApache(FormatCase):

    def test_common(self):
        self.name = "apache-common"
        self.assertEqual(self.line(PAGE),
                         '198.51.100.23 - - [13/Mar/2026:06:10:52 +0000] '
                         '"GET /search?q=oak%27&page=2 HTTP/1.1" 200 4028')

    def test_vhost_common(self):
        self.name = "apache-vhost-common"
        self.assertEqual(self.line(ASSET),
                         'shop.test 100.64.1.9 - - [13/Mar/2026:06:10:53 +0000] '
                         '"GET /assets/css/site.css HTTP/1.1" 304 -')

    def test_vhost_combined(self):
        self.name = "apache-vhost-combined"
        self.assertEqual(self.line(PAGE),
                         'shop.test:80 198.51.100.23 - - [13/Mar/2026:06:10:52 +0000] '
                         '"GET /search?q=oak%27&page=2 HTTP/1.1" 200 4028 '
                         '"http://shop.test/" "Mozilla/5.0 (X11; Linux x86_64)"')

    def test_combined_io_carries_both_lower_bounds(self):
        self.name = "apache-combined-io"
        self.assertTrue(self.line(PAGE).endswith(
            f'"Mozilla/5.0 (X11; Linux x86_64)" {PAGE_REQUEST_BYTES} 4028'))
        # 33 + 2 for the request line, 22 + 2 for the User-Agent, 2 to end.
        self.assertTrue(self.line(ASSET).endswith('"curl/8.4.0" 61 0'))

    def test_apache_writes_its_own_dummy_connections(self):
        self.name = "apache-common"
        self.assertIsNone(self.flag(DUMMY))
        self.assertIsNone(self.flag(GARBAGE))


class TestNginx(FormatCase):

    def test_main_has_no_forwarder(self):
        self.name = "nginx-main"
        self.assertEqual(self.line(ASSET),
                         '100.64.1.9 - - [13/Mar/2026:06:10:53 +0000] '
                         '"GET /assets/css/site.css HTTP/1.1" 304 0 "-" '
                         '"curl/8.4.0" "-"')

    def test_combined_forwarded(self):
        self.name = "nginx-combined-forwarded"
        self.assertTrue(self.line(PAGE).endswith(
            '"Mozilla/5.0 (X11; Linux x86_64)" "-" 0.000'))

    def test_nginx_escapes_a_quote_as_hex(self):
        self.name = "nginx-main"
        line = ('203.0.113.9 - - [13/Mar/2026:06:10:54 +0000] "GET /a HTTP/1.1"'
                ' 200 1 "-" "x \\"y\\""')
        request = Request.from_line(line, n=1, when=GARBAGE.when, request_id=None)
        self.assertIn('"x \\x22y\\x22"', self.line(request))

    def test_ingress(self):
        self.name = "ingress-nginx"
        self.assertEqual(self.line(PAGE),
                         '198.51.100.23 - - [13/Mar/2026:06:10:52 +0000] '
                         '"GET /search?q=oak%27&page=2 HTTP/1.1" 200 4028 '
                         '"http://shop.test/" "Mozilla/5.0 (X11; Linux x86_64)" '
                         f'{PAGE_REQUEST_BYTES} 0.000 [default-shop-80] [] '
                         '10.0.0.20:80 4028 0.000 200 '
                         '95ec4fa14ae91a124df1a176da634f8e')

    def test_nginx_logs_garbage_as_it_came(self):
        self.name = "nginx-main"
        self.assertIn('"GARBAGE" 400 352', self.line(GARBAGE))
        self.assertEqual(self.flag(GARBAGE), "kept_as_received")

    def test_nginx_never_wrote_apaches_dummy_connections(self):
        self.name = "nginx-main"
        self.assertEqual(self.flag(DUMMY), "server_would_not_log")


class TestTraefik(FormatCase):

    def test_common(self):
        self.name = "traefik-common"
        self.assertEqual(self.line(PAGE),
                         '198.51.100.23 - - [13/Mar/2026:06:10:52 +0000] '
                         '"GET /search?q=oak%27&page=2 HTTP/1.1" 200 4028 '
                         '"http://shop.test/" "Mozilla/5.0 (X11; Linux x86_64)" '
                         '7 "shop@file" "http://10.0.0.20:80" 0ms')

    def test_common_writes_a_missing_part_as_a_dash(self):
        self.name = "traefik-common"
        self.assertEqual(self.line(GARBAGE),
                         '203.0.113.6 - - [13/Mar/2026:06:10:54 +0000] '
                         '"GARBAGE - -" 400 352 "-" "-" 9 "shop@file" '
                         '"http://10.0.0.20:80" 0ms')
        self.assertEqual(self.flag(GARBAGE), "server_would_not_log")

    def test_json(self):
        self.name = "traefik-json"
        line = self.line(PAGE)
        self.assertIn('"RequestPath":"/search?q=oak%27\\u0026page=2"', line)
        record = json.loads(line)
        self.assertEqual(list(record), sorted(record))
        self.assertEqual(record["StartUTC"], "2026-03-13T06:10:52.123456Z")
        self.assertEqual(record["request_User-Agent"],
                         "Mozilla/5.0 (X11; Linux x86_64)")
        self.assertEqual((record["ClientHost"], record["ClientAddr"],
                          record["DownstreamStatus"],
                          record["DownstreamContentSize"], record["RequestCount"]),
                         ("198.51.100.23", "198.51.100.23:0", 200, 4028, 7))

    def test_json_trims_a_whole_second_as_go_does(self):
        self.name = "traefik-json"
        record = json.loads(self.line(ASSET))
        self.assertEqual(record["StartUTC"], "2026-03-13T06:10:53Z")
        self.assertNotIn("request_Referer", record)


class TestJson(FormatCase):

    def test_nginx_json(self):
        self.name = "nginx-json"
        self.assertEqual(
            self.line(ASSET),
            '{"time_local":"13/Mar/2026:06:10:53 +0000","remote_addr":"100.64.1.9",'
            '"request":"GET /assets/css/site.css HTTP/1.1","status":"304",'
            '"body_bytes_sent":"0","http_referer":"","http_user_agent":"curl/8.4.0"}')

    def test_caddy(self):
        self.name = "caddy-json"
        expected = (
            '{"level":"info","ts":%s,"logger":"http.log.access.log0",'
            '"msg":"handled request","request":{"remote_ip":"198.51.100.23",'
            '"remote_port":"0","client_ip":"198.51.100.23","proto":"HTTP/1.1",'
            '"method":"GET","host":"shop.test","uri":"/search?q=oak%%27&page=2",'
            '"headers":{"User-Agent":["Mozilla/5.0 (X11; Linux x86_64)"],'
            '"Referer":["http://shop.test/"]}},"bytes_read":0,"user_id":"",'
            '"duration":0,"size":4028,"status":200,"resp_headers":{}}'
            % repr((EPOCH * 10**9 + 123456000) / 10**9))
        self.assertEqual(self.line(PAGE), expected)

    def test_caddy_writes_a_whole_second_without_a_fraction(self):
        self.name = "caddy-json"
        self.assertIn(f'"ts":{EPOCH + 1},', self.line(ASSET))

    def test_cloudflare(self):
        self.name = "cloudflare-json"
        record = json.loads(self.line(PAGE))
        self.assertEqual(record, {
            "ClientIP": "198.51.100.23",
            "ClientRequestHost": "shop.test",
            "ClientRequestMethod": "GET",
            "ClientRequestPath": "/search",
            "ClientRequestProtocol": "HTTP/1.1",
            "ClientRequestReferer": "http://shop.test/",
            "ClientRequestURI": "/search?q=oak%27&page=2",
            "ClientRequestUserAgent": "Mozilla/5.0 (X11; Linux x86_64)",
            "EdgeResponseBytes": 4028,
            "EdgeResponseStatus": 200,
            "EdgeStartTimestamp": EPOCH * 10**9 + 123456000,
            "RayID": "95ec4fa14ae91a12",
        })

    def test_gcp(self):
        self.name = "gcp-http-json"
        self.assertEqual(json.loads(self.line(PAGE)), {
            "timestamp": "2026-03-13T06:10:52.123456Z",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": "http://shop.test/search?q=oak%27&page=2",
                "status": 200,
                "userAgent": "Mozilla/5.0 (X11; Linux x86_64)",
                "remoteIp": "198.51.100.23",
                "referer": "http://shop.test/",
                "protocol": "HTTP/1.1",
            },
        })

    def test_gcp_omits_what_the_request_lacked(self):
        self.name = "gcp-http-json"
        record = json.loads(self.line(ASSET))
        self.assertEqual(record["timestamp"], "2026-03-13T06:10:53Z")
        self.assertNotIn("referer", record["httpRequest"])

    def test_ecs(self):
        self.name = "ecs-http"
        self.assertEqual(json.loads(self.line(PAGE)), {
            "@timestamp": "2026-03-13T06:10:52.123Z",
            "client": {"ip": "198.51.100.23"},
            "source": {"ip": "198.51.100.23"},
            "http": {"version": "1.1",
                     "request": {"method": "GET", "referrer": "http://shop.test/"},
                     "response": {"status_code": 200, "body": {"bytes": 4028}}},
            "url": {"original": "/search?q=oak%27&page=2", "path": "/search",
                    "query": "q=oak%27&page=2", "domain": "shop.test"},
            "user_agent": {"original": "Mozilla/5.0 (X11; Linux x86_64)"},
        })

    def test_ecs_leaves_out_what_was_not_there(self):
        self.name = "ecs-http"
        record = json.loads(self.line(ASSET))
        self.assertNotIn("query", record["url"])
        self.assertNotIn("body", record["http"]["response"])
        self.assertNotIn("referrer", record["http"]["request"])


class TestColumns(FormatCase):

    def test_iis_header(self):
        self.assertEqual(by_name("iis-w3c").header(PAGE), [
            "#Software: Microsoft Internet Information Services 10.0",
            "#Version: 1.0",
            "#Date: 2026-03-13 06:10:52",
            "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port "
            "cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus "
            "sc-win32-status time-taken",
        ])

    def test_iis(self):
        self.name = "iis-w3c"
        self.assertEqual(self.line(PAGE),
                         "2026-03-13 06:10:52 10.0.0.20 GET /search q=oak%27&page=2 "
                         "80 - 198.51.100.23 Mozilla/5.0+(X11;+Linux+x86_64) "
                         "http://shop.test/ 200 0 0 0")
        self.assertEqual(self.line(GARBAGE),
                         "2026-03-13 06:10:54 10.0.0.20 GARBAGE - - 80 - "
                         "203.0.113.6 - - 400 0 0 0")
        self.assertEqual(self.flag(GARBAGE), "server_would_not_log")

    def test_cloudfront_header_names_all_33_fields(self):
        header = by_name("cloudfront").header(PAGE)
        self.assertEqual(header[0], "#Version: 1.0")
        self.assertEqual(len(header[1].split(" ")) - 1, 33)

    def test_cloudfront(self):
        self.name = "cloudfront"
        self.assertEqual(self.line(PAGE).split("\t"), [
            "2026-03-13", "06:10:52", "LAX1", "4028", "198.51.100.23", "GET",
            "d111111abcdef8.cloudfront.net", "/search", "200", "http://shop.test/",
            "Mozilla/5.0%20(X11;%20Linux%20x86_64)",
            # The client's own %27 is encoded again: CloudFront encodes '%'.
            "q=oak%2527&page=2",
            "-", "Miss", "lexPoUrpGhJN8aF22mNPjg==", "shop.test", "http",
            str(PAGE_REQUEST_BYTES), "0.000", "-", "-", "-", "Miss", "HTTP/1.1",
            "-", "-", "0", "0.000", "Miss", "-", "-", "-", "-"])

    def test_cloudfront_calls_a_client_error_an_error(self):
        self.name = "cloudfront"
        self.assertEqual(self.line(GARBAGE).split("\t")[13], "Error")


class TestProxies(FormatCase):

    def test_haproxy(self):
        self.name = "haproxy"
        self.assertEqual(self.line(PAGE),
                         '198.51.100.23:0 [13/Mar/2026:06:10:52.123] http-in shop/web1 '
                         '0/0/0/0/0 200 4028 - - ---- 1/1/0/0/0 0/0 '
                         '{http://shop.test/|Mozilla/5.0 (X11; Linux x86_64)} '
                         '"GET /search?q=oak%27&page=2 HTTP/1.1"')

    def test_haproxy_leaves_a_missing_header_empty(self):
        self.name = "haproxy"
        self.assertIn(' 304 0 - - ---- 1/1/0/0/0 0/0 {|curl/8.4.0} ',
                      self.line(ASSET))

    def test_haproxy_encodes_what_would_break_its_line(self):
        self.name = "haproxy"
        line = ('203.0.113.9 - - [13/Mar/2026:06:10:54 +0000] '
                '"GET /a?x=#1 HTTP/1.1" 200 1 "-" "a \\"b\\" {c|d}"')
        request = Request.from_line(line, n=1, when=GARBAGE.when, request_id=None)
        self.assertTrue(self.line(request).endswith(
            '{|a #22b#22 #7Bc#7Cd#7D} "GET /a?x=#231 HTTP/1.1"'))

    def test_haproxy_refuses_garbage_its_own_way(self):
        self.name = "haproxy"
        self.assertEqual(self.line(GARBAGE),
                         '203.0.113.6:0 [13/Mar/2026:06:10:54.500] http-in '
                         'http-in/<NOSRV> -1/-1/-1/-1/0 400 0 - - CR-- 1/1/0/0/0 '
                         '0/0 {|} "<BADREQ>"')
        self.assertEqual(self.flag(GARBAGE), "rendered_as_server_rejects")

    def test_envoy(self):
        self.name = "envoy"
        self.assertEqual(self.line(PAGE),
                         '[2026-03-13T06:10:52.123Z] "GET /search?q=oak%27&page=2 '
                         'HTTP/1.1" 200 - 0 4028 0 0 "198.51.100.23" '
                         '"Mozilla/5.0 (X11; Linux x86_64)" '
                         '"95ec4fa1-4ae9-1a12-4df1-a176da634f8e" "shop.test" '
                         '"10.0.0.20:80"')

    def test_envoy_refuses_garbage_as_the_capture_shows(self):
        self.name = "envoy"
        self.assertEqual(self.line(GARBAGE),
                         '[2026-03-13T06:10:54.500Z] "- - HTTP/1.1" 400 DPE 0 11 0 - '
                         '"-" "-" "-" "-" "-"')

    def test_istio(self):
        self.name = "istio"
        self.assertEqual(self.line(PAGE),
                         '[2026-03-13T06:10:52.123Z] "GET /search?q=oak%27&page=2 '
                         'HTTP/1.1" 200 - via_upstream - "-" 0 4028 0 0 '
                         '"198.51.100.23" "Mozilla/5.0 (X11; Linux x86_64)" '
                         '"95ec4fa1-4ae9-1a12-4df1-a176da634f8e" "shop.test" '
                         '"10.0.0.20:80" inbound|80|| 127.0.0.6:0 10.0.0.20:80 '
                         '198.51.100.23:0 - default')

    def test_istio_keeps_the_connections_address_on_a_refusal(self):
        self.name = "istio"
        self.assertEqual(self.line(GARBAGE),
                         '[2026-03-13T06:10:54.500Z] "- - HTTP/1.1" 400 DPE '
                         'http1.codec_error - "-" 0 11 0 - "-" "-" "-" "-" "-" '
                         '- - 10.0.0.20:80 203.0.113.6:0 - -')

    def test_alb(self):
        self.name = "aws-alb"
        trace = f"Root=1-{EPOCH:08x}-95ec4fa14ae91a124df1a176"
        self.assertEqual(self.line(PAGE),
                         'http 2026-03-13T06:10:52.123456Z app/shop-alb/50dc6c495c0c9188 '
                         '198.51.100.23:0 10.0.0.20:80 0.000 0.000 0.000 200 200 '
                         f'{PAGE_REQUEST_BYTES} 4028 '
                         '"GET http://shop.test:80/search?q=oak%27&page=2 HTTP/1.1" '
                         '"Mozilla/5.0 (X11; Linux x86_64)" - - '
                         'arn:aws:elasticloadbalancing:us-east-1:123456789012:'
                         'targetgroup/shop/73e2d6bc24d8a067 '
                         f'"{trace}" "-" "-" 0 2026-03-13T06:10:52.123456Z '
                         '"forward" "-" "-" "10.0.0.20:80" "200" "-" "-" '
                         'TID_95ec4fa14ae91a12 "-" "-" "-" 10.0.0.5 - -')

    def test_alb_still_logs_a_malformed_request(self):
        self.name = "aws-alb"
        fields = self.line(GARBAGE)
        self.assertIn(' 203.0.113.6:0 - -1 -1 -1 400 - ', fields)
        self.assertIn('"GARBAGE http://shop.test:80- -"', fields)
        self.assertEqual(self.flag(GARBAGE), "kept_as_received")


class TestWhatEachServerDoesWithGarbage(unittest.TestCase):
    """The flag says what is known, and only that.

    "Would not log" is a claim about the server, and is made only where a
    source shows it: Go's net/http (Caddy, Traefik) and HTTP.sys (IIS). For
    the CDNs and Google's load balancer the pages cited say nothing, so the
    line is kept as received and flagged as exactly that.
    """

    EXPECTED = {
        "nginx-main": "kept_as_received", "nginx-combined-forwarded": "kept_as_received",
        "ingress-nginx": "kept_as_received", "nginx-json": "kept_as_received",
        "ecs-http": "kept_as_received", "aws-alb": "kept_as_received",
        "cloudflare-json": "kept_as_received", "gcp-http-json": "kept_as_received",
        "cloudfront": "kept_as_received",
        "traefik-common": "server_would_not_log", "traefik-json": "server_would_not_log",
        "caddy-json": "server_would_not_log", "iis-w3c": "server_would_not_log",
        "haproxy": "rendered_as_server_rejects", "envoy": "rendered_as_server_rejects",
        "istio": "rendered_as_server_rejects",
    }

    def test_each_format_flags_garbage_as_its_source_supports(self):
        for name, expected in self.EXPECTED.items():
            with self.subTest(format=name):
                self.assertEqual(by_name(name).flag(GARBAGE), expected)


class TestOnlyApacheWritesItsDummyConnections(unittest.TestCase):

    def test_every_other_format_flags_them(self):
        for fmt in FORMATS:
            with self.subTest(format=fmt.name):
                expected = (None if fmt.name.startswith("apache-")
                            else "server_would_not_log")
                self.assertEqual(fmt.flag(DUMMY), expected)


class TestHeaderLines(unittest.TestCase):

    def test_only_the_column_formats_have_any(self):
        for fmt in FORMATS:
            with self.subTest(format=fmt.name):
                expected = {"iis-w3c": 4, "cloudfront": 2}.get(fmt.name, 0)
                self.assertEqual(len(fmt.header(PAGE)), expected)


if __name__ == "__main__":
    unittest.main()
