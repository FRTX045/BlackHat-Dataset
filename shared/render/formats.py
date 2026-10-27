"""One captured request, written the way another server writes its log.

Every file this produces is **rendered from the Apache capture**, never a
capture: Apache and PHP answered every request, and this only moves what they
logged into another server's columns. docs/rendered-formats.md is the rule
book -- the layout of each format, where each field comes from, the escaping,
and the vendor source each was checked against. This module is that document
as code, and where the two disagree the document is the one to fix first.

Three things recur across the formats and are settled once, here:

- **What was not measured is a declared constant.** Durations, ports, the
  Host header, a proxy's own fields. Byte fields that count headers get the
  body size, a lower bound, and the manifest says so.
- **Escaping is the target server's.** The Apache escapes are undone first;
  each format then writes the raw bytes its own way.
- **A request line that is not METHOD TARGET HTTP/x.y** is written as that
  server writes one where that is documented, and otherwise kept as received.
  `flag()` says which, so a consumer can score with and without those lines.

Stdlib only, by project rule.
"""

import base64
import json
import re
from typing import NamedTuple

from shared.verify.combined import LINE_RE

HOST = "shop.test"
PORT = 80
UPSTREAM = "10.0.0.20"
UPSTREAM_ADDR = f"{UPSTREAM}:{PORT}"

#: Requests that reached Apache with no id: its own dummy connections, the
#: application fetching itself, and the noise client's malformed lines. A
#: format that always writes an id gets this one for them, declared.
NO_ID = "0" * 32

#: Lines a server would write differently from the bytes Apache received.
REJECTED = "rendered_as_server_rejects"
NOT_LOGGED = "server_would_not_log"
AS_RECEIVED = "kept_as_received"

_WELL_FORMED = re.compile(r"^(\S+) (\S+) (HTTP/\d\.\d)$")
_APACHE_ESCAPE = re.compile(r'\\(x[0-9a-fA-F]{2}|.)')
_C_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "v": "\v", "f": "\f",
              "b": "\b", "a": "\a"}
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _apache_unescape(text):
    """Undo mod_log_config's escaping: `\\"`, `\\\\`, `\\xhh`, C-style
    whitespace. Bytes come back as code points 0-255, so nothing is lost."""
    def one(match):
        code = match.group(1)
        if code[0] == "x" and len(code) == 3:
            return chr(int(code[1:], 16))
        return _C_ESCAPES.get(code, code)
    return _APACHE_ESCAPE.sub(one, text)


def _dash(value):
    return None if value == "-" else value


class Request(NamedTuple):
    """One line of the shipped access.log, plus what the capture adds."""

    n: int
    client_ip: str
    ident: str
    user: str
    #: The bracketed stamp exactly as shipped, `13/Mar/2026:06:10:52 +0000`.
    stamp: str
    #: The remap's time for this line, sub-second part modelled.
    when: object
    #: The request line, undone of Apache's escaping.
    request: str
    #: The Apache-written fields, escapes intact, for the Apache formats.
    raw_request: str
    raw_referer: str
    raw_user_agent: str
    status: int
    #: `%b`: None where Apache wrote `-`.
    body: object
    referer: object
    user_agent: object
    request_id: object

    @classmethod
    def from_line(cls, line, *, n, when, request_id):
        match = LINE_RE.match(line.rstrip("\r\n"))
        if match is None:
            raise ValueError(f"line {n} is not Apache Combined")
        fields = match.groupdict()
        referer, agent = _dash(fields["referer"]), _dash(fields["user_agent"])
        return cls(
            n=n, client_ip=fields["client_ip"], ident=fields["ident"],
            user=fields["user"], stamp=fields["ts"], when=when,
            request=_apache_unescape(fields["request"]),
            raw_request=fields["request"], raw_referer=fields["referer"],
            raw_user_agent=fields["user_agent"], status=int(fields["status"]),
            body=None if fields["bytes"] == "-" else int(fields["bytes"]),
            referer=None if referer is None else _apache_unescape(referer),
            user_agent=None if agent is None else _apache_unescape(agent),
            request_id=request_id)

    @property
    def well_formed(self):
        return _WELL_FORMED.match(self.request) is not None

    def _parts(self):
        parts = self.request.split(" ")
        return parts + [""] * (3 - len(parts)) if len(parts) <= 3 else \
            [parts[0], " ".join(parts[1:-1]), parts[-1]]

    @property
    def method(self):
        return self._parts()[0]

    @property
    def target(self):
        return self._parts()[1]

    @property
    def protocol(self):
        return self._parts()[2]

    @property
    def path(self):
        return self.target.partition("?")[0]

    @property
    def query(self):
        path, mark, query = self.target.partition("?")
        return query if mark else None

    @property
    def size(self):
        """The body size as a number: what every format but Apache's writes
        for a response Apache logged as `-`."""
        return self.body or 0

    @property
    def request_bytes_lower_bound(self):
        """Request line, the two headers the capture holds, the blank line.

        Everything else the client sent -- Host, Accept, cookies, a body --
        was never recorded, so this is a floor, flagged as one wherever it is
        written."""
        total = len(self.request) + 2 + 2
        for name, value in (("Referer", self.referer),
                            ("User-Agent", self.user_agent)):
            if value is not None:
                total += len(name) + 2 + len(value) + 2
        return total

    @property
    def is_apache_internal(self):
        # Apache's parent waking its children. Only Apache writes these.
        return (self.client_ip == "127.0.0.1"
                and self.request == "OPTIONS * HTTP/1.0")

    @property
    def id(self):
        return self.request_id or NO_ID

    @property
    def uuid(self):
        i = self.id
        return f"{i[:8]}-{i[8:12]}-{i[12:16]}-{i[16:20]}-{i[20:]}"


# -- time ------------------------------------------------------------------

def _iso(when, digits):
    """UTC, `Z`, with exactly `digits` fractional digits (0 for none)."""
    base = when.strftime("%Y-%m-%dT%H:%M:%S")
    if digits:
        base += "." + f"{when.microsecond:06d}{'000'}"[:digits]
    return base + "Z"


def _iso_trimmed(when):
    """Go's RFC3339Nano: trailing zeros dropped, and the dot with them."""
    fraction = f"{when.microsecond:06d}".rstrip("0")
    return when.strftime("%Y-%m-%dT%H:%M:%S") + (f".{fraction}" if fraction
                                                  else "") + "Z"


def _iso_google(when):
    """0, 3, 6 or 9 fractional digits, the fewest that hold the value."""
    micro = when.microsecond
    return _iso(when, 0 if not micro else 3 if not micro % 1000 else 6)


def _unix_nanos(when):
    whole = int(when.replace(microsecond=0).timestamp())
    return whole * 10**9 + when.microsecond * 1000


def _go_float(value):
    """strconv.FormatFloat(f, 'f', -1, 64): shortest, no trailing `.0`."""
    text = repr(value)
    return text[:-2] if text.endswith(".0") else text


def _haproxy_time(when):
    return (f"{when.day:02d}/{_MONTHS[when.month - 1]}/{when.year}:"
            f"{when.strftime('%H:%M:%S')}.{when.microsecond // 1000:03d}")


# -- escaping ----------------------------------------------------------------

def _nginx(value):
    """ngx_http_log_escape: 0x00-0x1F, `"`, `\\`, 0x7F-0xFF as `\\xXX`."""
    if value is None:
        return "-"
    return "".join(f"\\x{ord(c):02X}" if ord(c) < 0x20 or c in '"\\'
                   or ord(c) >= 0x7F else c for c in value)


def _haproxy(value, *, in_header):
    """HAProxy 8.6: `#XX` outside 32-126, for `#` and `"`; in a capture
    block also for `{`, `|`, `}`."""
    special = '#"{|}' if in_header else '#"'
    return "".join(f"#{ord(c):02X}" if ord(c) < 32 or ord(c) > 126
                   or c in special else c for c in value)


def _iis(value):
    """HTTP.sys: spaces and non-printables become `+`, empty is `-`."""
    if not value:
        return "-"
    return "".join("+" if c == " " or ord(c) < 32 or ord(c) > 126 else c
                   for c in value)


#: AWS's list: 0-32, 127 and up, and these.
_CLOUDFRONT_ENCODED = set('<>"#%{}|\\^~[]`\' ')


def _cloudfront(value):
    if not value:
        return "-"
    return "".join(f"%{ord(c):02X}" if ord(c) <= 32 or ord(c) >= 127
                   or c in _CLOUDFRONT_ENCODED else c for c in value)


def _json(record):
    return json.dumps(record, separators=(",", ":"), ensure_ascii=False)


def _go_json(record):
    """encoding/json with sorted keys: HTML-safe, so `&` is `\\u0026`."""
    text = json.dumps(record, separators=(",", ":"), ensure_ascii=False,
                      sort_keys=True)
    return (text.replace("&", "\\u0026").replace("<", "\\u003c")
            .replace(">", "\\u003e").replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029"))


def _quoted(value):
    return "-" if value is None else value


# -- formats -----------------------------------------------------------------

class Format:
    """A server's access-log layout. Subclasses write one line each."""

    name = None
    #: Fields that carry a lower bound because the real one counts headers.
    lower_bound = ()
    #: What this server does with a request line that is not well formed.
    malformed = AS_RECEIVED

    def header(self, first):
        return []

    def flag(self, request):
        if request.is_apache_internal:
            return NOT_LOGGED
        if not request.well_formed:
            return self.malformed
        return None

    def line(self, request):
        raise NotImplementedError


class _Apache(Format):
    def flag(self, request):
        return None          # Apache wrote every one of these itself

    def _common(self, r):
        return (f'{r.client_ip} {r.ident} {r.user} [{r.stamp}] '
                f'"{r.raw_request}" {r.status} {"-" if r.body is None else r.body}')

    def _combined(self, r):
        return f'{self._common(r)} "{r.raw_referer}" "{r.raw_user_agent}"'


class ApacheCommon(_Apache):
    name = "apache-common"

    def line(self, r):
        return self._common(r)


class ApacheVhostCommon(_Apache):
    name = "apache-vhost-common"

    def line(self, r):
        return f"{HOST} {self._common(r)}"


class ApacheVhostCombined(_Apache):
    name = "apache-vhost-combined"

    def line(self, r):
        return f"{HOST}:{PORT} {self._combined(r)}"


class ApacheCombinedIo(_Apache):
    name = "apache-combined-io"
    lower_bound = ("%I", "%O")

    def line(self, r):
        return f"{self._combined(r)} {r.request_bytes_lower_bound} {r.size}"


class _Nginx(Format):
    def _combined(self, r):
        return (f'{r.client_ip} - {r.user} [{r.stamp}] "{_nginx(r.request)}" '
                f'{r.status} {r.size} "{_nginx(r.referer)}" '
                f'"{_nginx(r.user_agent)}"')


class NginxMain(_Nginx):
    name = "nginx-main"

    def line(self, r):
        return f'{self._combined(r)} "-"'


class NginxCombinedForwarded(_Nginx):
    name = "nginx-combined-forwarded"

    def line(self, r):
        return f'{self._combined(r)} "-" 0.000'


class IngressNginx(_Nginx):
    name = "ingress-nginx"
    lower_bound = ("$request_length",)

    def line(self, r):
        return (f"{self._combined(r)} {r.request_bytes_lower_bound} 0.000 "
                f"[default-shop-80] [] {UPSTREAM_ADDR} {r.size} 0.000 "
                f"{r.status} {r.id}")


def _traefik_quoted(value):
    return "-" if not value else value.replace('"', '\\"')


class TraefikCommon(Format):
    name = "traefik-common"
    malformed = NOT_LOGGED

    def line(self, r):
        method, target, protocol = (r.method or "-", r.target or "-",
                                    r.protocol or "-")
        return (f'{r.client_ip} - - [{r.stamp}] "{method} {target} {protocol}" '
                f'{r.status} {r.size} "{_traefik_quoted(r.referer)}" '
                f'"{_traefik_quoted(r.user_agent)}" {r.n} "shop@file" '
                f'"http://{UPSTREAM_ADDR}" 0ms')


class TraefikJson(Format):
    name = "traefik-json"
    malformed = NOT_LOGGED

    def line(self, r):
        record = {
            "ClientAddr": f"{r.client_ip}:0", "ClientHost": r.client_ip,
            "ClientPort": "0", "ClientUsername": "-",
            "DownstreamContentSize": r.size, "DownstreamStatus": r.status,
            "Duration": 0, "OriginContentSize": r.size, "OriginDuration": 0,
            "OriginStatus": r.status, "Overhead": 0, "RequestAddr": HOST,
            "RequestContentSize": 0, "RequestCount": r.n, "RequestHost": HOST,
            "RequestMethod": r.method, "RequestPath": r.target,
            "RequestPort": "-", "RequestProtocol": r.protocol,
            "RequestScheme": "http", "RetryAttempts": 0,
            "RouterName": "shop@file", "ServiceAddr": UPSTREAM_ADDR,
            "ServiceName": "shop@file", "ServiceURL": f"http://{UPSTREAM_ADDR}",
            "StartLocal": _iso_trimmed(r.when), "StartUTC": _iso_trimmed(r.when),
            "entryPointName": "web", "level": "info", "msg": "",
            "time": _iso(r.when, 0),
        }
        if r.referer is not None:
            record["request_Referer"] = r.referer
        if r.user_agent is not None:
            record["request_User-Agent"] = r.user_agent
        return _go_json(record)


class NginxJson(Format):
    name = "nginx-json"

    def line(self, r):
        # escape=json: a variable not found is written as nothing at all.
        return _json({
            "time_local": r.stamp, "remote_addr": r.client_ip,
            "request": r.request, "status": str(r.status),
            "body_bytes_sent": str(r.size), "http_referer": r.referer or "",
            "http_user_agent": r.user_agent or "",
        })


class CaddyJson(Format):
    name = "caddy-json"
    malformed = NOT_LOGGED

    def line(self, r):
        headers = {}
        if r.user_agent is not None:
            headers["User-Agent"] = [r.user_agent]
        if r.referer is not None:
            headers["Referer"] = [r.referer]
        ts = _go_float(_unix_nanos(r.when) / 10**9)
        body = _json({
            "request": {
                "remote_ip": r.client_ip, "remote_port": "0",
                "client_ip": r.client_ip, "proto": r.protocol,
                "method": r.method, "host": HOST, "uri": r.target,
                "headers": headers},
            "bytes_read": 0, "user_id": "", "duration": 0, "size": r.size,
            "status": r.status, "resp_headers": {},
        })
        return ('{"level":"info","ts":' + ts + ',"logger":"http.log.access.log0",'
                '"msg":"handled request",' + body[1:])


class CloudflareJson(Format):
    name = "cloudflare-json"
    lower_bound = ("EdgeResponseBytes",)

    def line(self, r):
        return _json({
            "ClientIP": r.client_ip, "ClientRequestHost": HOST,
            "ClientRequestMethod": r.method, "ClientRequestPath": r.path,
            "ClientRequestProtocol": r.protocol,
            "ClientRequestReferer": r.referer or "",
            "ClientRequestURI": r.target,
            "ClientRequestUserAgent": r.user_agent or "",
            "EdgeResponseBytes": r.size, "EdgeResponseStatus": r.status,
            "EdgeStartTimestamp": _unix_nanos(r.when), "RayID": r.id[:16],
        })


class GcpHttpJson(Format):
    name = "gcp-http-json"

    def line(self, r):
        request = {"requestMethod": r.method,
                   "requestUrl": f"http://{HOST}{r.target}",
                   "status": r.status}
        if r.user_agent is not None:
            request["userAgent"] = r.user_agent
        request["remoteIp"] = r.client_ip
        if r.referer is not None:
            request["referer"] = r.referer
        if r.protocol:
            request["protocol"] = r.protocol
        return _json({"timestamp": _iso_google(r.when), "httpRequest": request})


class EcsHttp(Format):
    name = "ecs-http"

    def line(self, r):
        http = {}
        if r.protocol.startswith("HTTP/"):
            http["version"] = r.protocol[len("HTTP/"):]
        http["request"] = {"method": r.method}
        if r.referer is not None:
            http["request"]["referrer"] = r.referer
        http["response"] = {"status_code": r.status}
        if r.body is not None:
            http["response"]["body"] = {"bytes": r.body}
        url = {"original": r.target, "path": r.path}
        if r.query is not None:
            url["query"] = r.query
        url["domain"] = HOST
        record = {"@timestamp": _iso(r.when, 3), "client": {"ip": r.client_ip},
                  "source": {"ip": r.client_ip}, "http": http, "url": url}
        if r.user_agent is not None:
            record["user_agent"] = {"original": r.user_agent}
        return _json(record)


class IisW3c(Format):
    name = "iis-w3c"
    malformed = NOT_LOGGED
    FIELDS = ("date time s-ip cs-method cs-uri-stem cs-uri-query s-port "
              "cs-username c-ip cs(User-Agent) cs(Referer) sc-status "
              "sc-substatus sc-win32-status time-taken")

    def header(self, first):
        return ["#Software: Microsoft Internet Information Services 10.0",
                "#Version: 1.0",
                f"#Date: {first.when.strftime('%Y-%m-%d %H:%M:%S')}",
                f"#Fields: {self.FIELDS}"]

    def line(self, r):
        return " ".join([
            r.when.strftime("%Y-%m-%d"), r.when.strftime("%H:%M:%S"), UPSTREAM,
            _iis(r.method), _iis(r.path), _iis(r.query), str(PORT),
            _iis(_dash(r.user)), r.client_ip, _iis(r.user_agent),
            _iis(r.referer), str(r.status), "0", "0", "0"])


class Cloudfront(Format):
    name = "cloudfront"
    lower_bound = ("sc-bytes", "cs-bytes")
    FIELDS = ("date time x-edge-location sc-bytes c-ip cs-method cs(Host) "
              "cs-uri-stem sc-status cs(Referer) cs(User-Agent) cs-uri-query "
              "cs(Cookie) x-edge-result-type x-edge-request-id x-host-header "
              "cs-protocol cs-bytes time-taken x-forwarded-for ssl-protocol "
              "ssl-cipher x-edge-response-result-type cs-protocol-version "
              "fle-status fle-encrypted-fields c-port time-to-first-byte "
              "x-edge-detailed-result-type sc-content-type sc-content-len "
              "sc-range-start sc-range-end")

    def header(self, first):
        return ["#Version: 1.0", f"#Fields: {self.FIELDS}"]

    def line(self, r):
        result = "Error" if r.status >= 400 else "Miss"
        request_id = (base64.urlsafe_b64encode(bytes.fromhex(r.request_id))
                      .decode() if r.request_id else "-")
        return "\t".join([
            r.when.strftime("%Y-%m-%d"), r.when.strftime("%H:%M:%S"), "LAX1",
            str(r.size), r.client_ip, _cloudfront(r.method),
            "d111111abcdef8.cloudfront.net", _cloudfront(r.path),
            str(r.status), _cloudfront(r.referer), _cloudfront(r.user_agent),
            _cloudfront(r.query), "-", result, request_id, HOST, "http",
            str(r.request_bytes_lower_bound), "0.000", "-", "-", "-", result,
            _cloudfront(r.protocol), "-", "-", "0", "0.000", result,
            "-", "-", "-", "-"])


class Haproxy(Format):
    name = "haproxy"
    lower_bound = ("bytes_read",)
    malformed = REJECTED

    def line(self, r):
        when = _haproxy_time(r.when)
        if not r.well_formed:
            # The manual's own example of an invalid request.
            return (f"{r.client_ip}:0 [{when}] http-in http-in/<NOSRV> "
                    f"-1/-1/-1/-1/0 400 0 - - CR-- 1/1/0/0/0 0/0 {{|}} "
                    f'"<BADREQ>"')
        captures = "|".join(_haproxy(v or "", in_header=True)
                            for v in (r.referer, r.user_agent))
        return (f"{r.client_ip}:0 [{when}] http-in shop/web1 0/0/0/0/0 "
                f"{r.status} {r.size} - - ---- 1/1/0/0/0 0/0 {{{captures}}} "
                f'"{_haproxy(r.request, in_header=False)}"')


class Envoy(Format):
    name = "envoy"
    malformed = REJECTED

    def _start(self, r):
        return f"[{_iso(r.when, 3)}]"

    def line(self, r):
        if not r.well_formed:
            # As Envoy 1.36.13 wrote one: the codec refused it before any
            # header existed, so no client, agent, id or host either.
            return (f'{self._start(r)} "- - HTTP/1.1" 400 DPE 0 11 0 - '
                    f'"-" "-" "-" "-" "-"')
        return (f'{self._start(r)} "{r.method} {r.target} {r.protocol}" '
                f'{r.status} - 0 {r.size} 0 0 "{r.client_ip}" '
                f'"{_quoted(r.user_agent)}" "{r.uuid}" "{HOST}" '
                f'"{UPSTREAM_ADDR}"')


class Istio(Envoy):
    name = "istio"

    def line(self, r):
        if not r.well_formed:
            # DOWNSTREAM_REMOTE_ADDRESS belongs to the connection, which
            # existed; everything about the request did not.
            return (f'{self._start(r)} "- - HTTP/1.1" 400 DPE '
                    f'http1.codec_error - "-" 0 11 0 - "-" "-" "-" "-" "-" '
                    f'- - {UPSTREAM_ADDR} {r.client_ip}:0 - -')
        return (f'{self._start(r)} "{r.method} {r.target} {r.protocol}" '
                f'{r.status} - via_upstream - "-" 0 {r.size} 0 0 '
                f'"{r.client_ip}" "{_quoted(r.user_agent)}" "{r.uuid}" '
                f'"{HOST}" "{UPSTREAM_ADDR}" inbound|{PORT}|| 127.0.0.6:0 '
                f'{UPSTREAM_ADDR} {r.client_ip}:0 - default')


class AwsAlb(Format):
    name = "aws-alb"
    lower_bound = ("received_bytes", "sent_bytes")
    malformed = AS_RECEIVED
    ELB = "app/shop-alb/50dc6c495c0c9188"
    TARGET_GROUP = ("arn:aws:elasticloadbalancing:us-east-1:123456789012:"
                    "targetgroup/shop/73e2d6bc24d8a067")

    def line(self, r):
        when = _iso(r.when, 6)
        tid = f"TID_{r.id[:16]}"
        if not r.well_formed:
            target = r.target or "-"
            request = (f'"{r.method} http://{HOST}:{PORT}{target} '
                       f'{r.protocol or "-"}"')
            return (f"http {when} {self.ELB} {r.client_ip}:0 - -1 -1 -1 "
                    f"{r.status} - {r.request_bytes_lower_bound} 0 {request} "
                    f'"{_quoted(r.user_agent)}" - - {self.TARGET_GROUP} "-" '
                    f'"-" "-" - {when} "-" "-" "-" "-" "-" "-" "-" {tid} '
                    f'"-" "-" "-" 10.0.0.5 - -')
        trace = f"Root=1-{int(r.when.timestamp()):08x}-{r.id[:24]}"
        return (f"http {when} {self.ELB} {r.client_ip}:0 {UPSTREAM_ADDR} "
                f"0.000 0.000 0.000 {r.status} {r.status} "
                f"{r.request_bytes_lower_bound} {r.size} "
                f'"{r.method} http://{HOST}:{PORT}{r.target} {r.protocol}" '
                f'"{_quoted(r.user_agent)}" - - {self.TARGET_GROUP} '
                f'"{trace}" "-" "-" 0 {when} "forward" "-" "-" '
                f'"{UPSTREAM_ADDR}" "{r.status}" "-" "-" {tid} "-" "-" "-" '
                f"10.0.0.5 - -")


FORMATS = (
    ApacheCommon(), ApacheVhostCommon(), ApacheVhostCombined(),
    ApacheCombinedIo(), NginxMain(), NginxCombinedForwarded(), IngressNginx(),
    TraefikCommon(), NginxJson(), CaddyJson(), TraefikJson(),
    CloudflareJson(), GcpHttpJson(), EcsHttp(), IisW3c(), Cloudfront(),
    Haproxy(), Envoy(), Istio(), AwsAlb(),
)


def by_name(name):
    for fmt in FORMATS:
        if fmt.name == name:
            return fmt
    raise KeyError(name)
