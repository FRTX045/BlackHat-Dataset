"""Parser for the Apache Combined Log Format, and its request-id-tagged twin.

Deliberately tolerant of the ugly lines a real server produces -- malformed
request lines, CONNECT attempts, requests Apache could not record at all. Those
are a real and intended part of these datasets, and a parser that rejected them
would silently drop exactly the content that makes the data worth having.

It is not tolerant of lines that are not Combined at all: those return None so
the verifier can count and report them rather than guess.
"""

import re
from datetime import datetime

# Apache escapes " inside a quoted field as \" and non-printables as \xHH, so
# a quoted field is any run of non-quote/non-backslash characters interleaved
# with backslash escapes.
_QUOTED = r'(?:[^"\\]|\\.)*'

LINE_RE = re.compile(
    r'^(?P<client_ip>\S+) (?P<ident>\S+) (?P<user>\S+) '
    r'\[(?P<ts>[^\]]+)\] '
    r'"(?P<request>' + _QUOTED + r')" '
    r'(?P<status>\d{3}) (?P<bytes>-|\d+) '
    r'"(?P<referer>' + _QUOTED + r')" '
    r'"(?P<user_agent>' + _QUOTED + r')"$'
)

_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"


def _dash_to_none(value):
    return None if value == "-" else value


def parse_line(line):
    """Parse one Combined line into a dict, or return None if it is not one.

    ``bytes`` is None for a "-" body size: a 304 sent no body, which is not
    the same fact as a zero-byte response.
    """
    match = LINE_RE.match(line.rstrip("\r\n"))
    if not match:
        return None
    fields = match.groupdict()

    # A malformed or unrecorded request line still has to parse. Only split
    # out method/path/protocol when the shape actually supports it.
    parts = fields["request"].split(" ")
    method = path = protocol = None
    if len(parts) == 3:
        method, path, protocol = parts
    elif len(parts) == 2:
        method, path = parts

    return {
        "client_ip": fields["client_ip"],
        "ident": _dash_to_none(fields["ident"]),
        "user": _dash_to_none(fields["user"]),
        "ts": datetime.strptime(fields["ts"], _TS_FMT),
        "request": fields["request"],
        "method": method,
        "path": path,
        "protocol": protocol,
        "status": int(fields["status"]),
        "bytes": None if fields["bytes"] == "-" else int(fields["bytes"]),
        "referer": _dash_to_none(fields["referer"]),
        "user_agent": _dash_to_none(fields["user_agent"]),
    }


def parse_tagged(line, with_remainder=False):
    """Split a tagged line into its request id and its Combined remainder.

    The remainder is returned verbatim when asked for, because the shipped
    access.log is built by writing it out unchanged -- reassembling it from
    parsed fields would make the shipped log our reconstruction of Apache's
    output rather than Apache's output.

    Apache writes "-" as the id when the request carried no X-Request-Id
    header. Such lines parse normally; deciding what to do about them is the
    join's job, not the parser's.
    """
    request_id, _, remainder = line.rstrip("\r\n").partition(" ")
    record = parse_line(remainder)
    if with_remainder:
        return request_id, record, remainder
    return request_id, record
