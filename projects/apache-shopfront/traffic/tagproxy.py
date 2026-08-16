"""An HTTP proxy that stamps a request id on everything passing through it.

Attack tools will not send a header for us, and labelling their traffic by
source address and time window is only ever as exact as the clock -- and can
only give a whole run one blanket category. Pointing them at this instead gives
every tool request the same per-line exactness a driver request has, and lets a
single nikto run split into `reconnaissance` for its fingerprint probes and
`injection` for its payload attempts.

Everything that decides what Apache will see, and therefore what the truth file
will claim, is in `build_forward` and `TagLedger`: pure functions over plain
data, tested without a socket. The asyncio layer underneath them does no
thinking.

Stdlib only, by project rule.
"""

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from shared.truth.ids import new_request_id  # noqa: E402

#: Apache, on the residential network. Fixed rather than configurable on
#: purpose: the address Apache sees us connecting from has to be our lab_res
#: interface, because that is the one address named in RemoteIPTrustedProxy.
#: Reaching Apache over any other network would make us an untrusted peer and
#: every declared client address would be silently discarded.
UPSTREAM_HOST = "203.0.113.2"
UPSTREAM_PORT = 80

#: Headers the client is never allowed to supply. A tool that sends its own
#: X-Forwarded-For must not get to choose what lands in %h, and one that sends
#: its own X-Request-Id must not get to choose which truth record its line
#: joins to.
_CLIENT_MUST_NOT_SET = ("x-forwarded-for", "x-request-id")

_MAX_HEADER_BYTES = 64 * 1024


class UnknownPortError(ValueError):
    """A request arrived on a port with no configured meaning."""


class Forward(NamedTuple):
    request_line: str
    headers: list
    request_id: str
    client_ip: str
    actor: str
    method: str
    path: str


def _header_name(line):
    return line.split(":", 1)[0].strip().lower()


def _split_request_line(line):
    parts = line.split(" ")
    if len(parts) >= 3:
        return parts[0], parts[1], " ".join(parts[2:])
    if len(parts) == 2:
        return parts[0], parts[1], None
    return (parts[0] if parts else ""), None, None


def _split_absolute_target(target):
    """Split an absolute-form request target into (authority, origin-form path).

    Deliberately hand-rolled rather than handed to urllib: a proxy in front of
    a deliberately vulnerable application must not normalise the path. The
    traversal and encoding tricks in the attack playbooks are the payload, and
    a parser that tidied them up would quietly defuse the very requests the
    dataset exists to contain.
    """
    _, _, rest = target.partition("://")
    authority, slash, path = rest.partition("/")
    return authority, ("/" + path) if slash else "/"


def build_forward(request_line, raw_headers, peer_ip, port_map, port):
    """Decide what to send upstream for one request.

    Args:
        request_line: the client's request line, verbatim, without CRLF.
        raw_headers: the client's header lines, verbatim, in order.
        peer_ip: the address the connection actually came from.
        port_map: {port: {"mode": "peer"|"fixed", "client_ip": ..., "actor": ...}}
        port: the local port the connection arrived on.

    Returns:
        A Forward. `headers` is the client's own headers in their original
        order and spelling, with the two forbidden ones removed and ours
        appended.

    Raises:
        UnknownPortError: if `port` has no entry in `port_map`.
    """
    binding = port_map.get(port)
    if binding is None:
        # A request on a port we did not configure is a request whose origin we
        # cannot name. Guessing is how a truth file becomes confidently wrong.
        raise UnknownPortError(f"no client identity configured for port {port}")

    mode = binding.get("mode")
    if mode == "peer":
        client_ip = peer_ip
    elif mode == "fixed":
        client_ip = binding["client_ip"]
    else:
        raise ValueError(f"port {port} has unknown mode {mode!r}")

    method, target, protocol = _split_request_line(request_line)

    host_override = None
    if target and "://" in target:
        # Absolute-form: the client is treating us as a forward proxy. Apache
        # would log the whole absolute URI in %r, which is not what an origin
        # server's access log looks like.
        host_override, target = _split_absolute_target(target)
        request_line = " ".join(
            part for part in (method, target, protocol) if part is not None)

    headers = [h for h in raw_headers
               if _header_name(h) not in _CLIENT_MUST_NOT_SET]
    if host_override is not None:
        headers = [h for h in headers if _header_name(h) != "host"]
        headers.insert(0, f"Host: {host_override}")

    request_id = new_request_id()
    headers.append(f"X-Forwarded-For: {client_ip}")
    headers.append(f"X-Request-Id: {request_id}")

    return Forward(request_line=request_line, headers=headers,
                   request_id=request_id, client_ip=client_ip,
                   actor=binding.get("actor", "unknown"),
                   method=method, path=target)


class TagLedger:
    """Streaming JSON Lines record of what the proxy sent, and on whose behalf.

    Deliberately records only what the proxy can actually observe. It cannot
    know that one request is reconnaissance and the next is injection -- that
    is derived from the request itself, by the project's labels module, during
    the join.
    """

    def __init__(self, fh):
        self._fh = fh

    def record(self, *, request_id, client_ip, actor, method, path, ts=None):
        self._fh.write(json.dumps({
            "request_id": request_id,
            "client_ip": client_ip,
            "actor": actor,
            "ts": ts or datetime.now(timezone.utc).isoformat(),
            "method": method,
            "path": path,
        }, separators=(",", ":")) + "\n")
        # Per record, not per buffer: a proxy killed at the end of a run must
        # not take the last requests' labels with it.
        self._fh.flush()


# --------------------------------------------------------------------------
# Socket handling. No decisions are made below this line.
# --------------------------------------------------------------------------

async def _read_body(reader, headers):
    """Read a request or response body, using whichever framing was declared."""
    lowered = {_header_name(h): h.split(":", 1)[1].strip() for h in headers
               if ":" in h}
    if lowered.get("transfer-encoding", "").lower() == "chunked":
        chunks = []
        while True:
            size_line = await reader.readuntil(b"\r\n")
            chunks.append(size_line)
            size = int(size_line.strip().split(b";")[0] or b"0", 16)
            if size == 0:
                chunks.append(await reader.readuntil(b"\r\n"))
                break
            chunks.append(await reader.readexactly(size + 2))
        return b"".join(chunks)
    length = lowered.get("content-length")
    if length and length.isdigit() and int(length):
        return await reader.readexactly(int(length))
    return b""


def _encode(request_line, headers):
    text = request_line + "\r\n" + "".join(h + "\r\n" for h in headers) + "\r\n"
    return text.encode("latin-1", "replace")


async def _serve_connection(reader, writer, port_map, ledger):
    peer = writer.get_extra_info("peername")
    port = writer.get_extra_info("sockname")[1]
    peer_ip = peer[0] if peer else "0.0.0.0"
    try:
        while True:
            try:
                head = await reader.readuntil(b"\r\n\r\n")
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError,
                    ConnectionResetError):
                return

            lines = head.decode("latin-1").split("\r\n")
            request_line, raw_headers = lines[0], [l for l in lines[1:] if l]
            plan = build_forward(request_line, raw_headers, peer_ip,
                                 port_map, port)
            body = await _read_body(reader, raw_headers)

            up_reader, up_writer = await asyncio.open_connection(
                UPSTREAM_HOST, UPSTREAM_PORT, limit=_MAX_HEADER_BYTES)
            try:
                up_writer.write(_encode(plan.request_line, plan.headers) + body)
                await up_writer.drain()

                ledger.record(request_id=plan.request_id,
                              client_ip=plan.client_ip, actor=plan.actor,
                              method=plan.method, path=plan.path)

                response_head = await up_reader.readuntil(b"\r\n\r\n")
                response_lines = response_head.decode("latin-1").split("\r\n")
                writer.write(response_head)
                response_body = await _read_body(
                    up_reader, [l for l in response_lines[1:] if l])
                if response_body:
                    writer.write(response_body)
                else:
                    # No declared framing: the response ends when upstream does.
                    writer.write(await up_reader.read())
                await writer.drain()
            finally:
                up_writer.close()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


async def _main(port_map, ledger_path):
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    # Truncated on start, matching the server's entrypoint: one container
    # lifetime is one run, and a ledger inherited from the previous run would
    # mislead anyone reading it.
    with open(ledger_path, "w", encoding="utf-8") as fh:
        ledger = TagLedger(fh)
        servers = [
            await asyncio.start_server(
                lambda r, w: _serve_connection(r, w, port_map, ledger),
                "0.0.0.0", port, limit=_MAX_HEADER_BYTES)
            for port in port_map
        ]
        await asyncio.gather(*(s.serve_forever() for s in servers))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ports", required=True, type=Path,
                        help="JSON file mapping listen port to client identity")
    parser.add_argument("--ledger", required=True, type=Path)
    args = parser.parse_args(argv)

    port_map = {int(k): v
                for k, v in json.loads(args.ports.read_text()).items()}
    asyncio.run(_main(port_map, args.ledger))


if __name__ == "__main__":
    main()
