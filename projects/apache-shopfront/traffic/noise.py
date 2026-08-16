"""The malformed end of the background noise, over raw sockets.

Well-formed opportunistic scanning is a persona and goes through the driver,
where it declares a datacenter address and carries a request id like everything
else. This file exists for the shapes that cannot: request lines Apache rejects
before it has read a header, and requests no HTTP client library will send.

**Measured against Apache 2.4.68, from a trusted source declaring an address:**

| Shape                          | `%h`      | request id |
|--------------------------------|-----------|------------|
| `CONNECT host:443`             | declared  | present    |
| `GET /x HTTP/1.0`, no Host     | declared  | present    |
| `G3T /x HTTP/1.1` (bad method) | declared  | present    |
| `GET /x HTTP/9.9` (bad version)| declared  | present    |
| `GET /x HTTP/1.1`, no Host     | **real**  | present    |
| `GARBAGE`                      | **real**  | **absent** |
| `GET /a b.php` (space in path) | **real**  | **absent** |
| `GET /x` (no version, HTTP/0.9)| **real**  | **absent** |

The last four never reach `mod_remoteip`, so they are logged against the
connection's real address. That is why this runs in a container whose address
is **reserved for nothing else**: with one source, labelling those lines by
address is exact rather than approximate. The join is told that address and the
category to use, and reports how many lines it labelled that way.

The middle row is the trap. The id survives, so the join matches the line by
id -- but `%h` is the real address, not the declared one. The ledger therefore
records the address Apache will actually log, not the one we would have liked.
Recording the declared one would trip the join's ledger-versus-log check and
fail the build.

Stdlib only.
"""

import argparse
import asyncio
import json
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/opt/logforge")

from shared.truth.ids import new_request_id  # noqa: E402

UPSTREAM = ("203.0.113.2", 80)

#: The address this container holds, and the only thing that ever uses it.
#: Whatever Apache logs for these requests is this, because none of these
#: shapes gets far enough for a declared address to be honoured.
SOURCE = "203.0.113.6"

ACTOR = "noise"

#: Shapes whose headers Apache still reads, so a request id survives and the
#: line joins exactly. Only the address is lost.
_ID_SURVIVES = (
    ("no_host_http11", "GET {path} HTTP/1.1\r\n", "reconnaissance"),
)

#: Shapes rejected before any header is read. Neither address nor id survives;
#: these are the lines the address fallback exists for.
_NOTHING_SURVIVES = (
    ("garbage_request_line", "GARBAGE\r\n", "unknown"),
    ("space_in_path", "GET {path} x HTTP/1.1\r\n", "reconnaissance"),
    ("no_version", "GET {path}\r\n", "reconnaissance"),
)

_PATHS = ("/wp-login.php", "/.env", "/phpmyadmin/", "/shell.php",
          "/admin.php", "/.git/config", "/cgi-bin/test.cgi", "/backup.zip")


async def _send(raw):
    """Write raw bytes at Apache and read whatever comes back."""
    try:
        reader, writer = await asyncio.open_connection(*UPSTREAM)
    except OSError:
        return
    try:
        writer.write(raw.encode("latin-1", "replace"))
        await writer.drain()
        try:
            await asyncio.wait_for(reader.read(4096), timeout=4)
        except (asyncio.TimeoutError, OSError):
            pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def run(ledger_path, count, seed, pause):
    rng = random.Random(seed ^ 0xB0155)
    shapes = [(*s, True) for s in _ID_SURVIVES] + \
             [(*s, False) for s in _NOTHING_SURVIVES]

    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    issued = 0
    with open(ledger_path, "w", encoding="utf-8") as fh:
        for _ in range(count):
            name, template, category, keeps_id = rng.choice(shapes)
            path = rng.choice(_PATHS)
            request_id = new_request_id()

            raw = template.format(path=path)
            if keeps_id:
                raw += (f"X-Request-Id: {request_id}\r\n"
                        f"User-Agent: Mozilla/5.0 (compatible)\r\n\r\n")
            else:
                # No header will be read, so sending any is pointless -- and
                # sending X-Forwarded-For would be a lie the log would not
                # reflect.
                raw += "\r\n"

            await _send(raw)

            if keeps_id:
                # client_ip is SOURCE, not a declared address: mod_remoteip
                # never ran for this shape, so SOURCE is what Apache logged.
                # Claiming otherwise would trip the join's ledger-versus-log
                # check and fail the build.
                fh.write(json.dumps({
                    "request_id": request_id, "client_ip": SOURCE,
                    "actor": ACTOR,
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "method": "GET", "path": path, "category": category,
                    "shape": name,
                }, separators=(",", ":")) + "\n")
                fh.flush()
            issued += 1
            await asyncio.sleep(pause * rng.random())

    print(f"issued {issued} malformed requests from {SOURCE}")
    return issued


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", required=True, type=Path)
    parser.add_argument("--count", type=int, default=40)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--pause", type=float, default=0.15,
                        help="mean seconds between requests")
    args = parser.parse_args(argv)
    asyncio.run(run(args.ledger, args.count, args.seed, args.pause))


if __name__ == "__main__":
    main()
