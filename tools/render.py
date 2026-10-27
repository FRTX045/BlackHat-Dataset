"""Render a shipped build into every other log format, for comparison.

    python3 tools/render.py datasets/apache-shopfront/2026-10-06-small

Writes `<build>/rendered/`: one `<format>.log` per format in
`shared/render/formats.py`, its `<format>.truth.jsonl` (the shipped labels,
`line_no` moved past the format's header lines), a `MANIFEST.json` naming the
offsets, the lower-bound fields and every flagged line, and a `SHA256SUMS`.

These files are **rendered from the Apache capture**. No other server saw this
traffic; docs/rendered-formats.md says exactly what each file is.

Two things a shipped line cannot carry come from re-running the remap on the
capture: each line's sub-second time and its request id. The re-run has to
reproduce the shipped log exactly, or nothing is written: a rendering of a log
the remap did not make would pair times and ids with the wrong lines.

Stdlib only, by project rule.
"""

import argparse
import hashlib
import json
import sys
import tomllib
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from shared.render.formats import FORMATS  # noqa: E402
from shared.timeline.remap import remap_placement  # noqa: E402
from shared.truth.reader import read_truth  # noqa: E402
from shared.verify.combined import LINE_RE, parse_tagged  # noqa: E402
from shared.render.formats import Request  # noqa: E402

DESCRIPTION = (
    "Every file here is rendered from the Apache capture, never a capture: "
    "Apache 2.4 and PHP answered every request, and each file writes what "
    "they logged in another server's columns. Fields the capture never "
    "measured are declared constants; byte fields that count headers carry "
    "the body size as a lower bound. docs/rendered-formats.md has the rules.")


class RenderRefused(Exception):
    """The build cannot be rendered without pairing data with wrong lines."""


def _without_stamp(line):
    match = LINE_RE.match(line)
    if match is None:
        return line
    lo, hi = match.span("ts")
    return line[:lo] + line[hi:]


def requests_of(build, *, timeline, seed, unpaced):
    raw = (build / "access.raw.log").read_text(encoding="utf-8").splitlines()
    _, raw_records = read_truth(build / "truth.raw.jsonl")
    shipped = (build / "access.log").read_text(encoding="utf-8").splitlines()
    ids = [parse_tagged(line)[0] for line in
           (build / "access.tagged.log").read_text(encoding="utf-8").splitlines()
           if line.strip()]
    if len(ids) != len(raw) or len(raw) != len(shipped):
        raise RenderRefused(
            f"{len(raw)} captured, {len(ids)} tagged and {len(shipped)} "
            f"shipped lines; they must correspond one to one")

    placement = remap_placement(
        raw, list(raw_records), start=datetime.fromisoformat(timeline["start"]),
        duration_seconds=timeline["duration_seconds"], seed=seed,
        unpaced=unpaced)

    requests = []
    for n, (line, (source, when)) in enumerate(zip(shipped, placement), 1):
        request = Request.from_line(
            line, n=n, when=when,
            request_id=None if ids[source] == "-" else ids[source])
        expected = when.strftime("%d/%b/%Y:%H:%M:%S %z")
        if (_without_stamp(line) != _without_stamp(raw[source])
                or request.stamp != expected):
            raise RenderRefused(
                f"line {n} of access.log is not what re-running the remap "
                f"gives; times and request ids would land on the wrong lines")
        requests.append(request)
    return requests


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def render_dataset(build, *, timeline, seed, unpaced, formats=FORMATS):
    build = Path(build)
    requests = requests_of(build, timeline=timeline, seed=seed, unpaced=unpaced)
    truth_header, records = read_truth(build / "truth.jsonl")
    records = list(records)
    out = build / "rendered"
    out.mkdir(exist_ok=True)

    entries = {}
    for fmt in formats:
        header = fmt.header(requests[0])
        offset = len(header)
        flagged = {}
        with open(out / f"{fmt.name}.log", "w", encoding="utf-8",
                  newline="\n") as fh:
            for line in header:
                fh.write(line + "\n")
            for request in requests:
                fh.write(fmt.line(request) + "\n")
                reason = fmt.flag(request)
                if reason:
                    flagged.setdefault(reason, []).append(request.n + offset)
        with open(out / f"{fmt.name}.truth.jsonl", "w", encoding="utf-8",
                  newline="\n") as fh:
            fh.write(json.dumps(dict(truth_header,
                                     source_file_id=f"{fmt.name}.log"),
                                separators=(",", ":")) + "\n")
            for record in records:
                fh.write(json.dumps(dict(record,
                                         line_no=record["line_no"] + offset),
                                    separators=(",", ":")) + "\n")
        entries[fmt.name] = {
            "file": f"{fmt.name}.log",
            "truth": f"{fmt.name}.truth.jsonl",
            "lines": len(requests) + offset,
            "records": len(requests),
            "header_lines": offset,
            "line_no_offset": offset,
            "lower_bound_fields": list(fmt.lower_bound),
            "flagged": {k: v for k, v in sorted(flagged.items())},
        }

    manifest = {
        "kind": "logforge-rendered",
        "version": 1,
        "description": DESCRIPTION,
        "rendered_from": "access.log",
        "rules": "docs/rendered-formats.md",
        "lines": len(requests),
        "flags": {
            "rendered_as_server_rejects": (
                "a request line this server refuses, written as it writes the "
                "refusal rather than as Apache received it"),
            "server_would_not_log": (
                "a line this server would not have written at all: a request "
                "line it rejects before logging, or Apache's own dummy "
                "connection"),
            "kept_as_received": (
                "a malformed request line written as received, where the "
                "server logs it but its exact handling is not documented"),
        },
        "formats": entries,
    }
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=1) + "\n",
                                       encoding="utf-8")
    names = sorted(p.name for p in out.iterdir() if p.name != "SHA256SUMS")
    (out / "SHA256SUMS").write_text(
        "".join(f"{_digest(out / name)}  {name}\n" for name in names),
        encoding="utf-8")
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dataset", type=Path)
    args = parser.parse_args(argv)

    manifest = json.loads((args.dataset / "MANIFEST.json").read_text())
    scenario = tomllib.loads((REPO / manifest["scenario_file"]).read_text())
    project = REPO / "projects" / manifest["project"]
    sys.path.insert(0, str(project / "attacks"))
    from toolruns import TOOL_RUNS  # noqa: PLC0415 - per-project module

    try:
        rendered = render_dataset(
            args.dataset, timeline=scenario["timeline"], seed=scenario["seed"],
            unpaced=frozenset(run.address for run in TOOL_RUNS))
    except RenderRefused as refusal:
        print(f"REFUSED: {refusal}", file=sys.stderr)
        return 1

    print(f"{args.dataset / 'rendered'}  ({rendered['lines']:,} records each)")
    for name, entry in rendered["formats"].items():
        flags = ", ".join(f"{k} {len(v)}" for k, v in entry["flagged"].items())
        print(f"  {name:26} {entry['lines']:>9,} lines  +{entry['line_no_offset']}"
              f"  {flags or 'none flagged'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
