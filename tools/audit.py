#!/usr/bin/env python3
"""Audit a log for the tells that mark it as generated.

    python3 tools/audit.py datasets/apache-shopfront/2026-08-16-small
    python3 tools/audit.py /var/log/apache2/access.log
    python3 tools/audit.py a-dataset --compare access.raw.log

Takes a dataset directory or any Combined-format log file, ours or somebody
else's, and reports what an analyst trying to work out whether it was
generated would find.

It is pointed at our own datasets first and hardest, and it does find things.
A remapped log is sorted by construction, so `perfectly_ordered_timestamps`
fires on every one we ship; our client addresses come from the documentation
ranges, so `sequential_client_addresses` fires too. Both are already in the
dataset README, and the point of owning the detector is that they are found
here rather than by a reader.

`--compare` runs the audit over a second file in the same dataset and prints
them side by side. Its use is on a remapped dataset: `access.raw.log` is what
the server wrote and `access.log` is what we rewrote, so the difference
between the two columns is exactly what the rewrite cost and what it bought.

Exit status is 0 whatever it finds. This reports; `tools/verify.py` is what
fails a build.

Standard library only, by project rule.
"""

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from shared.verify.combined import parse_line  # noqa: E402
from shared.verify.tells import audit, summary  # noqa: E402


def load(target, name="access.log"):
    """Return (path, parsed records, unparsed count) for a file or dataset."""
    path = Path(target)
    if path.is_dir():
        path = path / name
    if not path.exists():
        raise SystemExit(f"audit: no such log: {path}")

    parsed = [parse_line(line) for line in
              path.read_text(encoding="utf-8", errors="replace").splitlines()]
    return path, [p for p in parsed if p], sum(1 for p in parsed if p is None)


def _mark(finding):
    if finding.inconclusive:
        return "  ?"
    return "HIT" if finding.suspicious else "  ."


def report(path, findings, unparsed, verbose=False):
    counts = summary(findings)
    print(f"\n=== {path} ===")
    print(f"  {counts['tells_checked']} tells checked, "
          f"{counts['tells_fired']} fired, "
          f"{counts['inconclusive']} inconclusive, "
          f"{unparsed} lines unparsed")
    print()
    for finding in findings:
        print(f"  {_mark(finding)}  {finding.name:<32} "
              f"measured {finding.measured!r:<22} "
              f"threshold {finding.threshold!r}")
        if verbose or finding.suspicious:
            for line in _wrap(finding.explanation, 68):
                print(f"          {line}")
            print()
    return counts


def _wrap(text, width):
    words, line, out = text.split(), "", []
    for word in words:
        if len(line) + len(word) + 1 > width:
            out.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    if line:
        out.append(line)
    return out


def compare(rows_a, rows_b, name_a, name_b):
    """Two audits side by side, which is the useful view on a remapped
    dataset: what the rewrite fixed, and what it introduced."""
    print(f"\n=== {name_a}  vs  {name_b} ===\n")
    print(f"  {'tell':<32} {'captured':>12} {'shipped':>12}   changed")
    by_name_a = {f.name: f for f in rows_a}
    for finding in rows_b:
        other = by_name_a.get(finding.name)
        moved = "" if other and other.suspicious == finding.suspicious \
            else "  <-- changed"
        print(f"  {finding.name:<32} "
              f"{_mark(other) if other else '   -':>12} "
              f"{_mark(finding):>12}{moved}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="a dataset directory or a log file")
    parser.add_argument("--log", default="access.log",
                        help="which file inside a dataset directory to audit")
    parser.add_argument("--compare", default=None,
                        help="a second file in the same dataset to audit "
                             "alongside, e.g. access.raw.log")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="explain every tell, not only the ones that fired")
    args = parser.parse_args(argv)

    path, records, unparsed = load(args.target, args.log)
    findings = audit(records)
    report(path, findings, unparsed, args.verbose)

    if args.compare:
        other_path, other_records, other_unparsed = load(args.target,
                                                         args.compare)
        other = audit(other_records)
        report(other_path, other, other_unparsed, args.verbose)
        compare(other, findings, other_path.name, path.name)

    return 0


if __name__ == "__main__":
    sys.exit(main())
