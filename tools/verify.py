#!/usr/bin/env python3
"""Check a dataset, and print every number a consumer should look at.

    python3 tools/verify.py datasets/apache-shopfront/2026-08-16-small

Fails loudly. No dataset is finished until this passes and its output has been
read by a person.

It does three jobs:

**Integrity.** The truth file must describe the log it ships with -- one record
per line, addresses matching, categories in the vocabulary, episode groups
contiguous per client, and every line parsing as Apache Combined. Any failure
here means the labels cannot be trusted and the run is not shippable.

**Provenance.** The project README and the dataset README must both carry a
complete "How this dataset was produced" section, and every tool named in the
manifest must appear in its attack-tool table. A dataset that cannot say how it
was made does not ship.

**Realism, reported rather than judged.** Every statistic is printed with no
pass mark attached. A number that came out worse than hoped is printed
unchanged, because a dataset that claims realism it does not have is worse than
one that is honest about its limits -- the first one gets trusted.

Standard library only, by project rule.
"""

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from shared.clients.ippools import is_allowed  # noqa: E402
from shared.truth.reader import TruthFormatError, read_truth  # noqa: E402
from shared.truth.validate import validate_records  # noqa: E402
from shared.verify.agreement import compare_logs  # noqa: E402
from shared.verify.combined import parse_line  # noqa: E402
from shared.verify.provenance import check_provenance  # noqa: E402
from shared.verify.stats import summarise  # noqa: E402
from shared.verify.tells import audit  # noqa: E402
from shared.verify.tells import summary as audit_summary  # noqa: E402

REQUIRED_FILES = ("access.log", "truth.jsonl", "MANIFEST.json", "README.md")

#: Apache's own internal dummy connections come from here. They are real lines
#: that every Apache log contains, they are kept deliberately, and they are the
#: one address exempt from the client-range check.
LOOPBACK = "127.0.0.1"


class Failure(Exception):
    pass


def load(dataset):
    missing = [name for name in REQUIRED_FILES if not (dataset / name).exists()]
    if missing:
        raise Failure(f"{dataset} is missing {', '.join(missing)}")

    lines = (dataset / "access.log").read_text(
        encoding="utf-8", errors="replace").splitlines()
    try:
        header, records = read_truth(dataset / "truth.jsonl")
    except TruthFormatError as exc:
        raise Failure(str(exc)) from None
    manifest = json.loads((dataset / "MANIFEST.json").read_text())

    # A dataset whose manifest says the clock was rewritten but which does not
    # ship the capture is a dataset with no way back to what Apache wrote.
    # That is not a realism defect to print; it is a missing file.
    clock = manifest.get("timestamps", {})
    if clock.get("remapped"):
        absent = [name for name in (clock.get("capture_file"),
                                    clock.get("capture_truth_file"))
                  if name and not (dataset / name).exists()]
        if absent:
            raise Failure(
                f"{dataset} says its timestamps were rewritten but is missing "
                f"the capture it was rewritten from: {', '.join(absent)}")

    return lines, header, list(records), manifest


def integrity(lines, truth_records):
    """Everything that must be true, or the labels cannot be trusted."""
    problems = []

    parsed = [parse_line(line) for line in lines]
    unparseable = [n for n, p in enumerate(parsed, 1) if p is None]
    if unparseable:
        problems.append(
            f"{len(unparseable)} line(s) do not parse as Apache Combined, "
            f"first at line {unparseable[0]}")

    good = [p for p in parsed if p]
    problems.extend(validate_records(truth_records,
                                     (p["client_ip"] for p in good)))

    outside = {p["client_ip"] for p in good
               if p["client_ip"] != LOOPBACK and not is_allowed(p["client_ip"])}
    if outside:
        problems.append(
            f"{len(outside)} client address(es) outside the reserved "
            f"documentation and shared ranges: {sorted(outside)[:5]}")

    return problems, good


def provenance(dataset, manifest, repo, project):
    problems = []
    tools = [run.get("tool") for run in manifest.get("tool_runs", [])
             if run.get("tool")]

    for label, path in (("dataset", dataset / "README.md"),
                        ("project", repo / "projects" / project / "README.md")):
        if not path.exists():
            problems.append(f"the {label} README is missing: {path}")
            continue
        for problem in check_provenance(path.read_text(encoding="utf-8"),
                                        tool_names=tools):
            problems.append(f"{label} README: {problem}")
    return problems


def _print_block(title, mapping, indent="  "):
    print(f"\n{title}")
    for key, value in mapping.items():
        if isinstance(value, dict):
            print(f"{indent}{key}")
            for inner, number in value.items():
                print(f"{indent}  {inner:<28} {number}")
        else:
            print(f"{indent}{key:<30} {value}")


def report(dataset, records, truth_records, manifest):
    stats = summarise(records, truth_records)

    print(f"\n=== {dataset.name} ===")
    print(f"  lines                          {stats['lines']}")
    print(f"  seed                           {manifest.get('seed')}")
    print(f"  commit                         {manifest.get('commit')}")

    clock = manifest.get("timestamps", {})
    print(f"\nclock")
    if clock.get("remapped"):
        print(f"  timestamps                     rewritten "
              f"(capture kept as {clock['capture_file']})")
        print(f"  window                         {clock.get('start')} .. "
              f"{clock.get('end')}")
        print(f"  sessions pushed to avoid overlap "
              f"{clock.get('sessions_pushed')} of {clock.get('sessions')}")
    else:
        print("  timestamps                     as captured")

    # Against the capture, never the shipped log, when the clock was rewritten.
    # Comparing a deliberately rewritten log with Apache's own would diverge on
    # every line and say nothing about the labelling mechanism, which is the
    # only thing this check is about.
    capture = dataset / clock.get("capture_file", "access.log")
    agreement = compare_logs(capture, dataset / "access.apache.log")
    print(f"\nderived vs the log Apache wrote independently "
          f"({capture.name})")
    print(f"  {agreement.summary()}")

    print(f"\nlabelling")
    print(f"  unmatched request ids          "
          f"{manifest.get('unmatched_request_ids')}")
    print(f"  labelled by reserved address   "
          f"{manifest.get('address_fallback_lines')}")
    print(f"  unparsed log lines             "
          f"{manifest.get('unparsed_log_lines')}")

    _print_block("category shares", stats["category_shares"])
    print(f"\n  attack share                   {stats['attack_share']}")
    _print_block("attack overlap with ordinary traffic",
                 stats["attack_overlap"])
    _print_block("status distribution", stats["status_distribution"])
    _print_block("method distribution", stats["method_distribution"])
    _print_block("response shapes", stats["response_shapes"])
    _print_block("client concentration", stats["client_concentration"])
    _print_block("user agents", stats["user_agents"])
    _print_block("referer", stats["referer_share"])
    findings = audit(records)
    counts = audit_summary(findings)
    print(f"\nfake-log audit ({counts['tells_fired']} of "
          f"{counts['tells_checked']} tells fired)")
    for finding in findings:
        mark = "?" if finding.inconclusive else ("HIT" if finding.suspicious
                                                 else ".")
        print(f"  {mark:>3}  {finding.name:<32} {finding.measured!r}")

    _print_block("timespan", stats["timespan"])
    _print_block("inter-arrival", stats["inter_arrival"])
    _print_block("episodes", stats["episodes"])
    return stats


def verify(dataset, repo=REPO, project=None):
    dataset = Path(dataset)
    lines, header, truth_records, manifest = load(dataset)
    project = project or manifest.get("project")

    problems, records = integrity(lines, truth_records)
    problems.extend(provenance(dataset, manifest, repo, project))

    stats = report(dataset, records, truth_records, manifest)

    if problems:
        print(f"\nFAILED -- {len(problems)} problem(s):", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1, stats

    print("\nPASSED -- every integrity and provenance check.")
    return 0, stats


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset")
    parser.add_argument("--project", default=None)
    args = parser.parse_args(argv)
    try:
        code, _ = verify(args.dataset, project=args.project)
    except Failure as exc:
        print(f"verify failed: {exc}", file=sys.stderr)
        return 1
    return code


if __name__ == "__main__":
    sys.exit(main())
