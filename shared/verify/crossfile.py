"""Checks on the relationships between the files a dataset ships.

`validate_records` answers "does this truth file describe this log". That is
necessary and it is not sufficient for a dataset that ships more than one of
each. A remapped dataset ships the log the server wrote, the log we rewrote,
Apache's own independently written copy, two truth files and a committed
sample, and the interesting failures live in the relationships between them:

- a remap that dropped or duplicated a line
- a remap that rewrote something other than the timestamp field
- a truth file that describes the other log
- a sample that is not actually a slice of what it names

Every one of those would have passed every check that existed before this
module, because each file was individually consistent. They are cheap to check
and expensive to discover later, and one of them -- the shipped log being a
permutation of the capture and nothing more -- is the entire promise the
timestamp remap makes.

Stdlib only.
"""

import collections
import json

from shared.truth.reader import TruthFormatError, read_truth
from shared.truth.validate import validate_records
from shared.verify.combined import parse_line


def _lines(path):
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def _without_timestamp(line):
    """The line with its bracketed timestamp field removed.

    Split on the brackets rather than parsed, so a line the Combined parser
    cannot read is still comparable -- those lines are a real and deliberate
    part of these datasets and dropping them here would blind the check to
    exactly the traffic that is hardest to get right.
    """
    head, _, rest = line.partition("[")
    _, _, tail = rest.partition("]")
    return head + tail


def check_dataset(dataset):
    """Return a list of problems. Empty means the files agree with each other."""
    problems = []
    shipped_path = dataset / "access.log"
    if not shipped_path.exists():
        return [f"{dataset} has no access.log"]
    shipped = _lines(shipped_path)

    raw_path = dataset / "access.raw.log"
    remapped = raw_path.exists()

    if remapped:
        raw = _lines(raw_path)
        if len(raw) != len(shipped):
            problems.append(
                f"access.log has {len(shipped):,} lines but access.raw.log "
                f"has {len(raw):,}: the remap changed the line count")
        elif (collections.Counter(_without_timestamp(x) for x in shipped)
              != collections.Counter(_without_timestamp(x) for x in raw)):
            problems.append(
                "access.log is not a permutation of access.raw.log once "
                "timestamps are set aside: the remap rewrote something other "
                "than the timestamp field")

    tagged_path = dataset / "access.tagged.log"
    reference = raw_path if remapped else shipped_path
    if tagged_path.exists():
        tagged = _lines(tagged_path)
        expected = _lines(reference)
        if len(tagged) != len(expected):
            problems.append(
                f"access.tagged.log has {len(tagged):,} lines but "
                f"{reference.name} has {len(expected):,}")
        else:
            stripped = [x.split(" ", 1)[1] if " " in x else x for x in tagged]
            if stripped != expected:
                problems.append(
                    f"{reference.name} is not access.tagged.log with the "
                    f"request-id prefix removed")

    apache_path = dataset / "access.apache.log"
    if apache_path.exists():
        n = len(_lines(apache_path))
        if n != len(_lines(reference)):
            problems.append(
                f"access.apache.log has {n:,} lines but {reference.name} has "
                f"{len(_lines(reference)):,}")

    # Each truth file against its own log.
    pairs = [("access.log", "truth.jsonl")]
    if remapped:
        pairs.append(("access.raw.log", "truth.raw.jsonl"))
    for log_name, truth_name in pairs:
        truth_path = dataset / truth_name
        if not truth_path.exists():
            problems.append(f"{truth_name} is missing")
            continue
        try:
            _, records = read_truth(truth_path)
            errors = validate_records(
                list(records),
                (p["client_ip"] if p else None
                 for p in (parse_line(x) for x in _lines(dataset / log_name))))
        except TruthFormatError as exc:
            problems.append(f"{truth_name}: {exc}")
            continue
        if errors:
            problems.append(
                f"{truth_name} does not describe {log_name}: {errors[0]}")

    # Both truth files must carry the same labels: the remap reorders records,
    # it does not relabel them.
    if remapped and (dataset / "truth.raw.jsonl").exists():
        try:
            _, a = read_truth(dataset / "truth.jsonl")
            _, b = read_truth(dataset / "truth.raw.jsonl")
            if (collections.Counter((r["client_ip"], r["category"]) for r in a)
                    != collections.Counter(
                        (r["client_ip"], r["category"]) for r in b)):
                problems.append(
                    "truth.jsonl and truth.raw.jsonl carry different labels; "
                    "the remap reorders records, it must not relabel them")
        except (TruthFormatError, KeyError) as exc:
            problems.append(f"comparing the two truth files failed: {exc}")

    stamps = [p["ts"] for p in (parse_line(x) for x in shipped) if p]
    if stamps != sorted(stamps):
        problems.append(
            "timestamps in access.log go backwards; the shipped log is sorted "
            "by construction and this means the sort did not happen")

    problems.extend(_check_sample(dataset, shipped))
    return problems


def _check_sample(dataset, shipped):
    """The committed sample must be a genuine contiguous slice.

    A sample assembled from scattered lines would misrepresent the density and
    the session structure of the thing it is a sample of, which is most of
    what somebody reads a sample to find out.
    """
    sample_path = dataset / "sample.log"
    if not sample_path.exists():
        return []

    problems = []
    sample = _lines(sample_path)
    if not sample:
        return ["sample.log is empty"]

    # Every position the sample could start at, not just the first.
    #
    # Real logs repeat lines constantly -- the same address, second, path,
    # status and size -- and at a million lines it is close to certain that
    # the sample's first line appears earlier too. Anchoring on the first
    # occurrence finds the wrong one and reports a perfectly good sample as
    # corrupt, which is what happened on the first large build.
    contiguous = False
    start = -1
    while True:
        try:
            start = shipped.index(sample[0], start + 1)
        except ValueError:
            break
        if shipped[start:start + len(sample)] == sample:
            contiguous = True
            break
    if not contiguous:
        problems.append(
            "sample.log is not a contiguous slice of access.log")

    truth_path = dataset / "sample.truth.jsonl"
    if not truth_path.exists():
        return problems
    try:
        header, records = read_truth(truth_path)
        records = list(records)
    except TruthFormatError as exc:
        return problems + [f"sample.truth.jsonl: {exc}"]

    if header.get("source_file_id") != "sample.log":
        problems.append(
            f"sample.truth.jsonl names {header.get('source_file_id')!r} as its "
            f"source rather than sample.log")
    if [r["line_no"] for r in records] != list(range(1, len(sample) + 1)):
        problems.append(
            "sample.truth.jsonl is not renumbered from 1 to the sample's "
            "length, so it is a fragment rather than a truth file")
    for n, (line, record) in enumerate(zip(sample, records), 1):
        parsed = parse_line(line)
        if parsed and parsed["client_ip"] != record.get("client_ip"):
            problems.append(
                f"sample.truth.jsonl line {n} names "
                f"{record.get('client_ip')!r} but sample.log has "
                f"{parsed['client_ip']!r}")
            break
    return problems
