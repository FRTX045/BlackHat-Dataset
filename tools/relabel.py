#!/usr/bin/env python3
"""Relabel one captured dataset with a different labeller, on the same bytes.

    python3 tools/relabel.py datasets/apache-shopfront/2026-09-07-medium \\
        --ledgers projects/apache-shopfront/traffic/ledger \\
        --baseline-labels /tmp/labels-main.py \\
        --labels projects/apache-shopfront/labels.py \\
        --out /tmp/relabelled

A labelling fix has to be measured on the capture it fixes. Rebuilding would
draw new traffic, and the clock remap reads the labels (episode grouping, which
sessions sit on the human curve, how each gap is drawn), so even the same
capture relabelled end to end would ship a differently timed log. This tool
keeps the shipped `access.log` exactly as it is and projects a candidate
labeller's truth onto it.

It will only do that once the baseline has been proved. Given the labeller the
dataset was built with, it must reproduce the shipped `access.raw.log` and
`truth.raw.jsonl` byte for byte, and a replay of the remap must reproduce the
shipped `access.log` and `truth.jsonl` byte for byte. Only then is the line
permutation the remap applied known, and only then is the candidate's truth
projected through it. A replay that does not match is a finding about
provenance, and the tool stops there rather than presenting a relabelling it
cannot vouch for.

What it will not do is touch its inputs. The output directory must be new and
must not overlap the dataset or the ledgers; every input is hashed before and
after; and work happens in `<out>.partial`, renamed to `<out>` only once every
gate has passed and the report is written. A failed run is renamed to
`<out>.failed` and keeps diagnostics but no truth file. If cleanup itself
fails -- a truth file that cannot be deleted, say -- the error that stopped the
run is still the one raised, its notes name whatever was left behind, and
cleanup never publishes anything at `<out>`. The one way a result sits at
`<out>` while an exception is raised is an interrupt arriving just after the
final rename: that result is complete, cleanup recognises it by the run's
token and leaves it in place, and a note says so.

Neither `<out>` nor `<out>.failed` is replaced if it appears during the run,
but that is a check before each rename, not an atomic guarantee: concurrent
publication to the same destination is unsupported.

Standard library only, by project rule.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import secrets
import shutil
import sys
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from shared.timeline.remap import remap_records  # noqa: E402
from shared.truth.join import NO_ID, join  # noqa: E402
from shared.truth.reader import read_truth  # noqa: E402
from shared.truth.validate import validate_records  # noqa: E402
from shared.verify.combined import LINE_RE, parse_line  # noqa: E402
from tools.build import (ADDRESS_FALLBACK, ledger_paths,  # noqa: E402
                         load_scenario, seeded)

_COMPACT = (",", ":")

#: Dataset files hashed before and after. Missing ones are recorded as such.
_DATASET_FILES = ("access.tagged.log", "access.raw.log", "truth.raw.jsonl",
                  "access.log", "truth.jsonl", "MANIFEST.json")


class RelabelError(Exception):
    """A gate failed, or the run was refused. The message says which."""


# --------------------------------------------------------------------------
# Small pieces
# --------------------------------------------------------------------------

def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def load_labeller(path):
    """Load `categorise` from a labels module given by file, not by import
    path, so a frozen revision (`git show main:...`) can be compared.

    Compiled and executed by hand rather than through the import loader,
    because the loader writes `__pycache__/*.pyc` beside the source -- and the
    source is an input, often in an archive whose inventory matters.
    """
    path = Path(path)
    name = "relabel_labels_" + hashlib.sha256(
        str(path.resolve()).encode()).hexdigest()[:12]
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module.categorise


def build_parameters(repo, manifest):
    """The remap and join parameters the build used, from its manifest.

    Taken from the scenario at this checkout. If the scenario has changed since
    the build, the remap replay gate is what will say so.
    """
    project, tier = manifest["project"], manifest["tier"]
    project_dir = Path(repo) / "projects" / project
    scenario = seeded(load_scenario(project_dir / "scenarios" / f"{tier}.toml"),
                      manifest["seed"])
    sys.path.insert(0, str(project_dir / "attacks"))
    from toolruns import TOOL_RUNS  # noqa: PLC0415 - per-project module
    timeline = scenario["timeline"]
    return {
        "start": datetime.fromisoformat(timeline["start"]),
        "duration_seconds": timeline["duration_seconds"],
        "seed": scenario["seed"],
        "unpaced": frozenset(run.address for run in TOOL_RUNS),
        "address_fallback": dict(ADDRESS_FALLBACK),
    }


def _ancestors(path):
    """`path` and every directory above it that exists."""
    out = []
    for candidate in (path, *path.parents):
        if candidate.exists():
            out.append(candidate)
    return out


def check_out_dir(out, protected):
    """Refuse an output that exists or overlaps a protected input.

    Overlap is decided with `os.path.samefile` on real directories rather than
    by comparing strings: a symlink, a relative path or a case variant on a
    case-insensitive filesystem (`/mnt/d` under WSL is one) all name the same
    directory with a different spelling.

    Refusing any `out` that already exists also rules out `out` being an input
    or containing one, since every input exists: on a case-insensitive
    filesystem a case variant of an existing directory exists too.
    """
    out = Path(os.path.abspath(out))
    for sibling in (out, _partial(out), _failed(out)):
        if os.path.lexists(sibling):
            raise RelabelError(f"{sibling} exists; relabel never overwrites")
    for guarded in protected:
        for above in _ancestors(out):
            if os.path.samefile(above, guarded):
                raise RelabelError(
                    f"{out} is inside {guarded}, which is an input")


def _partial(out):
    return out.with_name(out.name + ".partial")


def _failed(out):
    return out.with_name(out.name + ".failed")


def _read_lines(path):
    # As `remap_files` reads it, so the replay sees the same strings.
    return Path(path).read_text(encoding="utf-8",
                                errors="replace").splitlines()


def _truth(path):
    """Header and every record, with the file closed. `read_truth` streams,
    and a caller that stops early would otherwise leave the file open."""
    with open(path, "r", encoding="utf-8") as fh:
        header, records = read_truth(fh)
        return header, list(records)


def _serialise_truth(header, records):
    parts = [json.dumps(header, separators=_COMPACT)]
    parts += [json.dumps(r, separators=_COMPACT) for r in records]
    return ("\n".join(parts) + "\n").encode("utf-8")


def _without_ts(line):
    match = LINE_RE.match(line.rstrip("\r\n"))
    if match is None:
        return None
    return line[:match.start("ts")] + line[match.end("ts"):]


# --------------------------------------------------------------------------
# Gates
# --------------------------------------------------------------------------

def check_ledgers(paths, tagged_ids):
    """Gate 1. Conflicting duplicate ids raise; unmatched ids are listed.

    The join itself keeps the last record it sees for an id, so a conflict
    between two ledgers would be resolved silently by file order. Here it is
    refused instead.
    """
    seen, identical, unmatched = {}, 0, {}
    for path in paths:
        missing = []
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                entry = json.loads(line)
                rid = entry["request_id"]
                if rid in seen:
                    first_path, first = seen[rid]
                    if first != entry:
                        raise RelabelError(
                            f"request id {rid} appears in {first_path.name} "
                            f"and {path.name} with different content")
                    identical += 1
                else:
                    seen[rid] = (path, entry)
                if rid not in tagged_ids:
                    missing.append(rid)
        unmatched[path.name] = missing
    return {"files": [p.name for p in paths], "entries": len(seen),
            "identical_duplicates": identical, "unmatched": unmatched}, \
        {rid: entry for rid, (_, entry) in seen.items()}


def check_permutation(perm, raw_lines, shipped_lines, raw_records,
                      shipped_records):
    """Gate 4. Return every way `perm` fails to be the remap's reordering.

    `perm[p]` is the capture index of shipped line `p`. It must be a bijection,
    and each pair must be the same request, from the same client, with only its
    timestamp changed.

    A client's own requests may legitimately change order. Apache stamps a
    request when it arrives and writes it when it finishes, so concurrent
    requests reach the capture out of time order (952 clients in
    2026-09-07-medium), and the remap keeps an unpaced tool run's captured
    offsets, which re-sorts it. Whether the projected episodes stay contiguous
    is checked where it matters, by validating the projection.
    """
    errors = []
    n = len(raw_lines)
    if len(perm) != n or len(shipped_lines) != n:
        errors.append(f"{len(perm)} mapped lines, {n} captured, "
                      f"{len(shipped_lines)} shipped")
        return errors
    if sorted(perm) != list(range(n)):
        bad = [i for i in perm if not 0 <= i < n]
        errors.append("not a bijection on the capture"
                      + (f"; out of range: {bad[:5]}" if bad else
                         "; an index repeats"))
        return errors

    for position, index in enumerate(perm):
        shipped_ip = shipped_records[position].get("client_ip")
        if raw_records[index].get("client_ip") != shipped_ip:
            errors.append(f"shipped line {position + 1}: client "
                          f"{shipped_ip!r} is not capture line "
                          f"{index + 1}'s")
        raw, shipped = raw_lines[index], shipped_lines[position]
        stripped = _without_ts(raw)
        if (stripped is None and raw != shipped) or \
                (stripped is not None and stripped != _without_ts(shipped)):
            errors.append(f"shipped line {position + 1} is not capture line "
                          f"{index + 1} with its timestamp changed")
        if len(errors) >= 20:
            break
    return errors


# --------------------------------------------------------------------------
# Diffing
# --------------------------------------------------------------------------

def _cuts(records, order):
    """Every episode boundary, as (client, earlier index, later index) for two
    requests from one client that are neighbours in `order` and carry
    different instance ids.

    `order` is the file's order as capture indices. Boundaries belong to the
    order a truth file is read in, which for the shipped file is not the
    capture's: a client the remap re-sorts has different neighbours.

    Compared instead of the id strings because derived ids are numbered in
    sequence per client: one merge renumbers every later episode, and a string
    diff would report all of those as changes.
    """
    last, cuts = {}, set()
    for index in order:
        record = records[index]
        ip = record["client_ip"]
        if ip in last:
            prior = last[ip]
            if records[prior]["instance_id"] != record["instance_id"]:
                cuts.add((ip, prior, index))
        last[ip] = index
    return cuts


def diff(baseline, candidate, tagged_lines, perm=None):
    """Every category change and every boundary added or removed.

    Without `perm` this is the capture's view; with it, boundaries are read
    in shipped order and every location carries its shipped line number.
    """
    changes = []
    order = range(len(baseline)) if perm is None else perm
    inverse = None
    if perm is not None:
        inverse = [0] * len(perm)
        for position, index in enumerate(perm):
            inverse[index] = position

    def where(index):
        spot = {"raw_line_no": index + 1}
        if inverse is not None:
            spot["shipped_line_no"] = inverse[index] + 1
        return spot

    for index, (old, new) in enumerate(zip(baseline, candidate)):
        if old["category"] != new["category"]:
            rid, _, remainder = tagged_lines[index].partition(" ")
            parsed = parse_line(remainder) or {}
            changes.append({
                "kind": "category", **where(index),
                "request_id": None if rid == NO_ID else rid,
                "client_ip": new["client_ip"],
                "method": parsed.get("method"), "path": parsed.get("path"),
                "status": parsed.get("status"),
                "old": old["category"], "new": new["category"]})

    rank = {index: n for n, index in enumerate(order)}
    before, after = _cuts(baseline, order), _cuts(candidate, order)
    for kind, cuts in (("boundary_removed", before - after),
                       ("boundary_added", after - before)):
        for ip, earlier, later in sorted(
                cuts, key=lambda c: (rank[c[1]], rank[c[2]])):
            changes.append({"kind": kind, "client_ip": ip,
                            "between": [where(earlier), where(later)]})
    return changes


def _summary(changes):
    counts = {}
    for change in changes:
        key = (f"{change['old']} -> {change['new']}"
               if change["kind"] == "category" else change["kind"])
        counts[key] = counts.get(key, 0) + 1
    return {"counts": counts,
            "clients": sorted({c["client_ip"] for c in changes})}


def _write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, separators=_COMPACT) + "\n")


# --------------------------------------------------------------------------
# The run
# --------------------------------------------------------------------------

def relabel(dataset, ledgers, baseline_labels, candidate_labels, out, *,
            start, duration_seconds, seed, unpaced, address_fallback,
            expect_within=None):
    """Run every gate and, if all pass, publish the relabelled truth at `out`.

    Returns the report dict (also written as `report.json`).

    Raises RelabelError when a gate fails or the run is refused. Anything else
    that goes wrong -- an OSError while writing, a KeyboardInterrupt -- is
    raised as itself. Before any of these propagates, `_clean_up_after` runs:
    if the result was already published at `out` (an interrupt just after the
    final rename), or if that cannot be told, it touches nothing and says so
    in a note; otherwise it tries to remove every truth file and move the work
    to `<out>.failed`. That is best effort, and what it could not do is
    attached to the exception as notes. A failure raised before
    `<out>.partial` exists (a refused `out`) leaves nothing to clean up.
    """
    dataset, ledgers = Path(dataset), Path(ledgers)
    out = Path(os.path.abspath(out))
    check_out_dir(out, (dataset, ledgers))

    ledger_files = ledger_paths(ledgers)
    inputs = {f"dataset/{name}": dataset / name for name in _DATASET_FILES
              if (dataset / name).exists()}
    inputs.update({f"ledger/{p.name}": p for p in ledger_files})
    inputs["labels/baseline"] = Path(baseline_labels)
    inputs["labels/candidate"] = Path(candidate_labels)
    hashes = {key: sha256(path) for key, path in inputs.items()}

    work = _partial(out)
    work.mkdir(parents=True)
    report = {}

    try:
        # Identifies this run's report, so cleanup can tell a result this run
        # published from anything else that might sit at `out`.
        report["run_token"] = secrets.token_hex(16)
        report.update({
            "dataset": str(dataset), "ledger_dir": os.path.abspath(ledgers),
            "inputs": hashes,
            "labellers": {"baseline": {"path": str(baseline_labels),
                                       "sha256": hashes["labels/baseline"]},
                          "candidate": {"path": str(candidate_labels),
                                        "sha256": hashes["labels/candidate"]}},
            "parameters": {"start": start.isoformat(),
                           "duration_seconds": duration_seconds, "seed": seed,
                           "unpaced": sorted(unpaced),
                           "address_fallback": address_fallback},
            "gates": {},
        })
        _run(dataset, ledger_files, baseline_labels, candidate_labels, work,
             report, start=start, duration_seconds=duration_seconds,
             seed=seed, unpaced=unpaced, address_fallback=address_fallback,
             expect_within=expect_within)
        changed = [key for key, path in inputs.items()
                   if sha256(path) != hashes[key]]
        report["inputs_unchanged"] = not changed
        if changed:
            raise RelabelError(
                "inputs changed during the run: " + ", ".join(
                    str(inputs[key]) for key in changed))
        _write_report(work, report)
        _rename_without_replacing(work, out)
    except BaseException as exc:
        _clean_up_after(exc, work, out, report)
        raise
    return report


def _rename_without_replacing(source, target):
    """Rename `source` to `target`, refusing if `target` already exists.

    Needed because rename(2) silently replaces an empty target directory.
    This is a check followed by a rename, not an atomic no-overwrite
    operation -- the standard library has none -- so a target created in the
    moment between the two can still be replaced. Concurrent publication to
    the same destination is unsupported; the check exists to catch an output
    that appeared at any earlier point in the run.
    """
    if os.path.lexists(target):
        raise RelabelError(f"{target} appeared during the run; relabel never "
                           f"replaces an existing output")
    source.rename(target)


def _describe(value):
    try:
        return str(value)
    except Exception:  # noqa: BLE001 - describing must not raise
        return f"<unprintable {type(value).__name__}>"


def _publication_state(work, out, token):
    """"unpublished", "published" or "unknown", decided from the disk.

    A flag set after the final rename would leave a window: an interrupt can
    land after rename(2) has returned and before the next statement runs. So
    this looks instead. `<out>.partial` still present means the rename never
    happened. Gone, with `<out>/report.json` carrying this run's token, means
    it did. Anything else -- including a report that cannot be read -- is
    unknown, and unknown is treated like published: nothing is deleted.
    Like the rename check, this assumes nothing else publishes to `out`
    concurrently.
    """
    try:
        if os.path.lexists(work):
            return "unpublished"
        published = json.loads((out / "report.json").read_text("utf-8"))
        return ("published" if published.get("run_token") == token
                else "unknown")
    except Exception:  # noqa: BLE001 - best effort
        return "unknown"


def _clean_up_after(exc, work, out, report):
    """Best-effort cleanup of a failed run. Never raises an Exception.

    First decides from the disk whether this run's result was already
    published at `out` -- an interrupt can arrive just after the final rename.
    If it was, or if that cannot be told, nothing is touched and a note says
    so. Otherwise deletes every truth file, writes a diagnostic report without
    the output hashes (they describe deleted files) and moves the work to
    `<out>.failed` if that name is free. If that report cannot be written,
    any earlier success report is removed so it cannot be mistaken for one.

    Each step that fails is attached to `exc` as a note rather than raised,
    so the error that stopped the run stays the one the caller sees. A truth
    file that cannot be deleted is named in a note at wherever it finally
    rests; nothing here renames to `out`, so it is never published. A
    BaseException raised during cleanup itself -- a second Ctrl-C --
    propagates, with the original as its `__context__`.

    `rglob` skips subdirectories it cannot read, so a truth file inside one
    would go unlisted. Every directory here is one this tool created.
    """
    state = _publication_state(work, out, report.get("run_token"))
    if state == "published":
        exc.add_note(f"the result had already been published at {out} when "
                     f"this happened; it is complete and was left in place")
        return
    if state == "unknown":
        exc.add_note(f"cleanup could not tell whether this run was published "
                     f"at {out}: {work} is gone and {out}/report.json is not "
                     f"this run's; nothing was touched")
        return

    report["failure"] = f"{type(exc).__name__}: {_describe(exc)}"
    report.pop("outputs", None)
    leftover = []
    try:
        strays = sorted(work.rglob("truth*.jsonl"))
    except Exception as err:  # noqa: BLE001 - cleanup must not raise
        strays = []
        exc.add_note(f"cleanup could not list {work}: {_describe(err)}")
    for stray in strays:
        try:
            stray.unlink()
        except Exception as err:  # noqa: BLE001
            leftover.append(stray.relative_to(work))
            exc.add_note(f"cleanup could not delete {stray.name}: "
                         f"{_describe(err)}")
    if leftover:
        report["leftover_truth_files"] = [str(p) for p in leftover]

    try:
        _write_report(work, report)
    except Exception as err:  # noqa: BLE001
        exc.add_note(f"cleanup could not write the diagnostic report: "
                     f"{_describe(err)}")
        try:
            (work / "report.json").unlink(missing_ok=True)
        except Exception as gone:  # noqa: BLE001
            exc.add_note(f"a stale report.json may remain in {work}: "
                         f"{_describe(gone)}")

    rests = work
    failed = _failed(out)
    try:
        _rename_without_replacing(work, failed)
        rests = failed
    except Exception as err:  # noqa: BLE001
        exc.add_note(f"cleanup could not move {work} to {failed}: "
                     f"{_describe(err)}; diagnostics remain in {work}")
    for name in leftover:
        exc.add_note(f"truth file left behind, not published: {rests / name}")


def _write_report(directory, report):
    (directory / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _join_into(dataset, ledger_files, labeller, directory, header,
               address_fallback):
    directory.mkdir()
    header_kwargs = {k: header[k] for k in
                     ("scenario", "seed", "source_file_id", "generated_at",
                      "kind", "version", "granularity") if k in header}
    join(dataset / "access.tagged.log", ledger_files,
         directory / "truth.raw.jsonl", directory / "access.raw.log",
         header_kwargs, labeller=labeller, address_fallback=address_fallback)
    same_log = ((directory / "access.raw.log").read_bytes()
                == (dataset / "access.raw.log").read_bytes())
    (directory / "access.raw.log").unlink()
    return same_log


def _run(dataset, ledger_files, baseline_labels, candidate_labels, work,
         report, *, start, duration_seconds, seed, unpaced, address_fallback,
         expect_within):
    gates = report["gates"]
    tagged_lines = _read_lines(dataset / "access.tagged.log")
    tagged_ids = {line.partition(" ")[0] for line in tagged_lines}

    # Gate 1.
    report["ledgers"], entries = check_ledgers(ledger_files, tagged_ids)
    gates["1_ledgers"] = True

    # Gate 2: the baseline reproduces the capture's truth exactly.
    header, raw_records = _truth(dataset / "truth.raw.jsonl")
    if not _join_into(dataset, ledger_files, load_labeller(baseline_labels),
                      work / "baseline", header, address_fallback):
        gates["2_baseline_join"] = False
        raise RelabelError("the baseline join does not reproduce "
                           "access.raw.log byte for byte")
    if ((work / "baseline" / "truth.raw.jsonl").read_bytes()
            != (dataset / "truth.raw.jsonl").read_bytes()):
        gates["2_baseline_join"] = False
        raise RelabelError("the baseline labeller does not reproduce "
                           "truth.raw.jsonl byte for byte; it is not the "
                           "labeller this dataset was built with, or the "
                           "ledgers are not the ones it was built from")
    gates["2_baseline_join"] = True
    shutil.rmtree(work / "baseline")

    # The candidate, at capture level. Written as diagnostics before any later
    # gate, so a remap that cannot be replayed still leaves the raw diff.
    if not _join_into(dataset, ledger_files, load_labeller(candidate_labels),
                      work / "candidate", header, address_fallback):
        raise RelabelError("the candidate join produced a different "
                           "access.raw.log; the join is not deterministic")
    _, candidate_raw = _truth(work / "candidate" / "truth.raw.jsonl")
    raw_changes = diff(raw_records, candidate_raw, tagged_lines)
    _write_jsonl(work / "changes.raw.jsonl", raw_changes)
    report["changes"] = _summary(raw_changes)

    if expect_within is not None:
        outside = sorted(set(report["changes"]["clients"]) - set(expect_within))
        gates["expected_scope"] = not outside
        if outside:
            raise RelabelError("changes reach clients outside the expected "
                               "set: " + ", ".join(outside))

    # Gate 3: the remap replays exactly, which yields its permutation.
    raw_lines = _read_lines(dataset / "access.raw.log")
    tracked = [dict(record, _src=index)
               for index, record in enumerate(raw_records)]
    new_lines, new_records, _ = remap_records(
        raw_lines, tracked, start=start, duration_seconds=duration_seconds,
        seed=seed, unpaced=unpaced)
    perm = [record.pop("_src") for record in new_records]
    shipped_header, shipped_records = _truth(dataset / "truth.jsonl")
    if (("\n".join(new_lines) + "\n").encode("utf-8")
            != (dataset / "access.log").read_bytes()):
        gates["3_remap_replay"] = False
        raise RelabelError("the remap replay does not reproduce access.log "
                           "byte for byte")
    if (_serialise_truth(shipped_header, new_records)
            != (dataset / "truth.jsonl").read_bytes()):
        gates["3_remap_replay"] = False
        raise RelabelError("the remap replay does not reproduce truth.jsonl "
                           "byte for byte")
    gates["3_remap_replay"] = True

    # Gate 4: the permutation, checked on its own terms.
    shipped_lines = _read_lines(dataset / "access.log")
    errors = check_permutation(perm, raw_lines, shipped_lines, raw_records,
                               shipped_records)
    for index, line in enumerate(tagged_lines):
        rid = line.partition(" ")[0]
        entry = entries.get(rid)
        if entry is not None and \
                entry["client_ip"] != raw_records[index]["client_ip"]:
            errors.append(f"capture line {index + 1}: request {rid} was "
                          f"joined from {entry['client_ip']}")
            break
    if errors:
        gates["4_permutation"] = False
        raise RelabelError("the permutation does not hold: "
                           + "; ".join(errors[:5]))
    gates["4_permutation"] = True
    report["permutation"] = {
        "lines": len(perm),
        "moved_lines": sum(1 for p, i in enumerate(perm) if p != i)}

    # Gate 5: project the candidate and validate it against the shipped log.
    projected = [dict(candidate_raw[index], line_no=position)
                 for position, index in enumerate(perm, 1)]
    ips = [line.split(" ", 1)[0] for line in shipped_lines]
    problems = validate_records(projected, ips)
    if problems:
        gates["5_projection"] = False
        raise RelabelError("the projected truth does not validate: "
                           + "; ".join(problems[:5]))
    gates["5_projection"] = True

    changes = diff(raw_records, candidate_raw, tagged_lines, perm)
    _write_jsonl(work / "changes.jsonl", changes)
    (work / "changes.raw.jsonl").unlink()
    (work / "truth.jsonl").write_bytes(
        _serialise_truth(shipped_header, projected))
    (work / "candidate" / "truth.raw.jsonl").rename(work / "truth.raw.jsonl")
    (work / "candidate").rmdir()
    report["clients_changed"] = report["changes"]["clients"]
    report["outputs"] = {name: sha256(work / name) for name in
                         ("truth.raw.jsonl", "truth.jsonl", "changes.jsonl")}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--ledgers", type=Path, required=True)
    parser.add_argument("--baseline-labels", type=Path, required=True,
                        help="the labeller the dataset was built with")
    parser.add_argument("--labels", type=Path, required=True,
                        help="the candidate labeller")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--expect-within", default=None,
                        help="comma-separated client addresses; fail if any "
                             "other client's labels change")
    args = parser.parse_args(argv)

    manifest = json.loads((args.dataset / "MANIFEST.json").read_text())
    header, _ = _truth(args.dataset / "truth.raw.jsonl")
    if header.get("seed") != manifest.get("seed"):
        raise SystemExit(f"the truth header's seed {header.get('seed')} is "
                         f"not the manifest's {manifest.get('seed')}")
    params = build_parameters(REPO, manifest)
    expect = (frozenset(a.strip() for a in args.expect_within.split(",")
                        if a.strip()) if args.expect_within else None)
    try:
        report = relabel(args.dataset, args.ledgers, args.baseline_labels,
                         args.labels, args.out, expect_within=expect, **params)
    except RelabelError as exc:
        # The notes are where cleanup says what it could not do -- a truth
        # file it failed to delete, a directory it could not move.
        print(f"relabel: {exc}", file=sys.stderr)
        for note in getattr(exc, "__notes__", ()):
            print(f"  {note}", file=sys.stderr)
        return 1
    print(json.dumps({k: report[k] for k in
                      ("gates", "permutation", "changes", "ledgers")},
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
