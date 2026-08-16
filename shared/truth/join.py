"""Join the tagged log Apache wrote to the ledgers the traffic wrote.

This produces the two files that ship, and it is the step the dataset's
credibility rests on. Getting it subtly wrong leaves every line looking
plausible and nothing downstream able to notice, so the failure modes are
treated differently on purpose:

- Something that means the labelling machinery is broken -- a ledger claiming a
  different client address than the log line, a category outside the vocabulary
  -- raises. The build stops. Every label after such a line is suspect and
  publishing them would be worse than publishing nothing.
- Something that is merely an absence -- a request id with no ledger record, a
  line Apache wrote that does not parse -- is labelled `unknown` and *counted*.
  The count is reported so it can be published rather than hidden.

The shipped access.log is the tagged log with its id prefix removed, written
out verbatim. Line N of it and line N of truth.jsonl are therefore the same
request by construction, at any amount of concurrency, with no ordering
assumption anywhere.
"""

import json
from typing import NamedTuple

from shared.truth.writer import CATEGORIES, TruthWriter
from shared.verify.combined import parse_tagged

#: Apache writes this when the request carried no X-Request-Id header -- a
#: request line malformed enough to be rejected before mod_remoteip ran, for
#: instance. Such a line is real and must ship; it simply cannot be joined.
NO_ID = "-"

UNKNOWN = "unknown"


class JoinReport(NamedTuple):
    lines: int
    unmatched_ids: int
    unparsed_lines: int
    derived_path: object
    truth_path: object


def _load_ledgers(paths):
    """Index every ledger record by request id.

    The one thing here that is not streamed, because the join needs random
    access by id and the log's order is not the ledgers' order. At a million
    lines this is on the order of a couple of hundred megabytes; the number is
    worth measuring and stating rather than describing this as streaming, which
    it is not.
    """
    entries = {}
    for path in paths:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    entry = json.loads(line)
                    entries[entry["request_id"]] = entry
    return entries


class _EpisodeCounter:
    """Assign instance ids to traffic whose ledger did not carry one.

    Ids are handed out in *log* order, incrementing whenever a client's
    category changes. Log order is the only order the truth file is read in, so
    doing it here makes episode groups contiguous by construction rather than
    by hope -- which is precisely what the validator checks.
    """

    def __init__(self):
        self._seq = {}
        self._current = {}

    def id_for(self, client_ip, category):
        if self._current.get(client_ip) != category:
            self._seq[client_ip] = self._seq.get(client_ip, 0) + 1
            self._current[client_ip] = category
        return f"{client_ip}#{self._seq[client_ip]}"


def join(tagged_log_path, ledger_paths, truth_out, access_out, header_kwargs,
         labeller=None):
    """Derive access.log and truth.jsonl from the tagged log and the ledgers.

    Args:
        tagged_log_path: the log Apache wrote with the id prefix.
        ledger_paths: one or more JSON Lines ledgers keyed by request_id.
        truth_out: where to write truth.jsonl.
        access_out: where to write the derived access.log.
        header_kwargs: passed to TruthWriter (scenario, seed, ...).
        labeller: called with a ledger entry to derive a category when the
            entry carries none. The proxy cannot know whether a request is
            reconnaissance or injection; the project's labels module can tell
            from the request itself.

    Returns:
        A JoinReport.

    Raises:
        ValueError: if a ledger contradicts the log, or names a category
            outside the controlled vocabulary.
    """
    entries = _load_ledgers(ledger_paths)
    episodes = _EpisodeCounter()
    lines = unmatched = unparsed = 0

    with open(tagged_log_path, "r", encoding="utf-8") as tagged, \
            open(access_out, "w", encoding="utf-8") as access, \
            open(truth_out, "w", encoding="utf-8") as truth_fh:
        writer = TruthWriter(truth_fh, **header_kwargs)

        for raw in tagged:
            if not raw.strip():
                continue
            request_id, record, remainder = parse_tagged(
                raw, with_remainder=True)

            # Written before anything can go wrong with the label: the shipped
            # log is what Apache wrote, and a line missing from it would shift
            # every line number after it.
            access.write(remainder + "\n")
            lines += 1

            if record is None:
                unparsed += 1

            entry = entries.get(request_id) if request_id != NO_ID else None
            if entry is None:
                unmatched += 1
                client_ip = record["client_ip"] if record else NO_ID
                writer.write(client_ip=client_ip, category=UNKNOWN,
                             instance_id=episodes.id_for(client_ip, UNKNOWN))
                continue

            client_ip = entry["client_ip"]
            if record is not None and client_ip != record["client_ip"]:
                raise ValueError(
                    f"line {lines}: ledger says request {request_id} came from "
                    f"{client_ip!r} but Apache logged {record['client_ip']!r}. "
                    f"The trust boundary or the proxy is broken; every label "
                    f"from here on is unsafe."
                )

            category = entry.get("category")
            if category is None:
                category = labeller(entry) if labeller else UNKNOWN
            if category not in CATEGORIES:
                raise ValueError(
                    f"line {lines}: request {request_id} was labelled "
                    f"{category!r}, which is not in the controlled vocabulary"
                )

            instance_id = entry.get("instance_id")
            if instance_id is None:
                instance_id = episodes.id_for(client_ip, category)

            writer.write(client_ip=client_ip, category=category,
                         instance_id=instance_id)

    return JoinReport(lines=lines, unmatched_ids=unmatched,
                      unparsed_lines=unparsed, derived_path=access_out,
                      truth_path=truth_out)
