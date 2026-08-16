"""Streaming reader for a `weblog-truth` JSON Lines file.

Returns the header eagerly (it is one line and every caller needs it) and the
records lazily, so a ten-million-line truth file can be walked without being
loaded.
"""

import json

_REQUIRED_HEADER_FIELDS = (
    "kind", "version", "scenario", "seed", "source_file_id",
    "granularity", "generated_at",
)

#: A header claiming a record count is not one of ours. Accepting it would
#: reintroduce exactly the disagreement the format exists to prevent.
_FORBIDDEN_HEADER_FIELDS = ("total", "count", "lines", "n_records")


class TruthFormatError(ValueError):
    """The file is not a well-formed truth file."""


def read_truth(source):
    """Open a truth file and return ``(header, records)``.

    Args:
        source: a path, or an already-open text file object.

    Returns:
        A tuple of the header dict and a lazy iterator of record dicts.

    Raises:
        TruthFormatError: if the header is missing, unparseable, missing a
            required field, or carries a record count. Malformed records raise
            during iteration, naming the physical line.
    """
    if hasattr(source, "readline"):
        fh, owned = source, False
    else:
        fh, owned = open(source, "r", encoding="utf-8"), True

    try:
        first = fh.readline()
    except Exception:
        if owned:
            fh.close()
        raise

    if not first.strip():
        if owned:
            fh.close()
        raise TruthFormatError("truth file is empty: no header line")

    try:
        header = json.loads(first)
    except json.JSONDecodeError as exc:
        if owned:
            fh.close()
        raise TruthFormatError(f"header line is not valid JSON: {exc}") from exc

    missing = [f for f in _REQUIRED_HEADER_FIELDS if f not in header]
    if missing:
        if owned:
            fh.close()
        raise TruthFormatError(
            f"header is missing required field(s): {', '.join(missing)}")

    present = [f for f in _FORBIDDEN_HEADER_FIELDS if f in header]
    if present:
        if owned:
            fh.close()
        raise TruthFormatError(
            f"header carries a record count ({', '.join(present)}); the count "
            f"must be derived on read so it cannot contradict the records")

    return header, _records(fh, owned)


def _records(fh, owned):
    line_no = 1  # the header
    try:
        for raw in fh:
            line_no += 1
            if not raw.strip():
                continue
            try:
                yield json.loads(raw)
            except json.JSONDecodeError as exc:
                raise TruthFormatError(
                    f"line {line_no} of the truth file is not valid JSON: {exc}"
                ) from exc
    finally:
        if owned:
            fh.close()
