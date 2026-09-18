"""Streaming JSON Lines ground-truth writer.

The contract is one header line, then exactly one record per log line, in
order. Records are handed to the file object as they are produced rather than
accumulated: at ten million lines, a truth file you must hold in memory before
writing is a truth file you cannot write.
"""

import json

#: The controlled vocabulary. A category outside this set is a bug in the
#: caller's labelling, not a new category -- consumers score against these
#: exact strings and nothing else.
CATEGORIES = frozenset({
    "browsing",           # Ordinary navigation of HTML pages by a person
    "static_asset",       # CSS, JS, images, fonts, favicon
    "api_call",           # XHR/JSON endpoints called by the front-end
    "authentication",     # Legitimate login, logout, registration, reset
    "crawling",           # Well-behaved bots
    "reconnaissance",     # Probing for what exists
    "enumeration",        # Systematic directory or file brute-forcing
    "injection",          # SQLi, command injection, SSTI, XSS payloads
    "path_traversal",     # ../ sequences, LFI, absolute path access
    "access_control",     # IDOR, forced browsing, verb tampering
    "credential_attack",  # Brute force, stuffing, spraying
    "ssrf",               # Making the server fetch an attacker-chosen URL
    "exploitation",       # CVE attempts, webshells, RCE, post-compromise
    "unknown",            # Genuinely unclassifiable
})

_COMPACT = (",", ":")


class TruthWriter:
    """Writes a `logarc-truth` JSON Lines file one record at a time.

    Args:
        fh: any object with a ``write`` method. Not closed by this class.
        scenario: scenario identifier, e.g. ``apache-shopfront-small``.
        seed: the seed the run was built with.
        source_file_id: the log file these records describe, e.g. ``access.log``.
        generated_at: ISO 8601 timestamp with offset.
        kind: read from the scenario config; defaults to ``logarc-truth``.
            Named for the consumer rather than for the format, deliberately:
            `logarc`'s reader refuses any file whose `kind` is not exactly
            this, so a neutral name meant every dataset this repository
            shipped was unreadable by the only tool built to read it. The
            field stays configurable for anything that wants a different one.
        version: truth format version.
        granularity: ``category`` when the producing activity is known -- which
            it always is for datasets built here. ``binary`` exists for
            imported public datasets that only know attack-or-not.
    """

    def __init__(self, fh, *, scenario, seed, source_file_id, generated_at,
                 kind="logarc-truth", version=1, granularity="category"):
        self._fh = fh
        self._line_no = 0
        # No total in the header. A count written up front can disagree with
        # the records beneath it, and then neither can be trusted.
        self._fh.write(json.dumps({
            "kind": kind,
            "version": version,
            "scenario": scenario,
            "seed": seed,
            "source_file_id": source_file_id,
            "granularity": granularity,
            "generated_at": generated_at,
        }, separators=_COMPACT) + "\n")

    def write(self, *, client_ip, category, instance_id):
        """Append one record and return its 1-based ``line_no``.

        Raises:
            ValueError: if ``category`` is outside the controlled vocabulary.
                The line number is not consumed, so a rejected write cannot
                put every later record out of step with the log.
        """
        if category not in CATEGORIES:
            raise ValueError(
                f"category {category!r} is not in the controlled vocabulary; "
                f"expected one of {sorted(CATEGORIES)}"
            )
        self._line_no += 1
        self._fh.write(json.dumps({
            "line_no": self._line_no,
            "client_ip": client_ip,
            "category": category,
            "instance_id": instance_id,
        }, separators=_COMPACT) + "\n")
        return self._line_no

    @property
    def line_count(self):
        """Records written so far. Derived, never stored in the header."""
        return self._line_no
