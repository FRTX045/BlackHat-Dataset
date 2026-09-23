"""What a shipped line may say, as opposed to where it came from.

`tools/verify.py` already fails a dataset whose *client* addresses fall outside
the reserved ranges. This is the other half: a dataset whose *content* names a
lab container. The fields checked are the two a client authors that can carry
a URL -- the request and the Referer.

It exists because the property was enforced one generator at a time, and that
is how it leaked twice. The benign admin import named the server by its bridge
address for a month; once that was fixed, the real-browser personas turned out
to be sending the tag proxy's address and port as the Referer of every
subresource. Each generator had its own test or none. This checks the artifact,
so the next leak fails the build whichever generator produced it.

The client field is deliberately left alone. When an SSRF against a lab host
succeeds, Apache logs the server fetching itself, under its own address, and
VULNERABILITIES.md documents that line as the most reliable tell in the file.

Standard library only, by project rule.
"""

from shared.clients.ippools import infrastructure_named_in

#: Parsed-line field, and what to call it in a problem.
_FIELDS = (("request", "request"), ("referer", "Referer"))


def lab_addresses_in_content(parsed):
    """Problems for shipped lines whose request or Referer names a lab container.

    Args:
        parsed: `shared.verify.combined.parse_line` applied to every line in
            order, with None where a line did not parse. The Nones are kept so
            that the line numbers reported are the file's own.

    Returns one problem per field that has any, empty when there are none.
    """
    tally = {field: [0, None, set()] for field, _ in _FIELDS}
    for number, record in enumerate(parsed, 1):
        if record is None:
            continue
        for field, _ in _FIELDS:
            named = infrastructure_named_in(record.get(field))
            if named:
                entry = tally[field]
                entry[0] += 1
                entry[2] |= named
                if entry[1] is None:
                    entry[1] = number

    problems = []
    for field, label in _FIELDS:
        count, first, named = tally[field]
        if count:
            problems.append(
                f"{count} line(s) carry a {label} naming a lab container "
                f"({', '.join(sorted(named))}), first at line {first}. The "
                f"shipped log calls this server shop.test, and an address that "
                f"exists only inside the lab is not something a visitor could "
                f"have sent.")
    return problems
