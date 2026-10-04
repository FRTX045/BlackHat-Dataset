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

The client field has its own check, `lab_machinery_as_client`, because its
rule is different: two lab containers are clients by design. When an SSRF
against a lab host succeeds, Apache logs the server fetching itself, under its
own address, and VULNERABILITIES.md documents that line as the most reliable
tell in the file. The noise container's malformed requests carry no id and are
labelled by its address. Any other lab container in that field is the lab's
own machinery showing through -- as the tag proxy did once per tier, when it
forwarded nmap's empty probe as a request line made of its own header.

Standard library only, by project rule.
"""

from shared.clients.ippools import INFRASTRUCTURE_ADDRESSES, infrastructure_named_in

#: Lab containers that legitimately appear as a line's client, and why.
_CLIENTS_BY_DESIGN = {
    "203.0.113.2": "the server fetching itself (SSRF)",
    "198.51.100.2": "the server fetching itself (SSRF)",
    "192.0.2.2": "the server fetching itself (SSRF)",
    "203.0.113.6": "the noise container",
}

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


def lab_machinery_as_client(parsed):
    """A problem if any line's client is a lab container not meant to be one.

    Args:
        parsed: as for `lab_addresses_in_content`.

    Returns one problem covering every such line, empty when there are none.
    """
    count, first, named = 0, None, set()
    for number, record in enumerate(parsed, 1):
        if record is None:
            continue
        client = record.get("client_ip")
        if client in INFRASTRUCTURE_ADDRESSES and client not in _CLIENTS_BY_DESIGN:
            count += 1
            named.add(client)
            if first is None:
                first = number
    if not count:
        return []
    return [f"{count} line(s) come from a lab container as the client "
            f"({', '.join(sorted(named))}), first at line {first}. Only the "
            f"server fetching itself and the noise container are clients by "
            f"design; any other lab address in this field is the lab's own "
            f"machinery showing through."]
