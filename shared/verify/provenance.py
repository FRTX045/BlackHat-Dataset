"""The release gate: a dataset cannot ship without saying how it was made.

How the data was produced has to be readable from the repository without
running anything, for every project, present and future. This module is what
makes that a build failure rather than a good intention -- `tools/verify.py`
calls it, and a missing or empty subsection stops the release.

The distinction it draws is between a project that genuinely has nothing to say
under a heading and one that forgot to write it. An explicit
`None - this project uses only hand-written attacks` is accepted; a heading with
nothing beneath it is not, because that is exactly what a scaffolded template
looks like before anybody fills it in.

Stdlib only.
"""

import re

SECTION = "How this dataset was produced"

#: Checked by name, in this order. Every project's README and every dataset's
#: README carries all six, and `tools/new_project.py` scaffolds them so nginx
#: and everything after it inherits the obligation.
REQUIRED_SUBSECTIONS = (
    "Server stack",
    "The application",
    "How the traffic was generated",
    "Which tools produced the attack traffic",
    "How the labels were produced",
    "How to rebuild it",
)

_HEADING = re.compile(r"^(#{2,4})\s+(.*?)\s*$", re.MULTILINE)


def _sections(text):
    """Map heading text to the body beneath it, up to the next heading."""
    found = {}
    matches = list(_HEADING.finditer(text))
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        found[match.group(2)] = text[start:end].strip()
    return found


def check_provenance(text, tool_names=()):
    """Return a list of reasons this document fails the gate. Empty means pass.

    Args:
        text: the README's contents.
        tool_names: tools the manifest says ran. Each must be named in the
            attack-tool table, because a tool that produced lines in the
            dataset and appears nowhere in its documentation is precisely the
            gap this gate exists to close.

    Every problem is reported in one pass. Fixing them one at a time and
    re-running the build is a waste of a person's day.
    """
    errors = []
    sections = _sections(text)

    if SECTION not in sections:
        errors.append(
            f'missing the "{SECTION}" section: a dataset must say how it was '
            f'made, and this document does not')

    for name in REQUIRED_SUBSECTIONS:
        if name not in sections:
            errors.append(f'missing subsection "### {name}"')
        elif not sections[name]:
            errors.append(
                f'subsection "### {name}" is empty. If it genuinely does not '
                f'apply, say so explicitly -- "None - ..." is accepted, a blank '
                f'heading is not')

    table = sections.get("Which tools produced the attack traffic", "")
    for tool in tool_names:
        if tool.lower() not in table.lower():
            errors.append(
                f'tool "{tool}" produced traffic in this dataset but is not '
                f'named in the attack-tool table')

    return errors
