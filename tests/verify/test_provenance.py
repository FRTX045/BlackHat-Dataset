"""The provenance gate.

A dataset must not be able to ship without saying how it was made. This is the
check that makes that true rather than aspirational: it runs in the verifier,
and a missing or empty subsection fails the build.

It deliberately accepts an explicit "None -- ..." for a subsection that genuinely
does not apply to a project, and deliberately does not accept a heading with
nothing under it. The difference is between a project that has no tool-driven
attacks and one that forgot to write the section.
"""

import unittest

from shared.verify.provenance import REQUIRED_SUBSECTIONS, check_provenance

GOOD = """
# Some dataset

## How this dataset was produced

### Server stack
Apache 2.4.68 in Docker, built from php:8.3-apache (sha256:abc).

### The application
A PHP shopfront, vulnerable in eight documented places.

### How the traffic was generated
1,800 sessions across seven personas.

### Which tools produced the attack traffic
| Tool | Version | Source IP | Invocations | Target |
|---|---|---|---|---|
| sqlmap | 1.7 | 192.0.2.31 | 1 | /search |

### How the labels were produced
Every request carries an X-Request-Id. 64490/64494 lines agreed.

### How to rebuild it
python3 tools/build.py apache-shopfront small
"""


def without(section):
    return GOOD.replace(f"### {section}", f"### {section}-renamed")


def emptied(section):
    lines = GOOD.splitlines()
    out = []
    skipping = False
    for line in lines:
        if line.startswith("### "):
            skipping = line == f"### {section}"
            out.append(line)
            continue
        if skipping and line.strip():
            continue
        out.append(line)
    return "\n".join(out)


class TestAcceptance(unittest.TestCase):

    def test_a_complete_section_passes(self):
        self.assertEqual(check_provenance(GOOD), [])

    def test_all_six_subsections_are_required(self):
        self.assertEqual(len(REQUIRED_SUBSECTIONS), 6)

    def test_an_explicit_none_is_accepted_for_a_subsection(self):
        text = GOOD.replace(
            "| sqlmap | 1.7 | 192.0.2.31 | 1 | /search |",
            "None - this project uses only hand-written attacks.")
        self.assertEqual(check_provenance(text), [])


class TestRejection(unittest.TestCase):

    def test_a_missing_top_level_section_fails(self):
        text = GOOD.replace("## How this dataset was produced", "## Notes")
        errors = check_provenance(text)
        self.assertTrue(errors)
        self.assertIn("How this dataset was produced", errors[0])

    def test_each_missing_subsection_is_reported_by_name(self):
        for section in REQUIRED_SUBSECTIONS:
            with self.subTest(section=section):
                errors = check_provenance(without(section))
                self.assertTrue(errors, f"{section} was not required")
                self.assertTrue(any(section in e for e in errors))

    def test_an_empty_subsection_fails_even_though_the_heading_is_there(self):
        # The failure mode this exists to catch: a scaffolded template that
        # nobody filled in still has every heading.
        for section in REQUIRED_SUBSECTIONS:
            with self.subTest(section=section):
                errors = check_provenance(emptied(section))
                self.assertTrue(errors, f"{section} may be left empty")

    def test_every_problem_is_reported_in_one_pass(self):
        # Fixing one at a time and re-running is a waste of a person's day.
        text = without("Server stack").replace("### How to rebuild it",
                                               "### How to rebuild it-renamed")
        self.assertGreaterEqual(len(check_provenance(text)), 2)

    def test_a_document_with_no_headings_at_all_fails_clearly(self):
        errors = check_provenance("just some prose\n")
        self.assertTrue(errors)


class TestToolTableAgreement(unittest.TestCase):
    """A tool in the manifest and not in the table is a hard failure."""

    def test_a_tool_named_in_the_manifest_must_appear_in_the_table(self):
        errors = check_provenance(GOOD, tool_names=["sqlmap", "nikto"])
        self.assertTrue(any("nikto" in e for e in errors))

    def test_a_table_covering_every_tool_passes(self):
        self.assertEqual(check_provenance(GOOD, tool_names=["sqlmap"]), [])

    def test_no_tools_at_all_is_fine(self):
        self.assertEqual(check_provenance(GOOD, tool_names=[]), [])


if __name__ == "__main__":
    unittest.main()
