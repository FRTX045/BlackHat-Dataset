"""A dataset's own README, as `tools/dataset_readme.py` writes it.

Covered for the audit paragraph, which had a count written into it by hand:
the audit gained a ninth tell and a clean result went on saying "these eight
checks". A count the README states has to be the count that ran.
"""

import unittest

from shared.verify.tells import TELLS
from tools.dataset_readme import _audit_text


def an_audit(fired=()):
    return {"audit": {"findings": [
        {"name": tell.__name__, "measured": 0, "threshold": 1,
         "suspicious": tell.__name__ in fired, "explanation": "."}
        for tell in TELLS]}}


class TestTheAuditParagraph(unittest.TestCase):

    def test_a_clean_result_names_the_checks_that_actually_ran(self):
        self.assertIn(f"these {len(TELLS)} checks", _audit_text(an_audit()))

    def test_a_result_that_fired_says_how_many_ran(self):
        text = _audit_text(an_audit(fired={"perfectly_ordered_timestamps"}))
        self.assertIn(f"runs {len(TELLS)} tells", text)
        self.assertIn("**1 of them fires**", text)


if __name__ == "__main__":
    unittest.main()
