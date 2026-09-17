"""What the source tree was when a build ran, and whether that is enough.

Every manifest this project has ever written recorded `commit` and
`commit_is_clean`. **Nothing read the second field.** All three shipped
datasets say `commit_is_clean: false`, and their READMEs told a consumer to
`git checkout <commit>` and rebuild, promising the same seed reproduces the
same request sequence. For the medium tier that promise was provably false:
the recorded commit predates the change that gave the URL space its long
tail, so rebuilding from it yields a corpus with a closed URL vocabulary.

A hash beside a figure reads as provenance. An unqualified one next to a
dirty-tree build is decoration.

The fix is not to forbid dirty-tree builds -- that would stop development
dead. It is to record the difference, ship the patch, and let the rebuild
recipe say what it actually takes. An unreconstructable build becomes a
reconstructable one, and the claim in the README becomes true.
"""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from shared.verify.sourcestate import (rebuild_recipe,
                                       rebuildability, source_state)

PATCH = ("diff --git a/shared/clients/personas.py "
         "b/shared/clients/personas.py\n@@ -1 +1 @@\n-old\n+new\n")
STAT = " shared/clients/personas.py | 2 +-\n 1 file changed"


def fake_git(answers):
    """A stand-in for the real `git`, so these stay hermetic."""
    def run(_repo, *args):
        return answers.get(" ".join(args))
    return run


CLEAN = fake_git({
    "rev-parse HEAD": "a" * 40,
    "status --porcelain": "",
})

DIRTY = fake_git({
    "rev-parse HEAD": "b" * 40,
    "status --porcelain": " M shared/clients/personas.py\n?? notes.txt",
    "diff HEAD": PATCH,
    "diff --stat HEAD": STAT,
})


class TestACleanTree(unittest.TestCase):

    def test_it_records_the_commit_and_says_it_is_clean(self):
        state, patch = source_state(Path("/repo"), git=CLEAN)
        self.assertEqual(state["commit"], "a" * 40)
        self.assertTrue(state["commit_is_clean"])
        self.assertIsNone(patch)

    def test_it_records_no_diff_fields_it_does_not_need(self):
        state, _ = source_state(Path("/repo"), git=CLEAN)
        self.assertNotIn("uncommitted_diff_sha256", state)

    def test_the_recipe_is_a_plain_checkout(self):
        state, _ = source_state(Path("/repo"), git=CLEAN)
        recipe = rebuild_recipe(state, "apache-shopfront", "medium")
        self.assertIn("git checkout " + "a" * 40, recipe)
        self.assertNotIn("git apply", recipe)


class TestADirtyTree(unittest.TestCase):

    def setUp(self):
        self.state, self.patch = source_state(Path("/repo"), git=DIRTY)

    def test_it_says_the_tree_was_dirty(self):
        self.assertFalse(self.state["commit_is_clean"])

    def test_it_hands_back_the_patch_so_the_build_can_ship_it(self):
        self.assertEqual(self.patch, PATCH)

    def test_it_records_a_hash_of_the_patch(self):
        self.assertEqual(self.state["uncommitted_diff_sha256"],
                         hashlib.sha256(PATCH.encode()).hexdigest())

    def test_it_records_the_stat_so_the_delta_is_named(self):
        self.assertIn("personas.py", " ".join(self.state["uncommitted_diff_stat"]))

    def test_it_records_untracked_files_separately(self):
        # `git diff HEAD` does not contain them, so a patch alone cannot
        # reconstruct a build that depended on an untracked file.
        self.assertEqual(self.state["untracked_files"], ["notes.txt"])

    def test_the_recipe_applies_the_patch(self):
        recipe = rebuild_recipe(self.state, "apache-shopfront", "medium")
        self.assertIn("git checkout " + "b" * 40, recipe)
        self.assertIn("git apply", recipe)
        self.assertIn("uncommitted.patch", recipe)

    def test_the_recipe_warns_about_untracked_files(self):
        recipe = rebuild_recipe(self.state, "apache-shopfront", "medium")
        self.assertIn("notes.txt", recipe)


class TestWhetherADatasetCanBeRebuilt(unittest.TestCase):

    def dataset(self, state, *, with_patch):
        d = Path(tempfile.mkdtemp())
        (d / "MANIFEST.json").write_text(json.dumps({"source_state": state}))
        if with_patch:
            (d / "uncommitted.patch").write_text(PATCH)
        return d

    def test_a_clean_build_needs_nothing_further(self):
        state, _ = source_state(Path("/repo"), git=CLEAN)
        d = self.dataset(state, with_patch=False)
        self.assertEqual(rebuildability(json.loads(
            (d / "MANIFEST.json").read_text()), d), [])

    def test_a_dirty_build_that_ships_its_patch_is_acceptable(self):
        state, _ = source_state(Path("/repo"), git=DIRTY)
        d = self.dataset(state, with_patch=True)
        self.assertEqual(rebuildability(json.loads(
            (d / "MANIFEST.json").read_text()), d), [])

    def test_a_dirty_build_with_no_patch_is_a_failure(self):
        # This is the state all three shipped datasets were in. It must not
        # pass, because the README beside it promises a rebuild that will not
        # reproduce the data.
        state, _ = source_state(Path("/repo"), git=DIRTY)
        d = self.dataset(state, with_patch=False)
        problems = rebuildability(json.loads(
            (d / "MANIFEST.json").read_text()), d)
        self.assertTrue(problems)
        self.assertIn("uncommitted.patch", problems[0])

    def test_a_patch_whose_hash_does_not_match_is_a_failure(self):
        state, _ = source_state(Path("/repo"), git=DIRTY)
        d = self.dataset(state, with_patch=True)
        (d / "uncommitted.patch").write_text("something else entirely\n")
        problems = rebuildability(json.loads(
            (d / "MANIFEST.json").read_text()), d)
        self.assertTrue(any("does not match" in p for p in problems), problems)

    def test_a_manifest_with_no_source_state_at_all_is_a_failure(self):
        # Every dataset written before this existed. Silence is not a pass.
        d = Path(tempfile.mkdtemp())
        (d / "MANIFEST.json").write_text(json.dumps({"commit": "c" * 40}))
        problems = rebuildability({"commit": "c" * 40}, d)
        self.assertTrue(problems)


if __name__ == "__main__":
    unittest.main()
