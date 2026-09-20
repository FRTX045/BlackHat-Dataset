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


#: Every git command fails. This is an ordinary situation, not a broken one:
#: a build run from an exported source archive has no .git at all.
NO_GIT = fake_git({})

#: rev-parse answers and status does not. An empty porcelain means clean; a
#: failed one means unknown, and the two must not read the same.
HALF_GIT = fake_git({"rev-parse HEAD": "c" * 40})


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


class TestATreeGitCannotRead(unittest.TestCase):
    """Git failing must not read as a clean tree.

    `commit_is_clean` is the one field a consumer checks before trusting the
    rebuild recipe, and nothing else in a manifest contradicts it. Recording
    true here, with a null commit beside it, is the most misleading pair this
    module can produce -- and it is what it produced until these tests.
    """

    def state(self, git):
        return source_state(Path(tempfile.mkdtemp()), git=git)

    def test_a_tree_with_no_git_is_not_recorded_as_clean(self):
        state, patch = self.state(NO_GIT)
        self.assertFalse(state["commit_is_clean"],
                         "a tree git could not read was recorded as clean")
        self.assertIsNone(patch)

    def test_it_says_why_no_patch_was_shipped(self):
        state, _ = self.state(NO_GIT)
        self.assertFalse(state["patch_shipped"])
        self.assertIn("git", state["patch_omitted_because"])

    def test_the_recipe_does_not_tell_anybody_to_check_out_none(self):
        # `git checkout None` is a command somebody would paste.
        state, _ = self.state(NO_GIT)
        recipe = rebuild_recipe(state, "apache-shopfront", "small")
        self.assertNotIn("None", recipe)
        self.assertIn("NOT REBUILDABLE", recipe)

    def test_a_build_with_no_commit_is_not_called_rebuildable(self):
        state, _ = self.state(NO_GIT)
        problems = rebuildability({"source_state": state},
                                  Path(tempfile.mkdtemp()))
        self.assertTrue(
            problems,
            "a build whose source tree git could not read passed the "
            "rebuildability check, so verify.py would call it reproducible")

    def test_it_does_not_claim_the_tree_was_modified(self):
        # It was not modified; git could not be read. Saying "built from a
        # modified tree" about a build with no commit at all is the same kind
        # of invented cause this module exists to stop.
        state, _ = self.state(NO_GIT)
        problems = rebuildability({"source_state": state},
                                  Path(tempfile.mkdtemp()))
        self.assertNotIn("modified tree", " ".join(problems))

    def test_a_status_that_failed_is_not_a_status_that_was_empty(self):
        state, _ = self.state(HALF_GIT)
        self.assertFalse(
            state["commit_is_clean"],
            "a failed `git status` was treated as an empty one, which is the "
            "difference between 'nothing changed' and 'we do not know'")
        self.assertEqual(state["commit"], "c" * 40)


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


class TestABuildsOwnOutputIsNotASourceChange(unittest.TestCase):
    """A previous build's dataset directory must not mark the next build dirty.

    Caught on the first run of three tiers in sequence. small built from a
    genuinely clean tree and recorded `commit_is_clean: True`. medium then ran
    with `?? datasets/apache-shopfront/2026-09-17-small/` in the working tree --
    the small build's own output, untracked because a dataset is added to git
    after it is verified -- and recorded `commit_is_clean: False` with a
    **zero-byte** uncommitted.patch whose sha256 is the hash of the empty
    string.

    That is worse than the defect it replaced. It reads as "here is the
    difference that made this build" when there is no difference, and the thing
    that actually differed is an untracked directory no patch can express
    anyway. A provenance field that cries wolf teaches people to ignore it.

    Build output is not source. Untracked files anywhere else still count,
    because one of them really could change what a build produces.
    """

    def porcelain(self, *lines):
        return fake_git({
            "rev-parse HEAD": "d" * 40,
            "status --porcelain": "\n".join(lines),
            "diff HEAD": "",
            "diff --stat HEAD": "",
        })

    def test_an_earlier_datasets_directory_leaves_the_tree_clean(self):
        git = self.porcelain("?? datasets/apache-shopfront/2026-09-17-small/")
        state, patch = source_state(Path("/repo"), git=git)
        self.assertTrue(state["commit_is_clean"])
        self.assertIsNone(patch)

    def test_several_of_them_are_still_clean(self):
        git = self.porcelain("?? datasets/apache-shopfront/2026-09-17-small/",
                             "?? datasets/apache-shopfront/2026-09-17-medium/")
        state, _ = source_state(Path("/repo"), git=git)
        self.assertTrue(state["commit_is_clean"])

    def test_it_still_records_that_the_outputs_were_there(self):
        # Filtered, not hidden. Somebody reading the manifest should be able to
        # see what was in the tree, and decide for themselves.
        git = self.porcelain("?? datasets/apache-shopfront/2026-09-17-small/")
        state, _ = source_state(Path("/repo"), git=git)
        self.assertEqual(state["build_outputs_present"],
                         ["datasets/apache-shopfront/2026-09-17-small/"])

    def test_an_untracked_file_anywhere_else_still_counts(self):
        # A stray module or scenario file genuinely could change what a build
        # produces, and no patch can restore it either.
        git = self.porcelain("?? shared/clients/experiment.py")
        state, _ = source_state(Path("/repo"), git=git)
        self.assertFalse(state["commit_is_clean"])
        self.assertEqual(state["untracked_files"], ["shared/clients/experiment.py"])

    def test_a_modified_tracked_file_still_counts_even_beside_outputs(self):
        git = fake_git({
            "rev-parse HEAD": "e" * 40,
            "status --porcelain": (" M shared/clients/personas.py\n"
                                   "?? datasets/apache-shopfront/2026-09-17-small/"),
            "diff HEAD": PATCH,
            "diff --stat HEAD": STAT,
        })
        state, patch = source_state(Path("/repo"), git=git)
        self.assertFalse(state["commit_is_clean"])
        self.assertEqual(patch, PATCH)
        self.assertTrue(state["patch_shipped"])

    def test_an_empty_diff_is_never_shipped_as_a_patch(self):
        # The specific thing that shipped: patch_shipped True beside a
        # zero-byte file and the sha256 of nothing.
        git = self.porcelain("?? shared/clients/experiment.py")
        state, patch = source_state(Path("/repo"), git=git)
        self.assertIsNone(patch)
        self.assertFalse(state.get("patch_shipped"))
        self.assertIn("no tracked file", state.get("patch_omitted_because", ""))

    def test_a_dirty_build_with_only_untracked_source_is_not_rebuildable(self):
        # Correct, and it should say so rather than pretend a patch fixes it.
        git = self.porcelain("?? shared/clients/experiment.py")
        state, _ = source_state(Path("/repo"), git=git)
        recipe = rebuild_recipe(state, "apache-shopfront", "small")
        self.assertIn("NOT REBUILDABLE", recipe)
        self.assertIn("experiment.py", recipe)


if __name__ == "__main__":
    unittest.main()
