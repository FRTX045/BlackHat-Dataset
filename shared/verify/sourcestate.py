"""What the source tree was when a build ran, and whether that is enough.

Every manifest this project writes records the commit the build ran at. For a
month it also recorded `commit_is_clean` and **nothing read it** -- all three
shipped datasets said `false` while their READMEs told a consumer to check that
commit out and rebuild, promising the same seed reproduces the same request
sequence. For the medium tier the recorded commit predated the change that gave
the URL space its long tail, so following that recipe produced a corpus with a
closed URL vocabulary. The claim was false and every check passed.

A hash beside a figure reads as provenance. An unqualified one next to a
dirty-tree build is decoration.

Refusing dirty-tree builds outright would stop development dead. The honest
alternative is cheaper: name the difference, ship the patch, and let the
rebuild recipe say what it actually takes. An unreconstructable build becomes a
reconstructable one, and the README stops promising something it cannot keep.

Stdlib only.
"""

import hashlib
import subprocess
from pathlib import Path

#: Where a dirty-tree build records the difference between the commit it names
#: and the code that actually ran.
PATCH_NAME = "uncommitted.patch"


def _git(repo, *args):
    result = subprocess.run(["git", "-C", str(repo), *args],
                            capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


#: A patch larger than this is recorded by hash and stat but not shipped. At
#: that size the working tree was not a few edits away from the commit, it was
#: a different program, and a dataset carrying it as "uncommitted changes"
#: would be claiming a lineage it does not have.
_MAX_PATCH_BYTES = 2 << 20


def source_state(repo, git=None):
    """What the source tree was when this build ran.

    Returns ``(state, patch)``. ``patch`` is None for a clean tree, and
    otherwise the full `git diff HEAD` for the build to ship beside the data.

    Recording the commit alone was not enough, and this project had the
    evidence in its own manifests for a month without reading it. All three
    shipped datasets said ``commit_is_clean: false`` while their READMEs told
    a consumer to check that commit out and rebuild. For the medium tier the
    recorded commit predated the change that gave the URL space its long tail,
    so the rebuild would have produced materially different data -- and the
    number of things that looked fine while that was true is the reason the
    field is now read rather than merely written.

    Refusing dirty-tree builds outright would stop development dead, and the
    honest alternative is cheaper: name the difference, ship the patch, and
    let the rebuild recipe say what it actually takes.
    """
    git = git or _git
    commit = git(repo, "rev-parse", "HEAD")
    porcelain = git(repo, "status", "--porcelain") or ""
    state = {"commit": commit, "commit_is_clean": porcelain == ""}
    if porcelain == "":
        return state, None

    patch = git(repo, "diff", "HEAD") or ""
    encoded = patch.encode("utf-8", "replace")
    state["uncommitted_diff_sha256"] = hashlib.sha256(encoded).hexdigest()
    state["uncommitted_diff_bytes"] = len(encoded)
    state["uncommitted_diff_stat"] = (
        (git(repo, "diff", "--stat", "HEAD") or "").splitlines()[-40:])
    # Untracked files are absent from `git diff HEAD`, so a patch alone cannot
    # reconstruct a build that depended on one. Named separately for that
    # reason rather than folded in.
    state["untracked_files"] = sorted(
        line[3:] for line in porcelain.splitlines()
        if line.startswith("??"))[:40]
    if len(encoded) > _MAX_PATCH_BYTES:
        state["patch_shipped"] = False
        state["patch_omitted_because"] = (
            f"the diff is {len(encoded):,} bytes, over the "
            f"{_MAX_PATCH_BYTES:,}-byte ceiling; at that size the tree was not "
            f"a few edits from the commit and this build is not "
            f"reconstructable from the repository")
        return state, None
    state["patch_shipped"] = True
    state["patch_file"] = PATCH_NAME
    return state, patch


def rebuild_recipe(state, project, tier):
    """The commands that actually reproduce this build, and nothing more.

    A bare ``git checkout <commit>`` beside a dirty-tree build is the part
    that actively misleads: it invites somebody to rebuild and trust what
    comes out.
    """
    lines = [f"git checkout {state.get('commit')}"]
    if not state.get("commit_is_clean"):
        if state.get("patch_shipped"):
            lines.append(f"git apply {PATCH_NAME}      "
                         f"# from this dataset folder")
        else:
            lines.append("# NOT REBUILDABLE: this build was made from a "
                         "modified tree whose")
            lines.append("# patch was too large to ship. See "
                         "source_state in MANIFEST.json.")
    lines.append(f"python3 tools/build.py {project} {tier}")
    if state.get("untracked_files"):
        lines.append("")
        lines.append("# The build also saw these untracked files, which no "
                     "patch can restore:")
        for name in state["untracked_files"][:10]:
            lines.append(f"#   {name}")
    return "\n".join(lines)


def rebuildability(manifest, dataset):
    """Reasons this dataset cannot be rebuilt from what it ships.

    Empty means the recipe in its README is one somebody can actually follow.
    """
    state = manifest.get("source_state")
    if not isinstance(state, dict):
        return ["MANIFEST.json records no source_state, so there is no way to "
                "tell what the tree was when this was built"]
    if state.get("commit_is_clean"):
        return []

    problems = []
    if not state.get("patch_shipped"):
        problems.append(
            f"built from a modified tree and ships no {PATCH_NAME}, so the "
            f"recorded commit does not reproduce it: "
            f"{state.get('patch_omitted_because', 'no patch was recorded')}")
        return problems

    path = Path(dataset) / state.get("patch_file", PATCH_NAME)
    if not path.exists():
        problems.append(
            f"source_state says {PATCH_NAME} was shipped and it is missing")
        return problems
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != state.get("uncommitted_diff_sha256"):
        problems.append(
            f"{PATCH_NAME} does not match the hash in source_state "
            f"({actual[:12]} against {str(state.get('uncommitted_diff_sha256'))[:12]})")
    return problems


