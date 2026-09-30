# Browser-persona labels, relabelled on one capture (2026-09-30)

A labelling correction measured on the capture it corrects. This records what
changed in the truth, what that did to logarc's scores on a frozen case, and
what it does not show.

## The defect

The Chromium personas (`traffic/browser.py`, 203.0.113.41–.45) reached
`labels.py` under the actor `browser`, which fell through to URL-shape
heuristics. Clicking our own header's Account link (302 when logged out) was
labelled `access_control`; clicking the footer's robots.txt or sitemap link,
`reconnaissance`. The personas only follow same-origin links, so those labels
described no intent that existed. The fix labels that actor from the
scenario: ordinary-use categories only. See `docs/methodology.md`, "Real
browsers".

## The relabel

`tools/relabel.py` on `datasets/apache-shopfront/2026-09-07-medium`, with the
labeller from `main` as baseline and the branch's as candidate, restricted to
changes within .41–.45. All five gates passed:

1. ledgers consistent: 243,293 ids, no conflicting duplicates;
2. the baseline reproduces `access.raw.log` and `truth.raw.jsonl` byte for
   byte, header included;
3. a remap replay reproduces the shipped `access.log` and `truth.jsonl` byte
   for byte;
4. the recovered permutation is a bijection over 243,908 lines (243,906 of
   them moved), each pair the same request and client with only the
   timestamp changed;
5. the projected candidate truth validates against the shipped `access.log`.

The shipped log was never rewritten: the corrected truth describes the same
bytes logarc's headline numbers were measured on.

**Changes: 10 labels and 2 episode boundaries, on four clients.**

| Change | Lines |
|---|---:|
| `access_control` → `browsing` (`/account/`, `/account/orders`, 302) | 6 |
| `reconnaissance` → `browsing` (`/robots.txt`, `/sitemap.xml`, 200) | 4 |
| episode boundaries removed | 2 |

Clients changed: .41, .42, .44, .45. .43 had no hostile line in this build.
No other client's category or boundary changed.

Ledger ids absent from the log, listed rather than resolved: 118 in four stale
attack ledgers from 2026-08-24 builds (they match no line in this log); 1 in
`tagproxy.jsonl`, a malformed nmap probe whose request line Apache logged
without an id (evidence is timestamp and header text, so circumstantial); and
2 in `driver.jsonl`, ordinary asset requests from mid-run, **not explained**.

## The evaluation

Frozen: proto2 `9ef8db9` with a clean `src/`, CRS `d694d465` at paranoia
level 2 (`eval-provenance.txt` records "0 dirty": the CRS checkout had no
uncommitted changes), one ingest and one enrich of the shipped `access.log`. Both truth
files were scored against that one case by `tools/logarc_frozen_eval.py`
(run twice, in separate processes) and by `logarc evaluate` (twice per truth).

**Repeatability.** Scores and the 243,908 request-level predictions repeat
exactly across both script runs and both CLI runs per truth, and the
in-process scores equal the CLI's. Timing and cache metadata differ between
runs (`scan_cached` is false on the first ranking call only). This
establishes repeatability for this setup, not determinism in general.

**What the case hash covers.** The script hashes the case before and after
each run, excluding `triage/` and `tmp/`, and both runs found it unchanged
outside those directories. The first ranking call of the first script run
did write logarc's triage cache (`case/triage/5a6e….sqlite`, preserved with
the artifacts), so the case directory as a whole was modified. The four CLI
runs came before the first script run and were not covered by any hash. The
script is kept exactly as it ran (`tools/logarc_frozen_eval.py`, sha256
below); this paragraph corrects the description, not the script.

**Ranking.** 28 ranking entries: 18 completed, 10 Isolation Forest entries
unavailable ("dependency unavailable: install the evaluation extra"), so the
Isolation Forest was not measured. For the 18 completed entries, every queue,
eligible set, judged population and quiet set is identical under both truths;
the three exclusions are identical. Only the positive set changed: 399 → 395
(operational), 57 → 53 (matched).

**Request level.** 6 of the 10 changed lines flip from wrong to right (logarc
read the account clicks as `browsing`). The other 4 are wrong under both
truths: logarc predicts `static_asset` for `/robots.txt` and `/sitemap.xml`.
That is a tool result, recorded here and not pursued.

**Aggregates**, old → new truth:

| Metric | Old | New |
|---|---:|---:|
| binary false negatives | 115 | 105 |
| binary recall | 0.99325 | 0.99383 |
| `browsing` F1 | 0.98915 | 0.98921 |
| boundary F1 | 0.85475 | 0.85455 |
| `suspicious` queue maximum recall (operational) | 0.990 | 1.000 |
| quiet-positive recall at budget 50 (`operational` view, `suspicious`) | 5/342 | 5/342 |

The comparison rankers placed the four clients anywhere from 23rd to 2,757th,
depending on the ranker. Where one fell inside a budget it had counted as a
hit and now counts as a miss, so those rankers score lower (e.g. `group_sum`
at budget 50: 5 → 3 relevant).

## What this does and does not show

- Every difference above is exact for this one capture. How far it
  generalises across builds or seeds is not established.
- **This correction does not establish improved prioritisation.** The queues
  are identical; only the truth they are scored against changed. The
  `suspicious` queue's maximum recall reaching 1.0 means the four unreachable
  positives were this labelling defect, not that logarc ranks anything better.
- Quiet-positive recall at budget 50 is 5/342 under both truths. The four
  clients were never in logarc's quiet set, so the quiet-attacker question as
  logarc defines it is untouched by this fix.

## Artifacts

Stored untracked, outside every repository, at

    /mnt/d/Kei Project/BINUS/Blackhat/experiments/2026-09-30-browser-labels/

98 files outside `reproduction/` and `reproduction-2/`, which have their own
manifests (see "Reproduction"). The top-level manifest covers 96 of them (169,352,112 bytes): both truth
versions, `changes.jsonl` and `report.json`, the first relabel run (failed on a
permutation check that was itself wrong, since corrected), the labeller
copies, predictions and evaluation outputs from both script runs, CLI outputs,
provenance, and the logarc case with its CRS evidence and triage cache. The
other two are `SHA256SUMS` itself and `SOURCES.tsv`, which maps each copy to
its original; each copy was verified against a hash taken from its original
before copying.

Known gaps in what was kept:

- The text output of the first CLI run on the old truth (`cli-eval-old.txt`)
  was printed to a terminal and never saved. Its JSON output was saved, and
  equals the second run's byte for byte.
- The originals named in `SOURCES.tsv`, and the paths recorded inside
  `report.json`, `eval-provenance.txt` and the run logs, are in a
  session-temporary directory that will not survive. The copies here are the
  durable record; those paths only say where the copies came from.
- The exact bytes of `tools/relabel.py` that produced `truth/new` were not
  retained, and the tool has changed since (the permutation-check fix and
  later cleanup work). The byte-for-byte gates recorded in `report.json` hold
  regardless, but the original tool revision is not recoverable. See
  "Reproduction" for a later run with a recorded tool.

Checksum manifest: `SHA256SUMS` in that directory,
sha256 `8750ab4afc62acb4df724da4d18fff97edc55464a3903a8931f89f6bd64f191a`.
Verify with `sha256sum -c SHA256SUMS` from inside it.

| Item | sha256 |
|---|---|
| shipped `access.log` (unchanged) | `a61205732cfcb9ce0369e95326c7daef3be60156b9be2553fcdf07e200e96e8e` |
| old `truth.jsonl` (shipped) | `5ad028400eb64cf50b8317a353a1016f6e5c0254aba50f010052daf26483e406` |
| new `truth.jsonl` | `98e89d1b95ca74a5b1b48eca75e679e142d760aa697553929a0aec885165de1b` |
| `changes.jsonl` | `90ce7ad90a3ddaac78f26da97cc9743eb1bd6cd5b4dd9895b646a333e50fdde5` |
| baseline labeller (`main`) | `066df2f2f8045a0c0a9d869ae5e63e34313d569c309e7f9f614315b0fe7fe333` |
| candidate labeller | `e4b76c9f9525e12bed76081b8769fe92fd7cde4792b3c13f9b54ed58084719d2` |
| `crs.jsonl` | `bfa327ad2049ade95b51df7e40e1e08ed1228b662e4dca759382471bd44af8af` |
| `tools/logarc_frozen_eval.py` | `35782936dfa85e8db270fb959604dca18cc7002b6d52a9ecf440d72279d15200` |
| request predictions (both runs) | `8c9d63ed345ce0dfbcd808def86616e84a3626857cb900e8f1081fcf10aa2194` |

The candidate labeller differs from the branch's `labels.py` in one comment
line only.

## Reproduction

The original tool's bytes were not retained, so the relabel was run again
with a recorded tool, to show that the preserved inputs and a known tool
reproduce the published truth. This verifies reproduction; it does not
supply the missing provenance of the original run. It was run twice, because
the first reproduction exposed a defect in the tool itself.

**Inputs**, the same for both runs, using only preserved copies and the
dataset in place:

- ledgers from `reproduction/inputs/ledger/`, archived from the live ledger
  directory and checked before each run against the original run's
  `report.json`: the same 13 file names and the same 13 sha256 values,
  nothing missing and nothing extra. (The join gate alone would not show
  that: four stale ledgers match no line, so leaving one out changes nothing
  the join produces.)
- labellers from `labellers/` in this directory.
- external dependency, not copied: `datasets/apache-shopfront/2026-09-07-medium/`
  in this repository. Its `USED-BY-logarc.md` pins `access.log` and
  `truth.jsonl`; all six files the relabel reads are covered by
  `dataset-checksums.sha256` here, and were checked against it before each
  run:

| File | sha256 |
|---|---|
| `access.log` | `a61205732cfcb9ce0369e95326c7daef3be60156b9be2553fcdf07e200e96e8e` |
| `truth.jsonl` | `5ad028400eb64cf50b8317a353a1016f6e5c0254aba50f010052daf26483e406` |
| `MANIFEST.json` | `94ed6380e17774f7f25fe693badcc50f66e0a783d5e3d288661caef3fd9e1ff0` |
| `access.raw.log` | `e9b5935685e5cab929cf31b0834c06f8021dedb1f543e2a9a0d0fd9b59b0a749` |
| `truth.raw.jsonl` | `f7adf0e5dff3d5ca4d055202e670243a037c969635b7aab31756bc1d718a89e3` |
| `access.tagged.log` | `c7e5a5459ae1b5c29f317305c1b9249a0e6436841d906fce2ab8debf80c3f5e4` |

Each run records its tool in `source/`: `HEAD.txt` (commit `0485a9a`),
`git-status.txt`, `git-diff-HEAD.patch` (every uncommitted change to tracked
files at that moment), a copy of the one untracked source the tool runs
(`untracked/tools/relabel.py`), and `tool-sources.sha256` for it and the
main modules it imports. The rest of what it imports (`shared/verify/*`,
`tools/dataset_readme.py`, the package `__init__.py` files) is tracked and
unmodified at that commit, so HEAD and the patch pin it. This report lives in untracked `docs/experiments/`, so
editing it does not change `git diff HEAD`.

### `reproduction/`: the earlier tool

All five gates passed. `truth.jsonl`, `truth.raw.jsonl` and `changes.jsonl`
are byte-identical to `truth/new/`; in `report.json` the gates, permutation,
change counts, changed clients, ledger summary, parameters, output hashes
and all 21 recorded input hashes are identical, and only the run token and
the labeller paths differ.

It also showed that this tool did not leave its inputs untouched. Loading
each labeller through Python's import loader wrote
`labellers/__pycache__/*.pyc` into the archive. The `.py` files were
unchanged and their hashes checked, but checksums cannot see a file that was
added, so both manifests still verified. A review compared the directory's
file inventory and found 100 files where 98 were expected. The two `.pyc`
files were deleted afterwards; `labellers/` again holds exactly
`labels-candidate.py` and `labels-main.py`. The tool now compiles labellers
itself and writes no bytecode, and tests compare every input directory's
inventory before and after a run. This run's recorded tool is therefore not
the current one.

Manifest: `reproduction/SHA256SUMS`, 24 files, sha256
`b2ba7876f8947739a2afbe65dec1d4853c51f76c771ab20f0e9e933fc6c42093`.

### `reproduction-2/`: the current tool

Run with the tool as it stands (`tools/relabel.py`, sha256
`c35aaed1e0c5f3d32579b31d289e8c2eade759b49cfde7f9f1c59dfbe3abe352`, identical to `reproduction-2/source/untracked/tools/relabel.py`).
`command.txt` holds the exact command line and working directory, and
`report.json` now records the ledger directory it read. `checks.txt` records
the checks made before and after the run:

- `labellers/` held exactly the two `.py` files before and after the run;
- the ledger archive's file list was unchanged (`checks.txt` compares names
  after the run; hashes were checked before it, and the tool re-hashes every
  input at the end of the run and recorded `inputs_unchanged: true`);
- `truth.jsonl`, `truth.raw.jsonl` and `changes.jsonl` are byte-identical
  to `truth/new/`;
- in `report.json`, the only fields that differ from the original run are
  the two labeller paths, the run token and the new `ledger_dir`.

Manifest: `reproduction-2/SHA256SUMS`, 13 files, sha256
`e96db0fde0a2f36fb9006779e84c1a0afededaa17dabdd68cb92cf4bd1e5ca63`.

Every directory's file inventory matches its manifest, with nothing unlisted
beyond the manifests themselves and `SOURCES.tsv`. The top-level `SHA256SUMS`
is unchanged and still verifies.

Tests at the time of writing: 664 run. Without `LOGFORGE_DOCKER=1`, 596
passed and 68 skipped (the stack-driving tests are opt-in). With it set and
Docker running, all 664 passed and none were skipped. That run starts the
real tag proxy, which truncates the live `traffic/ledger/tagproxy.jsonl`; it
was restored from `reproduction/inputs/ledger/` afterwards and the live
directory checked against a snapshot of its file list and hashes.
