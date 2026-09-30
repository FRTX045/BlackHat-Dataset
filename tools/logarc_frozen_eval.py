"""Score one frozen logarc case against two truth files, in one process.

Read-only use of logarc (proto2): nothing in it is changed. Two wrappers are
installed for the duration of the process, both pass-throughs:

- `analyse_ip` in logarc.evaluation.scoring is memoised, so the old and the
  new truth are scored against the *same* assignments object by construction.
  The analysis is still logarc's own; only its repetition is skipped.
- `evaluate_order` in logarc.evaluation.triage records every queue it is
  handed, because the ranking report carries scores but not the queues.

Usage: python eval_frozen.py <case> <access.log> <old truth> <new truth> <out.json>
"""

import hashlib
import json
import sys
from dataclasses import asdict
from pathlib import Path

import logarc.evaluation.scoring as scoring
import logarc.evaluation.triage as triage
from logarc.case import Case
from logarc.cli.main import _analysis_policy
from logarc.evaluation import triage_study
from logarc.evaluation.truth import read_truth

case, source, old_truth, new_truth, out = map(Path, sys.argv[1:6])


def tree_hash(root, skip=("triage", "tmp")):
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root)
        if rel.parts[0] in skip:
            continue
        digest.update(str(rel).encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def file_hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


result = {"case_before": tree_hash(case),
          "truth": {"old": file_hash(old_truth), "new": file_hash(new_truth)},
          "source": file_hash(source)}

# -- memoised analysis --------------------------------------------------------
real_analyse = scoring.analyse_ip
memo = {}


def analyse_once(store, client_ip, **kwargs):
    if client_ip not in memo:
        memo[client_ip] = real_analyse(store, client_ip, **kwargs)
    return memo[client_ip]


scoring.analyse_ip = analyse_once

# -- aggregate scores, exactly as `logarc evaluate` computes them --------------
policy = _analysis_policy(absorb=True, episode_gap=None, idle_timeout=None)
scores = {}
truths = {"old": read_truth(old_truth), "new": read_truth(new_truth)}
with Case.open(case) as opened:
    crs = opened.crs_evidence()
    engine = opened.rule_engine()
    for name, truth in truths.items():
        scores[name] = scoring.evaluate(
            opened.store, truth, engine=engine, policy=policy,
            crs=crs.index, crs_fingerprint=crs.fingerprint).to_dict()
result["scores"] = scores
result["clients_analysed"] = len(memo)

# -- request-level predictions -------------------------------------------------
rows = []
for client_ip in sorted(memo):
    for item in memo[client_ip].assignments:
        if item.evidence.source_file_id == truths["old"].source_file_id:
            rows.append((item.evidence.line_no, client_ip,
                         item.category.value, str(item.episode_id)))
rows.sort()
predictions = out.with_suffix(".predictions.tsv")
predictions.write_text("".join("\t".join(map(str, r)) + "\n" for r in rows))
result["predictions"] = {"rows": len(rows), "sha256": file_hash(predictions)}

# -- ranking, with every queue captured ------------------------------------------
real_order = triage.evaluate_order


def ranking(truth_path):
    captured = []

    def spy(order, judgments, *, eligible, quiet, status="complete"):
        captured.append({
            "order": list(order), "eligible": sorted(eligible),
            "judged": sorted(judgments),
            "positives": sorted(ip for ip, v in judgments.items() if v),
            "quiet": sorted(quiet), "status": status})
        return real_order(order, judgments, eligible=eligible, quiet=quiet,
                          status=status)

    triage.evaluate_order = spy
    try:
        report = triage_study.evaluate_case(case, source, truth_path)
    finally:
        triage.evaluate_order = real_order
    names = [(population, goal, name)
             for population, goals in report["report"]["comparisons"].items()
             for goal, orders in goals.items() for name in orders]
    assert len(names) == len(captured), (len(names), len(captured))
    queues = {"/".join(key): value for key, value in zip(names, captured)}
    return report, queues


result["ranking"] = {}
for name, path in (("old", old_truth), ("new", new_truth)):
    report, queues = ranking(path)
    result["ranking"][name] = {"report": report, "queues": queues}

result["case_after"] = tree_hash(case)
out.write_text(json.dumps(result, indent=1, sort_keys=True, default=str) + "\n")
print(json.dumps({"case_unchanged": result["case_before"] == result["case_after"],
                  "clients_analysed": result["clients_analysed"],
                  "predictions": result["predictions"]}))
