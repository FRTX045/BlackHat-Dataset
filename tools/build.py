#!/usr/bin/env python3
"""Build a dataset. The one entry point; there is no second step.

    python3 tools/build.py apache-shopfront small

Brings the stack up, drives the traffic, collects the logs Apache wrote, joins
them to the ledgers, checks the result, writes the manifest, and tears the
stack down. Any failure tears it down too and exits non-zero: a half-built
dataset with the stack still running is how the next run silently inherits the
previous run's log file.

Standard library only, by project rule -- argparse, tomllib, subprocess, json,
pathlib, datetime and nothing else.
"""

import argparse
import json
import shutil
import subprocess
import sys
import time
import tomllib
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from shared.truth.join import join  # noqa: E402
from shared.truth.reader import read_truth  # noqa: E402
from shared.truth.validate import validate_records  # noqa: E402
from shared.verify.agreement import compare_logs  # noqa: E402

#: `large` is deliberately absent. It was excluded by decision and has never
#: been exercised; accepting it would run for hours and produce something
#: nobody had verified was buildable.
TIERS = ("small", "medium")

WEB_HEALTH_URL = "http://203.0.113.2/.lab-health"
HEALTH_TIMEOUT = 90


class BuildError(RuntimeError):
    """Something went wrong that should stop the build and say why."""


# --------------------------------------------------------------------------
# Pure pieces
# --------------------------------------------------------------------------

def validate_tier(tier):
    if tier not in TIERS:
        raise BuildError(
            f"tier {tier!r} is not one of {', '.join(TIERS)}. The `large` tier "
            f"is deliberately unsupported: it has never been run, and a build "
            f"that took hours to fail would be worse than one that refuses.")


def load_scenario(path):
    try:
        data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise BuildError(f"no scenario file at {path}") from None
    except tomllib.TOMLDecodeError as exc:
        raise BuildError(f"{path} is not valid TOML: {exc}") from None

    if "seed" not in data:
        # The seed is the whole reproducibility claim. Inventing one silently
        # would produce a dataset nobody could rebuild.
        raise BuildError(f"{path} declares no seed")
    return data


def dataset_dir(repo, project, tier, now):
    return Path(repo) / "datasets" / project / f"{now:%Y-%m-%d}-{tier}"


def run_steps(steps, teardown):
    """Run each step in order, and tear down whatever happens.

    If a step raises, teardown still runs and the step's error is what
    propagates -- a failure while cleaning up must not hide the failure that
    caused it.
    """
    try:
        for name, action in steps:
            print(f"==> {name}", flush=True)
            action()
    finally:
        try:
            teardown()
        except Exception as exc:  # noqa: BLE001 - never mask the real error
            print(f"warning: teardown failed: {exc}", file=sys.stderr)


# --------------------------------------------------------------------------
# Docker
# --------------------------------------------------------------------------

def default_runner(*argv, check=True):
    result = subprocess.run(["docker", *argv], capture_output=True, text=True)
    if check and result.returncode != 0:
        raise BuildError(
            f"docker {' '.join(argv)} failed ({result.returncode}):\n"
            f"{result.stderr.strip()}")
    return result


class Stack:
    """The lab containers, driven through an injectable runner."""

    def __init__(self, compose_file, runner=default_runner):
        self._compose = ["compose", "-f", str(compose_file)]
        self._run = runner

    def compose(self, *args, check=True):
        return self._run(*self._compose, *args, check=check)

    def up(self, *services):
        self.compose("up", "-d", "--build", *services)

    def down(self):
        self.compose("down", "-v", check=False)

    def once(self, service, *args):
        """Run a one-shot service to completion."""
        self.compose("run", "--rm", "--no-deps", service, *args)

    def wait_for_web(self, timeout=HEALTH_TIMEOUT):
        # Probed from inside the running container rather than from a new one:
        # `compose run web` would try to claim the static addresses the running
        # web already holds. /.lab-health is excluded from both access logs, so
        # polling it seeds nothing into the dataset.
        deadline = time.monotonic() + timeout
        while True:
            probe = self.compose(
                "exec", "-T", "web", "curl", "-s", "-o", "/dev/null",
                "-w", "%{http_code}", "http://127.0.0.1/.lab-health",
                check=False)
            if probe.stdout.strip().endswith("200"):
                return
            if time.monotonic() > deadline:
                raise BuildError(
                    f"Apache did not answer {WEB_HEALTH_URL} within {timeout}s")
            time.sleep(1)


# --------------------------------------------------------------------------
# The build
# --------------------------------------------------------------------------

def _git(repo, *args):
    result = subprocess.run(["git", "-C", str(repo), *args],
                            capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


def _image_digest(runner, image):
    result = runner("image", "inspect", image, "--format",
                    "{{index .RepoDigests 0}}", check=False)
    digest = result.stdout.strip()
    if digest:
        return digest
    # A locally built image has no repo digest. Its config id still identifies
    # exactly what ran, which is what the manifest is for.
    result = runner("image", "inspect", image, "--format", "{{.Id}}",
                    check=False)
    return result.stdout.strip() or None


def build_manifest(*, project, tier, scenario, scenario_path, started_at,
                   finished_at, report, agreement, truth_errors, repo,
                   base_image_digest, tool_runs):
    """Assemble the record of how this dataset came to exist."""
    return {
        "kind": "logforge-manifest",
        "version": 1,
        "project": project,
        "tier": tier,
        "scenario_file": str(Path(scenario_path).relative_to(repo)),
        "seed": scenario["seed"],
        "commit": _git(repo, "rev-parse", "HEAD"),
        "commit_is_clean": _git(repo, "status", "--porcelain") == "",
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "wall_clock_seconds": round(
            (finished_at - started_at).total_seconds(), 3),
        "base_image_digest": base_image_digest,
        "lines": report.lines,
        # Published rather than hidden: a line whose request id matched no
        # ledger record is labelled `unknown`, and the count of those is part
        # of how good the labelling actually was.
        "unmatched_request_ids": report.unmatched_ids,
        "unparsed_log_lines": report.unparsed_lines,
        "derived_vs_apache_combined": {
            "agreed": agreement.agreed,
            "derived_lines": agreement.derived_lines,
            "apache_lines": agreement.reference_lines,
            "first_divergence": agreement.first_divergence,
            "summary": agreement.summary(),
        },
        "truth_validation_errors": truth_errors,
        "tool_runs": tool_runs,
    }


def run_build(project, tier, *, repo=REPO, runner=default_runner, now=None):
    validate_tier(tier)
    started_at = now or datetime.now(timezone.utc)

    project_dir = repo / "projects" / project
    if not project_dir.is_dir():
        raise BuildError(f"no project at {project_dir}")

    scenario_path = project_dir / "scenarios" / f"{tier}.toml"
    scenario = load_scenario(scenario_path)

    logs = project_dir / "server" / "logs"
    ledgers = project_dir / "traffic" / "ledger"
    driver_ledger = ledgers / "driver.jsonl"
    proxy_ledger = ledgers / "tagproxy.jsonl"

    out = dataset_dir(repo, project, tier, started_at)
    out.mkdir(parents=True, exist_ok=True)

    stack = Stack(project_dir / "docker-compose.yml", runner)
    state = {}

    def bring_up():
        # The server's entrypoint truncates the three log files as it starts,
        # so a run always begins from an empty log; the ledger writers do the
        # same. Nothing here has to remember to clean up after the last run.
        stack.up("web", "tagproxy")
        stack.wait_for_web()

    def drive():
        stack.once("driver")

    def collect():
        for name in ("access.tagged.log", "error.log"):
            shutil.copy2(logs / name, out / name)
        # Apache's own combined log ships under a name that cannot be confused
        # with the derived one, because the verifier compares them and a reader
        # should be able to see both.
        shutil.copy2(logs / "access.log", out / "access.apache.log")

    def label():
        sys.path.insert(0, str(project_dir))
        from labels import categorise  # noqa: PLC0415 - per-project module

        present = [p for p in (driver_ledger, proxy_ledger) if p.exists()]
        if not present:
            raise BuildError(f"no ledgers were written under {ledgers}")
        state["report"] = join(
            out / "access.tagged.log", present,
            out / "truth.jsonl", out / "access.log",
            dict(scenario=f"{project}-{tier}", seed=scenario["seed"],
                 source_file_id="access.log",
                 generated_at=started_at.isoformat(),
                 kind=scenario.get("kind", "weblog-truth")),
            labeller=categorise)

    def check():
        _, records = read_truth(out / "truth.jsonl")
        ips = (line.split(" ", 1)[0]
               for line in (out / "access.log").read_text().splitlines())
        errors = validate_records(records, ips)
        state["truth_errors"] = errors
        state["agreement"] = compare_logs(out / "access.log",
                                          out / "access.apache.log")
        if errors:
            raise BuildError(
                "the truth file does not describe the log it ships with:\n  "
                + "\n  ".join(errors[:20]))

    def manifest():
        finished_at = datetime.now(timezone.utc)
        state["manifest"] = build_manifest(
            project=project, tier=tier, scenario=scenario,
            scenario_path=scenario_path, started_at=started_at,
            finished_at=finished_at, report=state["report"],
            agreement=state["agreement"],
            truth_errors=state["truth_errors"], repo=repo,
            base_image_digest=_image_digest(
                runner, "logforge/apache-shopfront-web:dev"),
            tool_runs=[])
        (out / "MANIFEST.json").write_text(
            json.dumps(state["manifest"], indent=2) + "\n")

    run_steps([
        ("bringing the stack up", bring_up),
        ("driving traffic", drive),
        ("collecting what Apache wrote", collect),
        ("joining the labels", label),
        ("checking the result", check),
        ("writing the manifest", manifest),
    ], teardown=stack.down)

    return out, state["manifest"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project")
    parser.add_argument("tier", choices=[*TIERS, "large"],
                        help="small or medium; large is unsupported")
    args = parser.parse_args(argv)

    try:
        out, manifest = run_build(args.project, args.tier)
    except BuildError as exc:
        print(f"build failed: {exc}", file=sys.stderr)
        return 1

    print(f"\n{out}")
    print(f"  lines                    {manifest['lines']}")
    print(f"  unmatched request ids    {manifest['unmatched_request_ids']}")
    print(f"  unparsed log lines       {manifest['unparsed_log_lines']}")
    print(f"  derived vs Apache        "
          f"{manifest['derived_vs_apache_combined']['summary']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
