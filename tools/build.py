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

from shared.timeline.remap import remap_files  # noqa: E402
from shared.truth.join import join  # noqa: E402
from shared.truth.reader import read_truth  # noqa: E402
from shared.truth.validate import validate_records  # noqa: E402
from shared.verify.agreement import compare_logs  # noqa: E402
from shared.verify.stats import summarise  # noqa: E402
from shared.verify.tells import audit, summary as audit_summary  # noqa: E402
from tools import dataset_readme  # noqa: E402

#: `large` was refused here for a long time on the grounds that it had never
#: been exercised, and accepting a tier nobody had built would mean running
#: for an hour to produce something unverified. It has now been built and
#: verified, so that reasoning no longer applies and it is supported.
#:
#: Any tier added in future should be refused until the same is true of it.
TIERS = ("small", "medium", "large")

WEB_HEALTH_URL = "http://203.0.113.2/.lab-health"
HEALTH_TIMEOUT = 90

#: Lines of the finished log committed alongside the source, so the shape
#: of the data can be seen without downloading a release asset.
SAMPLE_LINES = 5000


class BuildError(RuntimeError):
    """Something went wrong that should stop the build and say why."""


# --------------------------------------------------------------------------
# Pure pieces
# --------------------------------------------------------------------------

def validate_tier(tier):
    if tier not in TIERS:
        raise BuildError(
            f"tier {tier!r} is not one of {', '.join(TIERS)}. A tier is "
            f"supported once it has been built and verified at least once; "
            f"a build that ran for an hour and then failed would be worse "
            f"than one that refuses up front.")


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

    def once(self, service, *args, check=True):
        """Run a one-shot service to completion, and return what it did.

        `check=False` for the tools: nikto exits non-zero having found
        nothing, sqlmap exits non-zero having been cut off, and neither is a
        build failure. The exit code goes in the manifest instead.
        """
        return self.compose("run", "--rm", "--no-deps", service, *args,
                            check=check)

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

def _requests_by_source(ledger):
    """How many requests the tag proxy recorded from each address.

    Read from the proxy's own ledger rather than from the tools' exit codes:
    nikto exits 0 having found nothing and 0 having reached nothing, and the
    difference is the whole question.
    """
    counts = {}
    if not Path(ledger).exists():
        return counts
    with open(ledger, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                address = json.loads(line).get("client_ip")
            except json.JSONDecodeError:
                continue
            if address:
                counts[address] = counts.get(address, 0) + 1
    return counts


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


def tool_run_record(run, *, version, command, started_at, finished_at,
                    exit_code, requests):
    """One row of the manifest's tool table, and of the README's.

    `requests` is the count the tag proxy actually saw from this tool's
    address. It is the field that stops the table being a claim: a tool that
    was started, exited cleanly and reached nothing would otherwise appear
    here indistinguishable from one that worked.
    """
    return {
        "tool": run.binary,
        "run": run.name,
        "version": version,
        "command": command,
        "source_ip": run.address,
        "network": run.network,
        "target": run.target,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "seconds": round((finished_at - started_at).total_seconds(), 3),
        # 124 is what `timeout` returns when it cut the tool off. Recorded
        # rather than smoothed over: it changes how the line count below
        # should be read.
        "exit_code": exit_code,
        "timed_out": exit_code == 124,
        "requests": requests,
    }


def tools_that_reached_nothing(records):
    """Tool runs the proxy saw no request from.

    A hard failure, not a warning. The attack runner once wrote 170
    consecutive timeouts into the ledger as completed attacks because an
    `OSError` was being swallowed, and the dataset said an attack happened
    where nothing had. A tool that produced no traffic is the same mistake
    wearing a different hat.
    """
    return [r["run"] for r in records if not r["requests"]]


def audit_block(findings):
    """The fake-log audit, as the manifest records it.

    Every dataset ships with the result of the detector being run against
    itself. The tells that fire on our own data -- a remapped log is sorted by
    construction, our client addresses come from the documentation ranges --
    are in here whether they flatter the dataset or not. A dataset that only
    published the checks it passed would be worse than one that published no
    checks, because the silence would read as a pass.
    """
    return {
        **audit_summary(findings),
        "findings": [
            {"name": f.name, "measured": f.measured, "threshold": f.threshold,
             "suspicious": f.suspicious, "inconclusive": f.inconclusive,
             "explanation": f.explanation}
            for f in findings],
    }


def timestamp_block(remap):
    """What the manifest says about the clock.

    Always present, and always explicit about which of the two files is the
    capture. A dataset whose timestamps were rewritten and whose manifest is
    silent about it is a dataset that will be read as a capture, which is the
    one thing a rewritten log must never be taken for.
    """
    if remap is None:
        return {
            "remapped": False,
            "capture_file": "access.log",
            "note": ("Timestamps are exactly as Apache wrote them. The driver "
                     "issues its whole plan as fast as the sockets allow, so "
                     "the request sequence is meaningful and the timing is "
                     "not -- see the achieved rate under realism."),
        }
    return {
        "remapped": True,
        "capture_file": "access.raw.log",
        "capture_truth_file": "truth.raw.jsonl",
        "start": remap.start,
        "end": remap.end,
        "span_seconds": round(remap.new_span_seconds, 3),
        "captured_span_seconds": round(remap.original_span_seconds, 3),
        "sessions": remap.episodes,
        # Sessions whose drawn start collided with the same address's previous
        # session and were pushed later. A large share means the window is too
        # short for the traffic in it, and the arrival curve has been distorted.
        "sessions_pushed": remap.episodes_pushed,
        "description": remap.description,
    }


def build_manifest(*, project, tier, scenario, scenario_path, started_at,
                   finished_at, report, agreement, truth_errors, repo,
                   base_image_digest, tool_runs, campaigns=(), remap=None,
                   tells=(), browser=None):
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
        # Lines with no usable request id that were labelled by their source
        # address instead. A weaker mechanism than the id, reported apart from
        # it so nobody has to assume which one produced a given label.
        "address_fallback_lines": report.address_fallback_lines,
        "timestamps": timestamp_block(remap),
        "audit": audit_block(tells),
        # Empty when no headless browser ran, which is a fact about the build
        # and is stated in the dataset README rather than left to inference.
        "browser": browser,
        "derived_vs_apache_combined": {
            # Named explicitly: once timestamps are remapped this check runs
            # against the capture, not the shipped log. Comparing a rewritten
            # log with Apache's own would report a divergence on every line
            # and prove nothing about the labelling mechanism, which is the
            # only thing the check is about.
            "compared_file": ("access.raw.log" if remap else "access.log"),
            "agreed": agreement.agreed,
            "derived_lines": agreement.derived_lines,
            "apache_lines": agreement.reference_lines,
            "first_divergence": agreement.first_divergence,
            "summary": agreement.summary(),
        },
        "truth_validation_errors": truth_errors,
        "tool_runs": tool_runs,
        "campaigns": campaigns,
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
    noise_ledger = ledgers / "noise.jsonl"

    #: Addresses reserved for traffic Apache logs without a request id, and the
    #: category to give those lines. Only the noise container ever uses this
    #: address, which is what makes labelling by it exact rather than a guess.
    address_fallback = {"203.0.113.6": "reconnaissance"}

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
        # The catalogue is seeded from the run's seed, so a run with a
        # different seed must not inherit the last one's products.
        stack.compose("exec", "-T", "-e", f"LOGFORGE_SEED={scenario['seed']}",
                      "web", "php", "/var/www/html/seed/seed.php", "--force")

    def drive():
        traffic = scenario.get("traffic", {})
        # The window the log will claim to cover, so the plan is a function of
        # the scenario and the seed rather than of what time the build ran.
        window_start = scenario.get("timeline", {}).get(
            "start", started_at.isoformat())
        stack.once(
            "driver",
            "python", "/opt/logforge/projects/apache-shopfront/traffic/driver.py",
            "--ledger=/opt/logforge/projects/apache-shopfront/traffic/ledger/driver.jsonl",
            "--catalogue=/opt/logforge/projects/apache-shopfront/app/data/catalogue.json",
            f"--seed={scenario['seed']}",
            f"--start={window_start}",
            f"--duration={traffic.get('duration_seconds', 300)}",
            f"--rate={traffic.get('session_rate', 0.06)}",
            f"--concurrency={traffic.get('concurrency', 32)}",
            f"--personas={json.dumps(scenario.get('personas', {}))}")

    def run_campaigns():
        """Run every campaign at once, alongside the driver's traffic.

        Concurrency here is the point. Attacks that occupy their own quiet
        window in the log can be separated by timestamp without looking at a
        single request, which teaches a detector nothing worth knowing.
        """
        import concurrent.futures

        campaigns = scenario.get("attacks", {}).get("campaigns", [])
        if not campaigns:
            return

        sys.path.insert(0, str(project_dir / "attacks"))
        from campaigns import by_name  # noqa: PLC0415 - per-project module
        state["campaign_outcomes"] = [
            {"name": name, "succeeds": by_name(name).succeeds,
             "phases": list(by_name(name).phases)}
            for name in campaigns]
        pace = scenario.get("attacks", {}).get("pace", 20.0)

        def one(name):
            service = "attacker-" + name.replace("_", "-")
            stack.once(
                service, "python",
                "/opt/logforge/projects/apache-shopfront/attacks/runner.py",
                name,
                f"--ledger=/opt/logforge/projects/apache-shopfront/traffic/"
                f"ledger/attack-{name}.jsonl",
                f"--seed={scenario['seed']}", f"--pace={pace}")

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=len(campaigns)) as pool:
            for outcome in concurrent.futures.as_completed(
                    [pool.submit(one, name) for name in campaigns]):
                outcome.result()

    def make_noise():
        traffic = scenario.get("traffic", {})
        stack.once(
            "noise",
            "python", "/opt/logforge/projects/apache-shopfront/traffic/noise.py",
            "--ledger=/opt/logforge/projects/apache-shopfront/traffic/ledger/noise.jsonl",
            f"--seed={scenario['seed']}",
            f"--count={traffic.get('noise_requests', 40)}",
            "--pause=0.02")

    def run_tools():
        """Real security tools, pointed at the tag proxy, alongside everything
        else.

        Concurrent with the ordinary traffic for the same reason the campaigns
        are: a tool run that owns a quiet window is separable by timestamp
        without reading a request.
        """
        wanted = scenario.get("attacks", {}).get("tools", [])
        state["tool_runs"] = []
        if not wanted:
            return

        import concurrent.futures

        sys.path.insert(0, str(project_dir / "attacks"))
        from toolruns import (TOOL_RUNS, command_line,  # noqa: PLC0415
                              container_argv, service_for)

        declared = {run.name: run for run in TOOL_RUNS}
        unknown = [name for name in wanted if name not in declared]
        if unknown:
            raise BuildError(
                f"the scenario asks for tool run(s) {', '.join(unknown)}, "
                f"which are not declared in attacks/toolruns.py")
        runs = [declared[name] for name in wanted]

        # Explicitly, before anything is run. `compose run` does not build a
        # missing image, it tries to pull one -- and the pull fails against a
        # tag that only exists here. The first build of this step recorded
        # five tools as having produced no requests, which was true and for
        # this reason.
        stack.compose("build", *sorted({service_for(r) for r in runs}))

        # Versions from dpkg rather than each tool's own --version flag: five
        # tools have five formats, and the Debian archive is what the image
        # actually pins.
        probe = stack.once(service_for(runs[0]), "dpkg-query", "-W",
                           *sorted({r.binary for r in runs}), check=False)
        versions = dict(
            line.split("\t", 1) for line in probe.stdout.splitlines()
            if "\t" in line)

        results = {}

        def one(run):
            began = datetime.now(timezone.utc)
            outcome = stack.once(service_for(run), *container_argv(run),
                                 check=False)
            results[run.name] = (began, datetime.now(timezone.utc),
                                 outcome.returncode, outcome.stderr)

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=len(runs)) as pool:
            for outcome in concurrent.futures.as_completed(
                    [pool.submit(one, run) for run in runs]):
                outcome.result()

        seen = _requests_by_source(proxy_ledger)
        state["tool_runs"] = [
            tool_run_record(
                run, version=versions.get(run.binary),
                command=command_line(run),
                started_at=results[run.name][0],
                finished_at=results[run.name][1],
                exit_code=results[run.name][2],
                requests=seen.get(run.address, 0))
            for run in runs]

        silent = tools_that_reached_nothing(state["tool_runs"])
        if silent:
            # With what the tool said. `check=False` is what lets a non-zero
            # exit be an ordinary outcome, and it also means nothing else in
            # the build would ever print the reason.
            lines = []
            for name in silent:
                stderr = (results[name][3] or "").strip().splitlines()
                said = stderr[-1][:160] if stderr else "no stderr"
                lines.append(f"  {name}: exit {results[name][2]}, {said}")
            why = "\n".join(lines)
            raise BuildError(
                f"tool run(s) {', '.join(silent)} produced no requests at "
                f"all. Recording them as having run would put attacks in the "
                f"dataset that never happened.\n{why}")

    def run_browsers():
        """Real Chromium sessions, alongside everything else.

        The browser is the only source here that does not decide what to
        request: it is handed a URL and the log records what Chromium chose to
        ask for, in the order it chose, including the requests it declined to
        make because the response was already in its cache.
        """
        browsers = scenario.get("browser", {})
        state["browser"] = {}
        if not browsers.get("enabled"):
            return

        sys.path.insert(0, str(project_dir / "traffic"))
        from browser import BROWSER_PERSONAS  # noqa: PLC0415

        wanted = browsers.get("personas") or [p.name for p in BROWSER_PERSONAS]
        outcome = stack.once(
            "browser", "python",
            "/opt/logforge/projects/apache-shopfront/traffic/browser.py",
            f"--seed={scenario['seed']}",
            f"--pace={browsers.get('pace', 1.0)}",
            f"--personas={','.join(wanted)}", check=False)

        claimed = {p.address for p in BROWSER_PERSONAS if p.name in wanted}
        seen = _requests_by_source(proxy_ledger)
        state["browser"] = {
            "personas": sorted(wanted),
            "requests": sum(seen.get(a, 0) for a in claimed),
            "exit_code": outcome.returncode,
        }
        # Same rule the tool runs and the attack runner are held to: a source
        # that reached the server zero times must not be recorded as one that
        # ran.
        if not state["browser"]["requests"]:
            tail = (outcome.stderr or outcome.stdout or "").strip().splitlines()
            raise BuildError(
                "the browser produced no requests at all. Recording it as "
                "browser traffic would put sessions in the dataset that never "
                "happened.\n  "
                + (tail[-1][:200] if tail else "no output"))

    def drive_and_attack():
        """Ordinary traffic, attack campaigns, tool runs and real browsers,
        all at the same time."""
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            jobs = [pool.submit(drive), pool.submit(run_campaigns),
                    pool.submit(run_tools), pool.submit(run_browsers)]
            for outcome in concurrent.futures.as_completed(jobs):
                outcome.result()

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

        present = [p for p in (driver_ledger, proxy_ledger, noise_ledger)
                   if p.exists()]
        present += sorted(ledgers.glob("attack-*.jsonl"))
        if not present:
            raise BuildError(f"no ledgers were written under {ledgers}")
        state["report"] = join(
            out / "access.tagged.log", present,
            out / "truth.jsonl", out / "access.log",
            dict(scenario=f"{project}-{tier}", seed=scenario["seed"],
                 source_file_id="access.log",
                 generated_at=started_at.isoformat(),
                 kind=scenario.get("kind", "weblog-truth")),
            labeller=categorise, address_fallback=address_fallback)

    def remap_clock():
        """Put the captured log on a realistic clock, keeping the capture.

        Runs after the join and before every check, so what gets validated and
        measured is what actually ships. The capture keeps the name
        `access.raw.log` and its own truth file, because the agreement check
        against Apache's independently written log is about the labelling
        mechanism and has to run on unrewritten bytes.
        """
        timeline = scenario.get("timeline", {})
        if not timeline.get("remap"):
            state["remap"] = None
            return
        for name in ("access.log", "truth.jsonl"):
            raw = name.replace(".log", ".raw.log").replace(
                ".jsonl", ".raw.jsonl")
            (out / name).replace(out / raw)
        state["remap"] = remap_files(
            out / "access.raw.log", out / "truth.raw.jsonl",
            out / "access.log", out / "truth.jsonl",
            start=datetime.fromisoformat(timeline["start"]),
            duration_seconds=timeline["duration_seconds"],
            seed=scenario["seed"])

    def check():
        _, records = read_truth(out / "truth.jsonl")
        ips = (line.split(" ", 1)[0]
               for line in (out / "access.log").read_text().splitlines())
        errors = validate_records(records, ips)
        state["truth_errors"] = errors
        capture = out / ("access.raw.log" if state.get("remap")
                         else "access.log")
        state["agreement"] = compare_logs(capture, out / "access.apache.log")

        from shared.verify.combined import parse_line
        parsed = [parse_line(line) for line
                  in (out / "access.log").read_text().splitlines()]
        _, again = read_truth(out / "truth.jsonl")
        good = [p for p in parsed if p]
        state["stats"] = summarise(good, list(again))
        # The detector, run against our own data, on the file that ships.
        state["tells"] = audit(good)
        if errors:
            raise BuildError(
                "the truth file does not describe the log it ships with:\n  "
                + "\n  ".join(errors[:20]))

    def write_sample():
        """A committed slice of the dataset, for eyeballing without a download.

        Taken from the middle rather than the head: the first few thousand
        lines of a run are the driver warming up, with the campaigns barely
        started, and a sample of those would misrepresent the whole.
        """
        lines = (out / "access.log").read_text(
            encoding="utf-8", errors="replace").splitlines()
        truth_lines = (out / "truth.jsonl").read_text(
            encoding="utf-8").splitlines()
        header, records = truth_lines[0], truth_lines[1:]

        take = min(SAMPLE_LINES, len(lines))
        start = max(0, (len(lines) - take) // 2)
        stop = start + take

        (out / "sample.log").write_text(
            "\n".join(lines[start:stop]) + "\n", encoding="utf-8")

        # Renumbered from 1 so the sample is a valid truth file in its own
        # right rather than a fragment whose line numbers point at a file
        # nobody has.
        renumbered = []
        for offset, raw in enumerate(records[start:stop], start=1):
            record = json.loads(raw)
            record["line_no"] = offset
            renumbered.append(json.dumps(record, separators=(",", ":")))
        sample_header = json.loads(header)
        sample_header["source_file_id"] = "sample.log"
        (out / "sample.truth.jsonl").write_text(
            json.dumps(sample_header, separators=(",", ":")) + "\n"
            + "\n".join(renumbered) + "\n", encoding="utf-8")

    def write_readme():
        dataset_readme.write(
            out / "README.md", project=project, tier=tier,
            manifest=state["manifest"], stats=state["stats"],
            tool_runs=state["manifest"].get("tool_runs", []),
            campaigns=state["manifest"].get("campaigns", []))

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
            tool_runs=state.get("tool_runs", []),
            campaigns=state.get("campaign_outcomes", []),
            remap=state.get("remap"), tells=state.get("tells", ()),
            browser=state.get("browser") or {})
        (out / "MANIFEST.json").write_text(
            json.dumps(state["manifest"], indent=2) + "\n")

    run_steps([
        ("bringing the stack up", bring_up),
        ("driving traffic and attacks together", drive_and_attack),
        ("adding background noise", make_noise),
        ("collecting what Apache wrote", collect),
        ("joining the labels", label),
        ("putting the log on a realistic clock", remap_clock),
        ("checking the result", check),
        ("writing the manifest", manifest),
        ("writing the dataset README", write_readme),
        ("writing the committed sample", write_sample),
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
    print(f"  labelled by address      {manifest['address_fallback_lines']}")
    print(f"  derived vs Apache        "
          f"{manifest['derived_vs_apache_combined']['summary']} "
          f"({manifest['derived_vs_apache_combined']['compared_file']})")
    clock = manifest["timestamps"]
    if clock["remapped"]:
        print(f"  clock                    {clock['start']} .. {clock['end']}")
        print(f"  sessions                 {clock['sessions']} "
              f"({clock['sessions_pushed']} pushed to avoid overlap)")
    else:
        print("  clock                    as captured, not remapped")
    browser = manifest.get("browser") or {}
    if browser.get("requests"):
        print(f"  browser                  {browser['requests']} requests "
              f"from {len(browser['personas'])} personas")
    else:
        print("  browser                  not run")
    fired = manifest["audit"]["fired"]
    print(f"  fake-log tells fired     {len(fired)}"
          + (f": {', '.join(fired)}" if fired else ""))
    for record in manifest.get("tool_runs", []):
        print(f"  {record['tool']:<24} {record['requests']} requests, "
              f"exit {record['exit_code']}"
              + (" (cut off)" if record["timed_out"] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
