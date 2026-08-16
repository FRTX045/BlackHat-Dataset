"""Helpers for the tests that drive the real lab stack.

Not named test_* so unittest does not collect it. Every test module that uses
these is skipped unless LOGFORGE_DOCKER=1: the ordinary suite has to stay
runnable on a bare python3 with no daemon and no network.
"""

import os
import subprocess
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PROJECT = REPO / "projects" / "apache-shopfront"
COMPOSE = PROJECT / "docker-compose.yml"
LOGS = PROJECT / "server" / "logs"
LEDGERS = PROJECT / "traffic" / "ledger"
IMAGE = "logforge/apache-shopfront-web:dev"

ACCESS = LOGS / "access.log"
TAGGED = LOGS / "access.tagged.log"
ERROR = LOGS / "error.log"

# Where the server and the tag proxy answer on each of the three lab networks.
WEB_RES = "203.0.113.2"
WEB_DC = "192.0.2.2"
PROXY_DC = "192.0.2.3"
PROXY_PORT = 8080

# An address inside RemoteIPTrustedProxy (the driver's), and one outside it.
TRUSTED = "203.0.113.4"
UNTRUSTED = "192.0.2.50"

DOCKER_AVAILABLE = os.environ.get("LOGFORGE_DOCKER") == "1"


def docker(*args, **kwargs):
    # errors="replace": responses whose body is an image or an icon are not
    # valid UTF-8, and a helper that raised on them would make every binary
    # asset untestable.
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True,
        errors="replace", **kwargs)


def compose(*args):
    result = docker("compose", "-f", str(COMPOSE), *args)
    if result.returncode != 0:
        raise RuntimeError(
            f"docker compose {' '.join(args)} failed:\n{result.stderr}")
    return result


def request(network, source_ip, url, headers=(), extra=()):
    """Issue one request from a container with a chosen address.

    Reuses the server image because it already carries curl; a separate client
    image would be one more version to pin and to name in the manifest.
    """
    argv = ["run", "--rm", "--network", network, "--ip", source_ip,
            "--entrypoint", "curl", IMAGE, "-s", "-o", "/dev/null",
            "-w", "%{http_code}", *extra]
    for header in headers:
        argv += ["-H", header]
    argv.append(url)
    result = docker(*argv)
    if result.returncode != 0:
        raise RuntimeError(f"request from {source_ip} failed: {result.stderr}")
    return result.stdout.strip()


def fetch(url, source_ip="203.0.113.90", network="lab_res", headers=(), extra=()):
    """Return (status, body) for one request. Body is text."""
    argv = ["run", "--rm", "--network", network, "--ip", source_ip,
            "--entrypoint", "curl", IMAGE, "-s", "-w", "\\n%{http_code}", *extra]
    for header in headers:
        argv += ["-H", header]
    argv.append(url)
    result = docker(*argv)
    if result.returncode != 0:
        raise RuntimeError(f"request for {url} failed: {result.stderr}")
    body, _, status = result.stdout.rpartition("\n")
    return status.strip(), body


def in_container(script, source_ip="203.0.113.90", network="lab_res"):
    """Run a shell snippet in one throwaway container on a lab network.

    Anything needing a session has to go through this rather than repeated
    `request()` calls: each `docker run` is a fresh container, so a cookie jar
    written by one call is gone by the next. Logging in and then acting as the
    logged-in user is one invocation, sharing /tmp/jar.
    """
    result = docker("run", "--rm", "--network", network, "--ip", source_ip,
                    "--entrypoint", "sh", IMAGE, "-c", script)
    if result.returncode != 0:
        raise RuntimeError(f"container script failed: {result.stderr}")
    return result.stdout


def response_headers(network, source_ip, url):
    """Return the response headers of one request, lowercased by name."""
    result = docker(
        "run", "--rm", "--network", network, "--ip", source_ip,
        "--entrypoint", "curl", IMAGE, "-s", "-o", "/dev/null", "-D", "-", url)
    if result.returncode != 0:
        raise RuntimeError(f"request from {source_ip} failed: {result.stderr}")
    headers = {}
    for line in result.stdout.splitlines():
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    return headers


def lines(path):
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def wait_for_lines(path, previous_count, expected=1, timeout=5.0):
    """Return the lines appended to `path` since `previous_count`.

    Apache writes its log line after the response is complete, so a client can
    return marginally before the line lands. Polling rather than sleeping keeps
    the suite fast when it is not racing and honest when it is.
    """
    deadline = time.monotonic() + timeout
    while True:
        current = lines(path)
        if len(current) >= previous_count + expected:
            return current[previous_count:]
        if time.monotonic() > deadline:
            return current[previous_count:]
        time.sleep(0.05)


#: SQL that puts the application back to the state a freshly seeded container
#: has, without regenerating 130 product images.
#:
#: The database is bind-mounted, so it survives between runs -- and a build
#: leaves it dirty in ways that break the tests silently. The credential_hunter
#: campaign locks the demo account out, and every test that signs in as demo
#: then gets a 429 rather than a 302. That is the application behaving exactly
#: as designed; it is the tests that were assuming a clean slate they had never
#: had to ask for.
_RESET_SQL = (
    "DELETE FROM login_attempts;"
    "DELETE FROM users WHERE id > 4;"
    "UPDATE users SET avatar = NULL;"
)


def reset_app_state():
    """Undo whatever a previous build or test left behind in the application."""
    compose("exec", "-T", "web", "sh", "-c",
            "php -r '$p=new PDO(\"sqlite:/var/www/html/data/catalogue.sqlite\");"
            f'$p->exec("{_RESET_SQL}");\' ; '
            "rm -f /var/www/html/uploads/*")


def wait_for_web(services=("web",), timeout=60, reset=True):
    """Bring the named services up, block until Apache answers, reset state."""
    compose("up", "-d", "--build", *services)
    deadline = time.monotonic() + timeout
    while True:
        try:
            if request("lab_res", "203.0.113.90",
                       f"http://{WEB_RES}/.lab-health") == "200":
                break
        except RuntimeError:
            pass
        if time.monotonic() > deadline:
            raise RuntimeError("web never became healthy")
        time.sleep(0.5)

    if reset:
        reset_app_state()
