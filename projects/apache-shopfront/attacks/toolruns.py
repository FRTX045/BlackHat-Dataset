"""Real security tools, declared so the manifest can record what actually ran.

Named toolruns rather than tools on purpose: the repository already has a
top-level `tools/` package, and a second module called `tools` shadows it in
sys.modules for whichever importer gets there first. That collision broke
the build entry point's own tests in a way that pointed nowhere near the
cause.

Every tool run gets its own container, its own fixed source address, **its own
tag-proxy port**, and is pointed at the proxy rather than at Apache. Tools will
not send our header, and labelling their traffic by address and time window is
only ever as exact as the clock -- the proxy stamps a request id on each
request instead, so a tool line joins as precisely as a driver line.

The port is what makes the label right. The proxy records the actor configured
for the port a request arrived on, and `labels.py` decides a tool run's
category from that actor rather than from the individual requests, because no
single request in a wordlist walk reveals that the activity is a wordlist walk.
An earlier version of this file put every tool on one shared port under the
generic actor `tool`; the labeller never saw the `tool:dirb` prefix it was
written to match, fell through to per-request guessing, and **98% of 9,293
tool requests in two shipped datasets were labelled `browsing`**. Directory
brute-forcing recorded as ordinary browsing is exactly the confidently-wrong
label this project exists not to produce.

That same docstring used to claim one nikto run would split into
`reconnaissance` for its fingerprint probes and `injection` for its payloads.
It would not have, and nikto is no longer here at all. Per-request labelling is
unreliable for tools: sqlmap's boolean payloads carry no UNION and no
`or 1=1`, so the payload regex catches about one request in forty-five.

The declarations are data rather than code so `tools/build.py` can execute them
and record each one verbatim: exact command line, source address, tool version,
start and end time. A tool that appears in the dataset and not in the manifest
is a hard failure of the provenance gate.

**Which tools are here, and which are not.** Checked against the archive
rather than assumed, after an earlier version of this note got it wrong in
both directions.

Here: sqlmap, dirb, gobuster, hydra, nmap and whatweb, plus curl for
hand-driven requests. All six are Debian packages, which is the version pin.

`nikto` is **not** here, and not by choice: it was dropped from Debian and has
no package in bookworm. `whatweb` covers the fingerprinting half of what nikto
was doing in this image, and the hand-written `recon` playbook covers the
known-file probing half with better labels.

`gobuster` and `ffuf` *are* packaged, contrary to what this file used to say
about them being Go release binaries needing their own download paths.
gobuster is now included on that basis; ffuf is left out because it would
duplicate gobuster and dirb against the same wordlist rather than add a
distinct signature.

Still absent: `nuclei` and `wpscan` (a Ruby gem), and ZAP, which needs a JRE.
Adding a JVM would triple the image and make the pin depend on upstream
release pages rather than on Debian's archive.

Stdlib only.
"""

from typing import NamedTuple

#: Where the tag proxy answers on each network. Tools are pointed here, never
#: at Apache directly, so their requests acquire an id on the way through.
PROXY = {"lab_dc": "192.0.2.3", "lab_cloud": "198.51.100.3"}

#: Ports start here, one per tool. Not one shared port, and the difference is
#: not cosmetic: the proxy's ledger records the actor configured for the port
#: the request arrived on, and `labels.py` decides a tool run's category from
#: that actor rather than from the individual requests, because no single
#: request in a wordlist walk reveals that the activity is a wordlist walk.
#:
#: Every tool sharing port 8080 under the generic actor `tool` is exactly what
#: went wrong once: the labeller never saw the `tool:dirb` prefix it was
#: written to match, fell through to per-request guessing, and labelled 98% of
#: 9,293 tool requests `browsing`.
PROXY_PORT_BASE = 8080


class ToolRun(NamedTuple):
    #: Short name, used for the compose service and the ledger's actor field.
    name: str
    #: The binary, for the manifest's version lookup.
    binary: str
    #: Argument vector. `{proxy}` is substituted with the proxy's address on
    #: this run's network and `{port}` with this run's own proxy port.
    argv: tuple
    network: str
    address: str
    #: What it was pointed at, in words, for the manifest table.
    target: str
    #: How its traffic should be labelled when the request itself is not
    #: self-describing. `labels.py` still decides per request where it can.
    actor: str
    #: The ceiling on this run, in seconds. sqlmap and dirb will keep going
    #: for as long as they are given, and a build that never returns is worse
    #: than a manifest recording that a tool was cut off -- which is a true
    #: fact about the run, and one a consumer needs in order to read the line
    #: count that tool produced.
    timeout_seconds: int = 120
    #: The tag-proxy port this run arrives on. Its own, so the proxy's ledger
    #: can name which tool sent each request. Assigned by `_numbered` below.
    port: int = PROXY_PORT_BASE


_DECLARED = (
    ToolRun(
        name="sqlmap-search",
        binary="sqlmap",
        argv=("sqlmap", "-u", "http://{proxy}:{port}/search?q=oak",
              "--batch", "--level=2", "--risk=1", "--technique=BU",
              "--dbms=sqlite", "--flush-session", "--disable-coloring",
              "--timeout=10", "--retries=1", "--crawl=0"),
        network="lab_dc", address="192.0.2.31",
        target="the planted SQL injection on /search",
        actor="tool:sqlmap",
        # The longest of the five. Boolean and UNION techniques against one
        # parameter is a small search, but sqlmap re-probes on every failure
        # and the ceiling has to leave room for that.
        timeout_seconds=240),
    ToolRun(
        name="whatweb-root",
        binary="whatweb",
        # Aggression 3 probes rather than only reading the first response,
        # which is what makes it show up in a log as more than one line.
        argv=("whatweb", "-a", "3", "--colour=never", "--max-threads=4",
              "--open-timeout=10", "--read-timeout=15",
              "http://{proxy}:{port}/"),
        network="lab_dc", address="192.0.2.32",
        target="the site root, fingerprinting",
        actor="tool:whatweb",
        timeout_seconds=150),
    ToolRun(
        name="gobuster-common",
        binary="gobuster",
        # The same wordlist dirb uses, deliberately: two tools over identical
        # ground leave visibly different traces -- different agent, different
        # concurrency, different ordering -- and a log containing both is a
        # better test of whether a detector learned the tool or the behaviour.
        argv=("gobuster", "dir", "-u", "http://{proxy}:{port}/",
              "-w", "/usr/share/dirb/wordlists/common.txt",
              "-t", "4", "-q", "--no-color", "--timeout", "10s"),
        network="lab_cloud", address="198.51.100.33",
        target="/ with dirb's common wordlist, at four threads",
        actor="tool:gobuster",
        timeout_seconds=180),
    ToolRun(
        name="dirb-common",
        binary="dirb",
        argv=("dirb", "http://{proxy}:{port}/",
              "/usr/share/dirb/wordlists/common.txt", "-S", "-r", "-z", "10"),
        network="lab_cloud", address="198.51.100.31",
        target="/ with dirb's common wordlist",
        actor="tool:dirb",
        # 4,600 words at a 10ms delay is about a minute if nothing stalls.
        timeout_seconds=180),
    # The same two tools over dirb's 959-word `small.txt` rather than its
    # 4,614-word `common.txt`.
    #
    # Not a convenience: the small tier covers one day, and two full
    # common.txt walks inside it put enumeration at 11% of the log and the
    # attack share at 14% against a 2-8% target. Two scans of that size
    # against one small shop in a single day is also simply a lot of
    # scanning. The week-long medium tier has room for the full wordlist and
    # uses it, so the tiers differ in how much scanning happened rather than
    # in what the scanning was.
    ToolRun(
        name="gobuster-small",
        binary="gobuster",
        argv=("gobuster", "dir", "-u", "http://{proxy}:{port}/",
              "-w", "/usr/share/dirb/wordlists/small.txt",
              "-t", "4", "-q", "--no-color", "--timeout", "10s"),
        network="lab_cloud", address="198.51.100.34",
        target="/ with dirb's small wordlist, at four threads",
        actor="tool:gobuster",
        timeout_seconds=120),
    ToolRun(
        name="dirb-small",
        binary="dirb",
        argv=("dirb", "http://{proxy}:{port}/",
              "/usr/share/dirb/wordlists/small.txt", "-S", "-r", "-z", "10"),
        network="lab_cloud", address="198.51.100.35",
        target="/ with dirb's small wordlist",
        actor="tool:dirb",
        timeout_seconds=120),
    # Declared, and deliberately not in any scenario's `tools` list.
    #
    # Measured: hydra 9.4's http-post-form module sends its first request and
    # then blocks, whatever the failure condition is set to -- `F=`, a
    # substring of the body, or `S=302` all behave the same. Three separate
    # 40-second runs produced three requests between them. The login answers
    # **401 with no `WWW-Authenticate` header**, which is a protocol violation
    # on the application's side, and hydra appears to be waiting on the
    # challenge that never comes.
    #
    # Kept here rather than deleted so the reason is recorded next to the
    # invocation, and because fixing the header on the application side would
    # change what the hardened login teaches. The hand-written `brute_force`
    # and `credential_stuffing` playbooks cover the same endpoint with better
    # labels, and the `credential_hunter` campaign is built around it.
    ToolRun(
        name="hydra-login",
        binary="hydra",
        argv=("hydra", "-l", "demo", "-P", "/opt/logforge/projects/"
              "apache-shopfront/attacks/wordlists/passwords.txt",
              "-s", "{port}", "-f", "-t", "4", "{proxy}", "http-post-form",
              "/login:username=^USER^&password=^PASS^:Those details"),
        network="lab_dc", address="192.0.2.33",
        target="POST /login",
        actor="tool:hydra",
        # -f stops at the first hit, and the hardened login locks the account
        # after five failures, so this one ends quickly either way.
        timeout_seconds=90),
    ToolRun(
        name="nmap-http",
        binary="nmap",
        # -sV is not optional here. nmap only applies its http-* scripts to
        # ports it already believes are HTTP, and it knows 8080 as http-proxy
        # but has no entry for the higher ports this tool now uses. Without
        # version detection it finds the port open, runs no script, and makes
        # no HTTP request at all -- which the build correctly refused to
        # record as a tool run that happened.
        #
        # The service probes it sends on the way are themselves useful: some
        # are not valid HTTP, so Apache logs them as malformed requests from a
        # known reconnaissance source, which is a shape the hand-written
        # playbooks cannot produce.
        argv=("nmap", "-Pn", "-sV", "--version-intensity", "2",
              "-p", "{port}", "--script",
              "http-headers,http-methods,http-title", "{proxy}"),
        network="lab_cloud", address="198.51.100.32",
        target="the proxy's HTTP port with http-* NSE scripts",
        actor="tool:nmap",
        timeout_seconds=90),
)


def _numbered(declared):
    """Give every run its own proxy port, in declaration order.

    Assigned here rather than written into each declaration so the ports
    cannot drift out of sequence or collide when a tool is added or removed --
    a duplicate would silently merge two tools under one actor, which is the
    bug this whole arrangement exists to prevent.
    """
    return tuple(run._replace(port=PROXY_PORT_BASE + index)
                 for index, run in enumerate(declared))


TOOL_RUNS = _numbered(_DECLARED)


def argv_for(run):
    """The exact argument vector, with the proxy address and port filled in."""
    return tuple(arg.format(proxy=PROXY[run.network], port=run.port)
                 for arg in run.argv)


def service_for(run):
    """The compose service that carries this run's image and address."""
    return f"tool-{run.name}"


def container_argv(run):
    """What the container is actually asked to execute.

    The timeout wraps the invocation rather than being folded into it, so the
    command line the manifest publishes is still the command line the tool
    saw. `--kill-after` matters as much as the timeout: a tool that ignores
    SIGTERM would otherwise sit there holding the static address the next run
    needs, and the failure would surface as "address already in use" three
    steps later with nothing pointing at the cause.
    """
    return ("timeout", "--kill-after=10", str(run.timeout_seconds),
            *argv_for(run))


def command_line(run):
    """The invocation as a single string, for the manifest."""
    return " ".join(argv_for(run))


def port_map_entries():
    """Tag-proxy port configuration these runs rely on.

    Every tool arrives in peer mode, so the address the proxy declares is the
    tool container's own -- which is what makes the manifest's source-address
    column true rather than asserted.

    One port each, carrying that tool's actor. `traffic/ports.json` is the
    committed copy the proxy actually reads, and a test asserts the two agree:
    if they drift, the proxy rejects the connection on an unconfigured port
    and the failure surfaces as a tool that reached nothing.
    """
    return {run.port: {"mode": "peer", "actor": run.actor}
            for run in TOOL_RUNS}
