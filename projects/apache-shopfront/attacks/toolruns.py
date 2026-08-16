"""Real security tools, declared so the manifest can record what actually ran.

Named toolruns rather than tools on purpose: the repository already has a
top-level `tools/` package, and a second module called `tools` shadows it in
sys.modules for whichever importer gets there first. That collision broke
the build entry point's own tests in a way that pointed nowhere near the
cause.

Every tool run gets its own container, its own fixed source address, and is
pointed at the **tag proxy** rather than at Apache. Tools will not send our
header, and labelling their traffic by address and time window is only ever as
exact as the clock -- the proxy stamps a request id on each request instead, so
a tool line joins as precisely as a driver line and one nikto run splits into
`reconnaissance` for its fingerprint probes and `injection` for its payloads.

The declarations are data rather than code so `tools/build.py` can execute them
and record each one verbatim: exact command line, source address, tool version,
start and end time. A tool that appears in the dataset and not in the manifest
is a hard failure of the provenance gate.

**Which tools are here, and which are not.** The plan named nine. This image
carries the six Debian packages: sqlmap, nikto, dirb, hydra and nmap, plus curl
for hand-driven requests. `gobuster`, `ffuf` and `nuclei` are Go release
binaries and `wpscan` is a Ruby gem; ZAP needs a JRE. Adding four download
paths and a JVM to the image would triple its size and make the version pin
depend on upstream release pages rather than on Debian's archive. Their
absence is stated in the dataset README rather than papered over -- and the
hand-written playbooks already cover the same ground with better labels.

Stdlib only.
"""

from typing import NamedTuple

#: Where the tag proxy answers on each network. Tools are pointed here, never
#: at Apache directly, so their requests acquire an id on the way through.
PROXY = {"lab_dc": "192.0.2.3", "lab_cloud": "198.51.100.3"}
PROXY_PORT = 8080


class ToolRun(NamedTuple):
    #: Short name, used for the compose service and the ledger's actor field.
    name: str
    #: The binary, for the manifest's version lookup.
    binary: str
    #: Argument vector. `{proxy}` is substituted with the proxy's address on
    #: this run's network.
    argv: tuple
    network: str
    address: str
    #: What it was pointed at, in words, for the manifest table.
    target: str
    #: How its traffic should be labelled when the request itself is not
    #: self-describing. `labels.py` still decides per request where it can.
    actor: str


TOOL_RUNS = (
    ToolRun(
        name="sqlmap-search",
        binary="sqlmap",
        argv=("sqlmap", "-u", "http://{proxy}:8080/search?q=oak",
              "--batch", "--level=2", "--risk=1", "--technique=BU",
              "--dbms=sqlite", "--flush-session", "--disable-coloring",
              "--timeout=10", "--retries=1", "--crawl=0"),
        network="lab_dc", address="192.0.2.31",
        target="the planted SQL injection on /search",
        actor="tool:sqlmap"),
    ToolRun(
        name="nikto-root",
        binary="nikto",
        argv=("nikto", "-h", "http://{proxy}:8080/", "-maxtime", "90s",
              "-Tuning", "123b", "-nointeractive"),
        network="lab_dc", address="192.0.2.32",
        target="the site root",
        actor="tool:nikto"),
    ToolRun(
        name="dirb-common",
        binary="dirb",
        argv=("dirb", "http://{proxy}:8080/",
              "/usr/share/dirb/wordlists/common.txt", "-S", "-r", "-z", "10"),
        network="lab_cloud", address="198.51.100.31",
        target="/ with dirb's common wordlist",
        actor="tool:dirb"),
    ToolRun(
        name="hydra-login",
        binary="hydra",
        argv=("hydra", "-l", "demo", "-P", "/opt/logforge/projects/"
              "apache-shopfront/attacks/wordlists/passwords.txt",
              "-s", "8080", "-f", "-t", "4", "{proxy}", "http-post-form",
              "/login:username=^USER^&password=^PASS^:Those details"),
        network="lab_dc", address="192.0.2.33",
        target="POST /login",
        actor="tool:hydra"),
    ToolRun(
        name="nmap-http",
        binary="nmap",
        argv=("nmap", "-Pn", "-p", "8080", "--script",
              "http-headers,http-methods,http-title", "{proxy}"),
        network="lab_cloud", address="198.51.100.32",
        target="the proxy's HTTP port with http-* NSE scripts",
        actor="tool:nmap"),
)


def argv_for(run):
    """The exact argument vector, with the proxy address substituted in."""
    proxy = PROXY[run.network]
    return tuple(arg.format(proxy=proxy) for arg in run.argv)


def command_line(run):
    """The invocation as a single string, for the manifest."""
    return " ".join(argv_for(run))


def port_map_entries():
    """Tag-proxy port configuration these runs rely on.

    Every tool arrives on the proxy's peer-mode port, so the address the proxy
    declares is the tool container's own -- which is what makes the manifest's
    source-address column true.
    """
    return {PROXY_PORT: {"mode": "peer", "actor": "tool"}}
