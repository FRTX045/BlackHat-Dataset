# The attacker image: real security tools, pinned by the distribution that
# ships them, run against the lab's own application and nothing else.
#
# One image rather than one per tool. Nine separate images would be nine
# version-drift surfaces, and the manifest has to name the exact version of
# everything that produced a line -- which is trivial from one image and
# tedious from nine.
#
# Debian's archive is the pin. `apt-cache policy` at build time records what
# was actually installed, and tools.py reads the versions back out at run time
# so the manifest carries what ran rather than what was intended.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# sqlmap   - the SQL injection surface on /search
# whatweb  - web server and framework fingerprinting
# dirb     - directory brute-forcing with a real wordlist
# gobuster - the same ground as dirb, with a visibly different signature
# hydra    - credential attacks against /login
# nmap     - service and http-* NSE scripts
# curl     - hand-driven requests and the manual playbooks' fallback
# python3  - runs the playbook runner, which is stdlib-only
#
# nikto is deliberately not here: it was dropped from Debian and bookworm has
# no package for it. whatweb covers the fingerprinting it was doing, and the
# hand-written recon playbook covers the known-file probing with better
# labels. Installing it from upstream would make the version pin depend on a
# release page instead of on the archive, which is the whole reason this image
# uses distribution packages.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      sqlmap whatweb dirb gobuster hydra nmap curl ca-certificates python3 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/logforge
