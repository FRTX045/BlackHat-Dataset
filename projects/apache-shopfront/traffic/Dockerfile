FROM python:3.12-slim

# The only third-party dependency in the traffic path, and it lives here rather
# than on the host: tools/ and shared/ must run on a bare python3 with no pip.
# Pinned so a rebuilt image drives the same client behaviour.
RUN pip install --no-cache-dir httpx==0.28.1

WORKDIR /opt/logforge
