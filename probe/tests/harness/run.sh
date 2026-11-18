#!/bin/sh
# Real-namespace tests for the probe: builds a tiny ubuntu:24.04 image (iproute2, busybox, python3,
# pytest, dnsmasq) and runs probe/tests/harness inside a PRIVILEGED container, so every veth and
# namespace the tests create lives in the container's own network namespace, never on the host.
#   probe/tests/harness/run.sh [extra pytest args]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
image=${EXP_PROBE_HARNESS_IMAGE:-exp-probe-harness:local}
docker build -q -t "$image" "$here" >/dev/null
exec docker run --rm --privileged -e EXP_HARNESS=1 -e PYTHONDONTWRITEBYTECODE=1 \
    -v "$repo:/exp:ro" "$image" \
    python3 -m pytest /exp/probe/tests/harness -m harness -p no:cacheprovider -q -rs "$@"
