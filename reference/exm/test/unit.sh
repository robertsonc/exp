#!/usr/bin/env bash
# Offline unit tests (no network, root or containers): about a minute. Needs python3 >= 3.11; node for the parity check.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 test/unit.py "$@"
