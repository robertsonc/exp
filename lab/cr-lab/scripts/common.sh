# shellcheck shell=bash disable=SC2034  # the arrays are used by the scripts that source this file
# Shared helpers for the cr-lab scripts (sourced, not run).
set -euo pipefail
LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB=cr-lab
CLIENTS=(client1 client2 client3 client4 client5)
AGENT_NODES=(collector box dash probe-a probe-b probe-c)
c() { printf 'clab-%s-%s' "$LAB" "$1"; }                 # container name of a node
dx() { local n="$1"; shift; docker exec "$(c "$n")" "$@"; }
say() { printf '%s\n' "$*"; }
die() { printf 'cr-lab: ERROR: %s\n' "$*" >&2; exit 1; }
running() { [ "$(docker inspect -f '{{.State.Running}}' "$(c "$1")" 2>/dev/null)" = true ]; }
