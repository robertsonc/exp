#!/usr/bin/env bash
# Obtain every vendored artifact pinned in packaging/vendor.lock into the cache
# (default packaging/.cache, or $EXP_VENDOR_CACHE) and verify its pinned sha256.
# A sha256 mismatch aborts (exit 1); an unreachable source falls through to the next one.
#   fetch-vendor.sh [--lock FILE] [--cache DIR] [--component C] [--arch A] [--verify-only]
# EXP_VENDOR_SOURCES=url,docker restricts which source types may be used.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"
lock="$HERE/vendor.lock"
cache="${EXP_VENDOR_CACHE:-$HERE/.cache}"
cmd=fetch
extra=()
while [ $# -gt 0 ]; do
  case "$1" in
    --lock) lock="$2"; shift 2 ;;
    --cache) cache="$2"; shift 2 ;;
    --component) extra+=(--component "$2"); shift 2 ;;
    --arch) extra+=(--arch "$2"); shift 2 ;;
    --verify-only) cmd=verify; shift ;;
    -h|--help) sed -n '2,7p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "fetch-vendor.sh: unknown argument: $1" >&2; exit 2 ;;
  esac
done
exec "$PYTHON" -I "$HERE/vendor.py" "$cmd" --lock "$lock" --cache "$cache" "${extra[@]+"${extra[@]}"}"
