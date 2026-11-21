#!/usr/bin/env bash
# Print the comma-separated components whose source tree satisfies the packaging convention's required files
# (bin/exp-<c>, exp_<c>/__init__.py, systemd/exp-*.service|timer, requirements.apt). CI uses this while
# components land in separate work packages so the package job tests what exists; the release workflow does
# NOT use it (every component must build). Empty output = nothing is ready yet.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out=()
for c in agent probe collector dashboard runner speedtest; do
  d="$root/$c"
  [ -f "$d/bin/exp-$c" ] && [ -f "$d/exp_$c/__init__.py" ] && [ -f "$d/requirements.apt" ] || continue
  compgen -G "$d/systemd/exp-*.service" >/dev/null || compgen -G "$d/systemd/exp-*.timer" >/dev/null || continue
  out+=("$c")
done
(IFS=,; echo "${out[*]:-}")
