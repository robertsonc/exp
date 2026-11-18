#!/usr/bin/env bash
# Generate an Ed25519 release keypair OUTSIDE the repository.
#   gen-release-key.sh <private-key-path> [<public-key-path>]
# The private key is written with mode 0600 and NEVER printed. Only the public key path is printed.
# Refuses to overwrite, and refuses a path inside a git checkout / this repo.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ $# -ge 1 ] && [ $# -le 2 ] || { sed -n '2,5p' "${BASH_SOURCE[0]}" >&2; exit 2; }
priv="$1"; pub="${2:-${1%.pem}-pub.pem}"
[ "$pub" != "$priv" ] || { echo "gen-release-key: public and private paths must differ" >&2; exit 2; }
for f in "$priv" "$pub"; do
  [ ! -e "$f" ] || { echo "gen-release-key: refusing to overwrite $f" >&2; exit 1; }
  d="$(cd "$(dirname "$f")" 2>/dev/null && pwd -P)" || { echo "gen-release-key: directory of $f does not exist" >&2; exit 1; }
  real="$d/$(basename "$f")"
  repo="$(cd "$HERE/.." && pwd -P)"
  case "$real" in "$repo"/*) echo "gen-release-key: $f is inside the repository; choose a path outside it" >&2; exit 1 ;; esac
  if git -C "$d" rev-parse --show-toplevel >/dev/null 2>&1; then
    echo "gen-release-key: $f is inside a git checkout; choose a path outside any repository" >&2; exit 1
  fi
done
umask 077
openssl genpkey -algorithm ed25519 -out "$priv" 2>/dev/null
chmod 600 "$priv"
openssl pkey -in "$priv" -pubout -out "$pub" 2>/dev/null
chmod 644 "$pub"
echo "$pub"
