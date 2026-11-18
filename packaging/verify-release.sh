#!/usr/bin/env bash
# Verify a release directory: manifest signature (Ed25519, openssl) and every artifact's size+sha256.
#   verify-release.sh <dist dir> <release-pub.pem> [--version X.Y.Z]
# Exit 0 only if everything checks out. Used by CI, by build.sh and by operators.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"
fail() { echo "verify-release: FAIL: $*" >&2; exit 1; }
[ $# -ge 2 ] || { sed -n '2,5p' "${BASH_SOURCE[0]}" >&2; exit 2; }
dist="$1"; pub="$2"; shift 2
version=""
while [ $# -gt 0 ]; do
  case "$1" in
    --version) version="${2:?}"; shift 2 ;;
    *) echo "verify-release: unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -d "$dist" ] || fail "no such directory: $dist"
[ -f "$pub" ] || fail "public key not found: $pub"
if [ -n "$version" ]; then
  manifest="$dist/exp-$version-manifest.json"
  [ -f "$manifest" ] || fail "no manifest $manifest"
else
  shopt -s nullglob
  ms=("$dist"/exp-*-manifest.json)
  [ ${#ms[@]} -eq 1 ] || fail "found ${#ms[@]} manifests in $dist; pass --version"
  manifest="${ms[0]}"
fi
sig="$manifest.sig"
[ -f "$sig" ] || fail "no signature file $(basename "$sig") (unsigned dev build?)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/exp-verify.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
base64 -d < "$sig" > "$tmp/sig.bin" 2>/dev/null || fail "signature is not valid base64"
[ "$(wc -c < "$tmp/sig.bin")" -eq 64 ] || fail "signature is not a 64-byte Ed25519 signature"
openssl pkeyutl -verify -pubin -inkey "$pub" -rawin -in "$manifest" -sigfile "$tmp/sig.bin" >/dev/null 2>&1 \
  || fail "manifest signature does not verify against $pub"
"$PYTHON" -I "$HERE/pack.py" check-manifest "$manifest" --dist "$dist" || fail "manifest/artifact check failed"
echo "verify-release: OK ($(basename "$manifest"))"
