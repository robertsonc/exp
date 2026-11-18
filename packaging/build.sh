#!/usr/bin/env bash
# exp release builder (WP-7). Reproducible, vendored, signed.
#
#   packaging/build.sh --release X.Y.Z [options]   signed release build (needs EXP_RELEASE_KEY)
#   packaging/build.sh [options]                   dev build of ./VERSION, UNSIGNED
#
# Options:
#   --release VERSION | --version VERSION   version to build (default: ./VERSION)
#   --unsigned          do not sign (manifest gets no .sig and an UNSIGNED-DEV-BUILD.txt marker)
#   --out DIR           output directory (default: <repo>/dist)
#   --repo DIR          source tree (default: parent of packaging/)
#   --lock FILE         vendor lock (default: packaging/vendor.lock)
#   --cache DIR         vendor cache (default: $EXP_VENDOR_CACHE or packaging/.cache)
#   --components a,b    restrict to these components
#   --pubkey FILE       public key used for the post-sign verification
#                       (default: $EXP_RELEASE_PUBKEY or packaging/keys/release-pub.pem)
#   --min-agent-version V   manifest min_agent_version (default 0.1.0)
#   --notes-url URL     manifest notes_url (default: derived from origin remote if it is on github.com)
#   --no-fetch          do not fetch vendor files; verify what is in the cache
#
# Environment: EXP_DIST_DIR (output dir), EXP_RELEASE_KEY (path to Ed25519 private key; outside the repo, mode 0600),
#   SOURCE_DATE_EPOCH (default: HEAD commit time), PYTHON (default python3).
# The key is never printed. See packaging/README.md.
set -euo pipefail
umask 022

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"
PACK=("$PYTHON" -I "$HERE/pack.py")

die() { echo "build.sh: ERROR: $*" >&2; exit 1; }
note() { echo "build.sh: $*" >&2; }

repo="$(cd "$HERE/.." && pwd)"
version="" ; signed=auto ; out="${EXP_DIST_DIR:-}" ; lock="$HERE/vendor.lock"
cache="${EXP_VENDOR_CACHE:-$HERE/.cache}"
only="" ; pubkey="${EXP_RELEASE_PUBKEY:-$HERE/keys/release-pub.pem}"
min_agent="0.1.0" ; notes_url="" ; fetch=1 ; release=0

while [ $# -gt 0 ]; do
  case "$1" in
    --release) release=1; version="${2:?--release needs a version}"; shift 2 ;;
    --version) version="${2:?--version needs a version}"; shift 2 ;;
    --unsigned) signed=no; shift ;;
    --out) out="${2:?}"; shift 2 ;;
    --repo) repo="$(cd "${2:?}" && pwd)"; shift 2 ;;
    --lock) lock="${2:?}"; shift 2 ;;
    --cache) cache="${2:?}"; shift 2 ;;
    --components) only="${2:?}"; shift 2 ;;
    --pubkey) pubkey="${2:?}"; shift 2 ;;
    --min-agent-version) min_agent="${2:?}"; shift 2 ;;
    --notes-url) notes_url="${2:?}"; shift 2 ;;
    --no-fetch) fetch=0; shift ;;
    -h|--help) sed -n '2,26p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

if [ "$release" = 1 ]; then
  [ "${EXP_ALLOW_FALLBACK_VENDOR:-}" = "1" ] && die "--release refuses EXP_ALLOW_FALLBACK_VENDOR=1: official releases must use only upstream-verified vendored files (SR-11)"
  export EXP_RELEASE_BUILD=1
fi

[ -n "$version" ] || version="$(tr -d '[:space:]' < "$repo/VERSION" 2>/dev/null)" || true
[ -n "$version" ] || die "no version: pass --release X.Y.Z or provide $repo/VERSION"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "version '$version' is not semver"
[ -n "$out" ] || out="$repo/dist"
if [ "$signed" = auto ]; then
  if [ "$release" = 1 ]; then signed=yes; else signed=no; fi
fi

# --- preflight: key hygiene BEFORE any work (SR-10) -------------------------------------------
if [ "$signed" = yes ]; then
  "${PACK[@]}" check-key --key "${EXP_RELEASE_KEY:-}" --repo "$repo" --repo "$(cd "$HERE/.." && pwd)" \
    || exit 1
  [ -f "$pubkey" ] || die "public key $pubkey not found (packaging/keys/release-pub.pem is provided by the owner; or set EXP_RELEASE_PUBKEY)"
fi
command -v openssl >/dev/null || [ "$signed" = no ] || die "openssl is required for signing"

epoch="$("${PACK[@]}" epoch --repo "$repo")" || exit 1
export SOURCE_DATE_EPOCH="$epoch"
note "version $version, SOURCE_DATE_EPOCH=$epoch ($signed signing)"

# --- which components ------------------------------------------------------------------------
comps=()
if [ -n "$only" ]; then
  IFS=, read -r -a comps <<< "$only"
else
  while IFS= read -r c; do [ -n "$c" ] && comps+=("$c"); done < <("${PACK[@]}" detect --repo "$repo")
fi
[ -n "$only" ] || for c in agent probe collector dashboard runner; do
  found=0; for x in ${comps[@]+"${comps[@]}"}; do [ "$x" = "$c" ] && found=1; done
  [ "$found" = 1 ] && continue
  [ "${EXP_PACKAGE_STRICT:-}" = 1 ] && die "component $c has no code (bin/ and exp_$c/ absent) and EXP_PACKAGE_STRICT=1"
  note "skipping $c (no code: bin/ and exp_$c/ absent)"
done
[ ${#comps[@]} -gt 0 ] || die "no components to package under $repo"

work="$(mktemp -d "${TMPDIR:-/tmp}/exp-build.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"
out="$(cd "$out" && pwd)"
rm -f "$out/exp-$version-manifest.json" "$out/exp-$version-manifest.json.sig" "$out/UNSIGNED-DEV-BUILD.txt"

artifacts=()
for c in "${comps[@]}"; do
  arches="$("${PACK[@]}" arches --lock "$lock" --component "$c")" || exit 1
  for a in $arches; do
    if [ "$fetch" = 1 ]; then
      "$HERE/fetch-vendor.sh" --lock "$lock" --cache "$cache" --component "$c" --arch "$a" || exit 1
    fi
    note "assembling $c ($a)"
    stage="$work/stage-$c-$a"; mkdir -p "$stage"
    top="$("${PACK[@]}" assemble --repo "$repo" --component "$c" --version "$version" --arch "$a" \
            --lock "$lock" --cache "$cache" --stage "$stage" --epoch "$epoch")" || exit 1
    "${PACK[@]}" compilecheck --stage-top "$top" || exit 1
    art="$out/exp-$c-$version-$a.tar.gz"
    "${PACK[@]}" tar --top "$top" --out "$art" --epoch "$epoch" || exit 1
    artifacts+=("$art")
    note "wrote $(basename "$art")"
  done
done

# --- manifest (canonical bytes, written once) -------------------------------------------------
if [ -z "$notes_url" ]; then
  remote="$(git -C "$repo" remote get-url origin 2>/dev/null || true)"
  if [[ "$remote" =~ ^(https://github\.com/|git@github\.com:)([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)$ ]]; then
    notes_url="https://github.com/${BASH_REMATCH[2]%.git}/releases/tag/v$version"
  fi
fi
manifest="$out/exp-$version-manifest.json"
"${PACK[@]}" manifest --version "$version" --epoch "$epoch" --min-agent "$min_agent" \
  ${notes_url:+--notes-url "$notes_url"} --out "$manifest" "${artifacts[@]}" || exit 1
"${PACK[@]}" check-manifest "$manifest" --dist "$out" || exit 1

if [ "$signed" = no ]; then
  cat > "$out/UNSIGNED-DEV-BUILD.txt" <<MSG
UNSIGNED DEV BUILD of exp $version. exp-$version-manifest.json has NO signature.
Agents will refuse it. Never publish or install these artifacts on a real site.
MSG
  note "WARNING: UNSIGNED dev build (no .sig); not releasable"
  note "done: $out"
  exit 0
fi

# --- sign + verify ----------------------------------------------------------------------------
sigbin="$work/manifest.sig.bin"
openssl pkeyutl -sign -rawin -inkey "$EXP_RELEASE_KEY" -in "$manifest" -out "$sigbin" 2>/dev/null \
  || die "signing failed (is EXP_RELEASE_KEY an Ed25519 private key PEM?)"
"${PACK[@]}" b64 "$sigbin" "$manifest.sig"
if ! "$HERE/verify-release.sh" "$out" "$pubkey" --version "$version" >/dev/null; then
  rm -f "$manifest.sig"
  die "signature does NOT verify against $pubkey (wrong keypair?); signature removed"
fi
note "signed and verified against $(basename "$pubkey")"
note "done: $out"
