#!/usr/bin/env bash
# Export the manager's D1 database to a file OUTSIDE the repository (nightly cron on an operator machine).
#
#   backup.sh --out-dir /secure/backups/exp [--d1-name exp-manager] [--keep 14] [--config FILE]
#
# The export holds the database as SQL: encrypted secrets (ciphertext only), audit log, fleet state. It does NOT hold
# EXP_MASTER_KEY: back that up separately and offline (without it the ciphertext cannot be read). Treat the file as
# sensitive: it is written 0600 into a 0700 directory. Needs CLOUDFLARE_API_TOKEN (D1:Edit) and CLOUDFLARE_ACCOUNT_ID.
# D1 Time Travel (point-in-time restore, 30 days) is the first line of defence; this is the independent copy.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANAGER="$(cd "$HERE/.." && pwd)"
REPO_ROOT="$(cd "$MANAGER/.." && pwd)"
OUT_DIR=""; D1_NAME="exp-manager"; KEEP=14; CONFIG=""
die() { printf 'backup: ERROR: %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//' >&2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --out-dir) OUT_DIR="${2:?--out-dir needs a directory}"; shift 2 ;;
    --d1-name) D1_NAME="${2:?--d1-name needs a value}"; shift 2 ;;
    --keep) KEEP="${2:?--keep needs a number}"; shift 2 ;;
    --config) CONFIG="${2:?--config needs a file}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown argument: $1" ;;
  esac
done
[ -n "$OUT_DIR" ] || { usage; die "--out-dir is required"; }
printf '%s' "$D1_NAME" | grep -Eq '^[a-z0-9][a-z0-9-]{0,62}$' || die "--d1-name must be lowercase letters, digits and hyphens"
printf '%s' "$KEEP" | grep -Eq '^[0-9]{1,3}$' && [ "$KEEP" -ge 1 ] || die "--keep must be a number from 1 to 999"
[ -n "${CLOUDFLARE_API_TOKEN:-}" ] && [ -n "${CLOUDFLARE_ACCOUNT_ID:-}" ] || die "set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID"

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd -P)"
case "$OUT_DIR/" in "$REPO_ROOT"/*) die "--out-dir is inside the repository ($REPO_ROOT); a backup must live outside it" ;; esac
chmod 700 "$OUT_DIR"

umask 077
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
FILE="$OUT_DIR/$D1_NAME-$STAMP.sql"
ARGS=(d1 export "$D1_NAME" --remote --output "$FILE")
[ -z "$CONFIG" ] || ARGS+=(-c "$CONFIG")
(cd "$MANAGER" && npx --no-install wrangler "${ARGS[@]}" </dev/null >&2) || { rm -f "$FILE"; die "wrangler d1 export failed"; }
[ -s "$FILE" ] || { rm -f "$FILE"; die "the export is empty"; }
chmod 600 "$FILE"
grep -q 'CREATE TABLE' "$FILE" || die "the export does not look like a database dump: $FILE"

# retention: keep the newest $KEEP exports of this database in this directory
# shellcheck disable=SC2012
ls -1t "$OUT_DIR/$D1_NAME"-*.sql 2>/dev/null | tail -n +"$((KEEP + 1))" | while IFS= read -r old; do rm -f -- "$old"; done
printf 'backup: wrote %s (%s bytes)\n' "$FILE" "$(wc -c < "$FILE")"
printf 'backup: reminder: EXP_MASTER_KEY is NOT in this file; keep your offline copy of it.\n'
