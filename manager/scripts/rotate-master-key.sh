#!/usr/bin/env bash
# Rotate EXP_MASTER_KEY WITH re-encryption (05-manager.md section 6, docs/deployments/exp-control.md "Master key rotation").
#
#   rotate-master-key.sh --old-key-file FILE [--new-key-file FILE | --new-key-stdin] [-c wrangler.toml] [--dry-run]
#   rotate-master-key.sh --old-key-stdin     [--new-key-file FILE]                    [-c wrangler.toml] [--dry-run]
#
# The script CANNOT read the current secret back from Cloudflare, so the operator supplies the OLD key (the one in your
# offline backup) by file or stdin, never argv. The NEW key is read from a file / stdin, or generated (default) and shown ONCE
# on the terminal only. Then:
#   1. wrangler secret put EXP_MASTER_KEY_PREVIOUS   <- old key   (stdin)
#   2. wrangler secret put EXP_MASTER_KEY            <- new key   (stdin)
# From that moment the manager decrypts by key id with either key and the 5-minute cron re-seals every stored value under the
# new key (200 rows per run). Watch GET /api/admin/v1/settings/master-key (or Settings -> Master key) until
# safe_to_remove_previous is true, then:  wrangler secret delete EXP_MASTER_KEY_PREVIOUS
#
# Options:
#   --old-key-file FILE   file holding the current (old) key, base64 of 32 bytes
#   --old-key-stdin       read the old key from stdin (then the new key cannot come from stdin)
#   --new-key-file FILE   file holding the new key
#   --new-key-stdin       read the new key from stdin (then the old key must come from a file)
#   (neither new-key flag) generate a new key with openssl and print it once, to the terminal only
#   -c, --config FILE     wrangler config (default: .deploy/wrangler.generated.toml when it exists, else wrangler.toml)
#   --dry-run             validate inputs and print what would be done; execute nothing, set nothing
#
# Never logs key material: keys are only ever passed to wrangler on stdin and (the generated one) to the terminal.
# Key ids shown are first 16 hex of sha256("exp-key-id/v1|" + key text): not secret, they match the ids in the admin API.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANAGER="$(cd "$HERE/.." && pwd)"

die() { printf 'rotate-master-key: %s\n' "$*" >&2; exit 1; }
log() { printf 'rotate-master-key: %s\n' "$*" >&2; }

OLD_FILE="" OLD_STDIN=0 NEW_FILE="" NEW_STDIN=0 CONFIG="" DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --old-key-file) [ $# -ge 2 ] || die "--old-key-file needs a value"; OLD_FILE="$2"; shift 2 ;;
    --old-key-stdin) OLD_STDIN=1; shift ;;
    --new-key-file) [ $# -ge 2 ] || die "--new-key-file needs a value"; NEW_FILE="$2"; shift 2 ;;
    --new-key-stdin) NEW_STDIN=1; shift ;;
    -c|--config) [ $# -ge 2 ] || die "$1 needs a value"; CONFIG="$2"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    --old-key|--new-key|--key) die "keys are never accepted as arguments (they would show up in ps and shell history): use --old-key-file / --old-key-stdin and --new-key-file / --new-key-stdin" ;;
    -h|--help) sed -n '2,29p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

command -v openssl >/dev/null || die "openssl is required"
[ -n "$OLD_FILE" ] || [ "$OLD_STDIN" = 1 ] || die "the OLD key must be supplied with --old-key-file FILE or --old-key-stdin (it cannot be read back from Cloudflare)"
[ -z "$OLD_FILE" ] || [ "$OLD_STDIN" = 0 ] || die "give the old key once: --old-key-file or --old-key-stdin"
[ -z "$NEW_FILE" ] || [ "$NEW_STDIN" = 0 ] || die "give the new key once: --new-key-file or --new-key-stdin"
[ "$OLD_STDIN" = 0 ] || [ "$NEW_STDIN" = 0 ] || die "only one key can come from stdin: use a file for the other"

read_key() { # read_key SOURCE(file path or "-") -> prints the key (first line, trimmed)
  local raw
  if [ "$1" = "-" ]; then IFS= read -r raw || true; else
    [ -f "$1" ] || die "key file not found: $1"
    IFS= read -r raw < "$1" || true
  fi
  printf '%s' "$raw" | tr -d '[:space:]'
}
valid_key() { # base64 of exactly 32 bytes
  [[ "$1" =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || return 1
  [ "$(printf '%s' "$1" | openssl base64 -d -A 2>/dev/null | wc -c | tr -d ' ')" = 32 ]
}
key_id() { printf 'exp-key-id/v1|%s' "$1" | openssl dgst -sha256 -r | cut -c1-16; }

if [ "$OLD_STDIN" = 1 ]; then OLD_KEY="$(read_key -)"; else OLD_KEY="$(read_key "$OLD_FILE")"; fi
valid_key "$OLD_KEY" || die "the old key is not base64 of exactly 32 bytes"

GENERATED=0
if [ "$NEW_STDIN" = 1 ]; then NEW_KEY="$(read_key -)"
elif [ -n "$NEW_FILE" ]; then NEW_KEY="$(read_key "$NEW_FILE")"
elif [ "$DRY" = 1 ]; then NEW_KEY=""  # nothing is generated (or shown) in a dry run
else NEW_KEY="$(openssl rand -base64 32)"; GENERATED=1
fi
if [ -n "$NEW_KEY" ]; then
  valid_key "$NEW_KEY" || die "the new key is not base64 of exactly 32 bytes"
  [ "$NEW_KEY" != "$OLD_KEY" ] || die "the new key is identical to the old key: refusing (a rotation needs a different key)"
fi

if [ -z "$CONFIG" ]; then
  if [ -f "$MANAGER/.deploy/wrangler.generated.toml" ]; then CONFIG="$MANAGER/.deploy/wrangler.generated.toml"; else CONFIG="$MANAGER/wrangler.toml"; fi
fi
[ -f "$CONFIG" ] || die "wrangler config not found: $CONFIG"
WR=(npx --no-install wrangler)

OLD_ID="$(key_id "$OLD_KEY")"
log "old key id: $OLD_ID"
if [ -n "$NEW_KEY" ]; then log "new key id: $(key_id "$NEW_KEY")"; fi

if [ "$DRY" = 1 ]; then
  log "[dry-run] would run: wrangler secret put EXP_MASTER_KEY_PREVIOUS -c $CONFIG   (old key on stdin)"
  log "[dry-run] would run: wrangler secret put EXP_MASTER_KEY -c $CONFIG            (new key on stdin$([ -n "$NEW_KEY" ] || printf ', generated and shown once on the terminal'))"
  log "[dry-run] then: watch GET /api/admin/v1/settings/master-key until safe_to_remove_previous is true"
  log "[dry-run] then: wrangler secret delete EXP_MASTER_KEY_PREVIOUS -c $CONFIG"
  log "[dry-run] nothing was changed"
  exit 0
fi

# order matters: PREVIOUS first, so there is never a moment where the new key is current and the old one is unknown
log "1/2 setting EXP_MASTER_KEY_PREVIOUS (old key)"
printf '%s' "$OLD_KEY" | "${WR[@]}" secret put EXP_MASTER_KEY_PREVIOUS -c "$CONFIG" >&2 || die "storing EXP_MASTER_KEY_PREVIOUS failed; nothing else was changed"
log "2/2 setting EXP_MASTER_KEY (new key)"
printf '%s' "$NEW_KEY" | "${WR[@]}" secret put EXP_MASTER_KEY -c "$CONFIG" >&2 || die "storing EXP_MASTER_KEY failed; EXP_MASTER_KEY_PREVIOUS is set to the old key, which is harmless: the old key is still current. Re-run to retry"

if [ "$GENERATED" = 1 ]; then
  TTY=/dev/stderr
  { : >/dev/tty; } 2>/dev/null && TTY=/dev/tty
  {
    echo
    echo "################################################################################"
    echo "#  NEW EXP_MASTER_KEY WAS GENERATED. BACK IT UP OFFLINE NOW. IT IS SHOWN ONCE.  #"
    echo "################################################################################"
    echo
    echo "    $NEW_KEY"
    echo
    echo "  Replace the old key in your offline backup with this one only AFTER the re-encryption"
    echo "  below has finished (keep both until then). It is not written to any file."
    echo
  } > "$TTY"
  [ "$TTY" != /dev/stderr ] || log "WARNING: no controlling terminal: the key above went to stderr; make sure stderr is not being logged"
fi
unset OLD_KEY NEW_KEY

cat >&2 <<MSG

Rotation started. Both keys are active: the manager decrypts each stored value by its key id, writes with the new key, and
the 5-minute cron re-encrypts the rest (200 rows per run).

  Watch:   GET /api/admin/v1/settings/master-key   (or Settings -> Master key in the admin UI)
           wait for  "safe_to_remove_previous": true   (remaining_previous: 0)
  Then:    npx --no-install wrangler secret delete EXP_MASTER_KEY_PREVIOUS -c $CONFIG
  Never delete EXP_MASTER_KEY_PREVIOUS earlier: values still sealed by the old key would become unreadable.
  Old key id: $OLD_ID (rows stamped with it are "remaining").
MSG
