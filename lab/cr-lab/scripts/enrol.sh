#!/usr/bin/env bash
# Enrol the lab's exp hosts with the manager. Reads tokens.env (gitignored, NODE=expe_...; see tokens.env.example) and
# runs the manager's own installer inside each node, exactly the command the manager's "Add host" page shows.
#   scripts/enrol.sh            enrol every node listed in tokens.env
#   scripts/enrol.sh box dash   only those nodes
# Tokens are single-use: delete tokens.env (or the used lines) afterwards.
source "$(dirname "$0")/common.sh"
MANAGER="${EXP_MANAGER:-https://exp-control.harnessed.cloud}"
[[ "$MANAGER" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || die "EXP_MANAGER must be https://host[:port]"
TOK="$LAB_DIR/tokens.env"
[ -f "$TOK" ] || die "no $TOK (copy tokens.env.example and paste the tokens from the manager)"
[ "$(stat -c %a "$TOK")" = 600 ] || { chmod 600 "$TOK"; say "tightened $TOK to 0600"; }
declare -A tokens=()
while IFS= read -r line || [ -n "$line" ]; do
  line="${line%%#*}"; line="${line//[[:space:]]/}"; [ -n "$line" ] || continue
  node="${line%%=*}"; val="${line#*=}"
  case " ${AGENT_NODES[*]} " in *" $node "*) ;; *) die "tokens.env: unknown node '$node' (one of: ${AGENT_NODES[*]})" ;; esac
  [[ "$val" =~ ^expe_[A-Za-z0-9_-]{43}$ ]] || die "tokens.env: the value for $node is not an enrol token (expe_ + 43 characters)"
  tokens[$node]="$val"
done < "$TOK"
targets=("$@"); [ ${#targets[@]} -gt 0 ] || targets=("${!tokens[@]}")
[ ${#targets[@]} -gt 0 ] || die "tokens.env has no tokens"
rc=0
for node in "${targets[@]}"; do
  [ -n "${tokens[$node]:-}" ] || { say "$node: no token in tokens.env, skipped"; continue; }
  running "$node" || die "$node is not running"
  say "== $node"
  # The token travels on stdin into the container and is handed to the installer the way the manager documents it.
  if printf '%s\n' "${tokens[$node]}" | docker exec -i ${HTTPS_PROXY:+-e HTTPS_PROXY="$HTTPS_PROXY"} "$(c "$node")" \
       bash -c 'set -euo pipefail; IFS= read -r t; curl -fsSL --max-time 60 "$0/install.sh" | bash -s -- "$t"' "$MANAGER"; then
    say "$node: enrolled"
  else
    say "$node: FAILED (see output above)"; rc=1
  fi
done
exit $rc
