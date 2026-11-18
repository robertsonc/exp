#!/usr/bin/env bash
# The board (static/pulse-core.js) and the alerter (lib/exm/pulse.py) must judge the same
# results the same way. This replays real results through both and fails on any difference:
# line states, "since", the last outage, flap counts and where the fault is.
#
#   test/parity.sh [BOARD_URL] [AT] [MINUTES]
#   test/parity.sh http://10.32.98.25 2026-10-27T04:00:00Z 60
#
# Needs node and python3 on this machine; reads /api/history from a running dashboard.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
URL="${1:-http://10.32.98.25}"; AT="${2:-}"; MIN="${3:-60}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
curl -sf "$URL/api/history?minutes=$MIN${AT:+&at=$AT}" > "$TMP/history.json"

# Evaluation times: every 30 s across the window, on the probe's clock.
python3 - "$TMP/history.json" > "$TMP/times.json" <<'PY'
import json, sys
j = json.load(open(sys.argv[1]))
ws = sorted(e["w"] for e in j["events"])
import datetime
ms = lambda s: int(datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000)
lo, hi = ms(ws[0]) + 120000, ms(ws[-1])
print(json.dumps(list(range(lo, hi, 30000))))
PY

node - "$ROOT/lib/exm/static/pulse-core.js" "$TMP/history.json" "$TMP/times.json" > "$TMP/js.json" <<'JS'
const fs = require('fs');
const [core, hist, times] = process.argv.slice(2);
const C = require(core);
const ev = JSON.parse(fs.readFileSync(hist)).events.sort((a, b) => Date.parse(a.w) - Date.parse(b.w));
const out = JSON.parse(fs.readFileSync(times)).map((t) => {
  const pool = ev.filter((e) => Date.parse(e.w) <= t);
  const bsets = [0, 1, 2, 3, 4].map((i) => C.beats(pool, i));
  const st = bsets.map((bs, i) => C.stateOf(bs, i, t));
  return { t, st: st.map((x) => [x.s, x.n, x.f, x.d]), since: bsets.map((bs) => C.sinceOf(bs, true)),
    outage: bsets.map((bs, i) => C.lastOutage(bs, i, t, 900000)), flaps: bsets.map((bs, i) => C.flaps(bs, i, t, 600000)),
    where: C.whereOf(pool, t, st) };
});
process.stdout.write(JSON.stringify(out));
JS

python3 - "$ROOT/lib" "$TMP/history.json" "$TMP/times.json" "$TMP/js.json" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[1])
from exm import pulse as P
ev = sorted(json.load(open(sys.argv[2]))["events"], key=lambda e: P.ms(e["w"]))
times = json.load(open(sys.argv[3]))
js = json.load(open(sys.argv[4]))

def clean(x):                     # JSON from JS drops undefined; treat null and missing alike
    if isinstance(x, dict):
        return {k: clean(v) for k, v in x.items() if v is not None}
    if isinstance(x, list):
        return [clean(v) for v in x]
    return x

diffs, kinds, segs = 0, {}, {}
for t, j in zip(times, js):
    pool = [e for e in ev if P.ms(e["w"]) <= t]
    bsets = [P.beats(pool, i) for i in range(5)]
    st = [P.state_of(bs, i, t) for i, bs in enumerate(bsets)]
    py = {"t": t, "st": [[x["s"], x["n"], x["f"], x["d"]] for x in st], "since": [P.since_of(bs, True) for bs in bsets],
          "outage": [P.last_outage(bs, i, t, 900000) for i, bs in enumerate(bsets)],
          "flaps": [P.flaps(bs, i, t, 600000) for i, bs in enumerate(bsets)], "where": P.where_of(pool, t, st)}
    for k in py:
        if clean(py[k]) != clean(j[k]):
            diffs += 1
            if diffs <= 5:
                print(f"DIFF at {t} {k}:\n  js {json.dumps(clean(j[k]))}\n  py {json.dumps(clean(py[k]))}")
    for x in py["st"]:
        kinds[x[0]] = kinds.get(x[0], 0) + 1
    seg = (py["where"] or {}).get("seg")
    segs[seg] = segs.get(seg, 0) + 1
print(f"{len(times)} moments, {len(ev)} results; line states seen {kinds}; where {segs}; differences: {diffs}")
raise SystemExit(1 if diffs else 0)
PY
