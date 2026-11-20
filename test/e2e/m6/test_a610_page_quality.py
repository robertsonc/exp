"""A6.10: page quality (12-speedtest-analytics.md sections 7.3, 11).

* self-contained: a capture of EVERY request the phone's browser made proves none left for a host other than the box, its DNS-leg names
  and (the fake) Cloudflare; nothing failed; no CSP violation;
* weight: the page's own resources (HTML + fonts) <= 200 KB gzip (gzip -9 of what the box serves, measured from the phone's namespace);
* animation: a CDP performance trace with 4x CPU throttling (the usual stand-in for a mid-range phone) and the phone's link emulated at
  50 / 25 Mb/s (a mid-range phone on busy venue Wi-Fi; an unthrottled gigabit client would spend the 4x-slowed main thread on data
  delivery, not on the page). The rAF frame timeline of the whole run is bucketed per second; REPORTED per phase; gate: median second
  >= 50 fps (target 60) and no freeze (never more than 2 consecutive seconds under 10 fps). KNOWN LIMIT (CR-m6-e2-correlation-quality): the
  vendored Cloudflare engine posts each upload body as a JS string; `fetch()` encodes it on the main thread (a CPU profile of the run shows
  ~3 s of native `fetch` self time at 4x), so the INTERNET UPLOAD phase drops to ~30-35 fps with isolated sub-10-fps seconds; the other
  phases run 50-60 fps. The trace file and its own frame count are kept;
* reduced motion: `prefers-reduced-motion` runs no animation at all (document.getAnimations() empty during the entire run, gauge jumps)
  and shows the SAME numbers: in both modes every number the page displays equals the number it submitted;
* layout at 390 px matches the reference prototype (docs/spec/prototypes/speed-check.html rendered with its own demo data, same fonts):
  same widths, same section order, section heights within [0.75, 1.30] of the prototype's ([0.4, 1.6] for the two data-driven sections: the header
  with its demo chip and the list of network-team checks), and per-section pixel comparison
  (luminance averaged over 16 x 16 device-pixel cells, sections cropped at their own tops) mean absolute difference <= 0.15 (0..1; 0.35 for the waterfall bar, whose segments are the data).
  The content differs by design (real numbers, the zone chip instead of the demo chip, longer notes), so this is a structural
  tolerance; the screenshots of both pages are kept under e2e-artifacts/m6/shots.
"""
from __future__ import annotations

import json
import re
import shutil
import statistics
import subprocess

import pytest

import m6lib as M

pytestmark = pytest.mark.e2e
LINK = {"downKbps": 50_000, "upKbps": 25_000, "latencyMs": 5}
SECTION_DIFF_MAX = 0.15
SECTION_DIFF_DATA = {"#wf": 0.35}          # the waterfall is a 34-px stacked bar whose segment widths ARE the data
HEIGHT_RATIO = (0.75, 1.30)
DATA_DRIVEN, DATA_RATIO = {".top", "#checks"}, (0.4, 1.6)      # sections whose height follows the data, not the layout
DOC_RATIO = (0.80, 1.30)
FPS_MEDIAN_MIN, FREEZE_FPS, FREEZE_MAX_RUN = 50.0, 10, 2
GZ_BUDGET = 200 * 1024
SECTION_ORDER = [".top", "#stage", ".legs", ".res-top", "#speeds", "#wf", "#checks"]


def per_second(frames: list[float]) -> list[int]:
    """Frames per whole second of the run (the trailing partial second is dropped)."""
    if len(frames) < 3:
        return []
    t0, t1 = frames[0], frames[-1]
    n = int((t1 - t0) / 1000)
    buckets = [0] * n
    for t in frames:
        i = int((t - t0) / 1000)
        if i < n:
            buckets[i] += 1
    return buckets


def trace_frames(path: str) -> int | None:
    """Presented-frame count from the CDP trace (PipelineReporter async spans: one per produced frame), None when absent."""
    try:
        doc = json.load(open(path))
    except (OSError, ValueError):
        return None
    ev = doc["traceEvents"] if isinstance(doc, dict) else doc
    n = sum(1 for e in ev if e.get("name") == "PipelineReporter" and e.get("ph") == "b")
    return n or sum(1 for e in ev if e.get("name") == "DrawFrame")


def gzip_sizes(phone: M.Client, urls: list[str]) -> dict[str, list[int]]:
    snippet = ("import gzip,json,sys,urllib.request\n"
               "out={}\n"
               "for u in json.loads(sys.argv[1]):\n"
               "    b=urllib.request.urlopen(u,timeout=20).read()\n"
               "    out[u]=[len(b),len(gzip.compress(b,9))]\n"
               "print(json.dumps(out))\n")
    r = phone.run("python3", "-I", "-c", snippet, json.dumps(urls))
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout.strip().splitlines()[-1])


def displayed(snap: dict) -> dict[str, float]:
    """The numbers the results page shows, parsed."""
    num = lambda t: float(re.search(r"[0-9]+(?:\.[0-9]+)?", t).group(0))  # noqa: E731
    sp = {s["k"]: num(s["v"]) for s in snap["speeds"]}
    legs = {k: num(v["val"]) for k, v in snap["legs"].items() if re.search(r"[0-9]", v["val"])}
    return {"score": num(snap["score"]), "local_down": sp["Local down"], "local_up": sp["Local up"], "internet_down": sp["Internet down"],
            "internet_up": sp["Internet up"], "local_idle": legs["Wi-Fi and venue network"], "cf_idle": legs["Cloudflare"]}


def same_numbers(snap: dict, req: dict) -> None:
    d, legs = displayed(snap), req["legs"]
    want = {"score": req["score"]["total"] if isinstance(req.get("score"), dict) else req.get("score"), "local_down": legs["local"]["down_mbps"],
            "local_up": legs["local"]["up_mbps"], "internet_down": legs["internet"]["down_mbps"], "internet_up": legs["internet"]["up_mbps"],
            "local_idle": legs["local"]["idle_ms"], "cf_idle": legs["internet"]["idle_ms"]}
    for k, v in want.items():
        if v is None:
            continue
        assert abs(d[k] - v) <= (0.51 if abs(v) >= 10 else 0.06), f"{k}: page shows {d[k]}, submitted {v}"


@pytest.fixture()
def slate(core: M.Core):
    core.clean_slate()
    yield core
    core.clean_slate()


def test_a610_capture_weight_fps_and_prototype(slate: M.Core, artifacts):
    ph = slate.new_client("q-perf")
    slate.identify(ph)
    shots = M.ARTIFACTS / "shots"
    trace = str(M.ARTIFACTS / "a610-trace.json")
    r, tid = slate.run_page(ph, name="a610-perf", timeoutMs=170000, cpuThrottle=4, throttle=LINK, tracePath=trace, waitChecksMs=60000,
                            shotPre="a610-01-start-390", shotResults="a610-02-results-390", shotFinal="a610-03-final-390")
    # ---------------------------------------------------------------- capture: every request went to the box, its DNS-leg names or the (fake) Cloudflare
    urls = r["requests"]
    hosts = {re.match(r"^[a-z]+://([^/:]+)", u).group(1) for u in urls if re.match(r"^https?://", u)}
    assert hosts and all(h in {M.CORE_IP, "speed.cloudflare.com"} or h.endswith("." + M.ZONE) for h in hosts), sorted(hosts)
    assert not [u for u in urls if re.match(r"^(ws|wss|ftp)://", u)], "no other schemes"
    # (the page aborts the in-flight streams of a transfer when its time/byte budget is reached: ERR_ABORTED is by design, any other failure is not)
    hard = [f for f in r["failed"] if "ERR_ABORTED" not in f]
    assert hard == [] and r["csp"] == [] and r["errors"] == [] and r["dialogs"] == [], (hard, r["csp"], r["errors"])
    assert r["cspHeader"] and "default-src 'self'" in r["cspHeader"]
    assert M.CORE_IP in hosts and "speed.cloudflare.com" in hosts
    print(f"A6.10 capture: {len(urls)} requests, hosts {sorted(hosts)}")

    # ---------------------------------------------------------------- weight: the page's own resources, gzip -9
    own = sorted({w["url"] for w in r["loadWire"] if w["url"].startswith(f"http://{M.CORE_IP}/") and "/st/api/" not in w["url"]
                  and "/st/down" not in w["url"] and "/st/up" not in w["url"]})
    assert any(u.endswith(".woff2") for u in own) and len(own) >= 4, own
    sizes = gzip_sizes(ph, own)
    gz = sum(v[1] for v in sizes.values())
    print(f"A6.10 weight: {len(own)} files, raw {sum(v[0] for v in sizes.values())} B, gzip {gz} B (budget {GZ_BUDGET})")
    assert gz <= GZ_BUDGET, (gz, sizes)

    # ---------------------------------------------------------------- animation: fps under 4x CPU throttle (rAF timeline of the run) + the trace
    frames = r["frameTimes"]
    buckets = per_second(frames)
    assert len(buckets) >= 10, f"too short a run to judge: {len(buckets)} s"
    med, p10 = statistics.median(buckets), sorted(buckets)[len(buckets) // 10]
    mean = len(frames) / ((frames[-1] - frames[0]) / 1000)
    by_phase: dict[str, list[float]] = {}
    for t in frames:
        pp = [x for x in r["phases"] if x[0] <= t]
        by_phase.setdefault(pp[-1][1] if pp else "?", []).append(t)
    print("A6.10 fps (4x CPU, link 50/25 Mb/s): mean %.1f, median %.1f, p10 %s, min %s over %d s" % (mean, med, p10, min(buckets), len(buckets)))
    for k, v in by_phase.items():
        if len(v) > 40:
            print("A6.10 fps phase %-26s %5.1f fps (%d frames)" % (k, len(v) / ((v[-1] - v[0]) / 1000), len(v)))
    tf = trace_frames(trace)
    print("A6.10 trace:", trace, "frames in trace:", tf)
    (M.ARTIFACTS / "a610-fps.json").write_text(json.dumps({"mean": mean, "median": med, "p10": p10, "min": min(buckets), "per_second": buckets,
                                                           "trace_frames": tf, "cpu_throttle": 4, "link_kbps": LINK}))
    assert med >= FPS_MEDIAN_MIN, f"median {med} fps < {FPS_MEDIAN_MIN} (target 60)"
    run = longest = 0
    for b in buckets:
        run = run + 1 if b < FREEZE_FPS else 0
        longest = max(longest, run)
    print(f"A6.10 fps: {sum(1 for b in buckets if b < FREEZE_FPS)} seconds under {FREEZE_FPS} fps, longest run {longest} s")
    assert longest <= FREEZE_MAX_RUN, f"the animation froze for {longest} consecutive seconds"
    assert r["animMax"] > 0, "control: the normal run does animate"
    same_numbers(r["first"], r["submissions"][-1]["req"])

    # ---------------------------------------------------------------- the 390-px layout against the reference prototype
    final = r["checked"] or r["final"]
    proto_cfg = {"proto": str(M.REPO / "docs" / "spec" / "prototypes" / "speed-check.html"),
                 "assets": str(M.REPO / "speedtest" / "exp_speedtest" / "static" / "assets"),
                 "realShot": str(shots / "a610-03-final-390.png"), "realBoxes": final["boxes"], "protoShot": str(shots / "a610-prototype-390.png")}
    cfg_path = slate.work / "proto-diff.json"
    cfg_path.write_text(json.dumps(proto_cfg))
    p = subprocess.run([shutil.which("node") or "node", str(M.HERE / "ui" / "proto_diff.js"), str(cfg_path)], capture_output=True, text=True,
                         timeout=240, env=M.node_env(), check=False)
    line = next((ln for ln in p.stdout.splitlines() if ln.startswith("@@RESULT ")), None)
    assert line, p.stdout[-1500:] + p.stderr[-1500:]
    pr = json.loads(line[9:])
    assert pr["scrollW"][0] <= pr["scrollW"][1], "the prototype itself must not scroll sideways at 390"
    rb, pb = final["boxes"], pr["boxes"]
    assert final["scrollWidth"] <= final["clientWidth"] == 390
    present = [s for s in SECTION_ORDER if s in rb and s in pb]
    assert {".top", "#stage", ".legs", ".res-top", "#speeds"} <= set(present), present
    assert [s for _y, s in sorted((rb[s]["y"], s) for s in present)] == [s for _y, s in sorted((pb[s]["y"], s) for s in present)], "section order"
    for s in present:
        assert abs(rb[s]["w"] - pb[s]["w"]) <= 2, (s, rb[s], pb[s])
        ratio = rb[s]["h"] / pb[s]["h"]
        if s in DATA_DRIVEN:   # .top: the prototype's header wraps for its "Demo data" chip; #checks: one line per piece of evidence found
            assert DATA_RATIO[0] <= ratio <= DATA_RATIO[1], (s, rb[s], pb[s])
            continue
        assert HEIGHT_RATIO[0] <= ratio <= HEIGHT_RATIO[1], f"{s}: real {rb[s]['h']:.0f} px vs prototype {pb[s]['h']:.0f} px"
    dr = final["docHeight"] / pr["docHeight"]
    assert DOC_RATIO[0] <= dr <= DOC_RATIO[1], (final["docHeight"], pr["docHeight"])
    sec = pr["cmp"]["sections"]
    print("A6.10 prototype diff (mean abs luminance per section, tolerance %.2f): %s; document height ratio %.2f" %
          (SECTION_DIFF_MAX, {k: round(v["meanAbsDiff"], 3) for k, v in sec.items()}, dr))
    for k, v in sec.items():
        assert v["meanAbsDiff"] <= SECTION_DIFF_DATA.get(k, SECTION_DIFF_MAX), f"{k}: mean abs diff {v['meanAbsDiff']:.3f}"
    (M.ARTIFACTS / "a610-prototype-diff.json").write_text(json.dumps({"sections": sec, "doc_height_ratio": dr, "tolerance": SECTION_DIFF_MAX,
                                                                      "real_boxes": rb, "proto_boxes": pb}))


def test_a610_reduced_motion_same_numbers_no_animation(slate: M.Core):
    ph = slate.new_client("q-red")
    slate.identify(ph)
    r, tid = slate.run_page(ph, name="a610-reduced", timeoutMs=120000, reducedMotion="reduce", shotResults="a610-04-reduced-results-390")
    assert r["animMax"] == 0, f"{r['animMax']} animations ran with prefers-reduced-motion"
    assert r["first"]["anims"] == 0 and r["final"]["anims"] == 0
    same_numbers(r["first"], r["submissions"][-1]["req"])
    assert r["first"]["score"] not in (None, "", "0") and len(r["first"]["speeds"]) == 4 and r["first"]["resultsHidden"] is False
    # the same page without the preference animates (control) and shows its numbers the same way
    ph2 = slate.new_client("q-norm")
    slate.identify(ph2)
    r2, tid2 = slate.run_page(ph2, name="a610-normal", timeoutMs=120000)
    assert r2["animMax"] > 0
    same_numbers(r2["first"], r2["submissions"][-1]["req"])
