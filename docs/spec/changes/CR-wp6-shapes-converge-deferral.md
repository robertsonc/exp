# CR-wp6-shapes-converge-deferral: 06-agent.md section 9 item 2 is verified by WP-7/WP-8, not WP-6

**Status:** proposed (acceptance-test ownership, no contract change) | **From:** WP-6 (agent) | **Affects:** WP-7 (packaging), WP-8 (integration)

## What

Acceptance item 2 ("all shapes converge: collector, dashboard, probe with veth ports, report healthy; probe data reaches
the collector through the compiled wiring") needs signed release tarballs of the collector, dashboard and probe. Those are
produced by `packaging/build.sh` (WP-7) from components owned by other WPs, so WP-6 cannot build them inside `agent/`.

## What WP-6 delivers instead

* `agent/tests/container/test_container_shapes.py::test_all_shapes_converge_and_probe_data_reaches_the_collector` is
  written and complete. It runs in a systemd container with veth wiring against `test/fakes/fake_manager.py`.
* It is skipped with an explicit reason only when `EXP_DIST_DIR` is unset, has no manifest, or holds an UNSIGNED dev build.
  Run it with `EXP_DIST_DIR=<dir with exp-<v>-manifest.json[.sig] and tarballs> pytest agent/tests/container -m harness`.
* The convergence mechanics it depends on (desired-state reconcile, unit install, health gating, rollback) are covered
  by WP-6 tests against synthetic signed releases (items 1, 3-9).

## Request

WP-7/WP-8 run the test above against the first real signed release and record the result in the integration report.
The integrator accepts item 2 as owned by WP-8 for the WP-6 definition of done.

## Compatibility

None: no schema, API or file-format change.
