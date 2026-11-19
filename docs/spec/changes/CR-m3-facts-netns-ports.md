# CR-m3-facts-netns-ports: host facts report a probe's test ports that live in their netns

Raised by: M3 step m3c (A3.3, manager unreachable). Affects: agent (`exp_agent/facts.py`). `06-agent.md` §3.1 (facts) and `05-manager.md` §5 (probe ports validation) are unchanged in wording; this makes the agent do what they already assume.

## Defect (found by the A3.3 end-to-end test)

In netns mode a running probe moves each test port into its own namespace `exp-<port id>` (`02-probe.md` §3). The agent collected `interfaces` with `ip -j link/addr show` in the host's namespace only, so a port in use by a running probe disappeared from the facts after the probe started. The manager validates a probe's `ports` against `facts.interfaces` (`validateProbePorts`: `unknown_interface`), so every `PATCH components/{id}` that carried the stored `ports` (any config edit of a running probe, including the admin UI's) and every `PUT components/{id}/ports` was refused with `422 unknown_interface` until the probe was stopped.

## Change (agent only; no contract change)

`interface_facts` additionally runs `ip -n exp-<port id> -j link|addr show` (argv only, `port id` validated against the slug pattern) for every port of the applied probe config that is not visible in the host namespace, and reports that interface (`in_use_by: probe:<port id>`, `state`, `mac`, `addrs`) like any other. A missing namespace or interface adds nothing. Interfaces visible in the host namespace are never looked up in a namespace.

## Test

`agent/tests/test_agent_metrics_facts.py::test_a_probe_port_inside_its_netns_is_still_reported_as_an_interface_in_use`; end to end `test/e2e/m3/test_a33_manager_down.py` (a probe config edit made while the manager is unreachable is applied after recovery).
