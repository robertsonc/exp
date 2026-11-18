# CR-wp1-allow-shared — `allow_shared` for host mode is not in `exp.probe.config/1`

**What.** `02-probe.md` section 2 says that in `host` mode `mgmt_iface` must differ from the test interface
"unless explicitly `allow_shared: true` (then traceroute's control path is disabled)". The frozen
`shared/schemas/probe.config.schema.json` has no such field, and `01-contracts.md` section 9.1 does not list it.

**Why.** Single-NIC VMs exist (the test interface IS the management interface). Without a field the manager
cannot express the opt-in.

**Workaround in WP-1.** The probe reads an optional top-level boolean `allow_shared` (unknown fields are ignored
by readers, so the frozen schema still validates). It is honoured **only** when `mode == "host"`; in `netns` mode
it is ignored and a port on `mgmt_iface` is always refused. With it set: the mgmt interface may be the single test
port (preflight no longer refuses it for being the mgmt iface / holding the default route / carrying the host's
address), and the control-path traceroute is disabled (`ProbeConfig.control_path` is false).

**Proposed change (additive).** Add `"allow_shared": {"type": "boolean", "default": false}` to the probe config
schema, document it in 9.1, and let the manager expose it only for host-mode components.

**Affected WPs.** WP-0 (schema, fixtures), WP-4/WP-5 (compiler + UI field), WP-6 (none).

**Compatibility.** Fully backward compatible: absent means false; existing documents are unchanged.
