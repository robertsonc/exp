# exp measurement schema

The single contract probes, collectors, and the dashboard share. Reference implementation:
`exp_schema.py` (`Measurement`). Wire format is JSON; one object per measured transaction.

```json
{
  "schema": "exp.measurement/1",
  "ts": "2026-11-18T20:00:00.123Z",
  "probe": "probe-a1",
  "site": "hall-b",
  "test": "dns",
  "target": "www.example.com",
  "outcome": "ok",
  "duration_ms": 23.4,
  "metrics": { "rtt_ms": 23.4, "rcode": 0 },
  "labels": { "resolver": "10.1.0.1" },
  "error": null,
  "agent_ver": "0.1.0"
}
```

| Field | Type | Notes |
|---|---|---|
| `schema` | string | `exp.measurement/1` |
| `ts` | string | UTC ISO-8601, ms precision, `Z`. Set at emit if omitted. |
| `probe` | slug | stable probe id, `[a-z0-9-]` |
| `site` | slug | logical location; defaults to `default` |
| `test` | ident | test kind: `gateway`, `dhcp`, `dns`, `app`, `throughput`, `heartbeat`, … |
| `target` | string | what was tested; becomes a series label only if ≤ 80 chars |
| `outcome` | enum | `ok` \| `degraded` \| `fail` \| `error` |
| `duration_ms` | number? | primary timing; mapped to `exp_<test>_duration_ms` |
| `metrics` | map<name,number> | numeric measurements → one VictoriaMetrics series each |
| `labels` | map<name,string> | **low-cardinality** dimensions only |
| `error` | string? | short message on `fail`/`error` |
| `agent_ver` | string | emitting probe/agent version |

## Mapping to VictoriaMetrics

Each entry in `metrics` (and `duration_ms`) becomes a time series:

- **series name:** `exp_<test>_<metric>` — e.g. `exp_dns_rtt_ms`, `exp_gateway_duration_ms`
- **labels:** `probe`, `site`, `outcome`, plus each key in `labels` (and `target` if short)
- **value / timestamp:** the metric value at `ts`

**Cardinality rule:** anything that can take many distinct values (full URLs, trace hops, IDs)
stays in the record/event log — never a series label. `metric` and `label` names must match
`[a-zA-Z_][a-zA-Z0-9_]*`.

## Untrusted input

Probe reports are **untrusted** at the collector. `Measurement.validate()` enforces:

- **Reserved labels** — a probe may not set `probe`, `site`, `outcome`, `target`, or any
  `__`-prefixed key in `labels`; those are set by the trusted base in `series()`. (And `series()`
  applies the trusted labels last, so they win even on an un-validated record.)
- **Bounds** — ≤ 20 labels, ≤ 50 metrics, label values ≤ 128 chars, `target` ≤ 256 chars; no
  control characters in `target` or label values; metrics must be finite numbers.
- **Timestamp** — `ts` must be a parseable ISO-8601 string (validated up front, not at write
  time). Clock-skew bounding is a **collector** policy, not the schema's — probes legitimately
  backfill old records from their local spool after an outage.
