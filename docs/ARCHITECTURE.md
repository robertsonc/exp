# exp — Architecture (summary)

**Superseded by [`SPEC.md`](../SPEC.md) and [`docs/spec/`](spec/).** This page is a short orientation only.

- **Control plane:** Cloudflare-hosted manager (Workers + D1 + R2 + Access) holds intent and
  compiles per-host desired state. Agents on Ubuntu hosts enrol with a one-line bootstrap and pull
  desired state over outbound HTTPS — no SSH, no stored host passwords (decision D1). Software is
  installed only from releases signed with an offline key (D10).
- **Data plane (on-prem only):** probes push measurements to collectors over pinned TLS; collectors
  store metrics in VictoriaMetrics (D2) and records/incidents in SQLite, run the single rules
  engine (D3), alert, and serve dashboards, which federate one or more collectors and stay usable
  with the internet down (D8).
- **Contracts:** [`spec/01-contracts.md`](spec/01-contracts.md). Measurement schema:
  [`../shared/SCHEMA.md`](../shared/SCHEMA.md).

Earlier drafts listed KV and Durable Objects for the manager; v1 drops both for simplicity (D4).
