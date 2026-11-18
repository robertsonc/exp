# CR-wp4-status-component-facts: component facts are validated strictly in status reports

**From:** WP-4 **Affects:** WP-6 (agent) **Status:** informational

`status.schema.json` validates `components[].facts.{tls_fingerprint_sha256,listen,url}` but allows extra keys.
The manager mirrors that exactly: a malformed fingerprint / listen / url rejects the **whole** report with
`400 invalid_request` (details list the paths). The agent should therefore drop invalid facts from a component
health document rather than send them, otherwise the host's status goes stale. Unknown extra facts are
accepted and stored only inside the bounded `status_latest.report_json`; only the three wiring facts are
copied into `components.facts_json`.
