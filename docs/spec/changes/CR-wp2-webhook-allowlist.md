# CR-wp2-webhook-allowlist

**From:** WP-2 (collector) - **Affects:** WP-0 (`collector.config.schema.json`), WP-4 (admin API/UI for webhooks), WP-6 (agent renders the config) - **Status:** proposed

## What
SR-15: webhooks must be `https`, destinations that resolve to private, loopback or link-local addresses are
refused "unless explicitly allowlisted", redirects are never followed. `01-contracts.md` has no place to put
the allowlist (`exp.collector.config/1` `alerts` has no such key; `webhooks.json` items are `{id, format, url}`).

## Why
On-prem chat servers (Mattermost, an internal Teams relay) live on private addresses; without an allowlist
they can never be reached, and with an implicit one SR-15 would be void.

## Proposed change
`exp.collector.config/1`: `alerts.webhook_allow`: array (max 16) of strings, each an IP address, a CIDR or a
host name (case-insensitive exact match). A destination whose every resolved address is public needs no entry.
An entry permits ONLY the matching addresses/host; `http://` and redirects stay refused regardless.

## Compatibility
Additive (optional key, readers ignore unknown keys). The collector already reads `alerts.webhook_allow` if
present (`exp_collector.app.CollectorApp`, `exp_collector.alerts.check_destination`); until the schema lists
it, nothing but a hand-edited `/etc/exp/collector/config.json` can set it, and the default is "public
destinations only".
