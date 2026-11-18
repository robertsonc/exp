"""Shared helpers for the end-to-end suites (test/e2e/): throwaway PKI, a local Access JWKS issuer, the
manager under `wrangler dev` with local D1/R2, docker systemd hosts and a tiny DHCP/DNS LAN.

Everything here is test-only and local: throwaway keys live in tmp dirs, nothing contacts a real network,
and no production code path knows about any of it (the Worker is configured by environment only)."""
