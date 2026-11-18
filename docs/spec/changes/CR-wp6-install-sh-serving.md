# CR-wp6-install-sh-serving: how the manager must serve `install.sh`

**Status:** proposed (clarification, no schema change) | **From:** WP-6 (agent) | **Affects:** WP-5 (manager), WP-7 (packaging)

## What

`agent/install/install.sh` is a template. The manager substitutes three literal tokens at serve time and nothing else:

| Token | Value | Rule the manager must enforce before substituting |
|---|---|---|
| `@@MANAGER_URL@@` | the manager origin, `https://host[:port]` | no path, userinfo, query, quotes or whitespace |
| `@@AGENT_VERSION@@` | the current agent version | semver `^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$` |
| `@@RELEASE_PUBKEY_PEM@@` | the release public key, PEM, newlines kept | `-----BEGIN PUBLIC KEY-----` ... `-----END PUBLIC KEY-----`, base64 body only |

* Each token occurs **exactly once** in the template (a plain string replace is enough) and sits inside single quotes in the
  script. A value containing a single quote would break out of the quoting, so the manager must validate the three values
  (and refuse to serve otherwise) rather than escape them. The installer re-validates the shapes and refuses to run on
  anything else, but it cannot defend against quote injection by whoever serves it.
* The installer pins `@@RELEASE_PUBKEY_PEM@@` as the trust anchor for the release manifest and writes it into
  `/etc/exp/agent.json`. If `POST /api/agent/v1/enrol` returns a different `release_pubkey_pem` the installer warns and keeps
  the pinned key (a key rotation therefore needs a fresh install.sh from the manager, as intended).
* Content type `text/x-shellscript`, `Cache-Control: no-store`; the manager must not add anything to it.

## Optional addition (backward compatible)

`EnrolResponse` may carry `host_name` (the name the admin gave the host). `additionalProperties` is already `true`, so no
schema change is required; install.sh prints it when present (otherwise the local hostname).

## Why

Spec 06-agent.md section 1 says the three values are substituted at serve time but not how safely; the unquoted-injection
risk is on the serving side.

## Compatibility

None needed: this documents what WP-5 must do. Uses only `GET /healthz`, `POST enrol`, `GET desired`, release manifest and
signature and artifact download, all already in `shared/openapi/agent.yaml`.
