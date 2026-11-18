#!/usr/bin/env bash
# Create the dev/test virtualenv (.venv) for CI with a chosen Python (default 3.10). Mirrors `make venv`
# (which pins 3.10) plus dnspython 2.7.0 so the probe tests can import the vendored dependency's twin.
# Dev tooling only: nothing installed here is shipped in a tarball.
set -euo pipefail
py="${1:-3.10}"
cd "$(dirname "${BASH_SOURCE[0]}")/.."
uv venv --python "$py" .venv
uv pip install --python .venv/bin/python pytest hypothesis ruff jsonschema referencing pyyaml openapi-spec-validator "dnspython==2.7.0"
